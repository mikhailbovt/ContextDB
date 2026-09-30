//! Bounded private pipe exchange. Timeout closes the child, never repeats work.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    sync::{Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use contextdb_service::ServiceResult;
use serde_json::Value;

use super::{LocalReaderConfig, unavailable};

const MAX_FRAME: usize = 16 * 1024 * 1024;
// Every observed response prefix fits the native inline capture boundary.
const MAX_RESPONSE: usize = 256 * 1024;
const CLEANUP_GRACE: Duration = Duration::from_millis(200);

pub(super) struct Frame {
    pub bytes: Vec<u8>,
    pub complete: bool,
}
impl Frame {
    pub fn value(self) -> ServiceResult<Value> {
        if !self.complete {
            return Err(unavailable("reader bridge response was interrupted"));
        }
        let value: Value = serde_json::from_slice(&self.bytes)
            .map_err(|_| unavailable("reader bridge response invalid"))?;
        if value.get("error").is_some() {
            return Err(unavailable("local reader bridge refused the operation"));
        }
        Ok(value)
    }
}
struct Job {
    bytes: Vec<u8>,
    response: mpsc::Sender<Frame>,
}
struct Process {
    child: Child,
    jobs: Option<mpsc::SyncSender<Job>>,
}
impl Process {
    fn stop(&mut self) {
        self.jobs.take();
        let _ = self.child.kill();
        let until = Instant::now() + CLEANUP_GRACE;
        while Instant::now() < until {
            match self.child.try_wait() {
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                _ => break,
            }
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) struct Bridge {
    process: Mutex<Process>,
    deadline: Mutex<Instant>,
    timeout: Duration,
}
impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}
impl Bridge {
    pub fn spawn(config: &LocalReaderConfig) -> ServiceResult<Self> {
        if !config.program.is_absolute()
            || !config.program.is_file()
            || config.args.len() > 32
            || config
                .args
                .iter()
                .any(|a| a.len() > 4096 || a.contains('\0'))
            || !(50..=120_000).contains(&config.timeout_millis)
        {
            return Err(unavailable(
                "reader launch configuration exceeds local bounds",
            ));
        }
        let mut command = Command::new(&config.program);
        command
            .args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for name in [
            "CONTEXTDB_TOKEN_KEY_HEX",
            "CONTEXTDB_TOKEN_KEY_FILE",
            "CONTEXTDB_NATIVE_MASTER_KEY_HEX",
            "CONTEXTDB_GATEWAY_KEY_HEX",
        ] {
            command.env_remove(name);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let child = command
            .spawn()
            .map_err(|_| unavailable("local reader process could not start"))?;
        let (jobs, incoming) = mpsc::sync_channel::<Job>(1);
        let mut process = Process {
            child,
            jobs: Some(jobs),
        };
        let mut input = process
            .child
            .stdin
            .take()
            .ok_or_else(|| unavailable("reader stdin unavailable"))?;
        let output = process
            .child
            .stdout
            .take()
            .ok_or_else(|| unavailable("reader stdout unavailable"))?;
        thread::Builder::new()
            .name("contextdb-reader-pipe".into())
            .spawn(move || {
                let mut output = BufReader::new(output);
                while let Ok(job) = incoming.recv() {
                    if input
                        .write_all(&job.bytes)
                        .and_then(|()| input.flush())
                        .is_err()
                    {
                        let _ = job.response.send(Frame {
                            bytes: Vec::new(),
                            complete: false,
                        });
                        break;
                    }
                    let frame = read_frame(&mut output);
                    let complete = frame.complete;
                    let _ = job.response.send(frame);
                    if !complete {
                        break;
                    }
                }
            })
            .map_err(|_| unavailable("reader pipe worker could not start"))?;
        let timeout = Duration::from_millis(config.timeout_millis);
        Ok(Self {
            process: Mutex::new(process),
            deadline: Mutex::new(Instant::now() + timeout),
            timeout,
        })
    }
    pub fn begin_turn(&self) -> ServiceResult<()> {
        *self
            .deadline
            .lock()
            .map_err(|_| unavailable("reader deadline unavailable"))? =
            Instant::now() + self.timeout;
        Ok(())
    }
    pub fn exchange(&self, request: &Value) -> ServiceResult<Frame> {
        let mut bytes = serde_json::to_vec(request)
            .map_err(|_| unavailable("reader request encoding failed"))?;
        if bytes.len() >= MAX_FRAME {
            return Err(unavailable("reader request exceeds bounded frame"));
        }
        bytes.push(b'\n');
        let mut process = self
            .process
            .lock()
            .map_err(|_| unavailable("reader process state unavailable"))?;
        let remaining = self
            .deadline
            .lock()
            .map_err(|_| unavailable("reader deadline unavailable"))?
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(unavailable("reader turn deadline expired"));
        }
        let (response, result) = mpsc::channel();
        process
            .jobs
            .as_ref()
            .ok_or_else(|| unavailable("reader process is closed"))?
            .try_send(Job { bytes, response })
            .map_err(|_| unavailable("reader pipe is unavailable"))?;
        match result.recv_timeout(remaining) {
            Ok(frame) if frame.complete => Ok(frame),
            Ok(frame) if !frame.bytes.is_empty() => {
                process.stop();
                Ok(frame)
            }
            Ok(_) => {
                process.stop();
                Err(unavailable("reader stopped without an observed response"))
            }
            Err(_) => {
                process.stop();
                match result.recv_timeout(CLEANUP_GRACE) {
                    Ok(mut frame) if !frame.bytes.is_empty() => {
                        frame.complete = false;
                        Ok(frame)
                    }
                    _ => Err(unavailable("reader exchange deadline or transport failed")),
                }
            }
        }
    }
}
fn read_frame(output: &mut impl BufRead) -> Frame {
    let mut bytes = Vec::new();
    loop {
        let chunk = match output.fill_buf() {
            Ok(chunk) if !chunk.is_empty() => chunk,
            _ => {
                return Frame {
                    bytes,
                    complete: false,
                };
            }
        };
        let length = chunk
            .iter()
            .position(|b| *b == b'\n')
            .map_or(chunk.len(), |end| end + 1);
        let available = MAX_RESPONSE.saturating_sub(bytes.len());
        let take = length.min(available);
        bytes.extend_from_slice(&chunk[..take]);
        let finished = take == length && chunk[length - 1] == b'\n';
        output.consume(take);
        if finished {
            bytes.pop();
            return Frame {
                bytes,
                complete: true,
            };
        }
        if take < length || bytes.len() == MAX_RESPONSE {
            return Frame {
                bytes,
                complete: false,
            };
        }
    }
}
