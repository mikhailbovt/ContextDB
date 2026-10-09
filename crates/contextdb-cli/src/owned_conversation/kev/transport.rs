//! One owned pipe, one inflight frame, no queued context or transport retry.

use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use contextdb_context::Result;
use contextdb_recall::QueryBudget;
use zeroize::Zeroizing;

use super::{
    config::{KevConfig, MAX_META},
    refused,
};

pub(super) struct Job {
    pub(super) bytes: Zeroizing<Vec<u8>>,
    pub(super) result: mpsc::Sender<Result<Vec<u8>>>,
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KevPipeJob")
            .field("frame_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

pub(super) struct Process {
    child: Child,
    jobs: Option<mpsc::SyncSender<Job>>,
    io: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KevProcess")
            .field("open", &self.jobs.is_some())
            .finish_non_exhaustive()
    }
}

impl Process {
    pub(super) fn spawn(
        config: &KevConfig,
        config_digest: &str,
    ) -> Result<(Self, mpsc::Receiver<Result<Vec<u8>>>)> {
        let mut command = Command::new(&config.program);
        command
            .args(&config.args)
            .arg(&config.worker)
            .arg("--corpus")
            .arg(&config.corpus)
            .arg("--model-lock")
            .arg(&config.model_lock)
            .arg("--output-root")
            .arg(&config.output_root)
            .arg("--run-name")
            .arg(&config.run_name)
            .arg("--bundle-sha256")
            .arg(&config.bundle_sha256)
            .arg("--config-sha256")
            .arg(config_digest)
            .arg("--worker-sha256")
            .arg(&config.worker_sha256)
            .arg("--startup-timeout-micros")
            .arg(config.limits.startup_timeout_micros.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
        // Keep OS/runtime discovery only; no owner credentials or Python import overrides.
        for name in ["SystemRoot", "WINDIR", "PATH", "TEMP", "TMP", "CUDA_PATH"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("HF_HUB_DISABLE_TELEMETRY", "1")
            .env("TOKENIZERS_PARALLELISM", "false");
        if let Some(parent) = config.worker.parent() {
            command.current_dir(parent);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let child = command
            .spawn()
            .map_err(|_| refused("worker launch refused"))?;
        let (sender, receiver) = mpsc::sync_channel::<Job>(1);
        let (ready, ready_result) = mpsc::channel();
        let mut process = Self {
            child,
            jobs: Some(sender),
            io: None,
        };
        let mut input = process
            .child
            .stdin
            .take()
            .ok_or_else(|| refused("worker pipe absent"))?;
        let mut output = process
            .child
            .stdout
            .take()
            .ok_or_else(|| refused("worker pipe absent"))?;
        process.io = Some(
            thread::Builder::new()
                .name("contextdb-kev-pipe".into())
                .spawn(move || {
                    let first = read_reply(&mut output);
                    let admitted = first.is_ok();
                    if ready.send(first).is_err() || !admitted {
                        return;
                    }
                    while let Ok(job) = receiver.recv() {
                        let result = input
                            .write_all(&job.bytes)
                            .and_then(|()| input.flush())
                            .map_err(|_| refused("worker write refused"))
                            .and_then(|()| read_reply(&mut output));
                        let complete = result.is_ok();
                        let _ = job.result.send(result);
                        if !complete {
                            break;
                        }
                    }
                })
                .map_err(|_| refused("worker pipe thread refused"))?,
        );
        Ok((process, ready_result))
    }

    pub(super) fn exchange(
        &mut self,
        bytes: Zeroizing<Vec<u8>>,
        deadline: Instant,
        budget: &QueryBudget,
    ) -> Result<Vec<u8>> {
        budget
            .check()
            .map_err(|_| refused("worker allowance exhausted"))?;
        let (result, receiver) = mpsc::channel();
        self.jobs
            .as_ref()
            .ok_or_else(|| refused("worker closed"))?
            .try_send(Job { bytes, result })
            .map_err(|_| refused("worker busy or closed"))?;
        let result = wait(&receiver, deadline, Some(budget));
        if result.is_err() {
            self.stop();
        }
        result
    }

    pub(super) fn stop(&mut self) {
        self.jobs.take();
        let _ = self.child.kill();
        // Close the owned child before joining the blocked pipe reader/writer.
        let _ = self.child.wait();
        if let Some(io) = self.io.take() {
            let _ = io.join();
        }
    }

    #[cfg(test)]
    pub(super) fn reaped(&mut self) -> bool {
        self.jobs.is_none() && self.child.try_wait().is_ok_and(|status| status.is_some())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) fn wait(
    receiver: &mpsc::Receiver<Result<Vec<u8>>>,
    deadline: Instant,
    budget: Option<&QueryBudget>,
) -> Result<Vec<u8>> {
    loop {
        if let Some(budget) = budget {
            budget
                .check()
                .map_err(|_| refused("worker allowance exhausted"))?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(refused("worker deadline exceeded"));
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(5))) {
            Ok(result) => {
                if Instant::now() >= deadline {
                    return Err(refused("late worker response"));
                }
                if let Some(budget) = budget {
                    budget
                        .check()
                        .map_err(|_| refused("worker allowance exhausted"))?;
                }
                return result;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(refused("worker disconnected"));
            }
        }
    }
}

fn read_reply(output: &mut impl Read) -> Result<Vec<u8>> {
    let mut outer = [0_u8; 4];
    output
        .read_exact(&mut outer)
        .map_err(|_| refused("worker response interrupted"))?;
    let length = u32::from_be_bytes(outer) as usize;
    if !(2..=MAX_META).contains(&length) {
        return Err(refused("worker reply length refused"));
    }
    let mut header = [0_u8; 2];
    output
        .read_exact(&mut header)
        .map_err(|_| refused("worker response interrupted"))?;
    if u16::from_be_bytes(header) as usize != length - 2 {
        return Err(refused("worker reply tail refused"));
    }
    let mut bytes = vec![0; length - 2];
    output
        .read_exact(&mut bytes)
        .map_err(|_| refused("worker response interrupted"))?;
    Ok(bytes)
}

pub(super) fn frame(metadata: &[u8], input: Vec<u8>) -> Result<Zeroizing<Vec<u8>>> {
    use super::config::{MAX_FRAME, MAX_INPUT};
    if metadata.len() > MAX_META || input.len() > MAX_INPUT {
        return Err(refused("worker frame cap exceeded"));
    }
    let length = 2 + metadata.len() + input.len();
    if length > MAX_FRAME {
        return Err(refused("worker frame cap exceeded"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length + 4));
    bytes.extend_from_slice(&(length as u32).to_be_bytes());
    bytes.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    bytes.extend_from_slice(metadata);
    let input = Zeroizing::new(input);
    bytes.extend_from_slice(&input);
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn decode_reply(bytes: &[u8]) -> Result<Vec<u8>> {
    read_reply(&mut std::io::Cursor::new(bytes))
}
