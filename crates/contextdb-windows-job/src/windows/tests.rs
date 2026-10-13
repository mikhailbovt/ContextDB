//! No model or shell: re-exec this test binary as owner, child and grandchild.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use super::JobChild;

const ROLE: &str = "CONTEXTDB_JOB_TEST_ROLE";
const ADDRESS: &str = "CONTEXTDB_JOB_TEST_ADDRESS";
const TOKEN: &str = "CONTEXTDB_JOB_TEST_VALUE";
const VALUE: &str = "Русский 😀 space=\"quoted\"\\tail\\";
const FIXTURE: &str = "windows::tests::fixture_process";

fn command(role: &str, address: &str) -> Command {
    let executable = std::env::current_exe().expect("fixture executable");
    let mut command = Command::new(&executable);
    command
        .args(["--exact", FIXTURE, "--nocapture", "--skip", VALUE])
        .current_dir(executable.parent().expect("fixture directory"))
        .env_clear()
        .env(ROLE, role)
        .env(ADDRESS, address)
        .env(TOKEN, VALUE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(value) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", value);
    }
    command
}

struct Owner(Child);
impl Drop for Owner {
    fn drop(&mut self) {
        // Only the exact standard Child created by this test is controlled.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Ordinary test execution returns immediately. The parent uses this exact test
// as a subprocess, so it exercises real OS handle teardown without Rust Drop.
#[test]
fn fixture_process() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let address = std::env::var(ADDRESS).expect("fixture address");
    assert_eq!(
        std::env::var(TOKEN).expect("explicit Unicode environment"),
        VALUE
    );
    assert_eq!(
        std::env::args_os().skip(1).collect::<Vec<_>>(),
        ["--exact", FIXTURE, "--nocapture", "--skip", VALUE].map(std::ffi::OsString::from),
        "literal Unicode, quote and trailing-backslash argv round trip"
    );
    assert_eq!(
        std::env::current_dir().expect("actual child directory"),
        std::env::current_exe()
            .expect("fixture executable")
            .parent()
            .expect("executable directory")
    );
    if role == "owner" {
        let _child = JobChild::spawn_null(&command("child", &address)).expect("atomic child job");
        thread::sleep(Duration::from_secs(60));
    } else {
        let mut stream = TcpStream::connect(&address).expect("fixture lifetime channel");
        stream
            .write_all(if role == "child" { &[1] } else { &[2] })
            .expect("fixture ready");
        let _descendant = if role == "child" {
            // This process inherits the job via ordinary CreateProcess. Neither
            // its PID nor a handle to it is passed to the outside parent.
            Some(Owner(
                command("grandchild", &address).spawn().expect("descendant"),
            ))
        } else {
            assert_eq!(role, "grandchild");
            None
        };
        thread::sleep(Duration::from_secs(60));
        drop(stream);
    }
}

#[test]
fn abrupt_owner_exit_terminates_created_child_and_its_descendant() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("fixture listener");
    listener.set_nonblocking(true).expect("bounded accept");
    let address = listener.local_addr().expect("fixture address").to_string();
    let mut owner = Owner(command("owner", &address).spawn().expect("fixture owner"));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut channels = Vec::new();
    while channels.len() < 2 {
        assert!(
            Instant::now() < deadline,
            "owned child tree did not become ready"
        );
        assert!(
            owner.0.try_wait().expect("owner status").is_none(),
            "owner exited before job setup"
        );
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("blocking accepted channel");
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .expect("bounded channel read");
                let mut identity = [0];
                stream
                    .read_exact(&mut identity)
                    .expect("actual subprocess ready");
                assert!([1, 2].contains(&identity[0]));
                assert!(channels.iter().all(|(seen, _)| *seen != identity[0]));
                channels.push((identity[0], stream));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("fixture accept: {error}"),
        }
    }
    // Both processes are alive before the owner's abrupt termination. A natural
    // fixture exit is 60 seconds away and cannot make this assertion pass.
    for (_, stream) in &mut channels {
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("liveness timeout");
        let error = stream
            .read(&mut [0])
            .expect_err("live process keeps lifetime channel open");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }
    owner.0.kill().expect("abruptly terminate exact owner");
    owner.0.wait().expect("owner reaped");
    for (identity, stream) in &mut channels {
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("termination timeout");
        match stream.read(&mut [0]) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            result => panic!("owned process {identity} survived owner termination: {result:?}"),
        }
    }
}
