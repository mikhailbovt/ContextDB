use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN: &str = "5959595959595959595959595959595959595959595959595959595959595959";

struct TestAuthority {
    #[cfg(windows)]
    selector: String,
    #[cfg(unix)]
    head: PathBuf,
    #[cfg(unix)]
    _directory: tempfile::TempDir,
}

impl TestAuthority {
    fn new(_label: &str) -> Self {
        #[cfg(windows)]
        {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            Self {
                selector: format!("custody-export-{_label}-{}-{nonce}", std::process::id()),
            }
        }
        #[cfg(unix)]
        {
            let directory = tempfile::tempdir().expect("authority directory");
            Self {
                head: directory.path().join("state-head.json"),
                _directory: directory,
            }
        }
    }

    fn configure(&self, command: &mut Command) {
        command
            .env("CONTEXTDB_TOKEN_KEY_HEX", TOKEN)
            .env_remove("CONTEXTDB_TOKEN_KEY_FILE");
        #[cfg(windows)]
        command
            .env("CONTEXTDB_STATE_HEAD_ID", &self.selector)
            .env_remove("CONTEXTDB_STATE_HEAD_FILE");
        #[cfg(unix)]
        command
            .env("CONTEXTDB_STATE_HEAD_FILE", &self.head)
            .env_remove("CONTEXTDB_STATE_HEAD_ID");
    }
}

#[cfg(windows)]
impl Drop for TestAuthority {
    fn drop(&mut self) {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        let digest = blake3::hash(self.selector.as_bytes()).to_hex();
        if let Ok(parent) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Software\\ContextDB\\StateHeads", winreg::enums::KEY_WRITE)
        {
            let _ = parent.delete_subkey_all(digest.to_string());
        }
    }
}

fn run(authority: &TestAuthority, arguments: &[OsString]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_contextdb"));
    command.args(arguments);
    authority.configure(&mut command);
    command.output().expect("run contextdb")
}

fn arguments(values: &[&OsStr]) -> Vec<OsString> {
    values.iter().map(|value| (*value).to_os_string()).collect()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(windows)]
fn create_directory_link(target: &Path, link: &Path) {
    const SCRIPT: &str = "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:CONTEXTDB_TEST_JUNCTION_PATH -Target $env:CONTEXTDB_TEST_JUNCTION_TARGET | Out-Null";
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        .env("CONTEXTDB_TEST_JUNCTION_PATH", link)
        .env("CONTEXTDB_TEST_JUNCTION_TARGET", target)
        .output()
        .expect("launch PowerShell junction helper");
    assert!(
        output.status.success(),
        "cannot create junction: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn create_directory_link(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("create destination directory symbolic link");
}

#[cfg(windows)]
fn remove_directory_link(link: &Path) {
    std::fs::remove_dir(link).expect("remove directory junction");
}

#[cfg(unix)]
fn remove_directory_link(link: &Path) {
    std::fs::remove_file(link).expect("remove directory symbolic link");
}

fn byte_manifest(archive: &Path) -> Vec<(String, u64, String)> {
    let mut manifest = Vec::new();
    let archive_bytes = std::fs::read(archive).expect("read archive manifest entry");
    manifest.push((
        "archive".to_owned(),
        u64::try_from(archive_bytes.len()).expect("archive length"),
        blake3::hash(&archive_bytes).to_hex().to_string(),
    ));

    let root = sidecar(archive, ".fjall");
    let mut stack = vec![root.clone()];
    while let Some(directory) = stack.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .expect("read Fjall manifest directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read Fjall manifest entries");
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(&root)
                .expect("relative Fjall manifest path")
                .to_string_lossy()
                .replace('\\', "/");
            let metadata = std::fs::symlink_metadata(&path).expect("Fjall manifest metadata");
            if metadata.is_dir() {
                manifest.push((format!("directory:{relative}"), 0, String::new()));
                stack.push(path);
            } else {
                assert!(metadata.is_file(), "non-regular Fjall test entry");
                let bytes = std::fs::read(path).expect("read Fjall manifest file");
                manifest.push((
                    format!("file:{relative}"),
                    u64::try_from(bytes.len()).expect("Fjall file length"),
                    blake3::hash(&bytes).to_hex().to_string(),
                ));
            }
        }
    }
    manifest.sort();
    manifest
}

#[test]
fn custody_snapshot_is_source_immutable_and_importable_after_detached_deep_verify() {
    let directory = tempfile::tempdir().expect("test directory");
    // macOS exposes its default temporary root through `/var`, which is a
    // system symlink to `/private/var`. Use the resolved custody root so the
    // positive path does not accidentally exercise the symlink-rejection
    // branch reserved for the explicit negative cases below.
    let directory_path = std::fs::canonicalize(directory.path()).expect("canonical test directory");
    let source_directory = directory_path.join("source-data");
    std::fs::create_dir(&source_directory).expect("source data directory");
    let source = source_directory.join("legacy-source.ctxb");
    let output = directory_path.join("custody-export.ctxb");
    let clone = directory_path.join("imported-clone.ctxb");
    let source_authority = TestAuthority::new("source");
    let clone_authority = TestAuthority::new("clone");

    let initialized = run(
        &source_authority,
        &arguments(&[OsStr::new("--json"), OsStr::new("init"), source.as_os_str()]),
    );
    assert_success(&initialized);
    let source_lock = sidecar(&source, ".fjall").join("lock");
    assert!(source_lock.is_file(), "initialized Fjall lock sentinel");
    std::fs::remove_file(&source_lock).expect("remove source Fjall lock sentinel");
    let before = byte_manifest(&source);

    let exported = run(
        &source_authority,
        &arguments(&[
            OsStr::new("--json"),
            OsStr::new("custody-snapshot-export"),
            source.as_os_str(),
            output.as_os_str(),
        ]),
    );
    assert_success(&exported);
    let receipt: serde_json::Value =
        serde_json::from_slice(&exported.stdout).expect("custody export receipt");
    assert_eq!(receipt["format"], "contextdb.logical.v1");
    assert!(
        receipt["digest"]
            .as_str()
            .is_some_and(|value| value.len() == 64)
    );
    assert_eq!(byte_manifest(&source), before);

    let imported = run(
        &clone_authority,
        &arguments(&[
            OsStr::new("--json"),
            OsStr::new("import"),
            clone.as_os_str(),
            output.as_os_str(),
        ]),
    );
    assert_success(&imported);
    let doctored = run(
        &clone_authority,
        &arguments(&[
            OsStr::new("--json"),
            OsStr::new("doctor"),
            clone.as_os_str(),
        ]),
    );
    assert_success(&doctored);

    let existing_output = directory_path.join("existing-output.ctxb");
    let existing_sentinel = b"must remain byte-identical";
    std::fs::write(&existing_output, existing_sentinel).expect("existing output sentinel");
    let existing_attempt = run(
        &source_authority,
        &arguments(&[
            OsStr::new("custody-snapshot-export"),
            source.as_os_str(),
            existing_output.as_os_str(),
        ]),
    );
    assert!(!existing_attempt.status.success());
    assert_eq!(
        std::fs::read(&existing_output).expect("existing output remains readable"),
        existing_sentinel
    );

    let source_link_parent = directory_path.join("source-link-parent");
    create_directory_link(&source_directory, &source_link_parent);
    let source_link = source_link_parent.join("legacy-source.ctxb");
    let source_link_output = directory_path.join("source-link-export.ctxb");
    let source_link_attempt = run(
        &source_authority,
        &arguments(&[
            OsStr::new("custody-snapshot-export"),
            source_link.as_os_str(),
            source_link_output.as_os_str(),
        ]),
    );
    assert!(!source_link_attempt.status.success());
    assert!(!source_link_output.exists());
    remove_directory_link(&source_link_parent);

    let destination_target = directory_path.join("destination-target");
    let destination_link = directory_path.join("destination-link");
    std::fs::create_dir(&destination_target).expect("destination link target");
    create_directory_link(&destination_target, &destination_link);
    let reparse_output = destination_link.join("reparse-output.ctxb");
    let reparse_attempt = run(
        &source_authority,
        &arguments(&[
            OsStr::new("custody-snapshot-export"),
            source.as_os_str(),
            reparse_output.as_os_str(),
        ]),
    );
    assert!(!reparse_attempt.status.success());
    assert!(!destination_target.join("reparse-output.ctxb").exists());
    remove_directory_link(&destination_link);

    let protected_alias = sidecar(&source, ".fjall").join("forbidden-export.ctxb");
    let alias_attempt = run(
        &source_authority,
        &arguments(&[
            OsStr::new("custody-snapshot-export"),
            source.as_os_str(),
            protected_alias.as_os_str(),
        ]),
    );
    assert!(!alias_attempt.status.success());
    assert!(!protected_alias.exists());

    let native = sidecar(&source, ".native-fjall");
    std::fs::create_dir(&native).expect("create native sidecar sentinel");
    let native_output = directory_path.join("must-not-export.ctxb");
    let native_attempt = run(
        &source_authority,
        &arguments(&[
            OsStr::new("custody-snapshot-export"),
            source.as_os_str(),
            native_output.as_os_str(),
        ]),
    );
    assert!(!native_attempt.status.success());
    assert!(!native_output.exists());
    assert!(String::from_utf8_lossy(&native_attempt.stderr).contains("native sidecar"));
}
