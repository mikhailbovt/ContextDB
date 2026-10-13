//! Uses Windows 10's job-list process attribute, rather than attaching a running
//! process after spawn. See the Microsoft CreateProcessW, UpdateProcThreadAttribute
//! and Job Objects contracts; no PID lookup or handwritten Win32 ABI is used.

use std::{
    ffi::OsStr,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::ExitStatusExt,
    },
    path::Path,
    process::{Command, ExitStatus},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
        Threading::{
            CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
            INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
            WaitForSingleObject,
        },
    },
};

const MAX_UTF16: usize = 32_767;
const MAX_ARGUMENTS: usize = 128;
const MAX_ENVIRONMENT: usize = 64;

/// A hidden child created atomically inside its own unnamed, noninheritable job.
/// Closing the owner process or dropping this value closes the last job handle,
/// terminating this child and its ordinary CreateProcess descendants.
#[derive(Debug)]
pub struct JobChild {
    // Drop the job before the process handle. The child never inherits this
    // handle, and no API exposes it for duplication or arbitrary assignment.
    _job: OwnedHandle,
    process: OwnedHandle,
    pid: u32,
    exit_status: Option<ExitStatus>,
}

impl JobChild {
    /// Launch an absolute executable with literal CRT arguments, explicit cleared
    /// environment, configured directory and null stdin/stdout/stderr.
    ///
    /// Only entries explicitly set on `command` are passed: inherited environment,
    /// removed variables, custom stdio and other Command flags are not supported.
    /// This restricted API is for the pinned local encoder, not a shell launcher.
    /// Job-list support is required; setup failures never fall back to bare spawn.
    pub fn spawn_null(command: &Command) -> io::Result<Self> {
        let executable = command.get_program();
        if !Path::new(executable).is_absolute() {
            return Err(invalid("owned executable must be absolute"));
        }
        let mut program = wide(executable, MAX_UTF16 - 1)?;
        if program.contains(&u16::from(b'"')) {
            return Err(invalid("owned executable contains a quote"));
        }
        let mut arguments = Vec::new();
        quote(&mut arguments, &program)?;
        for (index, argument) in command.get_args().enumerate() {
            if index >= MAX_ARGUMENTS {
                return Err(invalid("owned argument count exceeds bound"));
            }
            arguments.push(u16::from(b' '));
            quote(&mut arguments, &wide(argument, MAX_UTF16 - 1)?)?;
        }
        arguments.push(0);
        program.push(0);
        let environment = environment(command)?;
        let directory = command
            .get_current_dir()
            .map(|path| {
                if !path.is_absolute() {
                    return Err(invalid("owned directory must be absolute"));
                }
                let mut value = wide(path.as_os_str(), MAX_UTF16 - 1)?;
                value.push(0);
                Ok(value)
            })
            .transpose()?;

        let job = create_job()?;
        let null = null_handle()?;
        let mut attributes = Attributes::new(&job, &null)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = null.as_raw_handle();
        startup.StartupInfo.hStdOutput = null.as_raw_handle();
        startup.StartupInfo.hStdError = null.as_raw_handle();
        startup.lpAttributeList = attributes.pointer();
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: generated ABI; all NUL-terminated buffers, mutable command line,
        // initialized attributes and its boxed handle arrays remain live through
        // this call. The handle-list inherits ONLY NUL; the job is not inherited.
        // The absolute application is supplied separately, preventing path search.
        let created = unsafe {
            CreateProcessW(
                program.as_ptr(),
                arguments.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                directory
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
                ptr::from_ref(&startup.StartupInfo),
                &mut information,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful CreateProcessW returns two distinct owned handles.
        // Transfer each exactly once; the primary thread needs no further access.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess) };
        let _thread = unsafe { OwnedHandle::from_raw_handle(information.hThread) };
        Ok(Self {
            _job: job,
            process,
            pid: information.dwProcessId,
            exit_status: None,
        })
    }

    /// Identifier of this created child, for diagnostics only.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Terminate this exact child. Closing its job during cleanup also terminates
    /// descendants; this method never opens a process by identifier.
    pub fn kill(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // SAFETY: the process handle belongs to the child created by this object
        // and remains owned and valid for this call.
        if unsafe { TerminateProcess(self.process.as_raw_handle(), 1) } != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        // A concurrent natural exit is successful cleanup, matching std Child.
        if self.try_wait()?.is_some() {
            Ok(())
        } else {
            Err(error)
        }
    }

    /// Return the exit status only after the process handle becomes signaled.
    /// Exit code 259 is a legitimate completed code, not a liveness predicate.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.exit_status {
            return Ok(Some(status));
        }
        // SAFETY: valid owned process handle, zero timeout, no borrowed buffers.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => self.completed().map(Some),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected owned process wait result")),
        }
    }

    /// Reap this created child. Runtime uses this blocking method only on its
    /// cleanup thread; caller-budget shutdown uses `try_wait` instead.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.exit_status {
            return Ok(status);
        }
        // SAFETY: valid owned process handle; this method explicitly blocks.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), INFINITE) } {
            WAIT_OBJECT_0 => self.completed(),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected owned process wait result")),
        }
    }

    fn completed(&mut self) -> io::Result<ExitStatus> {
        let mut code = 0;
        // SAFETY: the process is signaled, the handle remains owned, and code is
        // an initialized writable DWORD. No STILL_ACTIVE interpretation is used.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let status = ExitStatus::from_raw(code);
        self.exit_status = Some(status);
        Ok(status)
    }
}

fn create_job() -> io::Result<OwnedHandle> {
    // SAFETY: NULL security/name creates an unnamed, noninheritable owned job.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this is the newly returned valid owned handle, transferred once.
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: correct generated information type and size, live input buffer,
    // valid job handle. No breakaway or unrelated limits are enabled.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            ptr::from_ref(&limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

fn null_handle() -> io::Result<OwnedHandle> {
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: literal terminated NUL-device name and correctly sized security
    // attributes; all optional input pointers are NULL.
    let raw = unsafe {
        CreateFileW(
            [u16::from(b'N'), u16::from(b'U'), u16::from(b'L'), 0].as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW returned an owned, valid device handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

#[derive(Debug)]
struct Attributes {
    storage: Vec<usize>,
    jobs: Box<[HANDLE; 1]>,
    inherited: Box<[HANDLE; 1]>,
}
impl Attributes {
    fn new(job: &OwnedHandle, null: &OwnedHandle) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: the documented size query uses NULL list and writable SIZE_T.
        let result =
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut bytes) };
        if result != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes == 0
            || bytes > 4096
        {
            return Err(io::Error::other("invalid owned process attribute size"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: allocation is pointer-aligned and at least the queried size;
        // initialization occurs once, before the RAII object's Drop is enabled.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = Self {
            storage,
            jobs: Box::new([job.as_raw_handle()]),
            inherited: Box::new([null.as_raw_handle()]),
        };
        let pointer = attributes.pointer();
        for (key, handles) in [
            (PROC_THREAD_ATTRIBUTE_JOB_LIST, &attributes.jobs),
            (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &attributes.inherited),
        ] {
            // SAFETY: initialized attribute storage and stable boxed handle
            // arrays remain live until DeleteProcThreadAttributeList, including
            // through CreateProcessW. The jobs themselves remain owned by caller.
            if unsafe {
                UpdateProcThreadAttribute(
                    pointer,
                    0,
                    key as usize,
                    handles.as_ptr().cast(),
                    size_of::<HANDLE>(),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(attributes)
    }
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: only successfully initialized lists reach this object; storage
        // and attribute values are still live, and deletion occurs exactly once.
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn wide(value: &OsStr, limit: usize) -> io::Result<Vec<u16>> {
    let length = value.encode_wide().count();
    if length > limit {
        return Err(invalid("owned process text exceeds bound"));
    }
    let units: Vec<_> = value.encode_wide().collect();
    if units.contains(&0) {
        return Err(invalid("owned process text contains NUL"));
    }
    Ok(units)
}
fn quote(output: &mut Vec<u16>, units: &[u16]) -> io::Result<()> {
    if output.len() + units.len() * 2 + 3 > MAX_UTF16 {
        return Err(invalid("owned command line exceeds bound"));
    }
    output.push(u16::from(b'"'));
    let mut slashes = 0;
    for &unit in units {
        if unit == u16::from(b'\\') {
            slashes += 1;
            continue;
        }
        if unit == u16::from(b'"') {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2 + 1));
        } else {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes));
        }
        slashes = 0;
        output.push(unit);
    }
    output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2));
    output.push(u16::from(b'"'));
    Ok(())
}
fn environment(command: &Command) -> io::Result<Vec<u16>> {
    let mut entries = Vec::new();
    let mut total = 1;
    for (index, (key, value)) in command.get_envs().enumerate() {
        if index >= MAX_ENVIRONMENT {
            return Err(invalid("owned environment entry count exceeds bound"));
        }
        let key = wide(key, 256)?;
        if key.is_empty()
            || key.iter().any(|&unit| {
                unit > 127 || !(unit as u8).is_ascii_alphanumeric() && unit != u16::from(b'_')
            })
        {
            return Err(invalid("owned environment key is not an ASCII OS variable"));
        }
        let value = wide(
            value.ok_or_else(|| invalid("owned environment removals are unsupported"))?,
            MAX_UTF16 - 1,
        )?;
        total += key.len() + value.len() + 2;
        if total > MAX_UTF16 {
            return Err(invalid("owned environment exceeds bound"));
        }
        let order: Vec<_> = key
            .iter()
            .map(|&unit| (unit as u8).to_ascii_uppercase())
            .collect();
        entries.push((order, key, value));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid("owned environment has duplicate OS variables"));
    }
    let mut result = Vec::with_capacity(total.max(2));
    for (_, key, value) in entries {
        result.extend(key);
        result.push(u16::from(b'='));
        result.extend(value);
        result.push(0);
    }
    if result.is_empty() {
        result.push(0);
    }
    result.push(0);
    Ok(result)
}

#[cfg(test)]
mod tests;
