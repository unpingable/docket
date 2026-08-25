//! Narrow platform adapter for invoking one already-opened executable object.
//!
//! The Docket domain remains safe Rust. This crate contains the smallest
//! FreeBSD-specific process boundary needed for `fexecve(2)` and captured
//! standard I/O. It does not resolve paths, decide policy, or interpret work.

use std::ffi::CString;
use std::fs::File;
#[cfg(not(target_os = "freebsd"))]
use std::io;
use std::path::Path;

#[derive(Debug)]
pub struct DescriptorExecOutput {
    pub descriptor_exec_accepted: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exec_errno: Option<i32>,
}

/// One private executable vnode populated from bounded candidate bytes.
///
/// On FreeBSD the file is unlinked before population, reopened read-only
/// through `O_EMPTY_PATH`, and returned only after every writable descriptor
/// owned by this adapter has been closed. The caller must measure this exact
/// descriptor before invoking it.
#[derive(Debug)]
pub struct ExecutionRepresentation {
    pub executable: File,
    pub method: &'static str,
    pub device: u64,
    pub inode: u64,
    pub links: u64,
    pub authority: ExecutionRepresentationAuthorityClosure,
}

pub const PRIVATE_UNLINKED_REGULAR_VNODE_V1: &str = "freebsd_private_unlinked_regular_vnode_v1";
pub const AUTHORITY_CLOSURE_SCHEMA_V1: &str =
    "civil.managed-file.execution-representation-authority-closure/v1";
pub const FIRST_STAGE_RIGHTS_PROFILE_V1: &str = "read_seek_fstat_fexecve_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRepresentationAuthorityClosure {
    pub schema: &'static str,
    pub creator: &'static str,
    pub representation_method: &'static str,
    pub writer_descriptors_created: u16,
    pub writer_descriptors_duplicated: u16,
    pub writer_descriptors_closed_before_measurement: u16,
    pub writable_descriptors_surviving_finalization: u16,
    pub writable_descriptors_inherited: u16,
    pub representation_links_at_finalization: u64,
    pub surviving_descriptor_access: &'static str,
    pub surviving_rights_profile: &'static str,
    pub direct_write_probe_errno: i32,
    pub write_reacquisition_method: &'static str,
    pub write_reacquisition_errno: i32,
    pub finalization_sequence: u8,
    pub measurement_sequence: u8,
    pub invocation_sequence: u8,
    pub descriptor_transfer: &'static str,
}

#[cfg(target_os = "freebsd")]
#[allow(unsafe_code)]
mod platform {
    use super::{
        CString, DescriptorExecOutput, ExecutionRepresentation, File, Path,
        AUTHORITY_CLOSURE_SCHEMA_V1, FIRST_STAGE_RIGHTS_PROFILE_V1,
        PRIVATE_UNLINKED_REGULAR_VNODE_V1,
    };
    use std::ffi::CStr;
    use std::fs::{OpenOptions, Permissions};
    use std::io::{self, Read as _, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    static REPRESENTATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    /// Copy the process environment directly from FreeBSD libc.
    ///
    /// Rust's standard-library environment iterator faults in a statically
    /// linked FreeBSD process before application logic on the qualified 15.1
    /// substrate.  The kernel/libc process ABI still exposes the ordinary
    /// null-terminated `environ` vector, which is also what `fexecve(2)`
    /// consumes.  This bootstrap is single-threaded while taking the copy.
    pub fn inherited_environment_bytes() -> io::Result<Vec<Vec<u8>>> {
        unsafe extern "C" {
            static mut environ: *mut *mut libc::c_char;
        }

        let mut cursor = unsafe { environ };
        if cursor.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FreeBSD process environment is unavailable",
            ));
        }
        let mut values = Vec::new();
        loop {
            let entry = unsafe { *cursor };
            if entry.is_null() {
                break;
            }
            values.push(unsafe { CStr::from_ptr(entry) }.to_bytes().to_vec());
            cursor = unsafe { cursor.add(1) };
        }
        Ok(values)
    }

    pub fn prepare_execution_representation(
        base_directory: &Path,
        bytes: &[u8],
    ) -> io::Result<ExecutionRepresentation> {
        prepare_execution_representation_for(base_directory, bytes, "docket_first_stage_adapter")
    }

    /// Create one finalized execution representation and identify its governed
    /// creator in the authority-closure receipt.
    ///
    /// The creator is a schema value selected by the caller, not a source of
    /// authority. It must be a compile-time constant so runtime input cannot
    /// relabel the authority holder.
    pub fn prepare_execution_representation_for(
        base_directory: &Path,
        bytes: &[u8],
        creator: &'static str,
    ) -> io::Result<ExecutionRepresentation> {
        let directory = base_directory.join(".gwr-execution-representations");
        match std::fs::create_dir(&directory) {
            Ok(()) => std::fs::set_permissions(&directory, Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let directory_metadata = std::fs::symlink_metadata(&directory)?;
        if !directory_metadata.is_dir()
            || directory_metadata.file_type().is_symlink()
            || directory_metadata.mode() & 0o077 != 0
            || directory_metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "execution representation directory custody",
            ));
        }

        let mut writer = loop {
            let sequence = REPRESENTATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                ".representation.{}.{}",
                std::process::id(),
                sequence
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(file) => {
                    std::fs::remove_file(&path)?;
                    break file;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };

        writer.write_all(bytes)?;
        writer.sync_all()?;
        writer.set_permissions(Permissions::from_mode(0o500))?;

        let executable_fd = unsafe {
            libc::openat(
                writer.as_raw_fd(),
                c"".as_ptr(),
                libc::O_EMPTY_PATH | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if executable_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let executable = unsafe { File::from_raw_fd(executable_fd) };
        let writer_metadata = writer.metadata()?;
        let executable_metadata = executable.metadata()?;
        if writer_metadata.dev() != executable_metadata.dev()
            || writer_metadata.ino() != executable_metadata.ino()
            || executable_metadata.nlink() != 0
            || !executable_metadata.is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "execution representation identity",
            ));
        }
        drop(writer);
        let status = unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_GETFL) };
        if status < 0 || status & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "execution representation reader is not read-only",
            ));
        }
        let descriptor = unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_GETFD) };
        if descriptor < 0 || descriptor & libc::FD_CLOEXEC == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "execution representation reader is not close-on-exec before transfer",
            ));
        }
        let mut rights = unsafe { std::mem::zeroed::<libc::cap_rights_t>() };
        if unsafe {
            libc::__cap_rights_init(
                libc::CAP_RIGHTS_VERSION,
                &mut rights,
                libc::CAP_READ,
                libc::CAP_SEEK,
                libc::CAP_FSTAT,
                libc::CAP_FEXECVE,
                0_u64,
            )
        }
        .is_null()
            || unsafe { libc::cap_rights_limit(executable.as_raw_fd(), &rights) } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let byte = [0_u8];
        if unsafe { libc::pwrite(executable.as_raw_fd(), byte.as_ptr().cast(), byte.len(), 0) } >= 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "rights-limited execution representation remained writable",
            ));
        }
        let direct_write_probe_errno = io::Error::last_os_error()
            .raw_os_error()
            .ok_or_else(|| io::Error::other("direct write probe returned no errno"))?;
        if direct_write_probe_errno != libc::EBADF && direct_write_probe_errno != libc::ENOTCAPABLE
        {
            return Err(io::Error::from_raw_os_error(direct_write_probe_errno));
        }

        let reopened = unsafe {
            libc::openat(
                executable.as_raw_fd(),
                c"".as_ptr(),
                libc::O_EMPTY_PATH | libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if reopened >= 0 {
            unsafe { libc::close(reopened) };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "rights-limited reader reacquired writable authority",
            ));
        }
        let write_reacquisition_errno = io::Error::last_os_error()
            .raw_os_error()
            .ok_or_else(|| io::Error::other("write reacquisition returned no errno"))?;
        if write_reacquisition_errno != libc::ENOTCAPABLE {
            return Err(io::Error::from_raw_os_error(write_reacquisition_errno));
        }

        Ok(ExecutionRepresentation {
            executable,
            method: PRIVATE_UNLINKED_REGULAR_VNODE_V1,
            device: executable_metadata.dev(),
            inode: executable_metadata.ino(),
            links: executable_metadata.nlink(),
            authority: super::ExecutionRepresentationAuthorityClosure {
                schema: AUTHORITY_CLOSURE_SCHEMA_V1,
                creator,
                representation_method: PRIVATE_UNLINKED_REGULAR_VNODE_V1,
                writer_descriptors_created: 1,
                writer_descriptors_duplicated: 0,
                writer_descriptors_closed_before_measurement: 1,
                writable_descriptors_surviving_finalization: 0,
                writable_descriptors_inherited: 0,
                representation_links_at_finalization: executable_metadata.nlink(),
                surviving_descriptor_access: "read_only",
                surviving_rights_profile: FIRST_STAGE_RIGHTS_PROFILE_V1,
                direct_write_probe_errno,
                write_reacquisition_method: "openat_empty_path_rdwr",
                write_reacquisition_errno,
                finalization_sequence: 4,
                measurement_sequence: 5,
                invocation_sequence: 7,
                descriptor_transfer: "read_only_reader_fork_inherited_for_fexecve",
            },
        })
    }

    struct Pipes {
        stdin: [RawFd; 2],
        stdout: [RawFd; 2],
        stderr: [RawFd; 2],
        exec: [RawFd; 2],
    }

    impl Pipes {
        fn create() -> io::Result<Self> {
            Ok(Self {
                stdin: pipe()?,
                stdout: pipe()?,
                stderr: pipe()?,
                exec: pipe()?,
            })
        }
    }

    fn pipe() -> io::Result<[RawFd; 2]> {
        let mut pair = [-1, -1];
        if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(pair)
        }
    }

    fn close(fd: RawFd) {
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }

    fn environment() -> io::Result<Vec<CString>> {
        inherited_environment_bytes()?
            .into_iter()
            .map(|bytes| {
                CString::new(bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "environment contains NUL")
                })
            })
            .collect()
    }

    pub fn invoke(
        executable: &File,
        argv: &[CString],
        stdin: &[u8],
    ) -> io::Result<DescriptorExecOutput> {
        invoke_with_exec_observer(executable, argv, stdin, || Ok(()))
    }

    /// Invoke one exact absolute path with explicit argv/environment custody.
    ///
    /// This preserves Docket's pre-existing standing-resolver process boundary
    /// while avoiding Rust's generic static-FreeBSD `Command` bootstrap.
    pub fn invoke_path(
        program: &Path,
        argv: &[CString],
        stdin: &[u8],
    ) -> io::Result<DescriptorExecOutput> {
        let program = CString::new(program.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "program path contains NUL")
        })?;
        invoke_target_with_exec_observer(ExecutionTarget::Path(&program), argv, stdin, || Ok(()))
    }

    #[derive(Clone, Copy)]
    enum ExecutionTarget<'a> {
        Descriptor(&'a File),
        Path(&'a CString),
    }

    /// Invoke an executable descriptor and call `on_exec_accepted` after the
    /// kernel has accepted `fexecve(2)`, but before waiting for child exit.
    ///
    /// The callback is an evidence hook only: if it fails, the child is still
    /// reaped and its output is drained before the callback error is returned.
    pub fn invoke_with_exec_observer<F>(
        executable: &File,
        argv: &[CString],
        stdin: &[u8],
        on_exec_accepted: F,
    ) -> io::Result<DescriptorExecOutput>
    where
        F: FnOnce() -> io::Result<()>,
    {
        invoke_target_with_exec_observer(
            ExecutionTarget::Descriptor(executable),
            argv,
            stdin,
            on_exec_accepted,
        )
    }

    fn invoke_target_with_exec_observer<F>(
        target: ExecutionTarget<'_>,
        argv: &[CString],
        stdin: &[u8],
        on_exec_accepted: F,
    ) -> io::Result<DescriptorExecOutput>
    where
        F: FnOnce() -> io::Result<()>,
    {
        if argv.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
        }
        let environment = environment()?;
        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let env_ptrs: Vec<*const libc::c_char> = environment
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let pipes = Pipes::create()?;
        let child = unsafe { libc::fork() };
        if child < 0 {
            for fd in pipes
                .stdin
                .into_iter()
                .chain(pipes.stdout)
                .chain(pipes.stderr)
                .chain(pipes.exec)
            {
                close(fd);
            }
            return Err(io::Error::last_os_error());
        }
        if child == 0 {
            close(pipes.stdin[1]);
            close(pipes.stdout[0]);
            close(pipes.stderr[0]);
            close(pipes.exec[0]);
            if unsafe { libc::dup2(pipes.stdin[0], libc::STDIN_FILENO) } < 0
                || unsafe { libc::dup2(pipes.stdout[1], libc::STDOUT_FILENO) } < 0
                || unsafe { libc::dup2(pipes.stderr[1], libc::STDERR_FILENO) } < 0
            {
                let errno = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                unsafe {
                    libc::write(
                        pipes.exec[1],
                        (&errno as *const i32).cast(),
                        std::mem::size_of::<i32>(),
                    );
                    libc::_exit(126);
                }
            }
            close(pipes.stdin[0]);
            close(pipes.stdout[1]);
            close(pipes.stderr[1]);
            unsafe {
                match target {
                    ExecutionTarget::Descriptor(executable) => libc::fexecve(
                        executable.as_raw_fd(),
                        argv_ptrs.as_ptr(),
                        env_ptrs.as_ptr(),
                    ),
                    ExecutionTarget::Path(program) => {
                        libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr())
                    }
                };
            }
            let errno = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            unsafe {
                libc::write(
                    pipes.exec[1],
                    (&errno as *const i32).cast(),
                    std::mem::size_of::<i32>(),
                );
                libc::_exit(127);
            }
        }

        close(pipes.stdin[0]);
        close(pipes.stdout[1]);
        close(pipes.stderr[1]);
        close(pipes.exec[1]);

        let stdout = unsafe { File::from_raw_fd(pipes.stdout[0]) };
        let stderr = unsafe { File::from_raw_fd(pipes.stderr[0]) };
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut file = stdout;
            file.read_to_end(&mut bytes).map(|_| bytes)
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut file = stderr;
            file.read_to_end(&mut bytes).map(|_| bytes)
        });

        let mut child_stdin = unsafe { File::from_raw_fd(pipes.stdin[1]) };
        let write_result = child_stdin.write_all(stdin);
        drop(child_stdin);

        let mut exec_pipe = unsafe { File::from_raw_fd(pipes.exec[0]) };
        let mut exec_bytes = Vec::new();
        exec_pipe.read_to_end(&mut exec_bytes)?;

        let exec_errno = match exec_bytes.as_slice() {
            [] => None,
            bytes if bytes.len() == std::mem::size_of::<i32>() => {
                let mut raw = [0_u8; std::mem::size_of::<i32>()];
                raw.copy_from_slice(bytes);
                Some(i32::from_ne_bytes(raw))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid descriptor-exec status channel",
                ))
            }
        };
        let observer_result = if exec_errno.is_none() {
            on_exec_accepted()
        } else {
            Ok(())
        };

        let mut status = 0;
        if unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        write_result?;
        let stdout = stdout_reader
            .join()
            .map_err(|_| io::Error::other("stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| io::Error::other("stderr reader panicked"))??;

        let exit_code = if libc::WIFEXITED(status) {
            Some(libc::WEXITSTATUS(status))
        } else {
            None
        };
        let signal = if libc::WIFSIGNALED(status) {
            Some(libc::WTERMSIG(status))
        } else {
            None
        };
        let output = DescriptorExecOutput {
            descriptor_exec_accepted: exec_errno.is_none(),
            exit_code,
            signal,
            stdout,
            stderr,
            exec_errno,
        };
        observer_result?;
        Ok(output)
    }
}

#[cfg(target_os = "freebsd")]
pub use platform::{
    inherited_environment_bytes, invoke, invoke_path, invoke_with_exec_observer,
    prepare_execution_representation, prepare_execution_representation_for,
};

#[cfg(not(target_os = "freebsd"))]
pub fn inherited_environment_bytes() -> io::Result<Vec<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt as _;

    Ok(std::env::vars_os()
        .map(|(name, value)| {
            let mut bytes = name.as_os_str().as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_os_str().as_bytes());
            bytes
        })
        .collect())
}

#[cfg(not(target_os = "freebsd"))]
pub fn invoke(
    _executable: &File,
    _argv: &[CString],
    _stdin: &[u8],
) -> io::Result<DescriptorExecOutput> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor executor is supported only on FreeBSD",
    ))
}

#[cfg(not(target_os = "freebsd"))]
pub fn invoke_path(
    _program: &Path,
    _argv: &[CString],
    _stdin: &[u8],
) -> io::Result<DescriptorExecOutput> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "path executor is supported only on FreeBSD",
    ))
}

#[cfg(not(target_os = "freebsd"))]
pub fn prepare_execution_representation(
    _base_directory: &Path,
    _bytes: &[u8],
) -> io::Result<ExecutionRepresentation> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "execution representations are supported only on FreeBSD",
    ))
}

#[cfg(not(target_os = "freebsd"))]
pub fn prepare_execution_representation_for(
    _base_directory: &Path,
    _bytes: &[u8],
    _creator: &'static str,
) -> io::Result<ExecutionRepresentation> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "execution representations are supported only on FreeBSD",
    ))
}

#[cfg(not(target_os = "freebsd"))]
pub fn invoke_with_exec_observer<F>(
    _executable: &File,
    _argv: &[CString],
    _stdin: &[u8],
    _on_exec_accepted: F,
) -> io::Result<DescriptorExecOutput>
where
    F: FnOnce() -> io::Result<()>,
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor executor is supported only on FreeBSD",
    ))
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::prepare_execution_representation;
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::PermissionsExt as _;

    fn assert_no_write_or_reacquisition(fd: libc::c_int) {
        let byte = [0_u8];
        assert_eq!(
            unsafe { libc::pwrite(fd, byte.as_ptr().cast(), byte.len(), 0) },
            -1
        );
        assert!(matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF) | Some(libc::ENOTCAPABLE)
        ));
        let reopened = unsafe {
            libc::openat(
                fd,
                c"".as_ptr(),
                libc::O_EMPTY_PATH | libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        assert_eq!(reopened, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOTCAPABLE)
        );

        for base in ["/dev/fd", "/proc/curproc/fd"] {
            if !std::path::Path::new(base).is_dir() {
                continue;
            }
            let alias = format!("{base}/{fd}");
            let error = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(alias)
                .expect_err("descriptor alias reacquired writable authority");
            println!(
                "M7_PATH_REACQUISITION_REFUSED {base} errno={:?}",
                error.raw_os_error()
            );
        }
    }

    #[test]
    fn representation_is_unlinked_read_only_and_source_decoupled() {
        let root =
            std::env::temp_dir().join(format!("gwr-m6-representation-test-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut source = b"expected executable bytes".to_vec();
        let mut representation = prepare_execution_representation(&root, &source).unwrap();
        source.fill(b'B');
        representation.executable.seek(SeekFrom::Start(0)).unwrap();
        let mut retained = Vec::new();
        representation
            .executable
            .read_to_end(&mut retained)
            .unwrap();
        assert_eq!(retained, b"expected executable bytes");
        assert_eq!(representation.links, 0);
        assert!(representation.executable.write_all(b"B").is_err());
        let empty = b"\0";
        let reopened = unsafe {
            libc::openat(
                representation.executable.as_raw_fd(),
                empty.as_ptr().cast(),
                libc::O_EMPTY_PATH | libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        assert_eq!(reopened, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOTCAPABLE)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicated_and_fork_inherited_readers_cannot_reacquire_writing() {
        let root = std::env::temp_dir().join(format!(
            "gwr-m7-representation-authority-test-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut representation =
            prepare_execution_representation(&root, b"finalized representation").unwrap();
        assert_no_write_or_reacquisition(representation.executable.as_raw_fd());

        let duplicate_fd = unsafe { libc::dup(representation.executable.as_raw_fd()) };
        assert!(duplicate_fd >= 0);
        let duplicate = unsafe { std::fs::File::from_raw_fd(duplicate_fd) };
        assert_no_write_or_reacquisition(duplicate.as_raw_fd());

        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let byte = [0_u8];
            let write_result = unsafe {
                libc::pwrite(
                    representation.executable.as_raw_fd(),
                    byte.as_ptr().cast(),
                    byte.len(),
                    0,
                )
            };
            let write_errno = std::io::Error::last_os_error().raw_os_error();
            let reopened = unsafe {
                libc::openat(
                    representation.executable.as_raw_fd(),
                    c"".as_ptr(),
                    libc::O_EMPTY_PATH | libc::O_RDWR | libc::O_CLOEXEC,
                )
            };
            let reopen_errno = std::io::Error::last_os_error().raw_os_error();
            let accepted = write_result == -1
                && matches!(write_errno, Some(libc::EBADF) | Some(libc::ENOTCAPABLE))
                && reopened == -1
                && reopen_errno == Some(libc::ENOTCAPABLE);
            unsafe { libc::_exit(if accepted { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        representation.executable.seek(SeekFrom::Start(0)).unwrap();
        let mut retained = Vec::new();
        representation
            .executable
            .read_to_end(&mut retained)
            .unwrap();
        assert_eq!(retained, b"finalized representation");

        drop(duplicate);
        drop(representation);
        std::fs::remove_dir_all(root).unwrap();
    }
}
