//! Narrow platform adapter for invoking one already-opened executable object.
//!
//! The Docket domain remains safe Rust. This crate contains the smallest
//! FreeBSD-specific process boundary needed for `fexecve(2)` and captured
//! standard I/O. It does not resolve paths, decide policy, or interpret work.

use std::ffi::CString;
use std::fs::File;
#[cfg(not(target_os = "freebsd"))]
use std::io;

#[derive(Debug)]
pub struct DescriptorExecOutput {
    pub descriptor_exec_accepted: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exec_errno: Option<i32>,
}

#[cfg(target_os = "freebsd")]
#[allow(unsafe_code)]
mod platform {
    use super::{CString, DescriptorExecOutput, File};
    use std::ffi::OsStr;
    use std::io::{self, Read as _, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::thread;

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
        std::env::vars_os()
            .map(|(name, value)| {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(OsStr::new(&name).as_bytes());
                bytes.push(b'=');
                bytes.extend_from_slice(OsStr::new(&value).as_bytes());
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
                libc::fexecve(
                    executable.as_raw_fd(),
                    argv_ptrs.as_ptr(),
                    env_ptrs.as_ptr(),
                );
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
        Ok(DescriptorExecOutput {
            descriptor_exec_accepted: exec_errno.is_none(),
            exit_code,
            signal,
            stdout,
            stderr,
            exec_errno,
        })
    }
}

#[cfg(target_os = "freebsd")]
pub use platform::invoke;

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
