//! PSI trigger: let the kernel decide when to wake us.
//!
//! Interval polling bounds the reaction to a memory emergency below by that
//! interval, and wastes every other tick. A PSI trigger blocks in `poll()`
//! until stall time crosses the threshold. Availability varies by kernel
//! config, so `arm` returns an error the caller can degrade from.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::time::Duration;

pub struct Trigger {
    file: File,
}

impl Trigger {
    /// Arm a trigger that fires when tasks are fully stalled on memory for
    /// `stall` within any `window`.
    ///
    /// The kernel requires the window to be 500ms..=10s and the stall threshold
    /// not to exceed it.
    pub fn arm(path: &str, stall: Duration, window: Duration) -> io::Result<Self> {
        let stall_us = u64::try_from(stall.as_micros()).unwrap_or(u64::MAX);
        let window_us = u64::try_from(window.as_micros()).unwrap_or(u64::MAX);
        if !(500_000..=10_000_000).contains(&window_us) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PSI window must be between 500ms and 10s",
            ));
        }
        if stall_us > window_us {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PSI stall threshold cannot exceed the window",
            ));
        }
        // psi_trigger_create rejects a window that is not a multiple of 2s
        // unless the caller holds CAP_SYS_RESOURCE, which the shipped unit
        // drops. Refuse here rather than emit a write the kernel will EINVAL.
        if window_us % 2_000_000 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PSI window must be a multiple of 2s without CAP_SYS_RESOURCE",
            ));
        }

        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        // One write_all, and a trailing newline. psi_write parses each write()
        // independently, so a formatting macro's multiple syscalls are each
        // rejected; and it NUL-terminates at buf_size-1, eating the final digit
        // when the newline is absent.
        file.write_all(format!("full {stall_us} {window_us}\n").as_bytes())?;
        file.flush()?;
        Ok(Self { file })
    }

    /// Block until the trigger fires or `timeout` elapses.
    ///
    /// Returns true if pressure crossed the threshold, false on timeout. An
    /// interrupted poll reports as a timeout so the caller simply re-evaluates.
    pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);

        // SAFETY: pfd points to a single valid pollfd for the duration of the
        // call, and the fd is kept alive by `self.file`.
        let rc = unsafe { libc::poll(std::ptr::addr_of_mut!(pfd), 1, ms) };

        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        if rc == 0 {
            return Ok(false);
        }
        if pfd.revents & libc::POLLERR != 0 {
            return Err(io::Error::other("PSI trigger returned POLLERR"));
        }
        Ok(pfd.revents & libc::POLLPRI != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_window_outside_the_kernel_range() {
        for bad in [Duration::from_millis(100), Duration::from_secs(30)] {
            let e = Trigger::arm("/proc/pressure/memory", Duration::from_millis(50), bad);
            assert!(e.is_err(), "accepted out-of-range window {bad:?}");
        }
    }

    #[test]
    fn rejects_a_stall_longer_than_its_window() {
        let e = Trigger::arm(
            "/proc/pressure/memory",
            Duration::from_secs(5),
            Duration::from_secs(1),
        );
        assert!(e.is_err());
    }

    #[test]
    fn missing_psi_file_is_an_error_the_caller_can_fall_back_from() {
        let e = Trigger::arm(
            "/proc/does-not-exist/pressure",
            Duration::from_millis(50),
            Duration::from_secs(2),
        );
        assert!(e.is_err());
    }

    #[test]
    fn rejects_a_window_the_kernel_will_refuse_without_cap_sys_resource() {
        let e = Trigger::arm(
            "/proc/pressure/memory",
            Duration::from_millis(150),
            Duration::from_secs(1),
        );
        assert!(e.is_err(), "1s window is not a multiple of 2s");
    }

    /// The whole reason this is a daemon rather than a timer. A silent fallback
    /// to interval polling looks healthy, so assert the arm actually succeeds
    /// wherever the kernel exposes PSI.
    #[test]
    fn arms_against_the_real_kernel_interface() {
        if !std::path::Path::new("/proc/pressure/memory").exists() {
            eprintln!("skipping: kernel has no PSI support");
            return;
        }
        match Trigger::arm(
            "/proc/pressure/memory",
            Duration::from_millis(150),
            Duration::from_secs(2),
        ) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: PSI needs write permission on /proc/pressure/memory");
            }
            Err(e) => panic!("PSI trigger failed to arm: {e}"),
        }
    }
}
