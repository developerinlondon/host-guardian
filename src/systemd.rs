//! The systemd interface: readiness/watchdog notification and unit control.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Send a `sd_notify` datagram. Implemented directly rather than via libsystemd
/// so the package depends only on systemd being present at runtime, not on its
/// development headers at build time.
///
/// Absent `NOTIFY_SOCKET` means we were not started by systemd; that is normal
/// for a foreground run and is not an error.
pub fn notify(state: &str) -> io::Result<()> {
    let Ok(socket) = std::env::var("NOTIFY_SOCKET") else {
        return Ok(());
    };
    if socket.is_empty() {
        return Ok(());
    }
    // A leading '@' denotes an abstract socket, encoded as a leading NUL.
    let path = if let Some(rest) = socket.strip_prefix('@') {
        format!("\0{rest}")
    } else {
        socket
    };
    let sock = UnixDatagram::unbound()?;
    sock.send_to(state.as_bytes(), Path::new(&path))?;
    Ok(())
}

pub fn notify_ready() {
    let _ = notify("READY=1");
}

pub fn ping_watchdog() {
    let _ = notify("WATCHDOG=1");
}

/// Watchdog interval from `WatchdogSec=`, halved.
///
/// systemd's own guidance is to ping at half the configured interval so a
/// single slow cycle does not trip the timeout.
#[must_use]
pub fn watchdog_interval() -> Option<Duration> {
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros(usec / 2))
}

fn systemctl(args: &[&str], timeout: Duration) -> io::Result<std::process::Output> {
    let mut child = Command::new("/usr/bin/systemctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // A wedged systemctl must not wedge the guardian: poll for completion and
    // kill it if it outlives the budget.
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(_status) = child.try_wait()? {
            return child.wait_with_output();
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "systemctl exceeded its timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn is_active(unit: &str, timeout: Duration) -> bool {
    // `is-active` exits non-zero for inactive units, which is not an error.
    // `--` so a unit name can never be read as an option.
    systemctl(&["is-active", "--quiet", "--", unit], timeout).is_ok_and(|o| o.status.success())
}

pub fn stop(unit: &str, timeout: Duration) -> Result<(), String> {
    match systemctl(&["stop", "--", unit], timeout) {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            Err(if err.is_empty() {
                format!("systemctl stop exited {}", o.status)
            } else {
                err
            })
        }
        Err(e) => Err(e.to_string()),
    }
}
