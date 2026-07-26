mod actions;
mod config;
mod metrics;
mod mounts;
mod pressure;
mod psi;
mod systemd;

use actions::{Budget, Decision};
use mounts::MountVerdict;
use pressure::Pressure;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_CONFIG: &str = "/etc/hostguard/config.json";
const PSI_MEMORY: &str = "/proc/pressure/memory";
const MEMINFO: &str = "/proc/meminfo";
const MOUNTINFO: &str = "/proc/self/mountinfo";

struct Args {
    config: String,
    once: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut config = DEFAULT_CONFIG.to_string();
    let mut once = false;
    let mut it = std::env::args().skip(1);

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => {
                config = it.next().ok_or("--config needs a path")?;
            }
            "--once" => once = true,
            "--version" => {
                println!("hostguard {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "hostguard {}\n\n\
                     Usage: hostguard [--config PATH] [--once]\n\n\
                       --config PATH  configuration file (default {DEFAULT_CONFIG})\n\
                       --once         evaluate once and exit; does not act\n\
                       --version      print version and exit",
                    env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            other => return Err(format!("unrecognised argument {other:?}")),
        }
    }
    Ok(Args { config, once })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Write via a temporary file and rename, so a reader never observes a
/// half-written file. node-exporter reads the metrics file on its own schedule
/// and would otherwise occasionally parse a truncated one.
fn write_atomic(path: &Path, contents: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("out")
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

struct Evaluation {
    pressure: Pressure,
    mounts: Vec<(String, MountVerdict)>,
    unit_active: Vec<(String, bool)>,
    errors: Vec<String>,
}

fn evaluate(cfg: &config::Config) -> Evaluation {
    let mut errors = Vec::new();

    let available_bytes = std::fs::read_to_string(MEMINFO)
        .map_err(|e| format!("{MEMINFO}: {e}"))
        .and_then(|t| pressure::parse_mem_available(&t).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| {
            errors.push(e);
            u64::MAX
        });

    let full_avg10_percent = std::fs::read_to_string(PSI_MEMORY)
        .map_err(|e| format!("{PSI_MEMORY}: {e}"))
        .and_then(|t| pressure::parse_psi_full_avg10(&t).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| {
            errors.push(e);
            0.0
        });

    let mounts = match std::fs::read_to_string(MOUNTINFO) {
        Ok(text) => match mounts::parse_mountinfo(&text) {
            Ok(table) => mounts::verify(&cfg.mount_expectations, &table),
            Err(e) => {
                errors.push(e.to_string());
                Vec::new()
            }
        },
        Err(e) => {
            errors.push(format!("{MOUNTINFO}: {e}"));
            Vec::new()
        }
    };

    let timeout = Duration::from_secs(2);
    let unit_active = cfg
        .shed_units
        .iter()
        .map(|u| (u.clone(), systemd::is_active(u, timeout)))
        .collect();

    Evaluation {
        pressure: Pressure {
            available_bytes,
            full_avg10_percent,
        },
        mounts,
        unit_active,
        errors,
    }
}

/// Require a condition to hold for N consecutive evaluations before it counts.
/// A single sample straddling a garbage-collection pause is not an emergency.
#[derive(Default)]
struct Gate {
    counters: HashMap<String, u32>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Gated {
    /// Below the sample threshold, or the condition is clear.
    No,
    /// Crossed the threshold on this evaluation.
    Newly,
    /// Already reported on an earlier evaluation.
    Still,
}

impl Gated {
    fn active(self) -> bool {
        self != Self::No
    }
}

impl Gate {
    fn observe(&mut self, key: &str, active: bool, required: u32) -> Gated {
        if !active {
            self.counters.remove(key);
            return Gated::No;
        }
        let c = self.counters.entry(key.to_string()).or_insert(0);
        *c = c.saturating_add(1);
        match (*c).cmp(&required) {
            std::cmp::Ordering::Less => Gated::No,
            std::cmp::Ordering::Equal => Gated::Newly,
            std::cmp::Ordering::Greater => Gated::Still,
        }
    }
}

fn write_incident(dir: &Path, now: u64, event: &str, payload: &serde_json::Value) {
    let slug: String = event
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let path = dir.join(format!("{now}-{slug}.json"));
    let body = serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".into());
    if let Err(e) = write_atomic(&path, &format!("{body}\n"), 0o600) {
        eprintln!("hostguard: cannot write incident {}: {e}", path.display());
    }
}

/// `Dry` is what `--once` runs: evaluate and report, touch nothing. The manual
/// and `--help` both promise that, and an operator sanity-checking a config as
/// root on a live host is exactly who would be harmed by it not being true.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Dry,
    Live,
}

fn run_once(
    cfg: &config::Config,
    gate: &mut Gate,
    budget: &mut Budget,
    mono: u64,
    mode: Mode,
) -> String {
    let now = now_secs();
    let ev = evaluate(cfg);

    let emergency_raw = pressure::is_emergency(ev.pressure, cfg.memory);
    let emergency = gate.observe("memory_emergency", emergency_raw, cfg.consecutive_samples);

    for (path, verdict) in &ev.mounts {
        let key = format!("mount:{path}");
        let bad = !matches!(verdict, MountVerdict::Ok);
        // Newly, not active: a condition left unresolved overnight would
        // otherwise write one file per poll and fill /var/log during exactly
        // the incident this daemon exists to report.
        if gate.observe(&key, bad, cfg.consecutive_samples) == Gated::Newly && mode == Mode::Live {
            write_incident(
                &cfg.incident_dir,
                now,
                &key,
                &serde_json::json!({
                    "event": "mount_identity",
                    "path": path,
                    "verdict": format!("{verdict:?}"),
                    "timestamp": now,
                }),
            );
        }
    }

    if emergency.active() && mode == Mode::Live {
        for (unit, active) in &ev.unit_active {
            if !active {
                continue;
            }
            let decision = budget.admit(unit, mono, &cfg.actions, cfg.observe_only);
            let result = match decision {
                Decision::Shed => match systemd::stop(unit, Duration::from_secs(2)) {
                    Ok(()) => "shed".to_string(),
                    Err(e) => format!("failed: {e}"),
                },
                other => format!("{other:?}"),
            };
            write_incident(
                &cfg.incident_dir,
                now,
                "memory-emergency",
                &serde_json::json!({
                    "event": "memory_emergency",
                    "unit": unit,
                    "result": result,
                    "available_bytes": ev.pressure.available_bytes,
                    "full_psi_percent": ev.pressure.full_avg10_percent,
                    "timestamp": now,
                }),
            );
        }
    }

    metrics::render(&metrics::Snapshot {
        up: ev.errors.is_empty(),
        observe_only: cfg.observe_only,
        timestamp: now,
        errors: ev.errors.len(),
        available_bytes: ev.pressure.available_bytes,
        full_psi_percent: ev.pressure.full_avg10_percent,
        emergency_active: emergency.active(),
        actions_in_window: budget.actions_in_window(),
        mounts: &ev.mounts,
        unit_active: &ev.unit_active,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hostguard: {e}");
            return ExitCode::from(2);
        }
    };

    let text = match std::fs::read_to_string(&args.config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hostguard: cannot read {}: {e}", args.config);
            return ExitCode::FAILURE;
        }
    };
    let cfg = match config::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hostguard: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut gate = Gate::default();
    let mut budget = Budget::new();

    // Monotonic: cooldown and budget must not be widened by an NTP step. A
    // forward jump past budget_window_sec on a host that boots with a bad RTC
    // would otherwise clear the history and release a full budget of stops.
    let started = std::time::Instant::now();
    let mono = || started.elapsed().as_secs();

    if args.once {
        print!(
            "{}",
            run_once(&cfg, &mut gate, &mut budget, mono(), Mode::Dry)
        );
        return ExitCode::SUCCESS;
    }

    let interval = Duration::from_secs(cfg.poll_interval_sec);
    let trigger = psi::Trigger::arm(
        PSI_MEMORY,
        Duration::from_millis(150),
        Duration::from_secs(2),
    );
    match &trigger {
        Ok(_) => eprintln!("hostguard: armed PSI trigger on {PSI_MEMORY}"),
        Err(e) => eprintln!("hostguard: PSI trigger unavailable ({e}); polling every {interval:?}"),
    }

    systemd::notify_ready();
    let watchdog = systemd::watchdog_interval();
    // Never sleep past a watchdog ping, or systemd concludes we are wedged.
    let wait_for = watchdog.map_or(interval, |w| interval.min(w));

    loop {
        let metrics = run_once(&cfg, &mut gate, &mut budget, mono(), Mode::Live);
        if let Err(e) = write_atomic(&cfg.metrics_path, &metrics, 0o644) {
            eprintln!("hostguard: cannot write metrics: {e}");
        }
        systemd::ping_watchdog();

        match &trigger {
            Ok(t) => match t.wait(wait_for) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("hostguard: PSI wait failed: {e}");
                    std::thread::sleep(wait_for);
                }
            },
            Err(_) => std::thread::sleep(wait_for),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_requires_consecutive_samples() {
        let mut g = Gate::default();
        assert_eq!(g.observe("k", true, 2), Gated::No);
        assert_eq!(g.observe("k", true, 2), Gated::Newly);
    }

    #[test]
    fn gate_reports_newly_once_then_still() {
        let mut g = Gate::default();
        g.observe("k", true, 1);
        for _ in 0..5 {
            assert_eq!(
                g.observe("k", true, 1),
                Gated::Still,
                "a persisting condition must not re-report, or it writes one \
                 incident file per poll and fills /var/log"
            );
        }
    }

    #[test]
    fn gate_resets_when_the_condition_clears() {
        let mut g = Gate::default();
        g.observe("k", true, 2);
        assert_eq!(g.observe("k", true, 2), Gated::Newly);
        assert_eq!(g.observe("k", false, 2), Gated::No);
        // A recurrence is a new incident and must report again.
        assert_eq!(g.observe("k", true, 2), Gated::No);
        assert_eq!(g.observe("k", true, 2), Gated::Newly);
    }

    #[test]
    fn gate_keys_are_independent() {
        let mut g = Gate::default();
        assert_eq!(g.observe("a", true, 1), Gated::Newly);
        assert_eq!(g.observe("b", true, 1), Gated::Newly);
    }

    #[test]
    fn gated_active_covers_newly_and_still() {
        assert!(Gated::Newly.active());
        assert!(Gated::Still.active());
        assert!(!Gated::No.active());
    }
}
