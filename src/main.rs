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

const DEFAULT_CONFIG: &str = "/etc/host-guardian/config.json";
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
                println!("host-guardian {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "host-guardian {}\n\n\
                     Usage: host-guardian [--config PATH] [--once]\n\n\
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

/// Filename-safe rendering of an event key, with a digest so distinct keys
/// cannot share a file.
///
/// Sanitising alone collides: `mount:/srv/data` and `mount:/srv-data` both
/// flatten to the same name, and one incident would silently overwrite the
/// other. The digest is for disambiguation, not security.
fn incident_slug(event: &str) -> String {
    let safe: String = event
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(96)
        .collect();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in event.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{safe}-{hash:016x}")
}

fn write_incident(dir: &Path, now: u64, event: &str, payload: &serde_json::Value) {
    let slug = incident_slug(event);
    let path = dir.join(format!("{now}-{slug}.json"));
    let body = serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".into());
    if let Err(e) = write_atomic(&path, &format!("{body}\n"), 0o600) {
        eprintln!(
            "host-guardian: cannot write incident {}: {e}",
            path.display()
        );
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

/// The two side effects, bundled so they can be swapped in tests. Injecting the
/// stop is what makes it impossible for a test to stop a unit on the machine
/// running it.
struct Effects<'a> {
    record: &'a mut dyn FnMut(&str, serde_json::Value),
    stop: &'a mut dyn FnMut(&str) -> Result<(), String>,
}

/// Acts on a gated memory emergency and records what happened.
///
/// Split out of `run_once` so the reporting rules stay legible: one record when
/// the emergency starts, and one per action actually taken. A suppression is
/// the steady state during a sustained emergency, so recording those would fill
/// /var/log precisely when the host is already in trouble.
fn handle_emergency(
    cfg: &config::Config,
    budget: &mut Budget,
    ev: &Evaluation,
    emergency: Gated,
    now: u64,
    mono: u64,
    fx: &mut Effects,
) {
    if !emergency.active() {
        return;
    }
    if emergency == Gated::Newly {
        (fx.record)(
            "memory-emergency",
            serde_json::json!({
                "event": "memory_emergency_began",
                "available_bytes": ev.pressure.available_bytes,
                "full_psi_percent": ev.pressure.full_avg10_percent,
                "timestamp": now,
            }),
        );
    }

    for (unit, active) in &ev.unit_active {
        if !active {
            continue;
        }
        if budget.admit(unit, mono, &cfg.actions, cfg.observe_only) != Decision::Shed {
            continue;
        }
        let result = match (fx.stop)(unit) {
            Ok(()) => "shed".to_string(),
            Err(e) => format!("failed: {e}"),
        };
        (fx.record)(
            // The unit is part of the name: two units shed within one wall
            // second would otherwise rename onto the same path, leaving a
            // record that names only the last.
            &format!("memory-emergency-{unit}"),
            serde_json::json!({
                "event": "memory_emergency_shed",
                "unit": unit,
                "result": result,
                "available_bytes": ev.pressure.available_bytes,
                "full_psi_percent": ev.pressure.full_avg10_percent,
                "timestamp": now,
            }),
        );
    }
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

    if mode == Mode::Live {
        let dir = cfg.incident_dir.clone();
        let mut record = |slug: &str, payload: serde_json::Value| {
            write_incident(&dir, now, slug, &payload);
        };
        let mut stop = |unit: &str| systemd::stop(unit, Duration::from_secs(2));
        handle_emergency(
            cfg,
            budget,
            &ev,
            emergency,
            now,
            mono,
            &mut Effects {
                record: &mut record,
                stop: &mut stop,
            },
        );
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
            eprintln!("host-guardian: {e}");
            return ExitCode::from(2);
        }
    };

    let text = match std::fs::read_to_string(&args.config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("host-guardian: cannot read {}: {e}", args.config);
            return ExitCode::FAILURE;
        }
    };
    let cfg = match config::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("host-guardian: {e}");
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
        Ok(_) => eprintln!("host-guardian: armed PSI trigger on {PSI_MEMORY}"),
        Err(e) => {
            eprintln!("host-guardian: PSI trigger unavailable ({e}); polling every {interval:?}")
        }
    }

    systemd::notify_ready();
    let watchdog = systemd::watchdog_interval();
    // Never sleep past a watchdog ping, or systemd concludes we are wedged.
    let wait_for = watchdog.map_or(interval, |w| interval.min(w));

    loop {
        let metrics = run_once(&cfg, &mut gate, &mut budget, mono(), Mode::Live);
        if let Err(e) = write_atomic(&cfg.metrics_path, &metrics, 0o644) {
            eprintln!("host-guardian: cannot write metrics: {e}");
        }
        systemd::ping_watchdog();

        match &trigger {
            Ok(t) => match t.wait(wait_for) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("host-guardian: PSI wait failed: {e}");
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

    fn emergency_cfg(observe_only: bool) -> config::Config {
        let json = serde_json::json!({
            "schema_version": 1,
            "observe_only": observe_only,
            "metrics_path": "/var/lib/host-guardian/textfile/host-guardian.prom",
            "incident_dir": "/var/log/host-guardian/incidents",
            "memory": { "available_bytes": 8_589_934_592_u64, "full_psi_percent": 10.0 },
            "shed_units": ["a.service", "b.service"],
            "mount_expectations": [],
            "actions": {
                "cooldown_sec": 600, "budget_window_sec": 3600, "max_actions_per_window": 3
            }
        });
        config::parse(&json.to_string()).unwrap()
    }

    fn emergency_ev() -> Evaluation {
        Evaluation {
            pressure: Pressure {
                available_bytes: 1024,
                full_avg10_percent: 99.0,
            },
            mounts: Vec::new(),
            unit_active: vec![("a.service".into(), true), ("b.service".into(), true)],
            errors: Vec::new(),
        }
    }

    #[derive(Default)]
    struct Recorded {
        slugs: Vec<String>,
        stopped: Vec<String>,
    }

    /// Drives one emergency cycle with both side effects captured. The stop is
    /// injected so a test can never stop a unit on the machine running it.
    fn drive(
        cfg: &config::Config,
        budget: &mut Budget,
        ev: &Evaluation,
        gated: Gated,
        t: u64,
        out: &mut Recorded,
    ) {
        // Destructured so the two closures borrow disjoint fields.
        let Recorded { slugs, stopped } = out;
        let mut record = |slug: &str, _p: serde_json::Value| slugs.push(slug.to_string());
        let mut stop = |u: &str| {
            stopped.push(u.to_string());
            Ok(())
        };
        handle_emergency(
            cfg,
            budget,
            ev,
            gated,
            t,
            t,
            &mut Effects {
                record: &mut record,
                stop: &mut stop,
            },
        );
    }

    /// The bug this exists to prevent: a sustained emergency recorded one file
    /// per unit per cycle, so an armed PSI trigger could write ~1,800 an hour
    /// into /var/log while the host was already short of memory.
    #[test]
    fn a_sustained_emergency_records_once_not_once_per_cycle() {
        let cfg = emergency_cfg(true);
        let ev = emergency_ev();
        let mut budget = Budget::new();
        let mut out = Recorded::default();
        drive(&cfg, &mut budget, &ev, Gated::Newly, 0, &mut out);
        for cycle in 1..20 {
            drive(&cfg, &mut budget, &ev, Gated::Still, cycle, &mut out);
        }
        assert_eq!(
            out.slugs,
            ["memory-emergency"],
            "observe-only recorded more than the onset over 20 cycles"
        );
    }

    #[test]
    fn each_shed_unit_gets_its_own_record_name() {
        let cfg = emergency_cfg(false);
        let ev = emergency_ev();
        let mut budget = Budget::new();
        let mut out = Recorded::default();
        drive(&cfg, &mut budget, &ev, Gated::Newly, 0, &mut out);

        assert_eq!(out.stopped.len(), 2, "expected both units shed");
        let shed: Vec<&String> = out.slugs.iter().filter(|s| s.contains("service")).collect();
        assert_eq!(shed.len(), 2, "got {:?}", out.slugs);
        assert_ne!(shed[0], shed[1], "two units shared one record name");
    }

    #[test]
    fn distinct_events_never_share_an_incident_filename() {
        // Sanitising alone flattens these onto one name, so one incident would
        // silently overwrite the other.
        let collide = [
            ("mount:/srv/data", "mount:/srv-data"),
            (
                "memory-emergency-foo-bar.service",
                "memory-emergency-foo.bar.service",
            ),
        ];
        for (a, b) in collide {
            assert_ne!(incident_slug(a), incident_slug(b), "{a} and {b} collided");
        }
    }

    #[test]
    fn incident_slug_is_stable_and_filename_safe() {
        let s = incident_slug("mount:/srv/data");
        assert_eq!(s, incident_slug("mount:/srv/data"), "not deterministic");
        assert!(
            s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "unsafe filename: {s}"
        );
        assert!(s.len() < 120, "unbounded slug length");
    }

    #[test]
    fn a_cleared_emergency_records_nothing() {
        let cfg = emergency_cfg(true);
        let ev = emergency_ev();
        let mut budget = Budget::new();
        let mut out = Recorded::default();
        drive(&cfg, &mut budget, &ev, Gated::No, 0, &mut out);
        assert!(out.slugs.is_empty());
        assert!(out.stopped.is_empty(), "stopped a unit with no emergency");
    }

    #[test]
    fn gated_active_covers_newly_and_still() {
        assert!(Gated::Newly.active());
        assert!(Gated::Still.active());
        assert!(!Gated::No.active());
    }
}
