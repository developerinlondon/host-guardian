//! Prometheus textfile output.
//!
//! This is the only publication channel: node-exporter's textfile collector
//! picks the file up, so host-guardian never listens on a socket and needs no
//! scrape target of its own.

use crate::mounts::MountVerdict;
use std::fmt::Write as _;

pub struct Snapshot<'a> {
    pub up: bool,
    pub observe_only: bool,
    pub timestamp: u64,
    pub errors: usize,
    pub available_bytes: u64,
    pub full_psi_percent: f64,
    pub emergency_active: bool,
    pub actions_in_window: usize,
    pub mounts: &'a [(String, MountVerdict)],
    pub unit_active: &'a [(String, bool)],
}

/// Escape a label value per the Prometheus exposition format. A mountpoint
/// containing a quote or backslash would otherwise produce a file that the
/// textfile collector rejects wholesale, taking every other metric with it.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

#[must_use]
pub fn render(s: &Snapshot) -> String {
    let mut out = String::with_capacity(1024);

    let _ = writeln!(
        out,
        "# HELP host_guardian_up Whether the last evaluation completed without errors."
    );
    let _ = writeln!(out, "# TYPE host_guardian_up gauge");
    let _ = writeln!(out, "host_guardian_up {}", u8::from(s.up));

    let _ = writeln!(out, "# TYPE host_guardian_observe_only gauge");
    let _ = writeln!(
        out,
        "host_guardian_observe_only {}",
        u8::from(s.observe_only)
    );

    let _ = writeln!(out, "# TYPE host_guardian_last_run_timestamp_seconds gauge");
    let _ = writeln!(
        out,
        "host_guardian_last_run_timestamp_seconds {}",
        s.timestamp
    );

    let _ = writeln!(out, "# TYPE host_guardian_errors gauge");
    let _ = writeln!(out, "host_guardian_errors {}", s.errors);

    let _ = writeln!(out, "# TYPE host_guardian_memory_available_bytes gauge");
    let _ = writeln!(
        out,
        "host_guardian_memory_available_bytes {}",
        s.available_bytes
    );

    let _ = writeln!(out, "# TYPE host_guardian_memory_full_psi_percent gauge");
    let _ = writeln!(
        out,
        "host_guardian_memory_full_psi_percent {:.6}",
        s.full_psi_percent
    );

    let _ = writeln!(out, "# TYPE host_guardian_memory_emergency gauge");
    let _ = writeln!(
        out,
        "host_guardian_memory_emergency {}",
        u8::from(s.emergency_active)
    );

    let _ = writeln!(out, "# TYPE host_guardian_actions_in_window gauge");
    let _ = writeln!(
        out,
        "host_guardian_actions_in_window {}",
        s.actions_in_window
    );

    let _ = writeln!(
        out,
        "# HELP host_guardian_mount_ok Whether a mount matches its expected identity."
    );
    let _ = writeln!(out, "# TYPE host_guardian_mount_ok gauge");
    for (path, verdict) in s.mounts {
        let ok = u8::from(matches!(verdict, MountVerdict::Ok));
        let _ = writeln!(
            out,
            "host_guardian_mount_ok{{path=\"{}\"}} {ok}",
            escape(path)
        );
    }

    let _ = writeln!(out, "# TYPE host_guardian_mount_present gauge");
    for (path, verdict) in s.mounts {
        let present = u8::from(!matches!(verdict, MountVerdict::Missing));
        let _ = writeln!(
            out,
            "host_guardian_mount_present{{path=\"{}\"}} {present}",
            escape(path)
        );
    }

    let _ = writeln!(out, "# TYPE host_guardian_unit_active gauge");
    for (unit, active) in s.unit_active {
        let _ = writeln!(
            out,
            "host_guardian_unit_active{{unit=\"{}\"}} {}",
            escape(unit),
            u8::from(*active)
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mounts::MountIdentity;

    fn snapshot(mounts: &[(String, MountVerdict)], units: &[(String, bool)]) -> String {
        render(&Snapshot {
            up: true,
            observe_only: false,
            timestamp: 1_700_000_000,
            errors: 0,
            available_bytes: 51_723_010_048,
            full_psi_percent: 0.0,
            emergency_active: false,
            actions_in_window: 0,
            mounts,
            unit_active: units,
        })
    }

    #[test]
    fn every_metric_line_is_key_space_value() {
        let out = snapshot(
            &[("/".into(), MountVerdict::Ok)],
            &[("a.service".into(), true)],
        );
        for line in out.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let fields: Vec<&str> = line.rsplitn(2, ' ').collect();
            assert_eq!(fields.len(), 2, "unparseable exposition line: {line}");
            assert!(
                fields[0].parse::<f64>().is_ok(),
                "value is not a number: {line}"
            );
        }
    }

    #[test]
    fn mount_mismatch_reports_present_but_not_ok() {
        let mounts = vec![(
            "/tmp".to_string(),
            MountVerdict::Mismatch {
                actual: MountIdentity {
                    source: "tmpfs".into(),
                    fstype: "tmpfs".into(),
                    root: "/".into(),
                },
            },
        )];
        let out = snapshot(&mounts, &[]);
        assert!(out.contains("host_guardian_mount_ok{path=\"/tmp\"} 0"));
        assert!(out.contains("host_guardian_mount_present{path=\"/tmp\"} 1"));
    }

    #[test]
    fn missing_mount_reports_absent_and_not_ok() {
        let mounts = vec![("/data".to_string(), MountVerdict::Missing)];
        let out = snapshot(&mounts, &[]);
        assert!(out.contains("host_guardian_mount_ok{path=\"/data\"} 0"));
        assert!(out.contains("host_guardian_mount_present{path=\"/data\"} 0"));
    }

    #[test]
    fn label_values_with_quotes_are_escaped() {
        let mounts = vec![(r#"/od"d\path"#.to_string(), MountVerdict::Ok)];
        let out = snapshot(&mounts, &[]);
        let line = out
            .lines()
            .find(|l| l.starts_with("host_guardian_mount_ok{"))
            .unwrap();
        assert!(line.contains(r#"\""#), "quote not escaped: {line}");
        assert!(line.contains(r"\\"), "backslash not escaped: {line}");
        assert_eq!(line.matches('"').count() - line.matches(r#"\""#).count(), 2);
    }

    #[test]
    fn empty_mount_and_unit_lists_still_render_valid_output() {
        let out = snapshot(&[], &[]);
        assert!(out.contains("host_guardian_up 1"));
        assert!(out.ends_with('\n'));
    }
}
