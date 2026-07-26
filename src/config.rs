//! Configuration, rendered per host by whatever manages it (Ansible, by hand).
//!
//! Deliberately small. The predecessor's config carried disk, inode, CPU, IO
//! and load thresholds plus a restart allowlist; every one of those is covered
//! by node-exporter alert rules or by systemd `Restart=`, so carrying them here
//! only created two places to disagree.

use crate::actions::ActionPolicy;
use crate::mounts::MountExpectation;
use crate::pressure::EmergencyThresholds;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub observe_only: bool,
    pub metrics_path: PathBuf,
    pub incident_dir: PathBuf,
    #[serde(default = "default_samples")]
    pub consecutive_samples: u32,
    #[serde(default = "default_poll")]
    pub poll_interval_sec: u64,
    pub memory: EmergencyThresholds,
    #[serde(default)]
    pub shed_units: Vec<String>,
    #[serde(default)]
    pub mount_expectations: Vec<MountExpectation>,
    pub actions: ActionPolicy,
}

fn default_samples() -> u32 {
    2
}

fn default_poll() -> u64 {
    30
}

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub enum ConfigError {
    Parse(String),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "config is not valid JSON: {e}"),
            Self::Invalid(e) => write!(f, "config is invalid: {e}"),
        }
    }
}

/// A unit name that reaches `systemctl stop` must be a plain service name.
/// Anything accepting shell metacharacters here would turn a config file into
/// arbitrary root execution.
fn is_safe_unit(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 255
        && unit.ends_with(".service")
        // A leading '-' is an option to systemctl, not a unit. Nothing that
        // both ends in .service and applies to `stop` is destructive today,
        // but making config-supplied argv unambiguous is this check's job.
        && !unit.starts_with('-')
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '-'))
}

pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let cfg: Config = serde_json::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;

    if cfg.schema_version != SCHEMA_VERSION {
        return Err(ConfigError::Invalid(format!(
            "schema_version {} is not supported (expected {SCHEMA_VERSION})",
            cfg.schema_version
        )));
    }
    if cfg.consecutive_samples == 0 {
        return Err(ConfigError::Invalid(
            "consecutive_samples must be at least 1, or every transient spike acts".into(),
        ));
    }
    if cfg.poll_interval_sec == 0 {
        return Err(ConfigError::Invalid(
            "poll_interval_sec must be at least 1".into(),
        ));
    }
    if cfg.memory.full_psi_percent < 0.0 || cfg.memory.full_psi_percent > 100.0 {
        return Err(ConfigError::Invalid(
            "memory.full_psi_percent must be a percentage between 0 and 100".into(),
        ));
    }
    for unit in &cfg.shed_units {
        if !is_safe_unit(unit) {
            return Err(ConfigError::Invalid(format!(
                "shed_units entry {unit:?} must be a plain *.service name"
            )));
        }
    }
    for m in &cfg.mount_expectations {
        if !m.path.starts_with('/') {
            return Err(ConfigError::Invalid(format!(
                "mount_expectations path {:?} must be absolute",
                m.path
            )));
        }
    }
    if !cfg.metrics_path.is_absolute() || !cfg.incident_dir.is_absolute() {
        return Err(ConfigError::Invalid(
            "metrics_path and incident_dir must be absolute".into(),
        ));
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "metrics_path": "/var/lib/hostguard/textfile/hostguard.prom",
            "incident_dir": "/var/log/hostguard/incidents",
            "memory": { "available_bytes": 8_589_934_592_u64, "full_psi_percent": 10.0 },
            "shed_units": ["code-server.service"],
            "mount_expectations": [
                {"path": "/", "source": "/dev/mapper/vg--root", "fstype": "ext4", "root": "/"}
            ],
            "actions": {
                "cooldown_sec": 600, "budget_window_sec": 3600, "max_actions_per_window": 3
            }
        })
    }

    fn parse_value(v: &serde_json::Value) -> Result<Config, ConfigError> {
        parse(&v.to_string())
    }

    #[test]
    fn accepts_a_representative_config() {
        let c = parse_value(&base()).unwrap();
        assert_eq!(c.shed_units, ["code-server.service"]);
        assert_eq!(c.consecutive_samples, 2, "default not applied");
        assert!(!c.observe_only);
    }

    #[test]
    fn rejects_a_future_schema_rather_than_guessing() {
        let mut v = base();
        v["schema_version"] = serde_json::json!(2);
        assert!(parse_value(&v).is_err());
    }

    #[test]
    fn rejects_unknown_keys_so_typos_are_not_silently_ignored() {
        let mut v = base();
        v["shed_unit"] = serde_json::json!(["typo.service"]);
        assert!(parse_value(&v).is_err());
    }

    #[test]
    fn rejects_shell_metacharacters_in_unit_names() {
        for bad in [
            "code-server.service; rm -rf /",
            "$(reboot).service",
            "a b.service",
            "../../etc/passwd.service",
            "-M.service",
            "-Hfoo.service",
        ] {
            let mut v = base();
            v["shed_units"] = serde_json::json!([bad]);
            assert!(parse_value(&v).is_err(), "accepted dangerous unit {bad:?}");
        }
    }

    #[test]
    fn rejects_non_service_units() {
        let mut v = base();
        v["shed_units"] = serde_json::json!(["something.timer"]);
        assert!(parse_value(&v).is_err());
    }

    #[test]
    fn accepts_templated_and_hyphenated_service_names() {
        let mut v = base();
        v["shed_units"] = serde_json::json!(["systemd-nspawn@eda-k3s.service"]);
        assert!(parse_value(&v).is_ok());
    }

    #[test]
    fn rejects_zero_consecutive_samples() {
        let mut v = base();
        v["consecutive_samples"] = serde_json::json!(0);
        assert!(parse_value(&v).is_err());
    }

    #[test]
    fn rejects_relative_paths() {
        let mut v = base();
        v["metrics_path"] = serde_json::json!("relative/path.prom");
        assert!(parse_value(&v).is_err());

        let mut v = base();
        v["mount_expectations"][0]["path"] = serde_json::json!("relative");
        assert!(parse_value(&v).is_err());
    }

    #[test]
    fn rejects_out_of_range_psi_percent() {
        let mut v = base();
        v["memory"]["full_psi_percent"] = serde_json::json!(150.0);
        assert!(parse_value(&v).is_err());
    }

    #[test]
    fn empty_shed_and_mount_lists_are_valid() {
        let mut v = base();
        v["shed_units"] = serde_json::json!([]);
        v["mount_expectations"] = serde_json::json!([]);
        assert!(
            parse_value(&v).is_ok(),
            "a sensing-only install must be allowed"
        );
    }
}
