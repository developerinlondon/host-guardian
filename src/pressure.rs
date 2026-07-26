//! Memory pressure sensing.
//!
//! Only the emergency signal lives here. Warning-level thresholds for memory,
//! CPU, IO, load and disk are node-exporter's job — it already exports all of
//! them and Prometheus can alert on them. Duplicating that in-process buys
//! nothing and drifts.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pressure {
    pub available_bytes: u64,
    pub full_avg10_percent: f64,
}

#[derive(Debug)]
pub enum SensorError {
    Malformed { file: String, reason: String },
}

impl fmt::Display for SensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { file, reason } => write!(f, "{file}: {reason}"),
        }
    }
}

/// `MemAvailable` is the kernel's own estimate of what is allocatable without
/// swapping. `MemFree` is not a substitute: reclaimable page cache counts as
/// available but not as free, so free alone reads as an emergency on a healthy
/// box with a warm cache.
pub fn parse_mem_available(meminfo: &str) -> Result<u64, SensorError> {
    for line in meminfo.lines() {
        let Some(rest) = line.strip_prefix("MemAvailable:") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let value = parts.next().ok_or_else(|| SensorError::Malformed {
            file: "meminfo".into(),
            reason: "MemAvailable has no value".into(),
        })?;
        let kib: u64 = value.parse().map_err(|_| SensorError::Malformed {
            file: "meminfo".into(),
            reason: format!("MemAvailable value {value:?} is not a number"),
        })?;
        return Ok(kib * 1024);
    }
    Err(SensorError::Malformed {
        file: "meminfo".into(),
        reason: "no MemAvailable line".into(),
    })
}

/// Read `full avg10` out of a PSI file.
///
/// `full` means every task was stalled, which is the signal that the machine is
/// genuinely wedged rather than merely busy; `some` fires under normal load.
pub fn parse_psi_full_avg10(psi: &str) -> Result<f64, SensorError> {
    for line in psi.lines() {
        let Some(rest) = line.strip_prefix("full ") else {
            continue;
        };
        for field in rest.split_whitespace() {
            if let Some(v) = field.strip_prefix("avg10=") {
                return v.parse().map_err(|_| SensorError::Malformed {
                    file: "pressure".into(),
                    reason: format!("avg10 value {v:?} is not a number"),
                });
            }
        }
    }
    Err(SensorError::Malformed {
        file: "pressure".into(),
        reason: "no 'full' line with avg10".into(),
    })
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct EmergencyThresholds {
    pub available_bytes: u64,
    pub full_psi_percent: f64,
}

/// Both conditions must hold. Low available memory alone is normal on a box
/// with a large page cache, and a PSI spike alone is normal during heavy IO;
/// only together do they mean the machine is failing to make progress.
#[must_use]
pub fn is_emergency(p: Pressure, t: EmergencyThresholds) -> bool {
    p.available_bytes < t.available_bytes && p.full_avg10_percent >= t.full_psi_percent
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO: &str = "\
MemTotal:       131923516 kB
MemFree:         2048000 kB
MemAvailable:   50510752 kB
Buffers:          123456 kB
";

    const PSI: &str = "\
some avg10=1.23 avg60=0.45 avg300=0.11 total=123456
full avg10=7.50 avg60=0.20 avg300=0.05 total=54321
";

    #[test]
    fn reads_mem_available_as_bytes() {
        assert_eq!(parse_mem_available(MEMINFO).unwrap(), 50_510_752 * 1024);
    }

    #[test]
    fn does_not_confuse_mem_free_for_mem_available() {
        let got = parse_mem_available(MEMINFO).unwrap();
        assert_ne!(got, 2_048_000 * 1024, "picked up MemFree");
    }

    #[test]
    fn reads_full_not_some_psi() {
        assert!((parse_psi_full_avg10(PSI).unwrap() - 7.50).abs() < f64::EPSILON);
    }

    #[test]
    fn missing_fields_error_rather_than_defaulting_to_zero() {
        // Defaulting to 0 would read as "no pressure" and silently disarm the
        // guardian on a kernel without PSI compiled in.
        assert!(parse_psi_full_avg10("some avg10=1.0 total=5").is_err());
        assert!(parse_mem_available("MemFree: 100 kB").is_err());
    }

    #[test]
    fn non_numeric_values_error() {
        assert!(parse_mem_available("MemAvailable:   banana kB").is_err());
        assert!(parse_psi_full_avg10("full avg10=banana total=1").is_err());
    }

    const T: EmergencyThresholds = EmergencyThresholds {
        available_bytes: 8 * 1024 * 1024 * 1024,
        full_psi_percent: 10.0,
    };

    fn p(gib: u64, psi: f64) -> Pressure {
        Pressure {
            available_bytes: gib * 1024 * 1024 * 1024,
            full_avg10_percent: psi,
        }
    }

    #[test]
    fn emergency_needs_both_signals() {
        assert!(is_emergency(p(4, 20.0), T));
        assert!(
            !is_emergency(p(4, 1.0), T),
            "low memory alone is not an emergency"
        );
        assert!(
            !is_emergency(p(64, 20.0), T),
            "psi alone is not an emergency"
        );
        assert!(!is_emergency(p(64, 1.0), T));
    }

    #[test]
    fn thresholds_are_inclusive_on_psi_and_exclusive_on_memory() {
        assert!(
            is_emergency(p(4, 10.0), T),
            "psi exactly at threshold counts"
        );
        assert!(
            !is_emergency(p(8, 20.0), T),
            "memory exactly at threshold does not"
        );
    }
}
