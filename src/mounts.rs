//! Mount identity verification against `/proc/self/mountinfo`.
//!
//! Checking a path is *mounted* is easy; checking the thing mounted there is
//! still the filesystem you expected is not covered by anything standard. A
//! vanished nested mount exposes its writable parent, so writes meant for a
//! dedicated volume silently fill the root filesystem instead.

use std::collections::BTreeMap;
use std::fmt;

/// One line of `/proc/self/mountinfo`, reduced to the fields that establish
/// identity. The device major:minor is deliberately excluded: minor numbers are
/// reallocated across boots, so pinning them produces false alarms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountIdentity {
    pub source: String,
    pub fstype: String,
    /// The subtree of the source filesystem that is mounted, not the mountpoint.
    /// A bind mount of `/data/sub` onto `/mnt` has root `/data/sub`.
    pub root: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct MountExpectation {
    pub path: String,
    pub source: String,
    pub fstype: String,
    #[serde(default = "default_root")]
    pub root: String,
}

fn default_root() -> String {
    "/".to_string()
}

#[derive(Debug)]
pub enum MountError {
    Malformed { line: usize, reason: String },
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { line, reason } => {
                write!(f, "mountinfo line {line}: {reason}")
            }
        }
    }
}

/// Decode the octal escapes the kernel applies to mountinfo fields.
///
/// A path containing a space is written `\040`; without decoding, such a mount
/// never matches its expectation and the guardian reports a phantom failure.
fn unescape(field: &str) -> String {
    // Byte-wise throughout: mountpoints are arbitrary UTF-8 and the kernel
    // escapes only space, tab, newline and backslash, so a `push(byte as char)`
    // would reinterpret every multi-byte path as Latin-1 and make a healthy
    // mount fail its expectation forever. Slicing by byte index would also
    // panic on a char boundary.
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &bytes[i + 1..i + 4];
            if octal.iter().all(|c| (b'0'..=b'7').contains(c)) {
                let value = octal
                    .iter()
                    .fold(0u16, |acc, c| acc * 8 + u16::from(c - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse mountinfo into mountpoint -> identity.
///
/// Later lines win: the kernel lists mounts in mount order, so when two
/// filesystems are stacked on one mountpoint the last one is what a process
/// actually sees.
pub fn parse_mountinfo(text: &str) -> Result<BTreeMap<String, MountIdentity>, MountError> {
    let mut mounts = BTreeMap::new();

    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        // Layout: ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTS... - FSTYPE SOURCE OPTS
        // The optional-fields run before "-" is variable length, so the tail is
        // located by the separator rather than by a fixed index.
        let Some((head, tail)) = line.split_once(" - ") else {
            return Err(MountError::Malformed {
                line: idx + 1,
                reason: "no ' - ' separator".into(),
            });
        };

        let head_fields: Vec<&str> = head.split_whitespace().collect();
        if head_fields.len() < 5 {
            return Err(MountError::Malformed {
                line: idx + 1,
                reason: format!(
                    "expected at least 5 fields before separator, got {}",
                    head_fields.len()
                ),
            });
        }

        let tail_fields: Vec<&str> = tail.split_whitespace().collect();
        if tail_fields.len() < 2 {
            return Err(MountError::Malformed {
                line: idx + 1,
                reason: "expected fstype and source after separator".into(),
            });
        }

        mounts.insert(
            unescape(head_fields[4]),
            MountIdentity {
                source: unescape(tail_fields[1]),
                fstype: unescape(tail_fields[0]),
                root: unescape(head_fields[3]),
            },
        );
    }

    Ok(mounts)
}

#[derive(Debug, PartialEq, Eq)]
pub enum MountVerdict {
    Ok,
    Missing,
    Mismatch { actual: MountIdentity },
}

pub fn verify(
    expectations: &[MountExpectation],
    mounts: &BTreeMap<String, MountIdentity>,
) -> Vec<(String, MountVerdict)> {
    expectations
        .iter()
        .map(|want| {
            let verdict = match mounts.get(&want.path) {
                None => MountVerdict::Missing,
                Some(got)
                    if got.source == want.source
                        && got.fstype == want.fstype
                        && got.root == want.root =>
                {
                    MountVerdict::Ok
                }
                Some(got) => MountVerdict::Mismatch {
                    actual: got.clone(),
                },
            };
            (want.path.clone(), verdict)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
25 0 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg--root rw
26 25 0:31 / /tmp rw,nosuid,nodev shared:2 - tmpfs tmpfs rw,size=32G
27 25 253:2 /sub /mnt/bind rw,relatime shared:3 - ext4 /dev/mapper/vg--data rw
28 25 0:44 / /odd\\040path rw,relatime shared:4 - ext4 /dev/sdz rw
";

    fn expect(path: &str, source: &str, fstype: &str, root: &str) -> MountExpectation {
        MountExpectation {
            path: path.into(),
            source: source.into(),
            fstype: fstype.into(),
            root: root.into(),
        }
    }

    #[test]
    fn parses_source_fstype_and_root() {
        let m = parse_mountinfo(SAMPLE).unwrap();
        let root = &m["/"];
        assert_eq!(root.source, "/dev/mapper/vg--root");
        assert_eq!(root.fstype, "ext4");
        assert_eq!(root.root, "/");
    }

    #[test]
    fn bind_mount_root_is_the_source_subtree_not_the_mountpoint() {
        let m = parse_mountinfo(SAMPLE).unwrap();
        assert_eq!(m["/mnt/bind"].root, "/sub");
    }

    #[test]
    fn decodes_octal_escaped_mountpoints() {
        let m = parse_mountinfo(SAMPLE).unwrap();
        assert!(m.contains_key("/odd path"), "got keys: {:?}", m.keys());
    }

    #[test]
    fn non_ascii_mountpoints_survive_intact() {
        // Latin-1 reinterpretation here would leave a perfectly healthy mount
        // permanently failing its expectation and crying wolf every cycle.
        let line = "25 0 253:1 / /srv/café_data rw - ext4 /dev/sdz rw";
        let m = parse_mountinfo(line).unwrap();
        assert!(m.contains_key("/srv/café_data"), "got keys: {:?}", m.keys());

        let want = expect("/srv/café_data", "/dev/sdz", "ext4", "/");
        assert_eq!(verify(&[want], &m)[0].1, MountVerdict::Ok);
    }

    #[test]
    fn a_backslash_before_a_multibyte_char_does_not_panic() {
        // panic = "abort" in release turns any panic here into instant death of
        // a root daemon, so the parser must not index across a char boundary.
        let line = "25 0 253:1 / /a\\€b rw - ext4 /dev/sdz rw";
        assert!(parse_mountinfo(line).is_ok());
    }

    #[test]
    fn a_non_octal_escape_is_left_alone() {
        let line = "25 0 253:1 / /a\\99x rw - ext4 /dev/sdz rw";
        let m = parse_mountinfo(line).unwrap();
        assert!(m.contains_key("/a\\99x"), "got keys: {:?}", m.keys());
    }

    #[test]
    fn later_mount_on_the_same_point_wins() {
        let stacked = "\
25 0 253:1 / /data rw - ext4 /dev/first rw
26 0 253:2 / /data rw - ext4 /dev/second rw
";
        let m = parse_mountinfo(stacked).unwrap();
        assert_eq!(m["/data"].source, "/dev/second");
    }

    #[test]
    fn variable_length_optional_fields_do_not_shift_the_tail() {
        // No optional fields at all, versus two of them.
        let bare = "25 0 253:1 / /a rw - ext4 /dev/x rw";
        let rich = "25 0 253:1 / /a rw shared:1 master:2 - ext4 /dev/x rw";
        assert_eq!(
            parse_mountinfo(bare).unwrap()["/a"],
            parse_mountinfo(rich).unwrap()["/a"]
        );
    }

    #[test]
    fn missing_mount_is_reported_not_silently_ok() {
        let m = parse_mountinfo(SAMPLE).unwrap();
        let v = verify(&[expect("/gone", "/dev/x", "ext4", "/")], &m);
        assert_eq!(v[0].1, MountVerdict::Missing);
    }

    #[test]
    fn replaced_filesystem_is_a_mismatch_even_though_the_path_is_mounted() {
        // The failure this crate exists for: /tmp is still a mountpoint, but a
        // different filesystem now backs it.
        let m = parse_mountinfo(SAMPLE).unwrap();
        let v = verify(&[expect("/tmp", "/dev/mapper/vg--tmp", "ext4", "/")], &m);
        match &v[0].1 {
            MountVerdict::Mismatch { actual } => assert_eq!(actual.fstype, "tmpfs"),
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn matching_mount_verifies() {
        let m = parse_mountinfo(SAMPLE).unwrap();
        let v = verify(&[expect("/", "/dev/mapper/vg--root", "ext4", "/")], &m);
        assert_eq!(v[0].1, MountVerdict::Ok);
    }

    #[test]
    fn malformed_line_errors_rather_than_being_skipped() {
        assert!(parse_mountinfo("25 0 253:1 / / rw ext4 /dev/x rw").is_err());
    }
}
