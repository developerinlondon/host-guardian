# hostguard

Verifies that your mountpoints are still backed by the filesystems you declared,
and stops units you nominate when the host is genuinely out of memory.

It is deliberately small, because most of what a "host guardian" sounds like it
should do is already running on your machine.

## What it does not do, and why

| Job | Already done by |
| --- | --- |
| memory / CPU / IO / load / filesystem metrics | `prometheus-node-exporter` |
| alerting on those thresholds | Prometheus alert rules |
| restarting a unit that failed | systemd `Restart=` |
| killing by cgroup memory pressure | `systemd-oomd` |

Re-implementing any of that gives you two places to disagree about the same
number. hostguard implements the two things none of them cover:

**Mount identity.** Plenty of things check a path is mounted. Nothing standard
checks that the filesystem mounted there is the one you expected. When a nested
mount silently disappears, its mountpoint becomes a normal directory on the
parent filesystem — writes meant for a dedicated volume start filling the root
disk, and every "is it mounted?" check still passes.

**Named-unit shedding.** `systemd-oomd` kills by cgroup pressure. It cannot
express "sacrifice the editor to keep sshd reachable" — its choice follows
pressure, not your ranking of what is expendable.

## Install

```sh
curl -LO https://github.com/developerinlondon/hostguard/releases/latest/download/hostguard_amd64.deb
sudo dpkg -i hostguard_amd64.deb
```

The package installs enabled but **not started**, and ships with
`observe_only: true`, no shed units, and no mount expectations — so it does
nothing until you configure it. Edit `/etc/hostguard/config.json`, then:

```sh
sudo systemctl start hostguard
```

`systemd-oomd` and `prometheus-node-exporter` are `Recommends:`, so apt installs
them by default. They are not hard dependencies: hostguard works without them,
you just lose the layers it is designed to complement.

## Configure

```json
{
  "schema_version": 1,
  "observe_only": false,
  "metrics_path": "/var/lib/hostguard/textfile/hostguard.prom",
  "incident_dir": "/var/log/hostguard/incidents",
  "consecutive_samples": 2,
  "poll_interval_sec": 30,
  "memory": { "available_bytes": 8589934592, "full_psi_percent": 10.0 },
  "shed_units": ["code-server.service"],
  "mount_expectations": [
    { "path": "/var/build", "source": "/dev/mapper/vg--targets", "fstype": "ext4", "root": "/" }
  ],
  "actions": { "cooldown_sec": 600, "budget_window_sec": 3600, "max_actions_per_window": 3 }
}
```

Find the values for a mount expectation with:

```sh
findmnt --noheadings --output TARGET,SOURCE,FSTYPE /var/build
```

`root` is the *subtree of the source filesystem* that is mounted, not the
mountpoint — `/` for an ordinary mount, and the source path for a bind mount.

Leave `observe_only: true` for a while. It runs every check and records what it
*would* have stopped, without stopping anything.

## Safety properties

- **An emergency needs both signals.** Available memory below the threshold
  *and* full memory PSI above it. Low memory alone is normal with a warm page
  cache; a PSI spike alone is normal during heavy IO.
- **Conditions must persist.** `consecutive_samples` evaluations in a row before
  anything acts, so a single sample straddling a GC pause does nothing.
- **Actions are rate limited.** Per-unit cooldown plus a global budget per
  rolling window. Suppressed attempts do not consume budget.
- **Unit names are validated**, so a config file cannot become arbitrary root
  execution.
- **It cannot delete anything.** There is no unlink, no prune, no reboot and no
  arbitrary-PID kill anywhere in the binary. The only mutation it can perform is
  `systemctl stop` on a unit you listed by name.

## Why a daemon rather than a timer

A timer is safe by construction — a process that cannot stay running cannot
wedge — but it pays process startup on every tick and needs a state file to
remember anything.

hostguard is resident, so cooldown state lives in memory, and it arms a **PSI
trigger**: the kernel wakes it when stall time crosses a threshold instead of it
waking up to ask. The safety a timer gave for free is restored by
`WatchdogSec=`: `Restart=` only fires when a process *exits*, so it cannot catch
a daemon that is alive but deadlocked. The watchdog treats silence itself as the
failure signal. Where PSI is unavailable it falls back to interval polling.

## Output

Everything is published as a Prometheus textfile for node-exporter to collect;
hostguard listens on no socket.

```
hostguard_up 1
hostguard_memory_available_bytes 5.1723010048e+10
hostguard_memory_emergency 0
hostguard_mount_ok{path="/var/build"} 1
hostguard_mount_present{path="/var/build"} 1
hostguard_actions_in_window 0
```

The alert worth having is `hostguard_mount_ok == 0`, which fires when a volume
you rely on is no longer the volume you think it is.

## Build

```sh
cargo build --release
cargo test
packaging/build-deb.sh
```

## Licence

MIT.
