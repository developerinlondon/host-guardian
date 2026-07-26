#!/usr/bin/env bash
# Build a .deb from an already-built release binary.
#
# Uses dpkg-deb directly rather than debhelper: the package is one binary and
# four config files, and the full source-package machinery would be more moving
# parts than the thing it packages.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)}"
arch="${ARCH:-$(dpkg --print-architecture)}"
outdir="${OUTDIR:-$repo/dist}"

# Ask cargo where it actually put things: a local .cargo/config.toml may point
# target-dir somewhere other than ./target.
if [ -z "${BINARY:-}" ]; then
  target_dir="$(cd "$repo" && cargo metadata --no-deps --format-version 1 2>/dev/null |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
  binary="${target_dir:-$repo/target}/release/hostguard"
else
  binary="$BINARY"
fi

if [ ! -x "$binary" ]; then
  echo "no release binary at $binary — build it first, or set BINARY" >&2
  exit 1
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

install -D -m 0755 "$binary" "$stage/usr/bin/hostguard"
install -D -m 0644 "$repo/packaging/systemd/hostguard.service" \
  "$stage/lib/systemd/system/hostguard.service"
install -D -m 0644 "$repo/packaging/config.example.json" \
  "$stage/etc/hostguard/config.json"
install -D -m 0644 "$repo/README.md" \
  "$stage/usr/share/doc/hostguard/README.md"
install -D -m 0644 "$repo/LICENSE" \
  "$stage/usr/share/doc/hostguard/copyright"

# Policy requires a changelog and lintian errors without one. Refuse to build a
# package whose changelog disagrees with the version being built, rather than
# shipping a plausible-looking lie about what changed.
changelog_version="$(sed -n '1s/^hostguard (\([^)]*\)).*/\1/p' "$repo/packaging/deb/changelog")"
if [ "$changelog_version" != "$version" ]; then
  echo "changelog top entry is $changelog_version but building $version" >&2
  exit 1
fi
gzip -9nc "$repo/packaging/deb/changelog" \
  > "$stage/usr/share/doc/hostguard/changelog.gz"
chmod 0644 "$stage/usr/share/doc/hostguard/changelog.gz"

install -d -m 0755 "$stage/usr/share/man/man1"
gzip -9nc "$repo/packaging/hostguard.1" > "$stage/usr/share/man/man1/hostguard.1.gz"
chmod 0644 "$stage/usr/share/man/man1/hostguard.1.gz"

install -d -m 0755 "$stage/DEBIAN"
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" \
  "$repo/packaging/deb/control.in" > "$stage/DEBIAN/control"
install -m 0755 "$repo/packaging/deb/postinst" "$stage/DEBIAN/postinst"
install -m 0755 "$repo/packaging/deb/prerm" "$stage/DEBIAN/prerm"

# Marking the config a conffile is what stops dpkg silently overwriting an
# operator's thresholds and mount expectations on every upgrade.
echo "/etc/hostguard/config.json" > "$stage/DEBIAN/conffiles"

mkdir -p "$outdir"
deb="$outdir/hostguard_${version}_${arch}.deb"
dpkg-deb --root-owner-group --build "$stage" "$deb" >/dev/null
echo "$deb"
