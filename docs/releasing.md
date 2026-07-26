# Releasing

## One-time setup

The apt repository is signed, because apt refuses an unsigned one by default.
Two things must exist before the first release:

**`APT_SIGNING_KEY` repository secret.** An ASCII-armoured *private* key. Export
the signing key and paste the whole block, including the header and footer
lines:

```sh
gpg --armor --export-secret-keys 11F993FCF5EEE14C
```

Use a signing subkey rather than a primary key if you have one. The workflow
fails loudly when this secret is missing instead of publishing an unsigned
repository that apt will reject.

**GitHub Pages set to "GitHub Actions".** Repository settings, Pages, Source.
The workflow deploys the artifact directly; there is no `gh-pages` branch.

## Cutting a release

1. Bump `version` in `Cargo.toml`.
2. Add an entry at the top of `packaging/deb/changelog` with the same version.
   `build-deb.sh` refuses to build if these disagree — a changelog that lags the
   version is a plausible-looking lie about what shipped.
3. Merge to `main`.
4. Tag and push:

   ```sh
   git tag -s v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

The release workflow builds amd64 and arm64, refuses to proceed if the tag
disagrees with `Cargo.toml`, and attaches both packages under stable asset names
so the `releases/latest/download/` URL keeps working.

Publishing the release triggers the apt workflow, which rebuilds the index from
**every** published release rather than appending to accumulated state, so the
repository always reflects what is actually downloadable.

## Verifying a release

```sh
docker run --rm -it ubuntu:24.04 bash -c '
  apt-get update -qq && apt-get install -y -qq curl ca-certificates
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://developerinlondon.github.io/hostguard/hostguard.gpg \
    > /etc/apt/keyrings/hostguard.gpg
  echo "deb [signed-by=/etc/apt/keyrings/hostguard.gpg] https://developerinlondon.github.io/hostguard stable main" \
    > /etc/apt/sources.list.d/hostguard.list
  apt-get update && apt-get install -y hostguard && hostguard --version'
```

If the signature is wrong or missing, `apt-get update` fails here rather than on
someone's server.
