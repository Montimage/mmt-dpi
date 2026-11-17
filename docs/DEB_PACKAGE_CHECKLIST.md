---
layout: default
title: ".deb Package Build & apt Repository Setup Checklist"
---

# .deb Package Build & apt Repository Setup Checklist

> **Status note (2026-09-16, issue #249):** the build report below describes the
> `mmt-dpi 1.7.10-3ab25616` package — recorded before the current `1.8.0`
> release (`rules/common.mk:1`), which added the DICOM plugin library
> `libmmt_tdicom.so` that this report originally omitted. The library list
> under *Package Info* has since been annotated, but the authoritative package
> contents and dependency set are now derived from the built `.so` files at
> package-build time (`tools/ci/shlib-deps.sh`, verified per artifact by
> `tools/ci/check-package-deps.sh --verify-package`), not maintained here.

## Build Testing Results

**Status:** ✓ Package builds successfully

**Package Info:**
- Name: `mmt-dpi`
- Version: `1.7.10-3ab25616`
- Architecture: `aarch64` (dynamically detected from `uname -m`)
- Size: ~1.5 MB
- Libraries: `libmmt_core.so`, `libmmt_tcpip.so`, `libmmt_tmobile.so`, `libmmt_business_app.so`, `libmmt_tdicom.so` — `libmmt_fuzz.so` and `libmmt_security.so` are built with `ENABLESEC=1` (as the release packages are, issue #219) and ship in the separate `mmt-dpi-security` package (issue #497)

## Issues Fixed

1. **Architecture Detection**: Changed from `all` to dynamic `$(shell uname -m)` to properly detect the system architecture (arm64/aarch64, x86_64, etc.)

2. **Dependencies**: `Depends:` is derived at package-build time from the `NEEDED` entries `objdump -p` reports for the shipped `.so` files — `tools/ci/shlib-deps.sh` maps each soname to its Debian package (issue #219). The toolchain floor (issue #218) survives in that output as `libc6 (>= 2.34), libstdc++6 (>= 11)` — the constants come from `rules/common.mk` (`MMT_GLIBC_MIN`, `MMT_LIBSTDCXX_MIN`). `libpcap`/`libnghttp2` are gone (nothing links them); `libxml2` appears when the package is built with `ENABLESEC=1`. Verify with `bash tools/ci/check-package-deps.sh --verify-package <pkg>.deb`.

3. **Post-install Script**: Added `postinst` to run `ldconfig` after installation

4. **Pre-remove Script**: Added `prerm` to remove ldconfig entry before removal

5. **Fixed control file formatting** (removed extra spaces)

---

## Testing Checklist

### Build Verification

- [ ] Build .deb package: `make -C sdk VERSION=<version> GIT_VERSION=$(git log --format="%h" -n 1) deb`
- [ ] Verify package integrity: `dpkg-deb -I mmt-dpi_*.deb`
- [ ] List package contents: `dpkg-deb -c mmt-dpi_*.deb`
- [ ] Extract and inspect control files: `dpkg-deb -e mmt-dpi_*.deb /tmp/control`

### Pre-Installation Checks

- [ ] Verify system architecture compatibility (aarch64 vs x86_64)
- [ ] Ensure `libc6 >= 2.34` is available: `dpkg -l libc6` (no shipped library NEEDs `libstdc++6` since issue #539)
- [ ] Check available disk space in `/opt/mmt` (requires ~50MB)

### Installation Testing

- [ ] Install package: `sudo dpkg -i mmt-dpi_*.deb`
- [ ] Verify installation: `dpkg -l mmt-dpi`
- [ ] Check libraries are registered: `ldconfig -p | grep mmt`
- [ ] Verify symlinks: `ls -la /opt/mmt/dpi/lib/`

### Functional Testing

- [ ] Test library loading with a sample application
- [ ] Verify plugin loading from `/opt/mmt/plugins/`
- [ ] Test header file accessibility from `/opt/mmt/dpi/include/`

### Removal Testing

- [ ] Uninstall: `sudo dpkg -r mmt-dpi`
- [ ] Verify ldconfig entry removed: `cat /etc/ld.so.conf.d/mmt-dpi.conf` (should fail)
- [ ] Run ldconfig to update: `sudo ldconfig`

---

## The apt repository

The signed APT repository is https://montimage.github.io/packages, built by
[Montimage/packages](https://github.com/Montimage/packages), which alone holds
the repository signing subkey (decided in issue #24). This repository builds
the `.deb` files and publishes them with each GitHub Release; the client
setup — keyring, deb822 source, `apt-get install mmt-dpi` — is the first
route of the [Quick Start](https://github.com/Montimage/mmt-dpi#install)
(`docs/_includes/quick-start.md`). `apt-key` is deprecated and is never used:
the source names its keyring with `Signed-By`, so the key is trusted for this
repository only.

### How it is built

- **Trigger.** The release job's last step, `tools/ci/notify-packages.sh`,
  sends a `repository_dispatch` of type `mmt-dpi-release` to
  Montimage/packages once the Release is published (issue #76). Its
  `apt-repo.yml` workflow also runs by hand (`workflow_dispatch`) and on
  pushes to its `main` that touch its `scripts/`, `site/` or the workflow.
- **Stateless.** Every run rebuilds the whole repository from the GitHub
  Releases of Montimage/mmt-dpi; nothing is kept between runs and no package
  is committed. A rerun of the same releases gives the same unsigned tree.
- **Last 2 releases.** It takes the last two published, non-draft,
  non-prerelease Releases, and from each only the `mmt-dpi` and
  `mmt-dpi-security` `.deb` files. A Release is used only when `SHA256SUMS`
  and every `.deb` carry a build-provenance attestation of this repository's
  `release-packages.yml` at that tag, and every `.deb` matches `SHA256SUMS`.
  A published release must never be deleted or demoted: the repository's
  `Date` would move backwards and apt would keep its older indexes. Publish a
  newer release instead.
- **Layout.** One suite per distribution, each with its own pool, because
  every distribution's package has the same Debian version:

  | Release asset | Suite |
  |---------------|-------|
  | `ubuntu-22.04` | `jammy` |
  | `ubuntu-24.04` | `noble` |
  | `ubuntu-26.04` | `resolute` |
  | `debian-12` | `bookworm` |
  | `debian-13` | `trixie` |

  ```text
  pool/<suite>/main/m/mmt-dpi/<package>_<version>_<arch>.deb
  dists/<suite>/main/binary-{amd64,arm64}/Packages{,.gz}
  dists/<suite>/{Release,InRelease,Release.gpg}
  montimage-archive-keyring.gpg
  ```

  `Release` has Origin and Label `Montimage`, Architectures `amd64 arm64`,
  Components `main` and no `Valid-Until`.
- **Signed.** `InRelease` and `Release.gpg` are signed by subkey A of the
  Montimage release signing key. The public keyring served at the root,
  `montimage-archive-keyring.gpg`, holds the same primary key as
  `debian/upstream/signing-key.asc` in this repository.
- **Checked here.** The `apt`, `apt-tamper` and `apt-ready` jobs of
  `.github/workflows/install-smoke.yml` (`tools/ci/smoke-apt.sh`, issue #78)
  install from the published repository on every suite and architecture,
  check that the served keyring's only primary key is the committed one, and
  require apt to refuse an `InRelease` with one byte changed.

The authoritative build description is the Montimage/packages
[README](https://github.com/Montimage/packages#how-the-repository-is-built).

### Signing key handling

One ed25519 primary key, `Montimage Release Signing <developer@montimage.eu>`
(certify-only, 5-year expiry), stays on the maintainer's signing machine and
never enters CI. It certifies two signing-only subkeys (2-year expiry), each
held by one repository only:

| Subkey | Signs | Held by |
|--------|-------|---------|
| A | The APT repository (`InRelease`, `Release.gpg`) | Montimage/packages, `apt-signing` environment |
| B | The source tarball (`mmt-dpi-<version>.tar.gz.asc`) | This repository, secrets `MMT_RELEASE_SIGNING_KEY` and `MMT_RELEASE_SIGNING_PASSPHRASE` |

Primary key fingerprint:

```text
2163 0C36 2624 FB20 5C3D  0B18 4F95 AECC FEF4 8443
```

The commands for every case below are in
[Montimage/packages `docs/signing-key.md`](https://github.com/Montimage/packages/blob/main/docs/signing-key.md);
this section lists what each case changes on the mmt-dpi side. No key
material, passphrase or secret value is ever committed or written in an
issue: only public keys and fingerprints.

- **Expiry extension** (about two months before a subkey expires). The
  maintainer extends both subkeys with the primary key and re-exports the
  public key. Commit the refreshed armoured export as
  `debian/upstream/signing-key.asc` here, and the binary keyring as
  `site/montimage-archive-keyring.gpg` in Montimage/packages, together. The
  CI secrets do not change: the expiry lives in the public key.
- **Rotation** (a new subkey, planned or after a leak). The maintainer adds
  a new subkey, exports it re-protected with a new CI-only passphrase and
  replaces that subkey's secrets: for subkey B, `MMT_RELEASE_SIGNING_KEY` and
  `MMT_RELEASE_SIGNING_PASSPHRASE` here; for subkey A, the three
  `apt-signing` values in Montimage/packages. The public key is republished
  in both repositories, because the keyring holds both subkeys.
- **Revocation.** A leaked subkey is revoked first, then rotated as above.
  A compromised or lost primary key is revoked with its revocation
  certificate (kept apart from the key backup), the revoked public key is
  republished in both repositories, and a new key is created and its
  fingerprint announced; every fingerprint in these docs then changes.

After any of these changes:

- Keep the two published copies in step. `tools/ci/smoke-apt.sh` fails when
  the served keyring's primary key differs from
  `debian/upstream/signing-key.asc`, and `tools/ci/sign-source-tarball.sh`
  fails a release whose secret and committed key disagree.
- Users must download the keyring again: apt never refreshes
  `/etc/apt/keyrings/montimage-archive-keyring.gpg` by itself. Say so in the
  release notes.

---

### Verification Commands

```bash
# Check package metadata
dpkg-deb -I mmt-dpi_*.deb

# Check for missing dependencies
dpkg-deb -I mmt-dpi_*.deb | grep -i depends

# List all files in package
dpkg-deb -c mmt-dpi_*.deb

# Verify conffiles (if any)
dpkg-deb -I mmt-dpi_*.deb conffiles

# Test installation without actually installing
dpkg-deb -x mmt-dpi_*.deb /tmp/test-install
dpkg-deb -e mmt-dpi_*.deb /tmp/test-control
```

---

### Troubleshooting

**Issue:** `dpkg: error: architecture 'aarch64' not allowed`

**Solution:** Add architecture to dpkg:

```bash
sudo dpkg --add-architecture aarch64
sudo apt update
```

**Issue:** `ldconfig` not finding libraries

**Solution:** Verify `/etc/ld.so.conf.d/mmt-dpi.conf` exists and contains `/opt/mmt/dpi/lib`

**Issue:** Missing symbols when linking

**Solution:** Ensure all dependencies are installed:
```bash
sudo apt install libc6-dev
```

