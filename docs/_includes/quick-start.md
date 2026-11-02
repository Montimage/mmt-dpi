Install MMT-DPI with one command. The routes below are listed in order of
preference: use the first one that covers your platform. Every route
installs under `/opt/mmt`, so the first run works after any of them, from an
empty directory.

<!-- Route order (issue #577): package repository, then the release
     bootstrap, then the source installer. The signed APT and dnf
     repositories (#575, #576) go first, here, once they are published. -->

**Verified package bootstrap** — Ubuntu 22.04/24.04/26.04, Debian 12/13,
Rocky Linux / AlmaLinux 9 and 10, CentOS Stream 9 and 10, amd64 or arm64. It
installs the release's native `.deb`/`.rpm` after checking its sha256 and its
build-provenance attestation. It is published from the first release after
v1.9.1; until then, use the source installer on these platforms too.

```bash
curl -fsSL https://github.com/montimage-projects/mmt-dpi/releases/latest/download/install.sh | sh
```

Add `-s -- --with-security` after `sh` to install the GPL security engines
too. To check the bootstrap before running it, download `install.sh`, run
`gh attestation verify install.sh --repo montimage-projects/mmt-dpi`, then
`sh install.sh`.

**Source installer** — every supported Linux. It installs the build
dependencies, then clones the pinned release tag (`v1.9.1`), verifies it after
checkout, builds it and installs it; moving branches are refused unless
explicitly opted in:

<!-- hero-install: docs/index.html shows the command of the next block above the fold -->

```bash
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

or using `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

The source installer and the first run are smoke-tested in CI on
Ubuntu 22.04/24.04, Debian 12, Rocky Linux 9, CentOS Stream 9, Fedora 44 and
openSUSE Leap 16.0. Arch, Alpine (musl: the SDK does not build there today)
and RHEL itself (CodeReady Builder must be enabled through
`subscription-manager` first) are **best-effort**. Its options are variants
of the same command:

```bash
# Preview the install plan without changing anything
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash -s -- --dry-run

# Install to a custom directory (substitute it for /opt/mmt in the first run)
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | MMT_BASE=/usr/local/mmt bash

# Build the tip of a branch (here main) instead of the pinned release (unverified — explicit opt-in)
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | BRANCH=main bash -s -- --unverified-branch

# Skip automatic dependency installation
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | SKIP_DEPS=1 bash

# Uninstall (add --prefix <dir> for a custom prefix)
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash -s -- --uninstall
```

Pre-built `.deb`/`.rpm` packages are on the
[Releases page](https://github.com/montimage-projects/mmt-dpi/releases); the
full install walkthrough, building from a checkout included, is the
[User Guide](https://github.com/montimage-projects/mmt-dpi/blob/main/docs/USER_GUIDE.md).
