Install MMT-DPI with one command. The routes below are listed in order of
preference: use the first one that covers your platform. Every route
installs under `/opt/mmt`, so the first run works after any of them, from an
empty directory.

<!-- Route order (issue #577): package repository, then the release
     bootstrap, then the source installer. The signed APT repository
     (issue #79) holds the first slot; the dnf repository (#576) joins it
     once it is published. -->

**APT repository** — Ubuntu 22.04/24.04/26.04 (`jammy`, `noble`,
`resolute`), Debian 12/13 (`bookworm`, `trixie`), amd64 or arm64. A signed
repository at https://montimage.github.io/packages that serves the last two
releases, so `apt-get upgrade` picks up new ones. Download the signing key
and look at it first:

```bash
sudo apt-get update && sudo apt-get install -y curl gnupg
keyring=$(mktemp)
curl -fsSL -o "$keyring" https://montimage.github.io/packages/montimage-archive-keyring.gpg
gpg --show-keys "$keyring"
```

Go on only if `gpg` prints the primary key fingerprint
`21630C362624FB205C3D0B184F95AECCFEF48443`. Then install the key into
`/etc/apt/keyrings`, add the repository as a deb822 source that trusts only
that key, and install the package:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 "$keyring" /etc/apt/keyrings/montimage-archive-keyring.gpg && rm -f "$keyring"
sudo tee /etc/apt/sources.list.d/montimage.sources >/dev/null <<EOF
Types: deb
URIs: https://montimage.github.io/packages
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: main
Signed-By: /etc/apt/keyrings/montimage-archive-keyring.gpg
EOF
sudo apt-get update && sudo apt-get install -y mmt-dpi
```

Add `mmt-dpi-security` to the last command to install the GPL security
engines too. apt never refreshes the keyring by itself: after a key change
(see *Signing key handling* in `docs/DEB_PACKAGE_CHECKLIST.md`), download it
again with the two blocks above.

**Verified package bootstrap** — Ubuntu 22.04/24.04/26.04, Debian 12/13,
Rocky Linux / AlmaLinux 9 and 10, CentOS Stream 9 and 10, amd64 or arm64. It
installs the release's native `.deb`/`.rpm` after checking its sha256 and its
build-provenance attestation. It is published with every release from
v1.10.0 on.

```bash
curl -fsSL https://github.com/Montimage/mmt-dpi/releases/latest/download/install.sh | sh
```

Add `-s -- --with-security` after `sh` to install the GPL security engines
too. To check the bootstrap before running it, download `install.sh`, run
`gh attestation verify install.sh --repo Montimage/mmt-dpi`, then
`sh install.sh`.

**Source installer** — every supported Linux. It installs the build
dependencies, then clones the pinned release tag (`v1.10.3`), verifies it after
checkout, builds it and installs it; moving branches are refused unless
explicitly opted in:

<!-- hero-install: docs/index.html shows the command of the next block above the fold -->

```bash
curl -fsSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash
```

or using `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash
```

The source installer and the first run are smoke-tested in CI on
Ubuntu 22.04/24.04, Debian 12, Rocky Linux 9, CentOS Stream 9, Fedora 44 and
openSUSE Leap 16.0. Arch, Alpine (musl: the SDK does not build there today)
and RHEL itself (CodeReady Builder must be enabled through
`subscription-manager` first) are **best-effort**. Its options are variants
of the same command:

```bash
# Preview the install plan without changing anything
curl -fsSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash -s -- --dry-run

# Install to a custom directory (substitute it for /opt/mmt in the first run)
curl -fsSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | MMT_BASE=/usr/local/mmt bash

# Build the tip of a branch (here main) instead of the pinned release (unverified — explicit opt-in)
curl -fsSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | BRANCH=main bash -s -- --unverified-branch

# Skip automatic dependency installation
curl -fsSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | SKIP_DEPS=1 bash

# Uninstall (add --prefix <dir> for a custom prefix)
curl -fsSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash -s -- --uninstall
```

Pre-built `.deb`/`.rpm` packages are on the
[Releases page](https://github.com/Montimage/mmt-dpi/releases); the
full install walkthrough, building from a checkout included, is the
[User Guide](https://github.com/Montimage/mmt-dpi/blob/main/docs/USER_GUIDE.md).
