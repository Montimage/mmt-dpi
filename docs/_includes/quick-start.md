Install MMT-DPI with a single command (installs dependencies, builds, and installs automatically):

```bash
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

or using `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

The installer clones the pinned release tag (`v1.9.1`) and verifies it after
checkout; moving branches are refused unless explicitly opted in. It supports
**Linux**: the one-liner and the first run below are smoke-tested in CI on
Ubuntu 22.04/24.04, Debian 12, Rocky Linux 9, CentOS Stream 9, Fedora 44 and
openSUSE Leap 16.0. Arch, Alpine (musl: the SDK does not build there today)
and RHEL itself (CodeReady Builder must be enabled through
`subscription-manager` first) are **best-effort**.

Pre-built `.deb`/`.rpm` packages are on the
[Releases page](https://github.com/montimage-projects/mmt-dpi/releases); the
full install walkthrough is the
[User Guide](https://github.com/montimage-projects/mmt-dpi/blob/main/docs/USER_GUIDE.md).
