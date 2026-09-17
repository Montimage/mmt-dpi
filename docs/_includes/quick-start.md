Install MMT-DPI with a single command (installs dependencies, builds, and installs automatically):

```bash
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

or using `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

The installer clones the pinned release tag (`v1.8.0`) and verifies it after
checkout; moving branches are refused unless explicitly opted in. It supports
**Linux** distributions: Debian/Ubuntu, Fedora/RHEL, Arch, Alpine, and openSUSE.

Pre-built `.deb`/`.rpm` packages are on the
[Releases page](https://github.com/montimage-projects/mmt-dpi/releases); the
full install walkthrough is the
[User Guide](https://github.com/montimage-projects/mmt-dpi/blob/main/docs/USER_GUIDE.md).
