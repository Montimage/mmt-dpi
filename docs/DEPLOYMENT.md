# Deployment Guide

This document is the canonical install / packaging reference for
operators. For the end-user walkthrough see
[USER_GUIDE.md](USER_GUIDE.md); for build options and developer
tooling see [DEVELOPMENT.md](DEVELOPMENT.md).

## One-liner install (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash
```

The installer (top-level `install.sh`):

- Detects the distribution and installs build dependencies. Supported:
  Debian/Ubuntu (`apt-get`), Fedora/RHEL (`dnf`/`yum`),
  openSUSE (`zypper`).
- Clones the chosen branch (default `main`).
- Builds with `make ARCH=linux MMT_BASE=$MMT_BASE -jN`.
- Runs `sudo make install` when targeting a system prefix.
- Refreshes `ldconfig` via `/etc/ld.so.conf.d/mmt.conf`.

Environment overrides:

| Variable | Default | Effect |
|---|---|---|
| `MMT_BASE` | `/opt/mmt` | Install prefix. Files land under `$MMT_BASE/dpi/`. |
| `BRANCH` | `main` | Git branch to clone and build. |
| `JOBS` | auto-detected | Parallelism for `make -j`. |
| `SKIP_DEPS` | `0` | Skip the dependency-install step. |

## Manual install from source

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi/sdk
make -j$(nproc)
sudo make install
```

To install into a non-default prefix:

```bash
sudo make install MMT_BASE=/usr/local/mmt
```

## Debian package

```bash
cd sdk
make deb
sudo dpkg -i mmt-dpi_*.deb
```

CI builds the `.deb` on every push to `main` and attaches it to the
GitHub Release on `v*` tags.

## ZIP distribution

```bash
cd sdk
make zip
```

Helpers for installing/uninstalling a ZIP drop on a target host live
under `dist/ZIP/install.sh` and `dist/ZIP/uninstall.sh`.

## Uninstall

```bash
cd sdk
sudo make dist-clean
```

This removes the install tree under `$MMT_BASE/dpi/`.

## Installed layout

After install, with the default `MMT_BASE=/opt/mmt`:

```
/opt/mmt/dpi/
  include/    Public C headers
  lib/        Shared libraries (libmmt_core.so, libmmt_tcpip.so, ...)
  plugins/    Protocol plugin .so files
  examples/   Pre-built example binaries
```

`/etc/ld.so.conf.d/mmt.conf` is updated to add `/opt/mmt/dpi/lib` to
the dynamic linker search path.

## Linking against MMT-DPI

Minimal:

```bash
gcc -o myapp myapp.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl
```

With TCP/IP extraction and live capture:

```bash
gcc -o myapp myapp.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -lmmt_tcpip -ldl -lpcap
```

## Runtime configuration

### Plugin loading

Plugins are searched first in `/opt/mmt/dpi/plugins/` and then in a
`plugins/` directory adjacent to the application binary. Drop a new
`.so` into either location to expose its protocols on the next handler
init.

### Environment variables

| Variable | Effect |
|---|---|
| `MMT_SEC_DTLS_CIPHER_ALLOWLIST` | Comma-separated list of allowed DTLS cipher suites. |

## Production tuning

See [Deployment-Consideration.md](Deployment-Consideration.md) for:

- Memory management and allocator choices.
- Multi-threading patterns when sharing a handler.
- Performance tuning for high packet rates.
- Session timeout configuration.
