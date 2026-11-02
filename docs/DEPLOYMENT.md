---
layout: default
title: "Deployment Guide"
---

# Deployment Guide

## Installation

To install a release, use the command for your platform in the Quick Start
— on the [landing page](index.html#quick-start), or in the
[root README](https://github.com/montimage-projects/mmt-dpi/blob/main/README.md#install)
on GitHub. This section builds and installs from a checkout instead: every
block runs from the root of the checkout and leaves you there.

### From Source

```bash
make -C sdk -j$(nproc)
sudo make -C sdk install
```

Default installation directory: `/opt/mmt/dpi/`

To install to a custom directory, build and install with the same
`MMT_BASE` (`make install` refuses a build made for another prefix):

```bash
make -C sdk -j$(nproc) MMT_BASE=/path/to/install
sudo make -C sdk install MMT_BASE=/path/to/install
```

### From Debian Package

```bash
make -C sdk deb
sudo dpkg -i sdk/mmt-dpi_*.deb
```

An `ENABLESEC=1` build also produces `mmt-dpi-security_*.deb`, which holds the
security and fuzz engines (GPL-3.0-or-later, issue #497). Install it alongside
`mmt-dpi`; it requires the same version.

### Uninstall

```bash
sudo make -C sdk uninstall    # same MMT_BASE as the install; removes the loader drop-in too
```

## Installed Files

After installation, the following files are placed:

```
/opt/mmt/
├── dpi/
│   ├── include/     # Header files for development
│   └── lib/         # Shared libraries (libmmt_core.so, etc.)
├── plugins/         # Protocol plugin libraries (rules/common.mk:7)
└── examples/        # Example sources (rules/common.mk:8)
```

The library path is configured via `/etc/ld.so.conf.d/mmt-dpi.conf` (`sdk/Makefile:139,374`): a root `make install` writes it whatever the prefix (opt out with `LDCONF=0`), and `make uninstall` removes it — see [Agent Environment Notes §4](./AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior).

## Linking Against MMT-DPI

```bash
gcc -o myapp myapp.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl
```

For TCP/IP protocol attributes:
```bash
gcc -o myapp myapp.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -lmmt_tcpip -ldl -lpcap
```

## Runtime Configuration

### Plugin Loading

By default, plugins are loaded from `/opt/mmt/plugins/` (`rules/common.mk:7`). They load only from that compiled-in `$(MMT_BASE)/plugins` directory, or from the absolute directory named by `MMT_DPI_PLUGINS_DIR`, read with `secure_getenv()` (`src/mmt_core/src/plugins_engine.c:48-60`); the working directory and the application binary's directory are never scanned.

### Environment Variables

The library reads these variables at run time; each is optional, and unset or
empty leaves the built-in behaviour unchanged. Build-time paths, including the
compiled-in plugin directory, follow `MMT_BASE`; that contract is stated once,
in [Agent Environment Notes §4 `MMT_BASE` Install-Prefix Behavior](./AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior).

| Variable | Effect | Read at |
|----------|--------|---------|
| `MMT_DPI_PLUGINS_DIR` | Absolute directory to load the plugins from instead of the compiled-in `$(MMT_BASE)/plugins`; a relative or unreadable value makes `init_extraction()` fail. Read with `secure_getenv()`, so a set-uid/set-gid process ignores it | `src/mmt_core/src/plugins_engine.c:50` (name: `src/mmt_core/private_include/plugins_engine.h:27`) |
| `MMT_DPI_LOG_LEVEL` | Threshold of the stderr diagnostics logger (default `off`); levels and the `SHOWLOG` build in [Agent Environment Notes §2](./AGENT_ENVIRONMENT.md#useful-build-flags) | `src/mmt_core/src/mmt_log.c:62` |
| `MMT_DPI_PROFILES_FILE` | File of custom DPI profiles, loaded before `MMT_DPI_PROFILE` is resolved — see [DPI Profiles](./DPI-Profiles.md) | `src/mmt_core/src/dpi_profiles.c:254` |
| `MMT_DPI_PROFILE` | Name of the DPI profile each new handler applies; an unknown name keeps the built-in defaults — see [DPI Profiles](./DPI-Profiles.md) | `src/mmt_core/src/dpi_profiles.c:265` |
| `MMT_DPI_PORT_MAP_FILE` | File of external port hints — see [External Attribution](./External-Attribution.md) | `src/mmt_tcpip/lib/mmt_tcpip_plugin_internal.c:672` |
| `MMT_DPI_IP_RANGES_FILE` | File of external IP-range attribution rules — see [External Attribution](./External-Attribution.md) | `src/mmt_tcpip/lib/mmt_tcpip_classif_utils.c:570` |
| `MMT_DETERMINISTIC_SEED` | Test and reproducibility knob: any non-empty value but `0` makes the hash-table seeds the fixed legacy sequence instead of a per-process random one. ⚠ It gives up the seeds' resistance to hash flooding — never set it in production. A set-uid/set-gid process (`AT_SECURE`) ignores it | `src/mmt_core/src/hash_utils.c:253-255` |
| `MMT_SEC_REACTION_DIR` | `ENABLESEC=1` security engine only: absolute folder for the reaction files, instead of the compiled-in `$(MMT_BASE)/probe/conf`; read with `secure_getenv()` | `src/mmt_security/tips_report.c:970` |

<!-- FLAG: unverified — MMT_SEC_DTLS_CIPHER_ALLOWLIST was previously documented
     but no code reference was found (grep across sdk/ and src/). -->

## Production Considerations

See [Deployment Considerations](Deployment-Consideration.md) for detailed guidance on:
- Memory management
- Multi-threading
- Performance tuning
- Session timeout configuration
