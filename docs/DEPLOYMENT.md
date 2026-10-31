---
layout: default
title: "Deployment Guide"
---

# Deployment Guide

## Installation

### From Source

```bash
cd sdk
make -j$(nproc)
sudo make install
```

Default installation directory: `/opt/mmt/dpi/`

To install to a custom directory, build and install with the same
`MMT_BASE` (`make install` refuses a build made for another prefix):

```bash
make -j$(nproc) MMT_BASE=/path/to/install
sudo make install MMT_BASE=/path/to/install
```

### From Debian Package

```bash
cd sdk
make deb
sudo dpkg -i mmt-dpi_*.deb
```

An `ENABLESEC=1` build also produces `mmt-dpi-security_*.deb`, which holds the
security and fuzz engines (GPL-3.0-or-later, issue #497). Install it alongside
`mmt-dpi`; it requires the same version.

### Uninstall

```bash
cd sdk
sudo make uninstall    # same MMT_BASE as the install; removes the loader drop-in too
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

`MMT_DPI_PLUGINS_DIR` overrides the plugin directory at run time; a relative or
unreadable value makes `init_extraction()` fail.
Otherwise the plugin load path is compiled in at build time from `MMT_BASE`; the contract is
stated once, in
[Agent Environment Notes §4 `MMT_BASE` Install-Prefix Behavior](./AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior).

<!-- FLAG: unverified — MMT_SEC_DTLS_CIPHER_ALLOWLIST was previously documented
     but no code reference was found (grep across sdk/ and src/). -->

## Production Considerations

See [Deployment Considerations](Deployment-Consideration.md) for detailed guidance on:
- Memory management
- Multi-threading
- Performance tuning
- Session timeout configuration
