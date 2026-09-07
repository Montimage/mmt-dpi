# Deployment Guide

## Installation

### From Source

```bash
cd sdk
make -j$(nproc)
sudo make install
```

Default installation directory: `/opt/mmt/dpi/`

To install to a custom directory:

```bash
sudo make install MMT_BASE=/path/to/install
```

### From Debian Package

```bash
cd sdk
make deb
sudo dpkg -i mmt-dpi_*.deb
```

### Uninstall

```bash
cd sdk
sudo make dist-clean
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

The library path is configured via `/etc/ld.so.conf.d/mmt-dpi.conf` (`sdk/Makefile:70,117`).

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

By default, plugins are loaded from `/opt/mmt/plugins/` (`rules/common.mk:7`). You can also place plugins in a `plugins/` directory relative to your application binary.

### Environment Variables

No environment variables are documented in the codebase for runtime configuration.
The plugin load path is compiled in at build time via `PLUGINS_REPOSITORY_OPT`
(`rules/common.mk:30`).

<!-- FLAG: unverified — MMT_SEC_DTLS_CIPHER_ALLOWLIST was previously documented
     but no code reference was found (grep across sdk/ and src/). -->

## Production Considerations

See [Deployment Considerations](Deployment-Consideration.md) for detailed guidance on:
- Memory management
- Multi-threading
- Performance tuning
- Session timeout configuration
