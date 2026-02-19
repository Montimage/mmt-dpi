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
/opt/mmt/dpi/
├── include/     # Header files for development
├── lib/         # Shared libraries (libmmt_core.so, etc.)
└── plugins/     # Protocol plugin libraries
```

The library path is configured via `/etc/ld.so.conf.d/mmt.conf`.

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

By default, plugins are loaded from `/opt/mmt/dpi/plugins/`. You can also place plugins in a `plugins/` directory relative to your application binary.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `MMT_SEC_DTLS_CIPHER_ALLOWLIST` | Comma-separated list of allowed DTLS cipher suites |

## Production Considerations

See [Deployment Considerations](Deployment-Consideration.md) for detailed guidance on:
- Memory management
- Multi-threading
- Performance tuning
- Session timeout configuration
