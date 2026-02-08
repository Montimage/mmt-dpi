# MMT-DPI

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![C/C++ CI](https://github.com/Montimage/mmt-dpi/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/Montimage/mmt-dpi/actions/workflows/c-cpp.yml)

A high-performance C library for deep packet inspection (DPI), designed to extract data attributes from network packets, server logs, and structured events for real-time traffic analysis.

## Key Features

- **Protocol Classification** - Automatic identification and classification of network traffic across 200+ protocols
- **Attribute Extraction** - Extract detailed protocol-specific fields (IPs, ports, headers, payloads, etc.)
- **Session Tracking** - Track and analyze network sessions with flow-level statistics (RTT, retransmissions, byte/packet counts)
- **Extensible Plugin Architecture** - Add new protocol support via modular plugins
- **Wide Protocol Coverage** - TCP/IP stack, HTTP/HTTP2, QUIC (RFC 9000), DNS, FTP, DTLS, GTP, MQTT, OSPF, RADIUS, and more
- **5G/LTE Mobile Protocols** - NAS, S1AP, NGAP, GTPv2, Diameter for mobile network monitoring
- **Cross-Platform** - Linux, macOS, and Windows (cross-compilation)

## Quick Start

### Prerequisites

- GCC (4.9 to 9.x) or compatible C compiler
- GNU Make
- `libxml2-dev`
- `libpcap-dev` (for examples)

### Build and Install

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi

# Install dependencies (Debian/Ubuntu)
sudo apt-get install build-essential gcc make cmake libxml2-dev libpcap-dev

# Build
cd sdk
make -j$(nproc)

# Install (default: /opt/mmt/dpi/)
sudo make install
```

To uninstall: `sudo make dist-clean`

### Verify Installation

```bash
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
sudo ./extract_all -i eth0
```

## Usage

### Basic Packet Processing

```c
#include "mmt_core.h"

void packet_handler(const ipacket_t *ipacket, void *user_args) {
    uint32_t *p_len = (uint32_t *)get_attribute_extracted_data_by_name(
        ipacket, "META", "PACKET_LEN");
    if (p_len)
        printf("Packet size: %u\n", *p_len);
}

int main() {
    init_extraction();
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, NULL);

    register_extraction_attribute_by_name(handler, "META", "PACKET_LEN");
    register_packet_handler(handler, 1, packet_handler, NULL);

    // Process packets from pcap or live capture...

    mmt_close_handler(handler);
    close_extraction();
}
```

### More Examples

See [`src/examples/`](src/examples/) for complete working examples:

- **extract_all** - Extract all protocol attributes from packets
- **proto_attributes_iterator** - List all registered protocols and attributes
- **simple_packet_handler** - Basic packet processing callback
- **mmt_online** - Live packet capture and analysis

For detailed API documentation, see the [full documentation](docs/).

## Project Structure

```
mmt-dpi/
├── src/
│   ├── mmt_core/          # Core packet processing engine
│   ├── mmt_tcpip/         # TCP/IP and application-layer protocols
│   ├── mmt_mobile/        # LTE/5G mobile network protocols
│   ├── mmt_business_app/  # Business application protocols
│   ├── mmt_security/      # Security protocol handling
│   ├── examples/          # Usage examples
│   └── lib/               # Shared library code
├── sdk/                   # Build system entry point
├── rules/                 # Platform-specific build rules
├── docs/                  # Documentation
└── dist/                  # Distribution packaging
```

## Platform Support

| Platform | Build Command |
|----------|--------------|
| Linux (GCC) | `make` |
| Linux (Clang) | `make ARCH=linux-clang` |
| macOS | `make ARCH=osx` |
| Windows 32-bit | `make ARCH=win32` (cross-compilation) |
| Windows 64-bit | `make ARCH=win64` (cross-compilation) |
| ARM | [Cross-compilation guide](docs/Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md) |

## Documentation

- [Compilation and Installation](docs/Compilation-and-Installation-Instructions.md)
- [Protocol Stack Architecture](docs/Protocol-Stack.md)
- [Adding New Protocols](docs/Add-New-Protocol.md)
- [API Examples](docs/Examples.md)
- [Handler Interface](docs/MMT-Handler.md)
- [Session Management](docs/MMT-Session.md)
- [Memory Management](docs/Memory-Management.md)
- [Deployment Considerations](docs/Deployment-Consideration.md)
- [Full Documentation](docs/)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## About

Developed and maintained by [Montimage](https://www.montimage.com) - 39 rue Bobillot, 75013 Paris, France.

Contact: [contact@montimage.com](mailto:contact@montimage.com)

![](https://komarev.com/ghpvc/?username=montimage-dpi&style=flat-square&label=Page+Views)
