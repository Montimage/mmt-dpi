# MMT-DPI

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![C/C++ CI](https://github.com/montimage-projects/mmt-dpi/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/montimage-projects/mmt-dpi/actions/workflows/c-cpp.yml)

A high-performance C library for deep packet inspection (DPI), designed to extract data attributes from network packets, server logs, and structured events for real-time traffic analysis (version 1.8.0 [`rules/common.mk:1`](rules/common.mk:1)).

## Key Features

- **Protocol Classification** - Automatic identification and classification of network traffic across 200+ protocols
- **Attribute Extraction** - Extract detailed protocol-specific fields (IPs, ports, headers, payloads, etc.)
- **Session Tracking** - Track and analyze network sessions with flow-level statistics (RTT, retransmissions, byte/packet counts)
- **Extensible Plugin Architecture** - Add new protocol support via modular plugins
- **Wide Protocol Coverage** - TCP/IP stack, HTTP/HTTP2, QUIC (RFC 9000), DNS, FTP, DTLS, GTP, MQTT, OSPF, RADIUS, DICOM, syslog (RFC 3164/5424), PTP, and more
- **5G/LTE Mobile Protocols** - NAS, S1AP, NGAP, GTPv2, Diameter for mobile network monitoring
- **Linux-Based** - Supports major Linux distributions (Debian/Ubuntu, Fedora/RHEL, Arch, Alpine, openSUSE)

## Quick Start

### One-Line Install

Install MMT-DPI with a single command (installs dependencies, builds, and installs automatically):

```bash
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

or using `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

The installer clones the pinned release tag (`v1.8.0`) and verifies it after
checkout; moving branches are refused unless explicitly opted in.

**Custom options** (via environment variables):

```bash
# Preview the install plan without changing anything
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash -s -- --dry-run

# Install to a custom directory
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | MMT_BASE=/usr/local/mmt bash

# Build a development branch instead of the pinned release (unverified — explicit opt-in)
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | BRANCH=dev bash -s -- --unverified-branch

# Skip automatic dependency installation
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | SKIP_DEPS=1 bash
```

Supports **Linux** distributions: Debian/Ubuntu, Fedora/RHEL, Arch, Alpine, and openSUSE.

### Pre-built packages

Every tagged release publishes ready-to-install `.deb` and `.rpm` packages
(amd64 and arm64) built in CI for the major Linux families. Download the one
matching your distribution from the
[Releases page](https://github.com/montimage-projects/mmt-dpi/releases) and
install it with your native package manager:

```bash
# Debian / Ubuntu (.deb)
sudo apt install ./mmt-dpi_*_ubuntu-24.04_x86_64.deb

# RedHat / Rocky / CentOS (.rpm)
sudo dnf install ./mmt-dpi_*_rocky-9_x86_64.rpm
```

Packages are produced by the `Build & release packages` workflow
(`.github/workflows/release-packages.yml`) for Ubuntu 22.04/24.04, Debian 12,
Rocky Linux 9, and CentOS Stream 9.

### Manual Build and Install

If you prefer to build manually, install the build dependencies first — the
`apt-get` line is maintained in one place,
[Agent Environment Notes §1 Toolchain Requirements](docs/AGENT_ENVIRONMENT.md#1-toolchain-requirements).
The install prefix is configurable; see
[§4 `MMT_BASE` Install-Prefix Behavior](docs/AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior).

```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi

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
- **packet_handler** - Basic packet processing callback with per-packet callbacks (`src/examples/packet_handler.c`)
- **mmt_export_info** - Dump exported protocol/attribute metadata (`src/examples/mmt_export_info.c`)

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
│   ├── mmt_dicom/         # DICOM medical-imaging protocol
│   └── examples/          # Usage examples
├── sdk/                   # Build system entry point
├── rules/                 # Platform-specific build rules
├── plugins/               # Protocol plugin engine
├── docs/                  # Documentation
└── dist/                  # Distribution packaging
```

## Platform Support

| Platform | Build Command |
|----------|--------------|
| Linux (GCC) | `make` |
| Linux (Clang) | `make ARCH=linux-clang` |
| ARM (cross-compilation) | [Cross-compilation guide](docs/Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md) |

> **Note:** macOS and Windows are not currently supported.

## Documentation

- [User Guide](docs/USER_GUIDE.md) — install, run the examples, write your first program
- [Compilation and Installation](docs/Compilation-and-Installation-Instructions.md)
- [Protocol Stack Architecture](docs/Protocol-Stack.md)
- [Adding New Protocols](docs/Add-New-Protocol.md)
- [API Examples](docs/Examples.md)
- [Handler Interface](docs/MMT-Handler.md)
- [Session Management](docs/MMT-Session.md)
- [Memory Management](docs/Memory-Management.md)
- [Deployment Considerations](docs/Deployment-Consideration.md)
- [Changelog](CHANGELOG.md)
- [Full Documentation](docs/)

## Related Publications

The following peer-reviewed publications and Montimage white papers present, evaluate, or apply MMT-DPI (and the wider MMT toolset that embeds it). Topic tags: `[dpi-core]` core engine, `[iot]` IoT monitoring, `[5g]` 5G/mobile networks, `[nids]` intrusion detection.

### Tools and frameworks built on MMT-DPI

- **Online Network Traffic Security Inspection Using MMT Tool** — W. Mallouli, B. Wehbi, E. Montes de Oca, M. Bourdelles. *System Testing and Validation*, Vol. 192, 2012. `[dpi-core]`
- **Events-Based Security Monitoring Using MMT Tool** — B. Wehbi, E. Montes de Oca, M. Bourdelles. *5th IEEE International Conference on Software Testing, Verification and Validation (ICST)*, 2012. IEEE Xplore: 6200200. `[dpi-core]`
- **Network Monitoring using MMT: An application based on the User-Agent field in HTTP headers** — A.R. Cavalli, W. Mallouli, et al., 2016. HAL: hal-01335530. `[dpi-core]`
- **5GReplay: A 5G Network Traffic Fuzzer — Application to Attack Injection** — Z. Salazar, H.N. Nguyen, W. Mallouli, A.R. Cavalli, E. Montes de Oca. *ARES 2021*, 16th International Conference on Availability, Reliability and Security. `[5g]` `[nids]`
- **A Network Traffic Mutation Based Ontology to Expand the Training Set of AI-Based Network Intrusion Detection Systems** — Z. Salazar, F. Zaïdi, H.N. Nguyen, A.R. Cavalli, E. Montes de Oca, W. Mallouli. *IEEE Access*, 2023. `[nids]`

### Applications of MMT in IoT and industrial monitoring

- **A Framework for Security Monitoring of Real IoT Testbeds** — W. Mallouli, A.R. Cavalli, E. Montes de Oca, et al. *ICSOFT 2021*, 16th International Conference on Software Technologies. `[iot]`
- **Industrial IoT Security Monitoring and Test on Fed4Fire+ Platforms** — W. Mallouli, A.R. Cavalli, et al. Springer, 2019. DOI: [10.1007/978-3-030-31280-0_17](https://doi.org/10.1007/978-3-030-31280-0_17). `[iot]`
- **A novel monitoring solution for 6LoWPAN-based Wireless Sensor Networks** — A.R. Cavalli, W. Mallouli, et al., 2016. HAL: hal-01391251. `[iot]`
- **A security monitoring system for internet of things** — V. Casola, A. De Benedictis, A. Riccio, D. Rivera, W. Mallouli, E. Montes de Oca. *Internet of Things* (Elsevier), Vol. 7, 100080, 2019. `[iot]`

### White papers and product literature

- **Cyber Secure Communications in Intelligent Transport Systems** — Montimage white paper. Available from the [Montimage publications page](https://www.montimage.eu/pubs/).

For additional Montimage publications on 5G, NDN security monitoring, DevOps security, and adjacent topics, see [Wissam Mallouli's Google Scholar profile](https://scholar.google.com/citations?user=LTKlUkwAAAAJ&hl=en), [Edgardo Montes de Oca's Google Scholar profile](https://scholar.google.com/citations?user=u2YE0WQAAAAJ&hl=en), and the [Montimage publications page](https://www.montimage.eu/pubs/).

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## About

Developed and maintained by [Montimage](https://www.montimage.eu) - 39 rue Bobillot, 75013 Paris, France.

Contact: [contact@montimage.eu](mailto:contact@montimage.eu)

![](https://komarev.com/ghpvc/?username=montimage-dpi&style=flat-square&label=Page+Views)
