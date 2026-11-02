# MMT-DPI

**[Documentation site → montimage-projects.github.io/mmt-dpi](https://montimage-projects.github.io/mmt-dpi/)**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![C/C++ CI](https://github.com/montimage-projects/mmt-dpi/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/montimage-projects/mmt-dpi/actions/workflows/c-cpp.yml)

A high-performance C library for deep packet inspection (DPI), designed to extract data attributes from network packets, server logs, and structured events for real-time traffic analysis. Current release: [v1.9.1](CHANGELOG.md).

## Key Features

<!-- begin-shared: docs/_includes/key-features.md -->

- **Protocol Classification** - Automatic identification and classification of network traffic across 673 protocols
- **Attribute Extraction** - Extract detailed protocol-specific fields (IPs, ports, headers, payloads, etc.)
- **Session Tracking** - Track and analyze network sessions with flow-level statistics (RTT, retransmissions, byte/packet counts)
- **Extensible Plugin Architecture** - Add new protocol support via modular plugins
- **Wide Protocol Coverage** - TCP/IP stack, HTTP/HTTP2, QUIC (RFC 9000), DNS, FTP, DTLS, GTP, MQTT, OSPF, RADIUS, DICOM, syslog (RFC 3164/5424), PTP, and more
- **5G/LTE Mobile Protocols** - NAS, S1AP, NGAP, GTPv2, Diameter for mobile network monitoring
- **Linux-Based** - Supports major Linux distributions (Debian/Ubuntu, Rocky Linux/CentOS Stream, Fedora, openSUSE; Arch, Alpine and RHEL best-effort)

<!-- end-shared: docs/_includes/key-features.md -->

## Quick Start

### Install

<!-- begin-shared: docs/_includes/quick-start.md -->

Install MMT-DPI with one command. The routes below are listed in order of
preference: use the first one that covers your platform. Every route
installs under `/opt/mmt`, so the first run works after any of them, from an
empty directory.

<!-- Route order (issue #577): package repository, then the release
     bootstrap, then the source installer. The signed APT and dnf
     repositories (#575, #576) go first, here, once they are published. -->

**Verified package bootstrap** — Ubuntu 22.04/24.04/26.04, Debian 12/13,
Rocky Linux / AlmaLinux 9 and 10, CentOS Stream 9 and 10, amd64 or arm64. It
installs the release's native `.deb`/`.rpm` after checking its sha256 and its
build-provenance attestation. It is published from the first release after
v1.9.1; until then, use the source installer on these platforms too.

```bash
curl -fsSL https://github.com/montimage-projects/mmt-dpi/releases/latest/download/install.sh | sh
```

Add `-s -- --with-security` after `sh` to install the GPL security engines
too. To check the bootstrap before running it, download `install.sh`, run
`gh attestation verify install.sh --repo montimage-projects/mmt-dpi`, then
`sh install.sh`.

**Source installer** — every supported Linux. It installs the build
dependencies, then clones the pinned release tag (`v1.9.1`), verifies it after
checkout, builds it and installs it; moving branches are refused unless
explicitly opted in:

<!-- hero-install: docs/index.html shows the command of the next block above the fold -->

```bash
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

or using `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

The source installer and the first run are smoke-tested in CI on
Ubuntu 22.04/24.04, Debian 12, Rocky Linux 9, CentOS Stream 9, Fedora 44 and
openSUSE Leap 16.0. Arch, Alpine (musl: the SDK does not build there today)
and RHEL itself (CodeReady Builder must be enabled through
`subscription-manager` first) are **best-effort**. Its options are variants
of the same command:

```bash
# Preview the install plan without changing anything
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash -s -- --dry-run

# Install to a custom directory (substitute it for /opt/mmt in the first run)
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | MMT_BASE=/usr/local/mmt bash

# Build the tip of a branch (here main) instead of the pinned release (unverified — explicit opt-in)
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | BRANCH=main bash -s -- --unverified-branch

# Skip automatic dependency installation
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | SKIP_DEPS=1 bash

# Uninstall (add --prefix <dir> for a custom prefix)
curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash -s -- --uninstall
```

Pre-built `.deb`/`.rpm` packages are on the
[Releases page](https://github.com/montimage-projects/mmt-dpi/releases); the
full install walkthrough, building from a checkout included, is the
[User Guide](https://github.com/montimage-projects/mmt-dpi/blob/main/docs/USER_GUIDE.md).

<!-- end-shared: docs/_includes/quick-start.md -->

### Pre-built packages

Every tagged release publishes ready-to-install `.deb` and `.rpm` packages
(amd64 and arm64) — one per distribution in the release matrix: **Ubuntu
22.04, Ubuntu 24.04, Ubuntu 26.04, Debian 12, Debian 13 (.deb), Rocky Linux 9,
Rocky Linux 10, CentOS Stream 9 and CentOS Stream 10 (.rpm)**. Download the one matching your distribution from the
[Releases page](https://github.com/montimage-projects/mmt-dpi/releases) and
install it with your native package manager:

```bash
# Debian / Ubuntu (.deb)
sudo apt install ./mmt-dpi_*_ubuntu-24.04_x86_64.deb

# Rocky Linux / CentOS Stream (.rpm)
sudo dnf install ./mmt-dpi_*_rocky-9_x86_64.rpm
```

Each distribution gets two packages. `mmt-dpi` is the SDK. The optional
security and fuzz engines (`libmmt_security`, `libmmt_fuzz`) are in
`mmt-dpi-security`, because their licence differs. It requires the same
`mmt-dpi` version, so install it next to that package only when you need the
engines, e.g. `sudo apt install ./mmt-dpi_*.deb ./mmt-dpi-security_*.deb`.
Each package installs `LICENSE` and `THIRD-PARTY-NOTICES` under
`/opt/mmt/dpi/share/doc/<package>/`, and the security package adds the GPL
text as `COPYING`. The `.rpm` `License:` field holds the SPDX expression (see
[License](#license)).

Packages are produced by the `Build & release packages` workflow
(`.github/workflows/release-packages.yml`). Builds are reproducible: two
builds of the same commit in the same release container produce
byte-identical packages (all timestamps are pinned to `SOURCE_DATE_EPOCH`),
and a CI job diffs the sha256 sums of a double build on every packaging
change.

#### Verify a package before installing it

Installing a package runs its maintainer scripts as root, so authenticate the
download first. Every release asset is verifiable: a `SHA256SUMS` manifest
covers all published files, each package ships an SPDX SBOM
(`<package>.sbom.json` listing what it was built and linked against, plus the
third-party sources vendored into it — `tools/ci/vendored-components.json`), and the
workflow records a build-provenance attestation for every asset.

Download `SHA256SUMS` and the package from the same release, then:

```bash
# Integrity — the package must match the release manifest
sha256sum --check SHA256SUMS --ignore-missing

# Provenance — the package must have been built by this repo's release workflow
gh attestation verify mmt-dpi_*_ubuntu-24.04_x86_64.deb \
  --repo montimage-projects/mmt-dpi
```

Install only after both checks pass.

#### Verified one-command package install

From the first release after v1.9.1, each release also publishes a bootstrap
installer that does all of the above for you and installs the native
package: it is the first route of the [Install](#install) commands above.
It is generated by the release job (`tools/ci/make-release-bootstrap.sh`)
with the sha256 of every package of that release embedded. It picks the
package for your distribution and architecture from the stable alias names
(`mmt-dpi_<distro>_<amd64|arm64>.deb/.rpm`, listed with their digests in the
release's `manifest.json`), checks the digest, verifies the build-provenance
attestation offline with a sha256-pinned GitHub CLI against the release's
Sigstore bundle (`mmt-dpi.intoto.jsonl` — signed itself, so it is the one
asset `SHA256SUMS` does not list), and only then installs the package with
`apt-get` or `dnf`, which pulls its dependencies and registers
`/opt/mmt/dpi/lib` with the loader. Any mismatch exits non-zero before
anything is installed. Other distributions, or another prefix, use the source
installer.

### Manual Build and Install

If you prefer to build manually, install the build dependencies first — the
`apt-get` line is maintained in one place,
[Agent Environment Notes §1 Toolchain Requirements](docs/AGENT_ENVIRONMENT.md#1-toolchain-requirements).
The install prefix is configurable; see
[§4 `MMT_BASE` Install-Prefix Behavior](docs/AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior).

From any directory (the block clones into `./mmt-dpi` and stays at the root
of that checkout):

```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi

# Build
make -C sdk -j$(nproc)

# Install (default: /opt/mmt/dpi/)
sudo make -C sdk install
```

To uninstall, from the same checkout: `sudo make -C sdk uninstall` (same
`MMT_BASE` as the install). A source-installer install is removed by its
uninstall line in [Install](#install).

### Verify Installation

Run the first program below ([Basic Packet Processing](#basic-packet-processing)):
it starts from an empty directory and works after every install route.

## Usage

### Basic Packet Processing

<!-- begin-shared: docs/_includes/first-example.md -->

A complete first program,
[`hello_packet.c`](https://montimage-projects.github.io/mmt-dpi/first-run/hello_packet.c),
and a small capture to run it on,
[`traffic.pcap`](https://montimage-projects.github.io/mmt-dpi/first-run/traffic.pcap),
are published with the documentation site. From an empty directory, with the
SDK installed under `/opt/mmt` (the quick-start default — substitute your
`MMT_BASE` prefix and add `LD_LIBRARY_PATH="$MMT_BASE/dpi/lib"` to the run
line otherwise). Compiling needs `gcc` and the libpcap headers: the source
installer adds both; after a `.deb`/`.rpm` install, add them with
`sudo apt-get install gcc libpcap-dev` (Debian/Ubuntu) or
`sudo dnf --enablerepo=crb install gcc libpcap-devel` (Rocky, AlmaLinux and
CentOS Stream 9, where `libpcap-devel` is in CRB; on RHEL 9 first run
`sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms`
and drop `--enablerepo=crb`; plain `dnf install` on Fedora):

```bash
curl -fsSL -O https://montimage-projects.github.io/mmt-dpi/first-run/hello_packet.c \
     -O https://montimage-projects.github.io/mmt-dpi/first-run/traffic.pcap
gcc -o hello_packet hello_packet.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./hello_packet traffic.pcap
```

The capture is synthetic and redistributable: one DNS lookup and one HTTP
exchange between documentation addresses (RFC 5737). The program prints each
packet's size and the protocol path MMT-DPI classified it as — the TCP
handshake stays `unknown` until the first payload identifies HTTP:

```text
packet 1: 71 bytes, meta.ethernet.ip.udp.dns
packet 2: 87 bytes, meta.ethernet.ip.udp.dns
packet 3: 54 bytes, meta.ethernet.ip.tcp.unknown
packet 4: 54 bytes, meta.ethernet.ip.tcp.unknown
packet 5: 54 bytes, meta.ethernet.ip.tcp.unknown
packet 6: 130 bytes, meta.ethernet.ip.tcp.http
packet 7: 138 bytes, meta.ethernet.ip.tcp.http
packet 8: 54 bytes, meta.ethernet.ip.tcp.http
packet 9: 54 bytes, meta.ethernet.ip.tcp.http
packet 10: 54 bytes, meta.ethernet.ip.tcp.http
10 packets processed
```

A missing capture fails with a clear message and the command that fetches
it. The program follows the embedding lifecycle — global init, one handler,
a `packet_process()` loop, handler teardown before the global teardown; the
[`src/examples/packet_handler.c`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/examples/packet_handler.c)
reference that CI compiles on every build does the same. `META`/`PACKET_LEN`
is a built-in meta attribute available on every packet:

```c
/* hello_packet.c - a first MMT-DPI program: print the size and the
 * classified protocol path of every packet in a capture.
 *
 * Build against an installed SDK (replace /opt/mmt with your MMT_BASE):
 *   gcc -o hello_packet hello_packet.c -I /opt/mmt/dpi/include \
 *       -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 * Run on the sample capture published next to this file:
 *   ./hello_packet traffic.pcap
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "mmt_core.h"

static int on_packet(const ipacket_t *ipacket, void *user_args) {
    uint32_t *len = (uint32_t *)get_attribute_extracted_data_by_name(
        ipacket, "META", "PACKET_LEN");
    char path[256] = "";
    (void)user_args;
    proto_hierarchy_to_str_with_size(ipacket->proto_hierarchy, path, sizeof(path));
    printf("packet %" PRIu64 ": %u bytes, %s\n", ipacket->packet_id,
           len ? *len : 0, path);
    return 0; // returning 1 skips the remaining handlers for this packet
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE > MMT_ERRBUF_SIZE ? PCAP_ERRBUF_SIZE : MMT_ERRBUF_SIZE];
    if (argc != 2) {
        fprintf(stderr, "usage: %s <capture.pcap>\n", argv[0]);
        return 1;
    }
    // Open the capture first: a missing file needs no MMT state to report.
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        fprintf(stderr, "hello_packet: cannot open capture '%s': %s\n", argv[1], errbuf);
        if (strcmp(argv[1], "traffic.pcap") == 0) // only the sample has a download
            fprintf(stderr, "  to fetch the sample capture into the current directory:\n"
                    "  curl -fsSLO https://montimage-projects.github.io/mmt-dpi/first-run/traffic.pcap\n");
        return 1;
    }
    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "hello_packet: '%s' is not an Ethernet capture\n", argv[1]);
        pcap_close(pcap);
        return 1;
    }

    // 1. global state, once, before any handler
    if (!init_extraction()) {
        fprintf(stderr, "hello_packet: init_extraction failed\n");
        pcap_close(pcap);
        return 1;
    }
    // 2. one handler for this packet stream
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!handler) {
        fprintf(stderr, "hello_packet: handler init failed: %s\n", errbuf);
        close_extraction();
        pcap_close(pcap);
        return 1;
    }
    // 3. register what to extract and the per-packet callback
    struct pcap_pkthdr *pkt_hdr;
    const u_char *data;
    unsigned long count = 0;
    int rc, status = 1;
    if (!register_extraction_attribute_by_name(handler, "META", "PACKET_LEN")
        || !register_packet_handler(handler, 1, on_packet, NULL)) {
        fprintf(stderr, "hello_packet: registration failed\n");
        goto out;
    }
    // 4. the processing loop: one packet_process() call per captured packet
    while ((rc = pcap_next_ex(pcap, &pkt_hdr, &data)) == 1) {
        struct pkthdr header;
        memset(&header, 0, sizeof(header));
        header.ts = pkt_hdr->ts;
        header.caplen = pkt_hdr->caplen;
        header.len = pkt_hdr->len;
        if (!packet_process(handler, &header, data))
            fprintf(stderr, "hello_packet: packet %lu not processed\n", count + 1);
        count++;
    }
    if (rc == -1) {
        fprintf(stderr, "hello_packet: read error: %s\n", pcap_geterr(pcap));
        goto out;
    }
    printf("%lu packets processed\n", count);
    status = 0;
out:
    // 5. every handler before the global teardown, which comes last
    mmt_close_handler(handler);
    close_extraction();
    pcap_close(pcap);
    return status;
}
```

<!-- end-shared: docs/_includes/first-example.md -->

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
| Linux arm64 (aarch64), native | `make` on an arm64 host — CI runs the full suite on `ubuntu-24.04-arm` ([ARM status](docs/Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md)) |

> **Note:** macOS and Windows are not currently supported.

## Documentation

- [Documentation site](https://montimage-projects.github.io/mmt-dpi/) — the rendered version of everything below
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

Montimage's code in this project is licensed under the
[Apache License 2.0](LICENSE). There are two exceptions:

- The security rule engine (`src/mmt_security`, `libmmt_security`) is
  GPL-3.0-or-later, as each of its source files states
  ([full text](LICENSES/GPL-3.0-or-later.txt)).
- Two third-party components are vendored and compiled into the protocol
  libraries: llhttp (MIT) and the asn1c runtime (BSD-2-Clause). They are
  listed, with their notices, in [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).

That file is generated from `tools/ci/vendored-components.json`. The packages
declare these SPDX expressions:

| Package | Contents | Licence |
|---------|----------|---------|
| `mmt-dpi` | core, protocol plugins, headers, examples | `Apache-2.0 AND BSD-2-Clause AND MIT` |
| `mmt-dpi-security` | `libmmt_security`, `libmmt_fuzz` (ENABLESEC=1) | `GPL-3.0-or-later AND Apache-2.0` |

## About

Developed and maintained by [Montimage](https://www.montimage.eu) - 39 rue Bobillot, 75013 Paris, France.

Contact: [contact@montimage.eu](mailto:contact@montimage.eu)

![](https://komarev.com/ghpvc/?username=montimage-dpi&style=flat-square&label=Page+Views)
