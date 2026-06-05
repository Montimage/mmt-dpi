# MMT-DPI

> A high-performance C library for **Deep Packet Inspection** — protocol classification, attribute extraction, and session tracking for live and recorded network traffic.

[![License: Apache 2.0](https://img.shields.io/github/license/Montimage/mmt-dpi)](LICENSE)
[![C/C++ CI](https://github.com/Montimage/mmt-dpi/actions/workflows/c-cpp.yml/badge.svg?branch=main)](https://github.com/Montimage/mmt-dpi/actions/workflows/c-cpp.yml)
[![Latest release](https://img.shields.io/github/v/release/Montimage/mmt-dpi)](https://github.com/Montimage/mmt-dpi/releases)
[![Open issues](https://img.shields.io/github/issues/Montimage/mmt-dpi)](https://github.com/Montimage/mmt-dpi/issues)

MMT-DPI (Montimage Monitoring Tool — Deep Packet Inspection) is the core
parsing engine used across the Montimage MMT product family. It identifies
network protocols, extracts protocol-specific attributes (headers, fields,
flow metadata), and tracks sessions across packets — from live capture
devices or pcap files. It is written in C, ships as a set of shared
libraries plus runtime-loaded protocol plugins, and targets Linux servers
and embedded boxes.

The library is intended for engineers building network probes, traffic
analysers, intrusion detection pipelines, QoE measurement tools, and
research platforms that need a programmable DPI back end.

## Key features

- **Broad protocol coverage** — TCP/IP stack plus application-layer parsers
  for HTTP, HTTP/2, QUIC, DNS, FTP, DTLS, GTP, MQTT, OSPF, RADIUS,
  DICOM, and many more (see `src/mmt_tcpip/lib/protocols/`).
- **Mobile-network protocols** — NAS, S1AP, NGAP, GTPv2, Diameter for
  4G/5G monitoring (see `src/mmt_mobile/`).
- **Attribute extraction by name or id** — register the fields you care
  about (e.g. `IP.SRC`, `HTTP.URI`, `META.PACKET_LEN`) and receive them
  through callbacks; no need to walk packet structures by hand.
- **Session and flow tracking** — bidirectional flow state with timing,
  byte/packet counters, retransmission accounting, and per-session
  callbacks.
- **Plugin architecture** — protocol parsers are loaded at runtime from
  `<MMT_BASE>/plugins/`, so new protocols can be added without rebuilding
  the core.
- **Live and offline input** — works against `libpcap` capture devices
  or pcap trace files; no I/O is hard-wired into the core.
- **Self-contained C SDK** — installs headers and shared libraries under
  a configurable prefix (default `/opt/mmt/dpi/`), ready to link from
  any C/C++ application.
- **Linux distribution coverage** — installer supports Debian/Ubuntu,
  Fedora/RHEL/CentOS, Arch, Alpine, and openSUSE; CI builds on Ubuntu
  and produces a `.deb` artefact.

## Quick start

### One-line install (Linux)

```bash
curl -sSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash
```

The installer detects your package manager, pulls build dependencies,
clones the repository, builds the SDK, and installs to `/opt/mmt/dpi/`.
Override the prefix with `MMT_BASE=/your/path`, the branch with
`BRANCH=dev`, or skip dependency installation with `SKIP_DEPS=1`. See
[`install.sh`](install.sh) for the full set of environment variables.

> macOS and Windows are not supported.

### Try it on a sample pcap

A small capture (`google-fr.pcap`) ships under `src/examples/` for smoke
testing. After `make install`:

```bash
cd src/examples
gcc -o extract_all extract_all.c \
    -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
./extract_all -t google-fr.pcap
```

`extract_all` walks every attribute the configured protocol stack can
extract for each packet. For more involved patterns (per-attribute
callbacks, session counters, live capture), see the other programs in
[`src/examples/`](src/examples/) and the
[User Guide](docs/USER_GUIDE.md).

## Documentation

End-user and contributor docs:

- [User Guide](docs/USER_GUIDE.md) — install, run examples, embed the
  library in your own program.
- [Architecture](docs/ARCHITECTURE.md) — components, plugin model, SDK
  boundary.
- [Development guide](docs/DEVELOPMENT.md) — building from source, debug
  builds, static analysis, testing.
- [Deployment](docs/DEPLOYMENT.md) — install paths, packaging, runtime
  configuration.
- [Roadmap](docs/ROADMAP.md) — planned protocols and milestones.
- [Changelog](CHANGELOG.md) — release history.

Reference / topic docs (under `docs/`):

- [Adding a new protocol](docs/Add-New-Protocol.md)
- [Protocol stack](docs/Protocol-Stack.md) ·
  [Packet journey](docs/Packet-Journey.md) ·
  [Memory management](docs/Memory-Management.md)
- Public API: [Handler](docs/MMT-Handler.md) ·
  [Packet](docs/MMT-Packet.md) ·
  [Session](docs/MMT-Session.md) ·
  [Attributes](docs/MMT-Attributes.md) ·
  [Exported symbols](docs/Exported-Symbols.md)
- Per-protocol design notes: [HTTP](docs/HTTP-protocol.md),
  [HTTP/2](docs/HTTP2-protocol.md), [DNS](docs/DNS-protocol.md),
  [FTP](docs/FTP-Protocol.md), [TCP](docs/TCP-protocol.md),
  [NDN](docs/NDN-protocol.md), and more.
- [Examples walk-through](docs/Examples.md)
- [Cross-compiling for ARM](docs/Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md)

Project policy:

- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)
- [Authors and maintainers](AUTHORS)

## Project structure

```
mmt-dpi/
├── src/        # Library source: core engine, protocol plugins, examples
├── sdk/        # Top-level Makefile entry point (build, install, deb, test)
├── rules/      # Per-architecture build rules (linux, linux-clang, ARM, ...)
├── docs/       # User guide, architecture, protocol references
├── dist/       # Packaging assets (Debian control files, etc.)
└── .github/    # CI workflow, issue/PR templates, Dependabot
```

Inside `src/`:

- `mmt_core/` — packet processing engine and public API.
- `mmt_tcpip/` — TCP/IP stack and application-layer protocol parsers.
- `mmt_mobile/` — 4G/5G mobile-network protocols.
- `mmt_business_app/` — business-application protocols.
- `mmt_security/` — security-related protocol handling.
- `mmt_dicom/`, `mmt_fuzz_engine/` — additional parsers / tooling.
- `examples/` — sample programs that link against the installed SDK.

## Building from source

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi/sdk
make -j$(nproc) && sudo make install
```

The full developer workflow — debug builds, `make test`,
cross-compilation, and adding new protocol parsers — is documented in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Distribution packaging
(`make deb`) and operator-side install options are in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Contributing

Contributions are welcome — bug reports, protocol parsers, documentation
fixes, and test cases. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
for the fork → branch → PR workflow, build prerequisites, the
Conventional Commits convention used in this repository, and the basic
coding-style expectations. All contributors are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Security-sensitive reports should
go through the channel described in [SECURITY.md](SECURITY.md).

## Related publications

<!-- RELATED_PUBLICATIONS_START -->

The following peer-reviewed publications and Montimage white papers
present, evaluate, or apply MMT-DPI (and the wider MMT toolset that
embeds it). Topic tags: `[dpi-core]` core engine, `[iot]` IoT
monitoring, `[5g]` 5G/mobile networks, `[nids]` intrusion detection.

### Tools and frameworks built on MMT-DPI

- **Online Network Traffic Security Inspection Using MMT Tool** —
  W. Mallouli, B. Wehbi, E. Montes de Oca, M. Bourdelles. *System
  Testing and Validation*, Vol. 192, 2012. `[dpi-core]`
- **Events-Based Security Monitoring Using MMT Tool** — B. Wehbi,
  E. Montes de Oca, M. Bourdelles. *5th IEEE International Conference
  on Software Testing, Verification and Validation (ICST)*, 2012.
  IEEE Xplore: 6200200. `[dpi-core]`
- **Network Monitoring using MMT: An application based on the
  User-Agent field in HTTP headers** — A.R. Cavalli, W. Mallouli,
  et al., 2016. HAL: hal-01335530. `[dpi-core]`
- **5GReplay: A 5G Network Traffic Fuzzer — Application to Attack
  Injection** — Z. Salazar, H.N. Nguyen, W. Mallouli, A.R. Cavalli,
  E. Montes de Oca. *ARES 2021*, 16th International Conference on
  Availability, Reliability and Security. `[5g]` `[nids]`
- **A Network Traffic Mutation Based Ontology to Expand the Training
  Set of AI-Based Network Intrusion Detection Systems** — Z. Salazar,
  F. Zaïdi, H.N. Nguyen, A.R. Cavalli, E. Montes de Oca, W. Mallouli.
  *IEEE Access*, 2023. `[nids]`

### Applications of MMT in IoT and industrial monitoring

- **A Framework for Security Monitoring of Real IoT Testbeds** —
  W. Mallouli, A.R. Cavalli, E. Montes de Oca, et al. *ICSOFT 2021*,
  16th International Conference on Software Technologies. `[iot]`
- **Industrial IoT Security Monitoring and Test on Fed4Fire+
  Platforms** — W. Mallouli, A.R. Cavalli, et al. Springer, 2019.
  DOI: [10.1007/978-3-030-31280-0_17](https://doi.org/10.1007/978-3-030-31280-0_17). `[iot]`
- **A novel monitoring solution for 6LoWPAN-based Wireless Sensor
  Networks** — A.R. Cavalli, W. Mallouli, et al., 2016.
  HAL: hal-01391251. `[iot]`
- **A security monitoring system for internet of things** —
  V. Casola, A. De Benedictis, A. Riccio, D. Rivera, W. Mallouli,
  E. Montes de Oca. *Internet of Things* (Elsevier), Vol. 7, 100080,
  2019. `[iot]`

### White papers and product literature

- **Cyber Secure Communications in Intelligent Transport Systems** —
  Montimage white paper. Available from the
  [Montimage publications page](https://montimage.com/pubs/).

For additional Montimage publications on 5G, NDN security monitoring,
DevOps security, and adjacent topics, see
[Wissam Mallouli's Google Scholar profile](https://scholar.google.com/citations?user=LTKlUkwAAAAJ&hl=en),
[Edgardo Montes de Oca's Google Scholar profile](https://scholar.google.com/citations?user=u2YE0WQAAAAJ&hl=en),
and the [Montimage publications page](https://montimage.com/pubs/).

<!-- RELATED_PUBLICATIONS_END -->

## License

MMT-DPI is released under the [Apache License, Version 2.0](LICENSE).
You may use it for commercial and non-commercial purposes, subject to
the terms of the licence (notice preservation, patent grant, no
warranty).

## Acknowledgments

MMT-DPI is developed and maintained by **[Montimage](https://www.montimage.eu)**
(39 rue Bobillot, 75013 Paris, France). It is the deep-packet-inspection
core that underpins Montimage's broader MMT monitoring product family
and has been used in numerous research and industrial network-monitoring
projects.

The current maintainers and the wider contributor community are listed
in [AUTHORS](AUTHORS) and on the
[GitHub contributors page](https://github.com/Montimage/mmt-dpi/graphs/contributors).
For commercial enquiries: [contact@montimage.eu](mailto:contact@montimage.eu).
