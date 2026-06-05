# User Guide

This guide walks through installing MMT-DPI, running the included example
binaries against a packet capture, and writing a small program that uses
the library to extract attributes from live or recorded traffic.

For deeper dives into specific subsystems, see:
- [ARCHITECTURE.md](ARCHITECTURE.md) — layered overview of the code base.
- [DEVELOPMENT.md](DEVELOPMENT.md) — building from source, debug builds,
  static analysis, adding new protocols.
- [DEPLOYMENT.md](DEPLOYMENT.md) — install paths, packaging, runtime
  configuration.

## 1. Install

The fastest path is the one-liner installer (Linux only):

```bash
curl -sSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash
```

This script:
1. Detects your distribution and installs build dependencies
   (`build-essential`, `libxml2-dev`, `libpcap-dev`, `cmake`).
2. Clones the `main` branch into a temporary directory.
3. Runs `make ARCH=linux MMT_BASE=/opt/mmt -jN`.
4. Installs to `/opt/mmt/dpi/` (override with `MMT_BASE=/custom/path`).
5. Refreshes the dynamic linker cache (`/etc/ld.so.conf.d/mmt.conf`).

Manual build:

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi/sdk
make -j$(nproc)
sudo make install
```

After installation, the layout under `MMT_BASE/dpi/` is:

```
include/      # Public C headers (mmt_core.h, ...)
lib/          # Shared libraries (libmmt_core.so, libmmt_tcpip.so, ...)
plugins/      # Protocol plugin .so files loaded at runtime
examples/     # Prebuilt example binaries
```

## 2. First run: extract attributes from a pcap

The `extract_all` example iterates over a pcap and prints every attribute
the configured protocol stack can extract:

```bash
cd src/examples
gcc -o extract_all extract_all.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
./extract_all -t google-fr.pcap
```

A sample pcap (`google-fr.pcap`) is shipped under `src/examples/` for
quick smoke testing.

Other ready-to-build examples in the same directory:

| File | Purpose |
|---|---|
| `extract_all.c` | Dump every extractable attribute per packet. |
| `packet_handler.c` | Register a per-packet callback. |
| `attribute_handler_session_counter.c` | Per-attribute callback that counts sessions. |
| `proto_attributes_iterator.c` | Walk the registered protocol/attribute tree. |
| `simple_traffic_reporting.c` | Lightweight traffic statistics. |
| `MAC_extraction.c` | Pull link-layer addresses. |
| `mmt_export_info.c` | Dump exported protocol/attribute metadata. |

## 3. Minimum embedding pattern

The typical lifecycle when embedding the library is:

1. Initialise a handler with `mmt_init_handler()`.
2. Register the attributes you care about with
   `register_extraction_attribute()` (by protocol id and attribute id, or
   by name with `register_extraction_attribute_by_name()`).
3. Optionally register packet-, attribute-, or session-level callbacks.
4. Feed packets in with `packet_process()`.
5. Tear down with `mmt_close_handler()` and `close_extraction()`.

Skim `src/examples/extract_all.c` for the most complete reference;
`src/examples/packet_handler.c` shows the callback registration shape.

## 4. Where to look next

- Conceptual reference for the public API: `docs/MMT-Handler.md`,
  `docs/MMT-Packet.md`, `docs/MMT-Session.md`, `docs/MMT-Attributes.md`.
- Adding a new protocol parser: `docs/Add-New-Protocol.md`.
- Per-protocol design notes: `docs/HTTP-protocol.md`,
  `docs/DNS-protocol.md`, `docs/FTP-Protocol.md`,
  `docs/TCP-protocol.md`, etc.
- Auto-extracted public symbol list: `docs/Exported-Symbols.md`.
- Performance / runtime tuning: `docs/Deployment-Consideration.md`.

If you hit something this guide doesn't answer, open an issue using the
[bug report template](../.github/ISSUE_TEMPLATE/bug_report.md) or start
a discussion on the repo.
