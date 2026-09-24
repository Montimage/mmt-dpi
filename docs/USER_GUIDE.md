---
layout: default
title: "User Guide"
---

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
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

This script (`install.sh`):
1. Detects your distribution and installs an equivalent distro-specific build
   dependency set (`install.sh:325-396`); the reference list is
   [Agent Environment Notes §1 Toolchain Requirements](./AGENT_ENVIRONMENT.md#1-toolchain-requirements).
2. Clones the pinned release tag into a temporary directory and verifies it
   (commit pin, plus the tag signature when present — issue #197).
3. Runs `make ARCH=linux MMT_BASE=/opt/mmt -jN`.
4. Installs to `/opt/mmt/dpi/` (override with `MMT_BASE=/custom/path` or
   `--prefix /custom/path`), elevating with `sudo` only when the prefix is not
   writable by the current user (issue #211).
5. Refreshes the dynamic linker cache (`ldconfig`) only when the install
   escalated — a user-local prefix skips it.

Manual build:

```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi/sdk
make -j$(nproc)
sudo make install
```

After installation (default `MMT_BASE=/opt/mmt`), the layout is:

```
/opt/mmt/
├── dpi/
│   ├── include/      # Public C headers (mmt_core.h, ...)
│   └── lib/          # Shared libraries (libmmt_core.so, libmmt_tcpip.so, ...)
├── plugins/          # Protocol plugin .so files loaded at runtime
└── examples/         # Prebuilt example binaries
```

Paths are defined in `rules/common.mk:4-7`.

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

No checkout at hand? A complete first program,
[`hello_packet.c`](first-run/hello_packet.c), and the synthetic,
redistributable capture it runs on, [`traffic.pcap`](first-run/traffic.pcap),
are published with the documentation site; the README's *Basic Packet
Processing* section and the site's landing page give the exact steps to
fetch, compile and run them from an empty directory, and the output to
expect.

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

The library has two levels of state, and the lifecycle follows them:
**global** state (the protocol registry and the loaded plugins), created once
per process, and **per-handler** state (sessions, registered attributes and
callbacks, statistics), one `mmt_handler_t` per packet stream. The order is:

1. Initialise the global state once with `init_extraction()`, **before any
   handler exists**, and check its return value — it returns `false` on
   failure (`src/mmt_core/src/packet_registry.c:1255`). It builds the
   protocol registry, loads the plugins and creates the map that tracks live
   handlers (`src/mmt_core/src/packet_registry.c:1303-1304`); nothing else
   in the API works before it. If it fails, do not call anything else,
   including `close_extraction()`.
2. Create a handler with `mmt_init_handler()` and check it for `NULL` — on
   failure it fills the `errbuf` you pass in (at least `MMT_ERRBUF_SIZE`
   bytes) (`src/mmt_core/src/packet_registry.c:950`). Each new handler is
   recorded in the global handler map
   (`src/mmt_core/src/packet_registry.c:1097`).
3. Register the attributes you care about with
   `register_extraction_attribute()` (by protocol id and attribute id) or
   `register_extraction_attribute_by_name()`, and optionally packet-,
   attribute- or session-level callbacks. Each returns `false` on failure.
4. Feed packets in with `packet_process()`
   (`src/mmt_core/src/packet_pipeline.c:1389`); it returns `false` when a
   packet could not be processed, and later packets can still be fed.
5. Release every handler with `mmt_close_handler()`: it expires the
   handler's sessions, frees everything the handler owns and removes it from
   the global handler map (`src/mmt_core/src/packet_registry.c:1130`,
   `src/mmt_core/src/packet_registry.c:1180`).
6. Tear down the global state last, once, with `close_extraction()`
   (`src/mmt_core/src/packet_registry.c:1333`). It force-closes any handler
   still registered (`src/mmt_core/src/packet_registry.c:1336`) and then
   unloads the plugins (`src/mmt_core/src/packet_registry.c:1350`), so a
   handler pointer is dangling afterwards: never call `mmt_close_handler()`
   or `packet_process()` on it once `close_extraction()` has run.

On an error part-way through, release only what was acquired, in reverse
order: a failed `mmt_init_handler()` is followed by `close_extraction()`
alone; a failure after the handler exists closes the handler and then the
global state.

**Worker ownership.** Handlers are not shared: each worker thread owns its
own `mmt_handler_t` and feeds packets only to it. `init_extraction()` and
all protocol/plugin registration run on one thread before any worker starts;
handlers may then be created on the main thread or inside the workers.
Shutdown stops every worker first, closes each worker's handler with
`mmt_close_handler()`, then calls `close_extraction()` once on a single
thread. The full contract, the locks behind it and the ThreadSanitizer
harness that checks it are in [THREADING.md](./THREADING.md).

`src/examples/packet_handler.c` is the runnable reference for this order:
it checks `init_extraction()` (`src/examples/packet_handler.c:63`) before
creating its handler (`src/examples/packet_handler.c:69`), unwinds each
failure path, processes a pcap (`src/examples/packet_handler.c:100`) and
closes the handler (`src/examples/packet_handler.c:108`) before the global
state (`src/examples/packet_handler.c:111`). Against an install prefix
(`/opt/mmt` or your `MMT_BASE`, see
[AGENT_ENVIRONMENT.md §4](./AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior)):

```bash
gcc -o packet_handler "$MMT_BASE/examples/packet_handler.c" \
    -I "$MMT_BASE/dpi/include" -L "$MMT_BASE/dpi/lib" -lmmt_core -ldl -lpcap
curl -fsSL -O https://montimage-projects.github.io/mmt-dpi/first-run/traffic.pcap
LD_LIBRARY_PATH="$MMT_BASE/dpi/lib" ./packet_handler traffic.pcap
```

Any Ethernet pcap works; the `curl` line fetches the published
[`traffic.pcap`](first-run/traffic.pcap) into the current directory, so the
commands run from any directory — a checkout's `src/examples/google-fr.pcap`
works too when passed by its full path.

`init_extraction()` loads the protocol plugins from a `plugins` directory
in the current working directory when one exists, and from
`$MMT_BASE/plugins` only otherwise
(`src/mmt_core/src/plugins_engine.c:43-50`), so run the program from a
directory without a stale `./plugins`.

The `docs_lifecycle` test suite builds and installs the SDK into a
throwaway prefix, compiles and runs this example against it, and checks
every `path:line` citation in this section. `src/examples/extract_all.c`
is the most complete attribute-extraction reference.

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
[bug report template](https://github.com/montimage-projects/mmt-dpi/blob/main/.github/ISSUE_TEMPLATE/bug_report.md) or start
a discussion on the repo.
