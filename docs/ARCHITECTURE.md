# Architecture

## Overview

MMT-DPI is a modular deep packet inspection library built around a
plugin-based architecture. A small core engine drives packet processing,
session management, and attribute extraction; protocol-specific logic
is implemented in dynamically loaded plugins. Applications consume the
library through a stable C SDK installed under `/opt/mmt/dpi/`.

The system has four layers:

```
+--------------------------------------------------------------+
|  Applications  (extract_all, packet_handler, your binary)    |
+--------------------------------------------------------------+
|  SDK boundary  (/opt/mmt/dpi/include, /opt/mmt/dpi/lib)      |
+--------------------------------------------------------------+
|  Core engine   (src/mmt_core)                                |
|    - handler / session / attribute / plugin loader           |
+--------------------------------------------------------------+
|  Protocol stack plugins (loaded at runtime from plugins/)    |
|    mmt_tcpip | mmt_mobile | mmt_business_app | mmt_security  |
|    mmt_dicom | mmt_fuzz_engine                               |
+--------------------------------------------------------------+
```

## Layer 1: Core engine (`src/mmt_core/`)

The central component. Responsibilities:

- Packet processing pipeline (`packet_process()`).
- Handler lifecycle (`mmt_init_handler()`, `mmt_close_handler()`).
- Attribute registration and extraction.
- Session lifecycle and state tracking.
- Plugin discovery and protocol registration.

Public headers (the SDK surface) live in
`src/mmt_core/public_include/` and are installed verbatim to
`/opt/mmt/dpi/include/`.

## Layer 2: Protocol stack plugins

Each plugin is a shared library loaded at runtime from
`/opt/mmt/dpi/plugins/`. A plugin provides one or more protocol
parsers; each parser registers:

- A classification function (decide whether a packet belongs to this
  protocol given the current stack position).
- Attribute extraction functions (parse fields out of the packet).
- Optional session hooks (per-protocol session state).

| Plugin | Library | Scope |
|---|---|---|
| `mmt_tcpip` | `libmmt_tcpip.so` | Ethernet through L7: IP, TCP/UDP, HTTP/1.1, HTTP/2, DNS, FTP, QUIC, TLS, and dozens more. |
| `mmt_mobile` | `libmmt_mobile.so` | Mobile-core protocols: NAS, S1AP, NGAP, GTP, Diameter. |
| `mmt_business_app` | `libmmt_business_app.so` | Business-application protocols. |
| `mmt_security` | `libmmt_security.so` | Security-related parsing (DTLS cipher policy, etc.). |
| `mmt_dicom` | `libmmt_dicom.so` | DICOM medical-imaging protocol. |
| `mmt_fuzz_engine` | `libmmt_fuzz_engine.so` | Fuzzing harness. |

Plugins are intentionally hot-pluggable: dropping a new `.so` into the
plugins directory makes its protocols visible to the core engine on the
next handler init.

## Layer 3: SDK boundary

What gets installed at `MMT_BASE/dpi/`:

```
include/      Public C headers (mmt_core.h and friends)
lib/          libmmt_core.so + plugin shared libraries
plugins/      Plugin .so files searched at handler init
examples/     Pre-built example binaries
```

The library path is exported to the dynamic linker through
`/etc/ld.so.conf.d/mmt.conf`. Applications link against
`-lmmt_core -ldl` (plus `-lmmt_tcpip -lpcap` for TCP/IP attribute
extraction).

## Layer 4: Applications

Anything that consumes the SDK. The in-tree examples under
`src/examples/` are minimal demonstrations of the public API. Real
deployments typically embed the engine inside a probe, a network
analyser, or a security pipeline.

## Packet processing flow

```
Network packet
    |
    v
packet_process()                           <- core entry point
    |
    v
Protocol classification                    <- walk ETH -> IP -> TCP -> L7
    |
    v
Attribute extraction                       <- run extractors registered for
    |                                          the matched protocols
    v
Session update                             <- update session state, stats
    |
    v
Handler callbacks                          <- packet / attribute / session
                                              callbacks fire in registration order
```

See [Packet-Journey.md](Packet-Journey.md) for the in-depth walkthrough.

## Key abstractions

| Type | Purpose |
|---|---|
| `mmt_handler_t` | Processing context. Owns registered extractions and callbacks. |
| `ipacket_t` | Internal packet representation, including the protocol hierarchy resolved so far. |
| `mmt_session_t` | Per-flow session state shared across packets. |
| `attribute_t` | Extracted attribute value with type and provenance metadata. |
| `proto_hierarchy_t` | Stack path of protocols matched on a single packet. |

## Further reading

- [Protocol-Stack.md](Protocol-Stack.md) — how parsers chain together.
- [Packet-Journey.md](Packet-Journey.md) — packet's path through the engine.
- [MMT-Session.md](MMT-Session.md) — session model.
- [MMT-Attributes.md](MMT-Attributes.md) — attribute model and types.
- [Add-New-Protocol.md](Add-New-Protocol.md) — adding a parser.
- [Memory-Management.md](Memory-Management.md) — allocation conventions.
- [Exported-Symbols.md](Exported-Symbols.md) — auto-generated public symbol surface.
