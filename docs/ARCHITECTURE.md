---
layout: default
title: "Architecture"
---

# Architecture

## Overview

MMT-DPI is a modular deep packet inspection library built around a plugin-based architecture. The core engine handles packet processing and session management, while protocol-specific logic is implemented in dynamically loaded plugins.

## Components

### Core Engine (`src/mmt_core/`)

The central component responsible for:
- Packet processing pipeline (`packet_process()`)
- Handler management (`mmt_init_handler()`, `mmt_close_handler()`)
- Attribute registration and extraction
- Session lifecycle management
- Plugin loading and protocol registration

### Protocol Plugins

Protocol implementations are organized into shared libraries loaded at runtime:

| Plugin | Library | Description |
|--------|---------|-------------|
| **mmt_tcpip** | `libmmt_tcpip.so` | TCP/IP stack and application-layer protocols (HTTP, DNS, FTP, QUIC, etc.) |
| **mmt_mobile** | `libmmt_mobile.so` | LTE/5G protocols (NAS, S1AP, NGAP, GTP, Diameter) |
| **mmt_business_app** | `libmmt_business_app.so` | Business application protocols |
| **mmt_security** | `libmmt_security.so` | Security protocol handling |

The LTE NAS decoder does not decrypt ciphered NAS messages (EEA1/EEA2/EEA3):
the per-UE NAS keys cannot be derived from the traffic, and the SDK has no API
for a host to supply them. A ciphered NAS PDU is decoded as plain text only
when its S1 connection's Security Mode Command selected EEA0 (null ciphering),
or, when that command was not seen, if its first octet is the one of a plain
NAS message. So after EEA1/EEA2/EEA3, `s1ap.ue_ipv4` and `s1ap.m_tmsi` are not
read from a ciphered Attach Accept. Background in the
[decision log](DECISIONS.md) (issue #452).

### Build System (`rules/`, `sdk/`)

Platform-specific build rules supporting Linux (GCC, Clang, ICC) and ARM cross-compilation.

## Packet Processing Flow

```
Network Packet
    │
    ▼
┌─────────────────┐
│ packet_process() │  ← Core engine entry point
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Protocol        │  ← Walk the protocol stack (ETH → IP → TCP → HTTP...)
│ Classification  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Attribute       │  ← Extract registered attributes
│ Extraction      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Session Update  │  ← Update session state, statistics
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Handler         │  ← Invoke registered callbacks
│ Callbacks       │    (packet handlers, attribute handlers, session handlers)
└─────────────────┘
```

## Key Abstractions

- **`mmt_handler_t`** - Processing context that holds registered extractions and handlers
- **`ipacket_t`** - Internal packet representation with protocol hierarchy
- **`mmt_session_t`** - Session state tracking across packets
- **`attribute_t`** - Extracted data attribute with type metadata
- **`proto_hierarchy_t`** - Protocol stack path for a packet

## Plugin Interface

Plugins register protocols and their attributes via the core API during initialization. Each protocol provides:
- Classification function (identify the protocol in traffic)
- Attribute extraction functions (parse protocol fields)
- Session management hooks (optional)

See [Add New Protocol](Add-New-Protocol.md) for implementation details.
