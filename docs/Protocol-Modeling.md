---
layout: default
title: "Protocol Model"
---

# Protocol Model

[TOC]

------------------

> ⚠️ This document is incomplete. It was never finalized and contains placeholder
> text (TBD, ???, "blablabla"). The protocol model is fully described in the
> code: see `src/mmt_core/private_include/packet_processing.h:509`
> (`protocol_struct`) and `sdk/include/plugin_defs.h` (plugin interface).

## What is a Protocol

In MMT, a protocol is represented by `protocol_t` (`protocol_struct`):
- **ID**: unique `uint32_t proto_id` (`src/mmt_core/private_include/packet_processing.h:515`)
- **Name**: unique `const char * protocol_name` (`src/mmt_core/private_include/packet_processing.h:516`)
- **Session support**: `int has_session` (`src/mmt_core/private_include/packet_processing.h:512`)
- **Classification**: `mmt_classify_next_t classify_next` (`src/mmt_core/private_include/packet_processing.h:530`)
- **Data analysis**: `mmt_analyser_t data_analyser` (`src/mmt_core/private_include/packet_processing.h:531`)
- **Attributes**: stored in `attributes_map` and `attributes_names_map` (`src/mmt_core/private_include/packet_processing.h:533-534`)

See [Add New Protocol](./Add-New-Protocol.md) for the workflow to register a new protocol.