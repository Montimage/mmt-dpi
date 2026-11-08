---
layout: default
title: "Protocol Model"
---

# Protocol Model

* TOC
{:toc}

------------------

> ⚠️ This document is incomplete. It was never finalized and contains placeholder
> text (TBD, ???, "blablabla"). The protocol model is fully described in the
> code: see `src/mmt_core/private_include/packet_processing.h:631`
> (`protocol_struct`) and `sdk/include/plugin_defs.h` (plugin interface).

## What is a Protocol

In MMT, a protocol is represented by `protocol_t` (`protocol_struct`):
- **ID**: unique `uint32_t proto_id` (`src/mmt_core/private_include/packet_processing.h:637`)
- **Name**: unique `const char * protocol_name` (`src/mmt_core/private_include/packet_processing.h:638`)
- **Session support**: `int has_session` (`src/mmt_core/private_include/packet_processing.h:634`)
- **Classification**: `mmt_classify_next_t classify_next` (`src/mmt_core/private_include/packet_processing.h:652`)
- **Data analysis**: `mmt_analyser_t data_analyser` (`src/mmt_core/private_include/packet_processing.h:653`)
- **Attributes**: stored in `attributes_map` and `attributes_names_map` (`src/mmt_core/private_include/packet_processing.h:655-656`)

See [Add New Protocol](./Add-New-Protocol.md) for the workflow to register a new protocol.