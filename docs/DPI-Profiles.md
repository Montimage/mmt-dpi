---
layout: default
title: "DPI profiles — per-level detection toggles"
---

# DPI profiles — per-level detection toggles (issue #87)

MMT-DPI applies a fixed detection strategy out of the box: every registered
checker runs, payload inspection walks the protocol path as deep as the
traffic encapsulates, and the hostname/IP-range heuristics are on while the
port-number hint is off. A **DPI profile** bundles the four independent
detection levers into one named setting so a deployment can trade detection
depth for throughput with a single call — or one environment variable —
instead of toggling flags one by one.

> **No behaviour change by default.** A handler that never applies a profile
> (and runs without `MMT_DPI_PROFILE` set) behaves exactly as before — the
> golden classification fingerprint is unchanged. Profiles are opt-in.

## The four levers

| Lever | Handler flag | What it gates |
| ----- | ------------ | ------------- |
| Deep-level inspection | `classification_max_depth` | Deepest index the classifier may write in the protocol path: 0 = `PROTO_META` only, 1 = link layer (ETH), 2 = network (IP), 3 = transport (TCP/UDP), 4 = first application protocol, 5+ = encapsulated/tunnelled protocols. `PROTO_PATH_SIZE - 1` (15) = unlimited. |
| Application-protocol detection | `hostname_classify` | Protocol attribution from TLS SNI, HTTP `Host` and the hostname fingerprint table (`proto_ssl.c`, `http.c`). |
| Port-based detection | `port_classify` | Well-known-port attribution, consulted only after payload and IP-range classification fail (`proto_tcp.c`, `proto_udp.c`). |
| IP-range detection | `ip_address_classify` | Attribution from the compiled-in or externally-loaded (`MMT_DPI_IP_RANGES_FILE`) IP ranges. |

The depth bound is enforced in two places
(`src/mmt_core/src/packet_pipeline.c`): `proto_packet_classify_next()` skips
the checker walk *and* post-classification once the next path index would
exceed it — that is where the CPU saving comes from — and
`set_classified_proto()` refuses path appends beyond it, so out-of-band
writers (sessionizers, tunnel handlers) honour the same bound. Header
parsing (`pre_classify`) still runs, so transport-level sessions and
attribute extraction keep working under a shallow cap.

## Predefined profiles

| Name | max depth | app | port | ip-range | Use case |
| ---- | --------- | --- | ---- | -------- | -------- |
| `default` | 15 (unlimited) | on | off | on | The stock configuration — applying it restores defaults. |
| `minimal` | 3 (transport) | off | off | off | Maximum throughput: structural classification only, L2–L4 sessions and statistics. |
| `balanced` | 5 | on | off | on | First application layer plus one encapsulation hop (enough for TLS SNI attribution). |
| `full` | 15 (unlimited) | on | on | on | Everything, including the port-number hint of last resort. |

## Selecting a profile

### Environment (no code changes)

```bash
export MMT_DPI_PROFILE=minimal        # applied by mmt_init_handler()
export MMT_DPI_PROFILES_FILE=/etc/mmt/dpi_profiles.txt  # optional custom names
```

An unknown `MMT_DPI_PROFILE` value logs a diagnostic and keeps the built-in
defaults.

### Custom profiles file

One profile per line:

```
# <name> <max_depth> <app> <port> <ip-range>
edge        4 1 0 0
dns-only    3 0 1 0
throughput  2 0 0 0
```

`#` starts a comment; blank and malformed lines are skipped. Names are
case-insensitive, may not collide with a predefined profile or an
already-loaded name, and values are validated (`max_depth` ≥ 0 — clamped to
`PROTO_PATH_SIZE - 1`; toggles must be 0/1). Up to 32 custom profiles may be
registered. Load explicitly with `mmt_load_dpi_profiles_file(path)` or once
at init via `MMT_DPI_PROFILES_FILE`.

### API

```c
mmt_apply_dpi_profile(h, &MMT_DPI_PROFILE_MINIMAL);          /* struct */
mmt_apply_dpi_profile_by_name(h, "balanced");                /* name */

mmt_dpi_profile_t mine = { 6, 1, 0, 1 };                     /* custom */
mmt_apply_dpi_profile(h, &mine);

set_classification_max_depth(h, 4);                          /* depth only */
uint8_t d = get_classification_max_depth(h);
```

Profiles may be applied any time after `mmt_init_handler()`; mid-stream
application affects only subsequent classification — layers already recorded
in existing session paths stay.

## What a shallow cap buys

Classification work scales with how deep the walk goes: skipping the
per-layer checker chains (dozens of `classify_me` probes per packet on the
first packets of a flow) is the dominant saving, ahead of the
hostname/IP-range lookups. `minimal` therefore keeps session tracking,
protocol-path statistics and attribute extraction while dropping every
payload-signature and heuristic pass.

Related configuration: [`External-Attribution.md`](External-Attribution.md)
(external IP ranges and port hints), [`Phase2-Heuristics.md`](Phase2-Heuristics.md)
(why the port/IP heuristics are opt-in hints).
