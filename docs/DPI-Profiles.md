---
layout: default
title: "DPI profiles — per-level detection toggles"
---

# DPI profiles — per-level detection toggles (issue #87)

MMT-DPI applies a fixed detection strategy out of the box: every registered
checker runs except the defunct-service ones (see [The `legacy`
profile](#the-legacy-profile)), payload inspection walks the protocol path as deep as the
traffic encapsulates, and the hostname/IP-range heuristics are on while the
port-number hint is off. A **DPI profile** bundles the five independent
detection levers (the four of `mmt_dpi_profile_t` below, plus the legacy
lever of [The `legacy` profile](#the-legacy-profile)) into one named setting so a deployment can trade detection
depth for throughput with a single call — or one environment variable —
instead of toggling flags one by one.

> **No behaviour change by default.** A handler that never applies a profile
> (and runs without `MMT_DPI_PROFILE` set) behaves exactly like the
> `default` profile. Profiles are opt-in. Since issue #540 the `default`
> chains no longer run the 38 defunct-service checker registrations; the `legacy` profile
> restores them.

## The levers

The four levers of the public `mmt_dpi_profile_t` struct; the fifth, the
legacy lever (`legacy_classify`), has no struct field and is set only by the
named `legacy` profile, `MMT_DPI_PROFILE=legacy` or a custom profile's sixth
file column (see [The `legacy` profile](#the-legacy-profile)).

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
| `full` | 15 (unlimited) | on | on | on | All four struct levers on, including the port-number hint of last resort. It does **not** enable the legacy lever: the defunct-service checkers stay off under `full` — use `legacy` for them. |
| `legacy` | 15 (unlimited) | on | off | on | `default` plus the defunct-service checkers (issue #540) — the classifier chains as they were before #540, apart from the MSN change below. |

## The `legacy` profile

The TCP and UDP classifier chains (`src/mmt_tcpip/lib/inter_proto_classif_list.def`)
hold 38 registrations (23 TCP, 15 UDP; 35 checkers) of checkers whose
service or client protocol is unequivocally retired — MSN Messenger, Yahoo
Messenger (YMSG), AIM/ICQ (OSCAR), Meebo, Kazaa (FastTrack), iMesh, Pando,
PPStream, Zattoo's P2P client protocol, pcAnywhere, MMS and others. Checkers
of services still live, even when old — Gnutella, NetEase POPO, SopCast,
Kontiki, PPLive/PPTV, WinMX, AppleJuice among them — stay in the default
chains. The full list and the criterion are in [DECISIONS.md](DECISIONS.md) (2026-10-29, #540). They
are `MMT_INTER_PROTO_LEGACY` rows: each keeps its place and weight in its
chain, but `proto_packet_classify_next()` (`src/mmt_core/src/packet_pipeline.c`)
skips it unless the handler's `legacy_classify` lever is set, so the
default chains no longer run them on every unknown flow.

The lever is a fifth one with no field in `mmt_dpi_profile_t` (the public
struct, and the ABI, are unchanged), so only named profiles set it:

- `mmt_apply_dpi_profile_by_name(h, "legacy")` or `MMT_DPI_PROFILE=legacy`;
- a custom profile with a sixth column of `1` (see below).

Applying a named profile without the lever (the other predefined ones, a
custom one whose sixth column is `0` or absent), or any profile struct with
`mmt_apply_dpi_profile()`, turns it off. Like the other levers it affects
only subsequent classification: a flow a legacy checker already classified
keeps dispatching to it.

The MSN checker no longer re-inspects flows already classified as SSL/TLS
(it used to, for up to 100 packets), with or without the `legacy` profile.

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
# <name> <max_depth> <app> <port> <ip-range> [<legacy>]
edge        4 1 0 0
dns-only    3 0 1 0
throughput  2 0 0 0
old-p2p     15 1 0 1 1
```

`#` starts a comment; blank and malformed lines are skipped. Names are
case-insensitive, may not collide with a predefined profile or an
already-loaded name, and values are validated (`max_depth` ≥ 0 — clamped to
`PROTO_PATH_SIZE - 1`; toggles must be 0/1). The optional sixth column
walks the defunct-service checkers (`1`) or not (`0`, the default when it is
omitted). Up to 32 custom profiles may be
registered. Load explicitly with `mmt_load_dpi_profiles_file(path)` or once
at init via `MMT_DPI_PROFILES_FILE`.

### API

```c
mmt_apply_dpi_profile(h, &MMT_DPI_PROFILE_MINIMAL);          /* struct */
mmt_apply_dpi_profile_by_name(h, "balanced");                /* name */
mmt_apply_dpi_profile_by_name(h, "legacy");                  /* + defunct-service checkers */

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
