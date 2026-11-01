---
layout: default
title: "Weak classification heuristics surfaced in Phase 2"
---

# Weak classification heuristics surfaced in Phase 2

*Part of the MMT-DPI Master Improvement Plan — Phase 7 (M9, issue #75).*

The Phase 7 task *"revisit weak heuristics surfaced in Phase 2"*
(`MASTER_IMPROVEMENT_PLAN.md` §3 line 214 — an internal, repo-local planning
document) was deliberately deferred until they were **enumerated**: the heuristics were
previously uncatalogued, and the plan requires this list to exist *before any
behaviour-changing code lands*. This document is that catalogue.

Phase 2 ("memory-safety hardening of packet parsers") audited the transport and
application parsers line by line. Alongside the memory-safety fixes it surfaced
a number of *classification* heuristics that are weak, magic-number-driven, or
carry standing `TODO`s but are **out of scope for a memory-safety change**. They
are recorded here with file/line, what makes them weak, and a recommended next
step. **No code is changed by this document** — each item below is a candidate
for its own measured, fingerprint-gated follow-up.

> How to act on an item: reproduce it under the precision/recall harness
> ([`tools/phase0/ci/check_precision.sh`](https://github.com/montimage-projects/mmt-dpi/blob/main/tools/phase0/ci/check_precision.sh)),
> add a labelled capture that exercises it, then make the change behind a
> default-off flag (as #75 did for port-only demotion) so the golden
> classification fingerprint holds until the gain is proven.

## Catalogue

Every `file:line` link below is checked by
[`scripts/validate-doc-drift.sh`](https://github.com/montimage-projects/mmt-dpi/blob/main/scripts/validate-doc-drift.sh): the cited
line must still hold the code the entry names, so a refactor that moves it fails
the `doc-validators` job until the citation is updated (issue #559). The
statuses were last re-verified against the sources for issue #559.

### H1 — No graded classification confidence — *highest impact*
- **Where:** `classified_proto_t`'s binary `status` field
  ([`plugin_defs.h:133`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_core/public_include/plugin_defs.h#L133)); the address/port fallbacks of
  [`proto_tcp.c:1217`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1217) and [`proto_udp.c:152`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L152).
- **Why weak:** the verdict is Classified / NonClassified with no confidence
  score, so the engine cannot distinguish a payload-proven verdict from a
  port-only guess.
- **Status:** the fallbacks' old `best_effort` TODO ("we should have different
  strategies") was answered by the DPI profiles (issue #87,
  [DPI-Profiles.md](DPI-Profiles.md)): each heuristic lever is now a profile
  toggle on the handler. A graded confidence is still missing.
- **Next step:** introduce a confidence/score concept. This is an ABI change to a
  public struct used across many plugins — large, must be staged. #75's
  payload-confirm predicate (`mmt_payload_confirms_proto`,
  [`mmt_tcpip_plugin_internal.c:488`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/mmt_tcpip_plugin_internal.c#L488)) is a side-effect-free building block
  toward this.

### H2 — Port-only attribution accepted without payload evidence — *mitigated by #75*
- **Where:** `mmt_guess_protocol_by_port_number` in the fallbacks
  ([`proto_tcp.c:1230`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1230), [`proto_udp.c:165`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L165)); the demotion gate
  [`mmt_tcpip_plugin_internal.c:565`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/mmt_tcpip_plugin_internal.c#L565).
- **Why weak:** a port number alone is the weakest signal; services move ports
  and ports get squatted.
- **Status:** addressed by the default-off `enable_port_classify_payload_confirm()`
  flag (issue #75) — see [`External-Attribution.md`](External-Attribution.md).
  Remaining work: extend the confirmation set beyond the current 7 protocols
  (HTTP, TLS, SSH, SMTP, POP, IMAP, FTP) and enable-by-default once
  precision/recall on port-only captures proves the gain.

### H3 — Stale compiled-in IP ranges — *mitigated by #26 / #74 / #75*
- **Where:** `ip_range_intervals[]`
  ([`mmt_tcpip_classif_proto_ip_address.inc:11`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/mmt_tcpip_classif_proto_ip_address.inc#L11), ~10k ranges generated from
  `data/ip_ranges.txt` since #557, included by
  `mmt_tcpip_classif_utils.c`), consulted via `get_proto_id_from_address`
  ([`proto_tcp.c:1226`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1226), [`proto_udp.c:160`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L160)).
- **Why weak:** CDN/cloud allocations drift; compiled-in ranges go stale and
  misattribute.
- **Status:** external `MMT_DPI_IP_RANGES_FILE` (extend/override, IPv4+IPv6,
  read at [`mmt_tcpip_classif_utils.c:570`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/mmt_tcpip_classif_utils.c#L570)) plus the refreshable
  [`data/ip_ranges.cdn.txt`](https://github.com/montimage-projects/mmt-dpi/blob/main/data/ip_ranges.cdn.txt) and
  [`tools/refresh_cdn_ranges.sh`](https://github.com/montimage-projects/mmt-dpi/blob/main/tools/refresh_cdn_ranges.sh) (issue #75).

### H4 — Magic-number classification window
- **Where:** UDP stops classifying past `CFG_CLASSIFICATION_THRESHOLD * 2`
  packets ([`proto_udp.c:126`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L126)) and attempts the address/port fallback only
  within that window ([`proto_udp.c:147`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L147)); TCP gives up on a still-unknown
  flow past the same window ([`proto_tcp.c:1058`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1058), [`proto_tcp.c:1189`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1189)).
- **Why weak:** `CFG_CLASSIFICATION_THRESHOLD` is `20`
  ([`cfg_defaults.h:24`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_core/private_include/cfg_defaults.h#L24)) and the `* 2` factor is an unexplained constant.
  Long flows that only become classifiable after 40 packets are silently
  abandoned.
- **Status:** the TCP/UDP asymmetry this entry first recorded is gone: issue #99
  gave TCP the UDP window, gated on the flow still being unknown so that
  classified flows keep their per-packet path. The constant itself is unchanged.
- **Next step:** document the rationale or make the window configurable; measure
  recall impact of widening it on long-flow captures.

### H5 — `tcp_retransmission == 0` gate on UDP packets
- **Where:** [`proto_udp.c:122`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L122).
- **Why weak:** a TCP-named field is consulted in the UDP path to set
  `MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION`. On UDP the gate is
  always taken: `mmt_connection_tracking` clears the field on every packet
  ([`mmt_tcpip_plugin_internal.h:380`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/mmt_tcpip_plugin_internal.h#L380)) and only the TCP sequence check sets
  it ([`mmt_tcpip_plugin_internal.h:502`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/mmt_tcpip_plugin_internal.h#L502)). The author's "do we need to keep
  this???" TODO was removed by the marker triage (issue #232) without an answer.
- **Next step:** trace which selection-bitmask consumers depend on this bit for
  UDP; drop the `if` (behaviour-neutral) or rename the bit if it is vestigial.

### H6 — GTP forced re-classification special-case
- **Where:** [`proto_tcp.c:1212`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1212)
  — `if (retval.proto_id == PROTO_UNKNOWN || retval.proto_id == PROTO_GTP)`
- **Why weak:** GTP is singled out by id to re-enter the address/port fallback
  path; the reason is undocumented and the pattern does not generalise to other
  tunnelling protocols.
- **Next step:** document why GTP needs this, or generalise to a "tunnel
  carrier" protocol class.

### H7 — `flow == NULL` early return drops UDP classification
- **Where:** [`proto_udp.c:105`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L105) — returns `MMT_CLASSIFY_SKIP`.
- **Why weak:** when connection tracking yields no flow the packet is abandoned
  as unknown; the conditions under which this happens are not characterised.
- **Status:** issue #150 replaced the old `return (PROTO_UNKNOWN)` — a protocol
  id used as a verdict — with the named verdict and dropped its "check this
  out" TODO; the investigation itself is still open.
- **Next step:** determine when `packet->flow` is NULL post-`mmt_connection_tracking`
  and whether stateless attribution is still possible.

### H8 — Speculative `memset` of the flow on SYN — *resolved by #330*
- **Where:** [`proto_tcp.c:1021`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1021), [`proto_tcp.c:1139`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L1139).
- **Why it was flagged:** the author asked whether the `memset` was needed; not
  strictly a *classification* heuristic but surfaced in the same audit.
- **Status:** the marker audit (issue #330) found it redundant on a flow fresh
  from allocation, which is zeroed there, and kept it with that justification
  in a comment: one `memset` per new flow guarantees a clean detection state
  whatever ran on the packet before. This is the "keep with a comment" outcome
  the entry proposed; nothing is left to do.

## Priority

| Item | Theme | Status | Suggested order |
| ---- | ----- | ------ | --------------- |
| H1 | confidence model | open (ABI); profiles landed (#87) | after H2 proven |
| H2 | port-only demotion | flag landed (#75) | enable-by-default once measured |
| H3 | stale IP ranges | data file landed (#75) | ongoing refresh |
| H4 | magic window | open; TCP/UDP symmetric (#99) | measure then tune |
| H5 | UDP retransmission bit | open | low risk cleanup |
| H6 | GTP special-case | open | document first |
| H7 | NULL-flow drop | open; verdict named (#150) | investigate |
| H8 | SYN memset | resolved (#330) | — |

H1–H3 are the substantive accuracy levers and are the M9 focus; H2 and H3 are
addressed (behind a flag / as a data file) by issue #75. H4–H7 are smaller,
mostly-documentation or low-risk cleanups suitable as standalone follow-ups.
