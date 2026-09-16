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

### H1 — No graded classification confidence (`best_effort`) — *highest impact*
- **Where:** [`proto_tcp.c:662`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L662),
  [`proto_udp.c:97`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L97)
  — `//BW - TODO: We should have different strategies: best_effort = …`
- **Why weak:** `classified_proto_t`
  ([`plugin_defs.h`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_core/public_include/plugin_defs.h)) carries only a
  binary `status` (Classified / NonClassified) and no confidence score, so the
  engine cannot distinguish a payload-proven verdict from a port-only guess.
- **Next step:** introduce a confidence/score concept. This is an ABI change to a
  public struct used across many plugins — large, must be staged. #75's
  payload-confirm predicate (`mmt_payload_confirms_proto`) is a side-effect-free
  building block toward this.

### H2 — Port-only attribution accepted without payload evidence — *mitigated by #75*
- **Where:** [`proto_tcp.c:667-668`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L667),
  [`proto_udp.c:104-105`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L104)
- **Why weak:** a port number alone is the weakest signal; services move ports
  and ports get squatted.
- **Status:** addressed by the default-off `enable_port_classify_payload_confirm()`
  flag (issue #75) — see [`External-Attribution.md`](External-Attribution.md).
  Remaining work: extend the confirmation set beyond the current 7 protocols and
  enable-by-default once precision/recall on port-only captures proves the gain.

### H3 — Stale compiled-in IP ranges — *mitigated by #26 / #74 / #75*
- **Where:** `proto_ip_address[]` in
  [`mmt_tcpip_classif_utils.c`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/mmt_tcpip_classif_utils.c)
  (~10k ranges), consulted via `get_proto_id_from_address`
  ([`proto_tcp.c:665`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L665),
  [`proto_udp.c:101`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L101)).
- **Why weak:** CDN/cloud allocations drift; compiled-in ranges go stale and
  misattribute.
- **Status:** external `MMT_DPI_IP_RANGES_FILE` (extend/override, IPv4+IPv6) plus
  the refreshable [`data/ip_ranges.cdn.txt`](https://github.com/montimage-projects/mmt-dpi/blob/main/data/ip_ranges.cdn.txt) and
  [`tools/refresh_cdn_ranges.sh`](https://github.com/montimage-projects/mmt-dpi/blob/main/tools/refresh_cdn_ranges.sh) (issue #75).

### H4 — Magic-number classification window, asymmetric TCP vs UDP
- **Where:** [`proto_udp.c:71`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L71)
  (`packet_count > CFG_CLASSIFICATION_THRESHOLD * 2` → stop) and
  [`proto_udp.c:92`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L92)
  (`<= CFG_CLASSIFICATION_THRESHOLD * 2` → attempt fallback); TCP
  ([`proto_tcp.c:657`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L657)) uses no
  such packet-count window.
- **Why weak:** `CFG_CLASSIFICATION_THRESHOLD` is `20`
  ([`cfg_defaults.h:24`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_core/private_include/cfg_defaults.h#L24)); the
  `* 2` factor is an unexplained constant and the TCP/UDP asymmetry is
  undocumented. Long flows that only become classifiable after 40 packets are
  silently abandoned on UDP.
- **Next step:** document the rationale or make the window configurable; measure
  recall impact of widening it on long-flow captures.

### H5 — `tcp_retransmission == 0` gate on UDP packets
- **Where:** [`proto_udp.c:67`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L67)
  — `if (packet->tcp_retransmission == 0) { … } //TODO: do we need to keep this???`
- **Why weak:** a TCP-named field is consulted in the UDP path to set
  `MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION`; intent is unclear and
  the author flagged it for review.
- **Next step:** trace which selection-bitmask consumers depend on this bit for
  UDP; remove or rename if it is vestigial.

### H6 — GTP forced re-classification special-case
- **Where:** [`proto_tcp.c:657`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L657)
  — `if (retval.proto_id == PROTO_UNKNOWN || retval.proto_id == PROTO_GTP)`
- **Why weak:** GTP is singled out by id to re-enter the address/port fallback
  path; the reason is undocumented and the pattern does not generalise to other
  tunnelling protocols.
- **Next step:** document why GTP needs this, or generalise to a "tunnel
  carrier" protocol class.

### H7 — `flow == NULL` early return drops UDP classification
- **Where:** [`proto_udp.c:50-51`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_udp.c#L50)
  — `return (PROTO_UNKNOWN); //TODO: check this out`
- **Why weak:** when connection tracking yields no flow the packet is abandoned
  as unknown with a standing `TODO`; the conditions under which this happens are
  not characterised.
- **Next step:** determine when `packet->flow` is NULL post-`mmt_connection_tracking`
  and whether stateless attribution is still possible.

### H8 — Speculative `memset` of the flow on SYN
- **Where:** [`proto_tcp.c:481`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L481),
  [`proto_tcp.c:572`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/protocols/proto_tcp.c#L572)
  — `//BW - TODO: Is this memset needed? the syn should be …`
- **Why weak:** correctness/perf heuristic flagged by the author as possibly
  unnecessary; not strictly a *classification* heuristic but surfaced in the same
  audit and worth resolving.
- **Next step:** confirm whether the flow is already zero-initialised on first
  use; drop the `memset` if redundant (perf), keep with a comment if required.

## Priority

| Item | Theme | Status | Suggested order |
| ---- | ----- | ------ | --------------- |
| H1 | confidence model | open (ABI) | after H2 proven |
| H2 | port-only demotion | flag landed (#75) | enable-by-default once measured |
| H3 | stale IP ranges | data file landed (#75) | ongoing refresh |
| H4 | magic window | open | measure then tune |
| H5 | UDP retransmission bit | open | low risk cleanup |
| H6 | GTP special-case | open | document first |
| H7 | NULL-flow drop | open | investigate |
| H8 | SYN memset | open | low risk cleanup |

H1–H3 are the substantive accuracy levers and are the M9 focus; H2 and H3 are
addressed (behind a flag / as a data file) by issue #75. H4–H8 are smaller,
mostly-documentation or low-risk cleanups suitable as standalone follow-ups.
