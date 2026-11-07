---
layout: default
title: "Externally-updatable IP-range / port attribution (M9)"
---

# Externally-updatable IP-range / port attribution (M9)

*Part of the MMT-DPI Master Improvement Plan — Phase 7 (M9, issues #26 & #74).*

Historically MMT-DPI shipped ~10,000 IP ranges and a fixed set of L4 ports
**hardcoded** in the C sources (`src/mmt_tcpip/lib/mmt_tcpip_classif_proto_ip_address.inc`,
`src/mmt_tcpip/lib/mmt_tcpip_plugin_internal.c`). Refreshing a stale CDN/cloud range or adding a
port hint meant editing C and rebuilding the library.

Since issue #557 the compiled-in IPv4 ranges come from the versioned data file
[`data/ip_ranges.txt`](https://github.com/Montimage/mmt-dpi/blob/main/data/ip_ranges.txt):
`python3 tools/gen-ip-range-table.py` flattens its prefixes into the const,
sorted array of disjoint intervals the `.inc` holds (one binary search per
address, longest prefix inside nested ranges), and the `core_engine` suite
fails when the committed `.inc` is not the generator's output. Since issue #565
the cloud and CDN part of that file is regenerated from the providers'
published feeds (*Refreshing CDN/cloud ranges* below), with cloud-tenancy and
CDN labels kept apart from first-party applications.

M9 makes this attribution data **externally updatable**. The compiled-in tables
remain the bundled **default/fallback**, and operators can additionally supply
plain-text data files whose entries are merged on top of the built-in tables at
initialization time.

> **No behaviour change by default.** When the environment variables below are
> unset (the default, and what CI uses), nothing extra is loaded and
> classification is byte-identical to the compiled-in baseline. This is gated by
> the golden classification fingerprint in CI.

## IP-range attribution — `MMT_DPI_IP_RANGES_FILE`

```
export MMT_DPI_IP_RANGES_FILE=/etc/mmt/ip_ranges.txt
```

Each line is `<addr>/<prefixlen>  <PROTOCOL>  [override]`:

```
# comments and blank lines are ignored
142.250.0.0/16          GOOGLE
13.32.0.0/15            AMAZON
142.250.0.0/16    9              # numeric protocol id is also accepted (rename-proof)
2606:4700::/32          CLOUDFLARE   # IPv6 ranges are supported (issue #74)
198.51.100.0/24   SSL    override   # 'override' wins over the built-in table
```

* The address is **IPv4** (`A.B.C.D`) or **IPv6** (`x:x:…`, detected by a `:`).
* `prefixlen` must be in `[1, 32]` for IPv4 (it indexes the per-prefix AVL
  trees of the external rules) or `[1, 128]` for IPv6.
* `<PROTOCOL>` is a registered protocol name (resolved via
  `get_protocol_id_by_name`) or a bare numeric protocol id.
* Invalid lines are skipped with a warning.

### Extend vs. override (issue #74)

By default a rule **extends** the attribution tables:

* For **IPv4**, an extend rule is added to per-prefix AVL trees that are
  matched together with the compiled-in table. Lookup is longest-prefix-first,
  so a *more-specific* external rule already wins over a broader built-in
  one — but an extend rule **cannot displace** a built-in entry at the *same*
  prefix+network (the built-in match wins the tie).
* For **IPv6** (which has no compiled-in table) extend rules are simply the
  attribution source, matched longest-prefix-first.

Adding the `override` keyword as the trailing token makes the rule **win over a
compiled-in mapping** (and over any extend rule). Override rules are kept in a
separate set that is consulted *before* the built-in/extend tables. Use this to
*correct* a stale built-in attribution, not just to add new ranges.

> Override is still inert by default: with `MMT_DPI_IP_RANGES_FILE` unset (or a
> file with no `override` rules) classification is byte-identical to the
> compiled-in baseline, as gated by the golden classification fingerprint.

See [`data/ip_ranges.example.txt`](https://github.com/Montimage/mmt-dpi/blob/main/data/ip_ranges.example.txt) (`data/ip_ranges.example.txt`).

### Refreshing CDN/cloud ranges (issues #75, #565)

CDN/cloud allocations change often, so their ranges are regenerated from each
provider's own published, machine-readable feed by
[`tools/refresh_cdn_ranges.sh`](https://github.com/Montimage/mmt-dpi/blob/main/tools/refresh_cdn_ranges.sh):

```
tools/refresh_cdn_ranges.sh               # download every feed, then rebuild
tools/refresh_cdn_ranges.sh --feeds DIR   # rebuild offline from a kept download
git diff data/                            # review, then rerun both phase0 gates
```

The script downloads the feeds into a new empty directory and records, in its
`MANIFEST`, each feed's URL, fetch date (UTC) and sha256. It then runs
[`tools/gen-ip-range-data.py`](https://github.com/Montimage/mmt-dpi/blob/main/tools/gen-ip-range-data.py)
on that directory, which never touches the network and refuses a file whose
sha256 differs from the `MANIFEST`. The builder rewrites:

- the **feed entries** of
  [`data/ip_ranges.txt`](https://github.com/Montimage/mmt-dpi/blob/main/data/ip_ranges.txt),
  the IPv4 prefixes the library compiles in. Its **hand-maintained entries**,
  for providers without a published feed, are kept verbatim. The script then
  regenerates the `.inc` with `tools/gen-ip-range-table.py`.
- [`data/ip_ranges.cdn.txt`](https://github.com/Montimage/mmt-dpi/blob/main/data/ip_ranges.cdn.txt),
  the IPv6 prefixes of the same feeds under the same labels. The
  compiled-in table is IPv4 only, so this file is the IPv6 half; load it with
  `export MMT_DPI_IP_RANGES_FILE=/path/to/ip_ranges.cdn.txt`.

Both files record every feed's URL, fetch date and sha256 next to its
entries. The build and the tests read only the committed files, so they stay
offline and reproducible: the kept download directory, passed back with
`--feeds`, rebuilds both files byte for byte.

| Feed | Label | Covers |
| ---- | ----- | ------ |
| AWS `https://ip-ranges.amazonaws.com/ip-ranges.json` | `CLOUDFRONT` | services `CLOUDFRONT`, `CLOUDFRONT_ORIGIN_FACING` (CDN edge) |
| | `AWS` | every other AWS prefix, minus CloudFront (cloud tenancy) |
| Google `https://www.gstatic.com/ipranges/cloud.json` | `GOOGLE_CLOUD` | Google Cloud customer ranges (cloud tenancy) |
| Google `https://www.gstatic.com/ipranges/goog.json` | `GOOGLE` | Google's own services: `goog.json` minus `cloud.json` |
| Microsoft Azure Service Tags (`ServiceTags_Public_YYYYMMDD.json`, linked from `https://www.microsoft.com/en-us/download/details.aspx?id=56519`) | `AZURE` | service tag `AzureCloud` (cloud tenancy) |
| Cloudflare `https://www.cloudflare.com/ips-v4`, `ips-v6` | `CLOUDFLARE` | CDN edge |
| Fastly `https://api.fastly.com/public-ip-list` | `FASTLY` | CDN edge |

A cloud-tenancy or CDN address therefore gets the cloud or CDN label, never the
first-party application that a customer's service happens to be. An unknown
flow to a CloudFront edge is `cloudfront`, not `amazon`, and one to a GCP VM is
`google_cloud`, not `google`. The verdict is still an IP-range guess, so its
classification method is `ip` (issue #567). The table no longer labels any
prefix `amazon`. Its pre-2017 Google, Amazon, AWS, Azure and Cloudflare
entries were replaced by the feed entries. The providers with no published
feed (Apple, Yahoo, Webex, Kakao, Facebook, Netflix, Twitter, Skype) keep their
May 2017 entries as hand-maintained ones
([DECISIONS.md](https://github.com/Montimage/mmt-dpi/blob/main/docs/DECISIONS.md),
2026-11-02).

IP allocation lists are factual data the providers publish for this purpose,
but **confirm each provider's terms of use before redistributing** the
generated ranges. A relabel is a classification change, so rerun both phase0
gates after a refresh (`tools/phase0/README.md`).

## Port hints — `MMT_DPI_PORT_MAP_FILE`

```
export MMT_DPI_PORT_MAP_FILE=/etc/mmt/port_map.txt
```

Each line is `<tcp|udp>  <port>  <PROTOCOL>  [override]`:

```
tcp 8443 SSL
udp 5353 DNS
tcp 80   HTTP_PROXY  override   # 'override' replaces the built-in port mapping
```

By default these are consulted **only after** the compiled-in port switch
returns no match, so they never override a built-in mapping. A rule tagged
`override` (issue #74) is consulted **before** the switch, so it can replace a
built-in port→protocol mapping.

See [`data/port_map.example.txt`](https://github.com/Montimage/mmt-dpi/blob/main/data/port_map.example.txt) (`data/port_map.example.txt`).

### Port attribution is a hint, not a verdict

Port-based attribution is the **weakest** signal in the pipeline and is already
demoted to a *hint of last resort*:

* Callers (`proto_tcp.c`, `proto_udp.c`) consult the port guess **only after**
  payload-signature classification *and* IP-range classification have failed.
* It is gated behind `enable_port_classify()`, which is **OFF by default**
  (`mmt_init_handler` sets `port_classify = 0`).

Sourcing extra ports from an updatable file keeps that weak signal out of the
compiled-in tables and lets operators refresh it without a rebuild.

### Payload-confirmed port-only demotion (issue #75)

Even with `enable_port_classify()` on, a port number alone is a weak signal: a
service can run on a non-standard port and an unrelated service can squat on a
well-known one. `enable_port_classify_payload_confirm()` tightens this — when
set, a port-based guess is accepted **only if the packet payload carries a
signature consistent with the guessed protocol** (leading-byte checks for HTTP,
TLS/SSL, SSH, SMTP, POP, IMAP, FTP via `mmt_payload_confirms_proto`). An
unconfirmed guess is *demoted*: the protocol stays unknown rather than being
attributed on the port alone.

```c
enable_port_classify(mmt);                  // turn on port-based guessing
enable_port_classify_payload_confirm(mmt);  // require payload confirmation (src/mmt_core/public_include/mmt_core.h:779)
```

> **OFF by default.** `mmt_init_handler` sets
> `port_classify_payload_confirm = 0`, so the bundled behaviour is unchanged
> and the golden classification fingerprint holds. The confirmation set is
> intentionally conservative (a protocol with no signature is treated as
> unconfirmed); measure precision/recall on labelled port-only captures (see
> below) before enabling it in production.

## Threading / lifecycle

Both files are loaded once, single-threaded, during
`init_extraction()` → `init_tcpip_plugin()`, before any worker thread exists,
and are only read afterwards on the hot path. This respects the threading
contract in [`THREADING.md`](THREADING.md) (init-time writers, hot-path
readers). Heap allocations are released by `_free_proto_avltrees()` (IPv4 extend
+ override trees and the IPv6 range list) and `cleanup_tcpip_plugin()` →
`mmt_tcpip_free_external_port_map()` (port hints, extend + override).

`get_proto_id_from_address()` memoises its verdict on the flow, once per
address orientation (issue #557): a flow keeps its two addresses, so the
ranges are looked up at most once per flow direction. Rules are loaded before
any flow exists, so a memoised verdict always reflects them.

## Measuring accuracy — the precision/recall harness (issue #74)

The golden classification fingerprint
([`tools/phase0/ci/check_classification.sh`](https://github.com/Montimage/mmt-dpi/blob/main/tools/phase0/ci/check_classification.sh))
proves *that* per-packet classification decisions do not change, but it is
unlabelled — it cannot say whether a change made classification more or less
*correct*. The Phase 7 precision/recall harness adds ground truth:

* [`tools/phase0/phase0_precision.c`](https://github.com/Montimage/mmt-dpi/blob/main/tools/phase0/phase0_precision.c) —
  given a pcap and the application protocol it is known to carry, counts true
  positives / false positives / no-verdict packets from the classifier's
  deterministic decisions.
* [`tools/phase0/ci/labels.txt`](https://github.com/Montimage/mmt-dpi/blob/main/tools/phase0/ci/labels.txt) — labels for the
  single-application captures in the CI golden subset.
* [`tools/phase0/ci/check_precision.sh`](https://github.com/Montimage/mmt-dpi/blob/main/tools/phase0/ci/check_precision.sh) —
  runs the harness over the labelled set and diffs the micro-averaged
  precision/recall against the committed baseline
  (`tools/phase0/ci/baseline/precision.txt`). Wired into CI as the
  `precision-gate` job, this enforces the Phase 7 acceptance criterion that
  precision/recall **holds or improves**. Refresh the baseline (and explain the
  change) when an improvement is intentional.

This harness is the measurement tool for evaluating behaviour-changing
attribution work (e.g. payload-confirmed port-only demotion, CDN range
refreshes) before it is enabled by default.
