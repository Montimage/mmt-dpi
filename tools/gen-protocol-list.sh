#!/usr/bin/env bash
#
# gen-protocol-list.sh — regenerate docs/PROTOCOLS.md, the protocol listing
# the landing page's protocol chip links to (issue #247, F-UX-014).
#
# The names come from the single source of truth for protocol registration,
# src/mmt_tcpip/lib/proto_init_list.def — one MMT_PROTO_INIT(init_fn, "name")
# or MMT_PROTO_SIMPLE(id, alias, "name") row per protocol (issue #542) — so
# the published listing can never drift from what the engine actually
# registers. Only rows that start a line are read (issue #559): the file's
# header comment shows both row forms with a "display_name" placeholder, and
# an unanchored match listed that placeholder as a protocol.
#
# Usage: bash tools/gen-protocol-list.sh [OUT]
#   OUT defaults to docs/PROTOCOLS.md; tools/ci/check-protocol-count.sh
#   writes a scratch copy and diffs it with the committed listing.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEF="src/mmt_tcpip/lib/proto_init_list.def"
OUT="${1:-docs/PROTOCOLS.md}"

[ -f "$DEF" ] || { echo "✗ protocol list not found: $DEF" >&2; exit 2; }

names="$(grep -oE '^MMT_PROTO_(INIT\([a-zA-Z0-9_]+|SIMPLE\([a-zA-Z0-9_]+,[[:space:]]*[a-zA-Z0-9_]+),[[:space:]]*"[^"]+"' "$DEF" \
          | sed -E 's/.*"([^"]+)"/\1/' | LC_ALL=C sort -u)"
count="$(printf '%s\n' "$names" | grep -c .)"

{
  cat <<'HDR'
---
layout: default
title: "Protocol coverage"
---

# Protocol coverage

Every protocol initializer registered with the core engine, generated from
[`src/mmt_tcpip/lib/proto_init_list.def`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_tcpip/lib/proto_init_list.def)
by `tools/gen-protocol-list.sh` — do not edit by hand. Plugin protocols
(5G/LTE NAS, S1AP, NGAP, GTPv2, Diameter, DICOM, business-app data) register
through their own plugin entry points on top of this list, so the
landing page's headline count is larger: it is the run-time total of every
installed plugin, which CI measures from the built SDK with
`tools/ci/check-runtime-protocol-count.sh`.

HDR
  printf '**%s registered protocol initializers**\n\n' "$count"
  # three-column table keeps a ~650-entry list skimable
  printf '| | | |\n|---|---|---|\n'
  printf '%s\n' "$names" | awk '
    { c[NR] = $0 }
    END {
      for (i = 1; i <= NR; i += 3) {
        printf "|"
        for (j = 0; j < 3; j++) {
          v = c[i + j]
          printf " %s |", (v == "" ? "" : "`" v "`")
        }
        printf "\n"
      }
    }'
} > "$OUT"

echo "✓ wrote $OUT ($count protocol initializers)"
