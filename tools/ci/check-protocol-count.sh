#!/usr/bin/env bash
#
# check-protocol-count.sh — the headline protocol count is quoted identically
# everywhere (issue #248, F-UX-003/F-DOCS-016; helper committed under #190).
#
# The coverage metric contradicted itself across one doc set: the site hero,
# page title and FAQ said 643 protocols while the GitHub front page and the
# site meta description said 200+. The count must come from one source and be
# quoted identically in all five places.
#
# The five checked sites:
#   1. README.md feature claim          (… N+? protocols)
#   2. docs/index.html <title>          (for N protocols)
#   3. docs/index.html meta description (classify N protocols)
#   4. docs/index.html hero/stat        (<div class="num">N</div> protocols)
#   5. docs/index.html FAQ section      (into N protocols)
#
# The listing the landing page's protocol chip opens is a different, smaller
# metric — the TCP/IP plugin's proto_init_list.def rows — so it is checked on
# its own (issue #559, F-DOCS-012; issue #578, F-UX-012):
#   6. docs/PROTOCOLS.md is what tools/gen-protocol-list.sh generates now,
#      and its count equals the list's line-initial MMT_PROTO_INIT/
#      MMT_PROTO_SIMPLE rows (the header comment's example rows excluded;
#      an indented row, which the compiler would still register, fails)
#   7. the chip linking PROTOCOLS.html quotes that same count
#
# Exit codes: 0 = all agree, 1 = disagreement, 2 = helper broken.
#
# Usage: bash tools/ci/check-protocol-count.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

for f in README.md docs/index.html; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

rc=0
python3 - <<'PYEOF' || rc=$?
import re
import sys

readme = open("README.md", encoding="utf-8").read()
site = open("docs/index.html", encoding="utf-8").read()

claims = {}


def record(site_name, text, pattern):
    m = re.search(pattern, text, re.S)
    if m:
        claims[site_name] = int(m.group(1))
        print(f"    {site_name:<28} claims {m.group(1)}")
    else:
        claims[site_name] = None
        print(f"    {site_name:<28} no protocol-count claim found")


record("README feature line", readme,
       r'(\d+)\+?\s*protocols')
record("site <title>", site,
       r'<title>[^<]*?(\d+)\s*protocols')
record("site meta description", site,
       r'<meta name="description"[^>]*?(\d+)[, ]*protocols')
record("site hero stat", site,
       r'<div class="num">\s*(\d+)\s*</div><div class="lbl">\s*protocols')
faq = site[site.find('id="faq"'):] if 'id="faq"' in site else site
record("site FAQ", faq, r'(\d+)\s*protocols')

missing = [k for k, v in claims.items() if v is None]
distinct = {v for v in claims.values() if v is not None}

if len(missing) == len(claims):
    print("✗ no protocol-count claim found anywhere — wrong files?",
          file=sys.stderr)
    sys.exit(2)

if missing:
    print(f"  note: no claim found in: {', '.join(missing)}")

if len(distinct) > 1:
    print(f"✗ protocol-count claims disagree: "
          f"{sorted(distinct)}", file=sys.stderr)
    print("To fix:  generate the count from one source and quote it"
          " identically (issue #248)", file=sys.stderr)
    sys.exit(1)

print(f"✓ protocol count quoted identically: {sorted(distinct)}")
PYEOF
[ "$rc" -eq 2 ] && exit 2

# --- the generated listing and the chip that opens it (6, 7) -----------------
DEF="src/mmt_tcpip/lib/proto_init_list.def"
LISTING="docs/PROTOCOLS.md"
for f in "$DEF" "$LISTING" tools/gen-protocol-list.sh; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

rows="$(grep -cE '^MMT_PROTO_(INIT|SIMPLE)\(' "$DEF" || true)"
listed="$(sed -nE 's/^\*\*([0-9]+) registered protocol initializers\*\*$/\1/p' "$LISTING")"
chip="$(grep -oE 'href="PROTOCOLS\.html"[^>]*>[^<]*' docs/index.html \
        | grep -oE '[0-9]+' | head -n 1 || true)"
printf '    %-28s %s\n' "proto_init_list.def rows" "$rows" \
    "PROTOCOLS.md count" "${listed:-none}" "PROTOCOLS.html chip" "${chip:-none}"

bash tools/gen-protocol-list.sh "$tmp/PROTOCOLS.md" >/dev/null \
    || { echo "✗ tools/gen-protocol-list.sh failed" >&2; exit 2; }
if ! diff -u "$LISTING" "$tmp/PROTOCOLS.md" >"$tmp/listing.diff"; then
    echo "✗ $LISTING is stale — regenerate it: bash tools/gen-protocol-list.sh" >&2
    head -n 20 "$tmp/listing.diff" >&2
    rc=1
fi
indented="$(grep -cE '^[[:space:]]+MMT_PROTO_(INIT|SIMPLE)\(' "$DEF" || true)"
if [ "$indented" -ne 0 ]; then
    echo "✗ $DEF has $indented indented row(s): the generator reads only rows that start a line" >&2
    rc=1
fi
if [ "$listed" != "$rows" ]; then
    echo "✗ $LISTING lists ${listed:-no count}, $DEF has $rows rows" >&2
    rc=1
fi
if [ "$chip" != "$rows" ]; then
    echo "✗ the PROTOCOLS.html chip quotes ${chip:-no count}; the listing it opens has $rows" >&2
    rc=1
fi
[ "$rc" -eq 0 ] && echo "✓ $LISTING is current and the chip quotes its $rows rows"
exit "$rc"
