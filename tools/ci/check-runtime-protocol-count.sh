#!/usr/bin/env bash
#
# check-runtime-protocol-count.sh — the protocol/attribute counts quoted in
# the docs must equal what the built SDK actually registers (issue #248,
# F-UX-003/F-DOCS-016).
#
# tools/ci/check-protocol-count.sh proves the five public claims agree with
# each other; this helper proves they agree with reality. It compiles
# src/examples/mmt_export_info.c against the installed SDK, runs it with the
# full plugin set loaded, then compares the printed totals with the numbers
# quoted in README.md, docs/index.html and docs/_config.yml — so the public
# figure is derived from the engine, not asserted twice by hand.
#
# Prerequisites: the SDK built and installed —
#   sudo make -C sdk install                      # default prefix /opt/mmt
#   make -C sdk install MMT_BASE=$PWD/local_install  # or a local prefix
# MMT_BASE may be overridden in the environment to match a non-default
# prefix. The enumerator is run from a scratch directory whose plugins/ is
# populated with every installed plugin .so, which is what
# plugins_engine.h's loader consults first — so the count is the full
# core+plugins figure a real deployment reports.
#
# Exit codes: 0 = quoted counts match the SDK, 1 = mismatch,
#             2 = prerequisite missing / helper broken.
#
# Usage: [MMT_BASE=/opt/mmt] bash tools/ci/check-runtime-protocol-count.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MMT_BASE="${MMT_BASE:-/opt/mmt}"
MMT_DPI="$MMT_BASE/dpi"
MMT_INC="$MMT_DPI/include"
MMT_LIB="$MMT_DPI/lib"
MMT_PLUGINS="$MMT_BASE/plugins"

for f in README.md docs/index.html docs/_config.yml src/examples/mmt_export_info.c; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
for d in "$MMT_INC" "$MMT_LIB" "$MMT_PLUGINS"; do
    [ -d "$d" ] || {
        echo "✗ SDK not installed at MMT_BASE=$MMT_BASE (missing $d)." >&2
        echo "  Run 'make -C sdk install' (sudo for the default prefix)," >&2
        echo "  or 'make -C sdk install MMT_BASE=<prefix>' and export MMT_BASE." >&2
        exit 2
    }
done
command -v cc >/dev/null 2>&1 || { echo "✗ a C compiler is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Compile the bundled exporter against the installed prefix.
cc -O2 -o "$tmpdir/mmt_export_info" src/examples/mmt_export_info.c \
    -I"$MMT_INC" -L"$MMT_LIB" -Wl,-rpath,"$MMT_LIB" -lmmt_core -ldl \
    || { echo "✗ mmt_export_info.c failed to compile against $MMT_INC" >&2; exit 2; }

# Stage every installed plugin under a scratch plugins/ — the loader checks
# the CWD-local plugins/ before PLUGINS_REPOSITORY_OPT, so this also covers
# SDKs built with a non-default MMT_BASE.
mkdir -p "$tmpdir/plugins"
shopt -s nullglob
plugins=("$MMT_PLUGINS"/*.so)
[ ${#plugins[@]} -gt 0 ] || { echo "✗ no plugin .so under $MMT_PLUGINS" >&2; exit 2; }
for so in "${plugins[@]}"; do ln -s "$(readlink -f "$so")" "$tmpdir/plugins/"; done

( cd "$tmpdir" && ./mmt_export_info ) > "$tmpdir/export.csv" \
    || { echo "✗ mmt_export_info failed to run" >&2; exit 2; }

export EXPORT_CSV="$tmpdir/export.csv"
python3 - <<'PYEOF'
import os
import re
import sys

csv = open(os.environ["EXPORT_CSV"], encoding="utf-8").read()

def runtime(label):
    m = re.search(rf"-1,{re.escape(label)},(\d+)", csv)
    if not m:
        print(f"✗ enumerator output lacks '{label}'", file=sys.stderr)
        sys.exit(2)
    return int(m.group(1))

rt_proto = runtime("Number of protocols")
rt_attr = runtime("Number of attributes (all)")
print(f"    SDK registers: {rt_proto} protocols, {rt_attr} attribute registrations")

readme = open("README.md", encoding="utf-8").read()
site = open("docs/index.html", encoding="utf-8").read()
config = open("docs/_config.yml", encoding="utf-8").read()

errors = 0

def check(name, text, pattern, expect):
    global errors
    m = re.search(pattern, text, re.S)
    if not m:
        print(f"  ✗ {name:<34} no count claim matched — drift?")
        errors += 1
        return
    got = int(m.group(1).replace(",", ""))
    if got == expect:
        print(f"  ✓ {name:<34} {got} == runtime")
    else:
        print(f"  ✗ {name:<34} quotes {got}, SDK registers {expect}")
        errors += 1

# Protocol count: README feature line, site title/meta/hero/FAQ, config.
check("README feature line", readme, r"(\d+)\+?\s*protocols", rt_proto)
check("site <title>", site, r"<title>[^<]*?(\d+)\s*protocols", rt_proto)
check("site meta description", site,
      r'<meta name="description"[^>]*?(\d+)[, ]*protocols', rt_proto)
check("site hero stat", site,
      r'<div class="num">\s*(\d+)\s*</div><div class="lbl">\s*protocols', rt_proto)
faq = site[site.find('id="faq"'):] if 'id="faq"' in site else site
check("site FAQ", faq, r"(\d+)\s*protocols", rt_proto)
check("_config.yml description", config, r"(\d+)\+?\s*protocol", rt_proto)

# Attribute count: only the site quotes one (meta description, hero sub,
# stats strip, FAQ, final CTA) — assert the first occurrence is the runtime
# "attributes (all)" figure; the inter-claim agreement is check-site-link
# territory via the count itself appearing consistently.
check("site meta description (attrs)", site,
      r'<meta name="description"[^>]*?(\d[\d,]*)\s*(?:named|typed)?\s*attributes',
      rt_attr)
check("site stats strip (attrs)", site,
      r'<div class="num">\s*(\d[\d,]*)\s*</div><div class="lbl">\s*named attributes',
      rt_attr)

if errors:
    print(f"✗ {errors} quoted count(s) disagree with the built SDK "
          f"({rt_proto} protocols / {rt_attr} attributes)", file=sys.stderr)
    sys.exit(1)
print(f"✓ all quoted counts match the built SDK: "
      f"{rt_proto} protocols, {rt_attr} attributes")
PYEOF
