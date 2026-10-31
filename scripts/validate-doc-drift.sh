#!/usr/bin/env bash
# validate-doc-drift.sh — Check-only validation for the drift class issue
# #249 closed (F-DOCS-004/010/013/014/018, F-CLEAN-019).
# Usage: ./validate-doc-drift.sh [--check] [--run-destructive]
#
# What it asserts, one check per recorded finding:
#
#   F-DOCS-004  docs/troubleshooting.md carries a correcting entry whose
#               statement of NDEBUG's semantics matches rules/common.mk
#               (the default build defines -DNDEBUG; NDEBUG=1 suppresses it).
#   F-DOCS-010  DEB_PACKAGE_CHECKLIST.md no longer sits at the root posing as
#               current status; the moved copy under docs/ carries a dated
#               header naming the version it describes (1.7.10) and the
#               library the original report omitted (libmmt_tdicom).
#   F-DOCS-013  every `gcc -o BIN` in docs/Examples.md is followed by run
#               commands that invoke ./BIN — never a different binary.
#   F-DOCS-018  every src/examples/*.c file is named on the page, and the
#               page either compiles each one or states it covers a subset.
#   F-DOCS-006  (issue #581) every Examples.md listing whose compile step
#               names a src/examples file is that file's code, so the one
#               copy tools/ci/compile-doc-listings.sh compiles is the page's.
#   F-DOCS-007  (issue #581) every prototype docs/*.md shows for a public
#               (MMTAPI) function matches src/mmt_core/public_include, as
#               tools/ci/public-prototypes.py normalises both.
#   F-DOCS-014  the unsupported-platform instruction blocks (Homebrew
#               formulas, ARCH=osx/win32/win64 builds, /opt/windows staging)
#               are gone from Compilation-and-Installation-Instructions.md,
#               and docs/DECISIONS.md records the deletion.
#   F-CLEAN-019 tools/ci/vendor-paths.txt lists the vendored sources, each
#               carries a VENDORED banner with a pinned upstream reference,
#               and the clean-code metrics read the list — exclusion by
#               configuration, not convention.
#
# Issue #559 (F-DOCS-010/011/012 of the modernization audit — not the
# F-DOCS-010 above):
#   catalogue   every file:line link of docs/Phase2-Heuristics.md lands on
#               the code its entry names (a needle per entry and file), and
#               every entry H1-H8 carries at least one such link.
#   add-proto   docs/Add-New-Protocol.md states both proto_init_list.def row
#               forms exactly as the list's header comment does.
#   listing     tools/ci/check-protocol-count.sh passes (docs/PROTOCOLS.md
#               current, the landing-page chip quoting its count).
# Issue #578 (F-UX-010..013), the landing page's claims:
#   line rate   no unmeasured "line rate" claim in the site or README; the
#               measured claim that replaces it quotes the bigFlows rows of
#               tools/phase0/baseline/perf/throughput.txt and links them and
#               the instruction-count gate (issue #555).
#   distros     the distro stat is the number of supported distributions in
#               .github/workflows/install-smoke.yml, and both the stat and
#               the platform FAQ link that workflow.
#   plugins     the plugin FAQ names the loader's init symbol and directory
#               variable as src/mmt_core/private_include/plugins_engine.h
#               defines them, and no longer says "drop it in".
#
# Same check-only contract as the other scripts/validate-*.sh: findings are
# reported, the script exits non-zero when any check fails.
#
# Exit codes: 0 = consistent, N = number of failed checks, 2 = broken.

set -euo pipefail

MODE="${1:---check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ERRORS=0

check() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "  ✓ $desc"
    else
        echo "  ✗ $desc"
        ERRORS=$((ERRORS + 1))
    fi
}

if [ "$MODE" = "--run-destructive" ]; then
    echo "Running in destructive mode (not implemented for this script)."
    exit 0
fi

if [ "$MODE" != "--check" ]; then
    echo "Usage: $0 [--check] [--run-destructive]"
    exit 1
fi

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

echo "=== doc-drift validation (issue #249) ==="

# --- F-DOCS-004: troubleshooting log correction -----------------------------
echo ""
echo "-- F-DOCS-004: NDEBUG semantics --"

# The rule file's own statement of the semantics: an `ifdef NDEBUG` block in
# which -DNDEBUG is added only on the else (default) side.
check "rules/common.mk: default build defines -DNDEBUG, NDEBUG=1 suppresses it" \
      "awk '/^ifdef NDEBUG/{f=1} f{print} f&&/^endif/{exit}' rules/common.mk \
          | grep -Eq '^else' \
       && awk '/^ifdef NDEBUG/{f=1} f{print} f&&/^endif/{exit}' rules/common.mk \
          | awk '/^else/{e=1} e&&/-DNDEBUG/{d=1} END{exit !(e&&d)}'"

# The correcting entry lives in the newest dated section of the append-only
# log and must state the suppress semantics against -DNDEBUG.
check "docs/troubleshooting.md carries a correcting NDEBUG entry" \
      "awk '/^## /{sec=\$0} /NDEBUG=1/{if (sec != \"## 2026-07-21\") print}' \
          docs/troubleshooting.md | grep -q 'suppress' \
       && awk '/^## /{sec=\$0} /suppress/{if (sec != \"## 2026-07-21\") print}' \
          docs/troubleshooting.md | grep -q -- '-DNDEBUG'"

# --- F-DOCS-010: DEB_PACKAGE_CHECKLIST.md ------------------------------------
echo ""
echo "-- F-DOCS-010: .deb checklist --"

check "DEB_PACKAGE_CHECKLIST.md is no longer at the repo root" \
      "test ! -f DEB_PACKAGE_CHECKLIST.md"
check "docs/DEB_PACKAGE_CHECKLIST.md exists with Jekyll front matter" \
      "head -4 docs/DEB_PACKAGE_CHECKLIST.md | grep -q 'layout: default'"
check "dated header names the described version (1.7.10)" \
      "sed -n '1,16p' docs/DEB_PACKAGE_CHECKLIST.md | grep -Eq '20[0-9]{2}-[0-9]{2}-[0-9]{2}' \
       && sed -n '1,16p' docs/DEB_PACKAGE_CHECKLIST.md | grep -q '1\.7\.10'"
check "dated header names the omitted library (libmmt_tdicom)" \
      "sed -n '1,16p' docs/DEB_PACKAGE_CHECKLIST.md | grep -q 'libmmt_tdicom'"

# --- F-DOCS-013 / F-DOCS-018: docs/Examples.md --------------------------------
echo ""
echo "-- F-DOCS-013/018: Examples.md --"

if ! python3 - <<'PYEOF'
import glob
import os
import re
import sys

errors = 0

doc = open("docs/Examples.md", encoding="utf-8").read()

# F-DOCS-013: inside ```sh fences, every `gcc -o BIN` sets the expected run
# binary; every `./X` (optionally via sudo) run line must invoke it.
compiled = None
pairs = 0
in_sh = False
for n, line in enumerate(doc.splitlines(), 1):
    if re.match(r"^```\s*sh\s*$", line):
        in_sh = True
        continue
    if in_sh and line.startswith("```"):
        in_sh = False
        continue
    if not in_sh:
        continue
    m = re.search(r"\bgcc\b[^#]*?\s-o\s+([A-Za-z0-9_.-]+)", line)
    if m:
        compiled = m.group(1)
        continue
    m = re.match(r"^\s*(?:sudo\s+)?\./([A-Za-z0-9_.-]+)", line)
    if m:
        pairs += 1
        if compiled is None or m.group(1) != compiled:
            errors += 1
            print(f"  ✗ line {n}: runs './{m.group(1)}' but the compile step "
                  f"produced '{compiled}'")
if pairs == 0:
    errors += 1
    print("  ✗ no compile/run pairs found in docs/Examples.md")
elif errors == 0:
    print(f"  ✓ all {pairs} run command(s) invoke the binary the preceding "
          f"compile step produced")

# F-DOCS-018: every example source is named on the page, and the page either
# compiles each one or says it covers a subset.
examples = sorted(os.path.basename(p)
                  for p in glob.glob("src/examples/*.c"))
if not examples:
    print("  ✗ no src/examples/*.c found", file=sys.stderr)
    sys.exit(2)
unnamed = [e for e in examples if e not in doc]
if unnamed:
    errors += 1
    print(f"  ✗ example source(s) not named in docs/Examples.md: {unnamed}")
else:
    print(f"  ✓ all {len(examples)} src/examples/*.c files are named on the page")
compiled_set = set(re.findall(r"\bgcc\b[^#\n]*?\s-o\s+([A-Za-z0-9_.-]+)", doc))
unwalked = [e[:-2] for e in examples if e[:-2] not in compiled_set]
if unwalked and not re.search(r"subset|not covered|walks through", doc):
    errors += 1
    print(f"  ✗ {unwalked} have no compile step and the page does not state "
          f"it covers a subset")
elif unwalked:
    print(f"  ✓ {len(unwalked)} example(s) without a walkthrough "
          f"({', '.join(unwalked)}) are covered by the page's subset statement")
else:
    print("  ✓ every example has a compile step")

# F-DOCS-006 (issue #581): a listing whose compile step names an example
# file is that file's code, from the first line after its header comment —
# one copy, compiled by tools/ci/compile-doc-listings.sh.
def example_body(path):
    lines = open(path, encoding="utf-8").read().split("\n")
    i = 0
    if lines and lines[0].lstrip().startswith("/*"):
        while i < len(lines) and "*/" not in lines[i]:
            i += 1
        i += 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    return "\n".join(l.rstrip() for l in lines[i:]).rstrip()

synced = 0
listed = set()
for m in re.finditer(r"^```c\n(.*?)^```\n", doc, re.S | re.M):
    rest = doc[m.end():]
    nxt = re.search(r"^```c\s*$", rest, re.M)
    g = re.search(r"\bgcc\b[^#\n]*?\s-o\s+([A-Za-z0-9_.-]+)",
                  rest[:nxt.start()] if nxt else rest)
    line = doc.count("\n", 0, m.start()) + 2
    if not g or not os.path.isfile(f"src/examples/{g.group(1)}.c"):
        continue
    listed.add(g.group(1))
    listing = "\n".join(l.rstrip() for l in m.group(1).split("\n")).rstrip()
    if listing != example_body(f"src/examples/{g.group(1)}.c"):
        errors += 1
        print(f"  ✗ line {line}: listing differs from src/examples/{g.group(1)}.c "
              "(copy the file's code after its header comment)")
    else:
        synced += 1
# Every compile step that names an example must follow its listing: a
# listing retagged or dropped would otherwise leave both gates unnoticed.
stepped = set(e[:-2] for e in examples) & compiled_set
for name in sorted(stepped - listed):
    errors += 1
    print(f"  ✗ the page compiles {name} but shows no ```c listing of "
          f"src/examples/{name}.c before that step")
if synced and errors == 0:
    print(f"  ✓ all {synced} listing(s) are the code of the example they compile")

sys.exit(errors)
PYEOF
then
    ERRORS=$((ERRORS + 1))
fi

# --- F-DOCS-007: API prototypes match the public headers (#581) -------------
echo ""
echo "-- F-DOCS-007: API prototypes vs src/mmt_core/public_include --"

# Every declaration a page shows for an MMTAPI function must be the header's,
# after normalisation (tools/ci/public-prototypes.py). DECISIONS.md is an
# append-only record, so it may quote a signature as it once was.
proto_docs=()
for d in docs/*.md; do
    [ "$d" = docs/DECISIONS.md ] || proto_docs+=("$d")
done
proto_rc=0
proto_out="$(python3 tools/ci/public-prototypes.py --check "${proto_docs[@]}" 2>&1)" || proto_rc=$?
[ -n "$proto_out" ] && printf '%s\n' "$proto_out" | sed 's/^/    /'
[ "$proto_rc" -le 1 ] || { echo "✗ tools/ci/public-prototypes.py is broken (exit $proto_rc)" >&2; exit 2; }
check "every public prototype in docs/*.md matches src/mmt_core/public_include" \
      "[ $proto_rc -eq 0 ]"

# --- F-DOCS-014: unsupported-platform sections -------------------------------
echo ""
echo "-- F-DOCS-014: macOS/Windows sections --"

check "no Homebrew install instructions remain" \
      "! grep -Eq 'brew install|Hombrew|libpth-dev' docs/Compilation-and-Installation-Instructions.md"
check "no ARCH=osx/win build instructions remain" \
      "! grep -Eq 'make.*ARCH=(osx|win32|win64)|mingw|/opt/windows' docs/Compilation-and-Installation-Instructions.md"
# `grep -c` (not `grep -q`) must consume the producer's whole stream: under
# `set -o pipefail`, `grep -q` exits on the first match and the producer dies
# on SIGPIPE (exit 141), which made this check flaky once DECISIONS.md grew
# past the match point.
check "docs/DECISIONS.md records the deletion" \
      "awk '/^## 2026-09-16/{f=1} f' docs/DECISIONS.md | grep -c '#249' | grep -qv '^0$' \
       && awk '/^## 2026-09-16/{f=1} f' docs/DECISIONS.md | grep -ci 'homebrew' | grep -qv '^0$'"

# --- F-CLEAN-019: vendored-source configuration ------------------------------
echo ""
echo "-- F-CLEAN-019: vendored sources --"

# shellcheck source=tools/ci/vendor-paths-lib.sh
. "$ROOT/tools/ci/vendor-paths-lib.sh"
check "tools/ci/vendor-paths.txt exists" "test -f $VENDOR_LIST"
check "vendor-paths.txt carries a pinned upstream reference" \
      "grep -Eq 'nodejs/llhttp.*v9\.4\.3|v9\.4\.3.*nodejs/llhttp' $VENDOR_LIST"

vendored_ok=1
vendor_paths_load "$VENDOR_LIST" || vendored_ok=0
for p in "${VENDOR_PATHS[@]}"; do
    if [ ! -f "$p" ]; then
        echo "  ✗ vendored path listed but missing: $p"
        vendored_ok=0
        continue
    fi
    if ! head -40 "$p" | grep -q 'VENDORED'; then
        echo "  ✗ $p carries no VENDORED banner in its first 40 lines"
        vendored_ok=0
    elif ! head -40 "$p" | grep -q 'v9\.4\.3'; then
        echo "  ✗ $p banner names no pinned upstream reference"
        vendored_ok=0
    fi
done
[ "$vendored_ok" -eq 1 ] && echo "  ✓ every listed vendored file exists and carries a pinned VENDORED banner" \
    || ERRORS=$((ERRORS + 1))

for s in tools/ci/report-function-shape.sh tools/ci/lint-markers.sh \
         tools/ci/lint-commented-code.sh tools/ci/lint-packet-path-io.sh \
         tools/ci/count-init-wrappers.sh tools/ci/run-cppcheck.sh; do
    check "$s excludes vendored sources via $VENDOR_LIST" \
          "grep -q 'vendor-paths.txt' $s \
           && grep -q '^\. \"\$ROOT/tools/ci/vendor-paths-lib\.sh\"' $s"
done

# --- #559: heuristics catalogue, add-protocol guide, protocol listing --------
echo ""
echo "-- #559: heuristics catalogue, add-protocol guide, listing --"

# One needle list per (entry, file): each link of the entry into that file
# must land on a line holding one of them, and each needle must be hit by a
# link. Moving code means updating the line numbers in the doc only; removing
# or changing the code an entry describes fails here until the entry is
# re-verified.
cite_rc=0
cite_out="$(python3 - <<'PYEOF' 2>&1
import os
import re
import sys

DOC = "docs/Phase2-Heuristics.md"
BASE = "https://github.com/montimage-projects/mmt-dpi/blob/main/"
NEEDLES = {
    ("H1", "plugin_defs.h"): ["uint16_t status; /**< the status of the classified protocol"],
    ("H1", "proto_tcp.c"): ['Issue #87: the "different strategies"'],
    ("H1", "proto_udp.c"): ['Issue #87: the "different strategies"'],
    ("H1", "mmt_tcpip_plugin_internal.c"): ["int mmt_payload_confirms_proto("],
    ("H2", "proto_tcp.c"): ["mmt_guess_protocol_by_port_number(ipacket)"],
    ("H2", "proto_udp.c"): ["mmt_guess_protocol_by_port_number(ipacket)"],
    ("H2", "mmt_tcpip_plugin_internal.c"): ["port_classify_payload_confirm != 0"],
    ("H3", "mmt_tcpip_classif_proto_ip_address.inc"): ["static const ip_range_interval_t ip_range_intervals[IP_RANGE_INTERVAL_COUNT] = {"],
    ("H3", "proto_tcp.c"): ["get_proto_id_from_address(ipacket)"],
    ("H3", "proto_udp.c"): ["get_proto_id_from_address(ipacket)"],
    ("H3", "mmt_tcpip_classif_utils.c"): ['getenv("MMT_DPI_IP_RANGES_FILE")'],
    ("H4", "proto_udp.c"): ["packet_count > (CFG_CLASSIFICATION_THRESHOLD * 2)",
                            "packet_count <= (CFG_CLASSIFICATION_THRESHOLD * 2)"],
    ("H4", "proto_tcp.c"): ["packet_count > (CFG_CLASSIFICATION_THRESHOLD * 2)"],
    ("H4", "cfg_defaults.h"): ["#define CFG_CLASSIFICATION_THRESHOLD     20"],
    ("H5", "proto_udp.c"): ["if (packet->tcp_retransmission == 0)"],
    ("H5", "mmt_tcpip_plugin_internal.h"): ["packet->tcp_retransmission = 0;",
                                            "packet->tcp_retransmission = 1;"],
    ("H6", "proto_tcp.c"): ["retval.proto_id == PROTO_GTP"],
    ("H7", "proto_udp.c"): ["packet->flow == NULL && packet->udp != NULL"],
    ("H8", "proto_tcp.c"): ["memset(packet->flow, 0, sizeof (*(packet->flow)));"],
}
LINK = re.compile(r"\[`([^`:]+):(\d+)`\]\(([^)#]+)#L(\d+)\)")
ANY_LINE_LINK = re.compile(r"\]\(([^)]*#L[^)]*)\)")

text = open(DOC, encoding="utf-8").read()
entries = re.split(r"^### (H\d)\b", text, flags=re.M)
bad = 0
hit = set()
seen_entries = set()
for i in range(1, len(entries), 2):
    entry, body = entries[i], entries[i + 1]
    checked = {m.group(0) for m in LINK.finditer(body)}
    for m in ANY_LINE_LINK.finditer(body):
        start = body.rfind("[", 0, m.start())
        if body[start:m.end()] not in checked:
            print(f"✗ {entry}: unchecked citation form {body[start:m.end()]!r} "
                  "(cite one line as [`file:N`](...#LN))")
            bad += 1
    for name, line, url, anchor in LINK.findall(body):
        where = f"{entry} {name}:{line}"
        if line != anchor or not url.startswith(BASE):
            print(f"✗ {where}: link text and target disagree ({url}#L{anchor})")
            bad += 1
            continue
        path = url[len(BASE):]
        if os.path.basename(path) != name or not os.path.isfile(path):
            print(f"✗ {where}: {path} is not the cited file")
            bad += 1
            continue
        needles = NEEDLES.get((entry, name))
        if needles is None:
            print(f"✗ {where}: no needle recorded for this entry and file")
            bad += 1
            continue
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        n = int(line)
        src = lines[n - 1] if 0 < n <= len(lines) else ""
        found = [x for x in needles if x in src]
        if not found:
            print(f"✗ {where}: line no longer holds {needles!r}: {src.strip()!r}")
            bad += 1
            continue
        hit.update((entry, name, x) for x in found)
        seen_entries.add(entry)
for (entry, name), needles in NEEDLES.items():
    for x in needles:
        if (entry, name, x) not in hit:
            print(f"✗ {entry} {name}: no link lands on {x!r}")
            bad += 1
for entry in (f"H{k}" for k in range(1, 9)):
    if entry not in seen_entries:
        print(f"✗ {entry}: no checked file:line citation")
        bad += 1
sys.exit(1 if bad else 0)
PYEOF
)" || cite_rc=$?
[ -n "$cite_out" ] && printf '%s\n' "$cite_out" | sed 's/^/    /'
check "docs/Phase2-Heuristics.md: every H1-H8 file:line link lands on the code it names" \
      "[ $cite_rc -eq 0 ]"

DEF=src/mmt_tcpip/lib/proto_init_list.def
for form in 'MMT_PROTO_INIT(init_function, "display_name")' \
            'MMT_PROTO_SIMPLE(PROTO_ID, PROTO_ID_ALIAS, "display_name")'; do
    check "docs/Add-New-Protocol.md states the row form $form as $DEF does" \
          "grep -qF '$form' $DEF && grep -qF '$form' docs/Add-New-Protocol.md"
done
check "docs/Add-New-Protocol.md says to regenerate the listing" \
      "grep -qF 'bash tools/gen-protocol-list.sh' docs/Add-New-Protocol.md"
check "docs/PROTOCOLS.md lists no header-comment placeholder" \
      "! grep -qF 'display_name' docs/PROTOCOLS.md"
check "tools/ci/check-protocol-count.sh passes (listing current, chip agrees)" \
      "bash tools/ci/check-protocol-count.sh"

# --- #578: landing-page claims ------------------------------------------------
echo ""
echo "-- #578: landing-page claims --"

SMOKE_URL='https://github.com/montimage-projects/mmt-dpi/actions/workflows/install-smoke.yml'
check "no unmeasured \"line rate\" claim in docs/index.html, docs/_config.yml or README.md" \
      "test -f docs/index.html && test -f docs/_config.yml && test -f README.md \
       && ! grep -qiE 'line[- ]?rate' docs/index.html docs/_config.yml README.md"

perf_rc=0
perf_out="$(python3 - <<'PYEOF' 2>&1
import re
import sys

BASE = "https://github.com/montimage-projects/mmt-dpi/"
pps = {}
for row in open("tools/phase0/baseline/perf/throughput.txt", encoding="utf-8"):
    f = row.rstrip("\n").split("\t")
    if len(f) > 6 and f[0] == "bigFlows.pcap":
        pps[f[1]] = int(f[6])
if "bare" not in pps or "attrs8" not in pps:
    print("✗ throughput.txt has no bigFlows.pcap bare/attrs8 rows")
    sys.exit(1)
site = open("docs/index.html", encoding="utf-8").read()
faq = re.search(r"<summary>What exactly is MMT-DPI\?</summary>\s*<p>(.*?)</p>", site, re.S)
faq = faq.group(1) if faq else ""
want = [f"about {pps['bare'] / 1e6:.1f} million packets per second",
        f"{pps['attrs8'] / 1e6:.1f} million with eight fetched",
        f'href="{BASE}blob/main/tools/phase0/baseline/perf/throughput.txt"',
        f'href="{BASE}actions/workflows/phase0-baseline.yml"']
missing = [w for w in want if w not in faq]
for w in missing:
    print(f"✗ the 'What exactly' FAQ lacks {w!r}")
sys.exit(1 if missing else 0)
PYEOF
)" || perf_rc=$?
[ -n "$perf_out" ] && printf '%s\n' "$perf_out" | sed 's/^/    /'
check "the performance claim quotes tools/phase0/baseline/perf/throughput.txt and links it and the instruction gate" \
      "[ $perf_rc -eq 0 ]"

distro_rc=0
distro_out="$(python3 - "$SMOKE_URL" <<'PYEOF' 2>&1
import re
import sys

url = sys.argv[1]
wf = open(".github/workflows/install-smoke.yml", encoding="utf-8").read()
legs = re.findall(r"\{\s*name:\s*([A-Za-z0-9.-]+),\s*tier:\s*supported\b", wf)
distros = sorted({leg.split("-")[0] for leg in legs})
site = open("docs/index.html", encoding="utf-8").read()
m = re.search(r'<div class="num">(\d+)</div><div class="lbl"><a href="([^"]+)">'
              r'Linux distros smoke-tested</a>', site)
if not distros:
    print("✗ no supported leg found in install-smoke.yml")
    sys.exit(1)
if not m:
    print("✗ docs/index.html has no linked 'Linux distros smoke-tested' stat")
    sys.exit(1)
if int(m.group(1)) != len(distros) or m.group(2) != url:
    print(f"✗ stat says {m.group(1)} -> {m.group(2)}; the workflow's supported "
          f"distributions are {len(distros)}: {', '.join(distros)}")
    sys.exit(1)
print(f"supported distributions ({len(distros)}): {', '.join(distros)}")
PYEOF
)" || distro_rc=$?
[ -n "$distro_out" ] && printf '%s\n' "$distro_out" | sed 's/^/    /'
check "the distro stat counts install-smoke.yml's supported distributions and links it" \
      "[ $distro_rc -eq 0 ]"
check "the platform FAQ links the install smoke workflow" \
      "grep -F 'smoke-tested in CI' docs/index.html | grep -qF 'href=\"$SMOKE_URL\"'"

ENGINE_H=src/mmt_core/private_include/plugins_engine.h
init_sym="$(sed -nE 's/^#define PLUGIN_INIT_FUNCTION_NAME "([^"]+)".*/\1/p' "$ENGINE_H")"
dir_env="$(sed -nE 's/^#define PLUGINS_DIR_ENV "([^"]+)".*/\1/p' "$ENGINE_H")"
plugin_faq="$(grep -F 'Adding New Protocols' docs/index.html || true)"
faq_loader_rc=0
{ [ -n "$init_sym" ] && [ -n "$dir_env" ] \
  && grep -qF "<code>$init_sym()</code>" <<<"$plugin_faq" \
  && grep -qF "<code>$dir_env</code>" <<<"$plugin_faq"; } || faq_loader_rc=1
faq_drop_rc=0
grep -qi 'drop it in' <<<"$plugin_faq" && faq_drop_rc=1
check "the plugin FAQ names the loader's init symbol (${init_sym:-?}) and directory variable (${dir_env:-?})" \
      "[ $faq_loader_rc -eq 0 ]"
check "the plugin FAQ no longer says \"drop it in\"" "[ $faq_drop_rc -eq 0 ]"

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
