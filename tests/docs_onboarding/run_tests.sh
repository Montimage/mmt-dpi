#!/usr/bin/env bash
# run_tests.sh — the documented first run works from an empty directory
# (issue #393, F-UX-001).
#
# docs/_includes/first-example.md (embedded in README.md and rendered on the
# site's landing page) displays the steps that fetch the published
# docs/first-run/hello_packet.c and docs/first-run/traffic.pcap, compile the
# program against an installed SDK and run it, plus the output to expect.
# docs/index.html repeats the steps as copyable hero commands. This suite
# keeps all of it true:
#   [1/5] traffic.pcap is exactly what make_traffic_pcap.py generates, so the
#         fixture stays synthetic and redistributable;
#   [2/5] the displayed source equals the published file and follows the
#         embedding lifecycle with a processing loop; the hero's copy
#         controls copy exactly the displayed commands and stay keyboard
#         accessible (real <button>s, visible focus, reduced motion);
#   [3/5] the SDK builds and installs into a throwaway MMT_BASE prefix;
#   [4/5] the displayed commands, run verbatim in an empty directory, obtain
#         both files, compile and print exactly the displayed output;
#   [5/5] a missing capture exits 1 with a clear message and the fetch hint.
#
# Only two substitutions are made to the displayed commands: the site URL
# https://montimage-projects.github.io/mmt-dpi/ becomes file://$DOCS_SITE_DIR/
# (default: the docs/ source tree, whose files the site serves verbatim — set
# DOCS_SITE_DIR=docs/_site, relative to the repository root, to verify a built
# site artifact instead), and
# /opt/mmt becomes the throwaway prefix. $EXTRA_CFLAGS (sanitizer modes) is
# added to the compile line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FRAGMENT="${REPO_ROOT}/docs/_includes/first-example.md"
INDEX="${REPO_ROOT}/docs/index.html"
SOURCE="${REPO_ROOT}/docs/first-run/hello_packet.c"
FIXTURE="${REPO_ROOT}/docs/first-run/traffic.pcap"
SITE_URL="https://montimage-projects.github.io/mmt-dpi/"
SITE_DIR="${DOCS_SITE_DIR:-docs}"
case "${SITE_DIR}" in /*) ;; *) SITE_DIR="${REPO_ROOT}/${SITE_DIR}" ;; esac  # relative = repo root
SITE_DIR="$(cd "${SITE_DIR}" && pwd)"

ERRORS=0
ok()   { echo "    ✓ $1"; }
fail() { echo "    ✗ $1"; ERRORS=$((ERRORS + 1)); }

for tool in python3 curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "✗ docs_onboarding needs ${tool}" >&2; exit 1; }
done

WORK="$(mktemp -d)"
PREFIX="$(mktemp -d)"
trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT

# Split the fragment's fenced blocks: <lang>.block files in ${WORK}/blocks.
mkdir -p "${WORK}/blocks"
python3 - "$FRAGMENT" "${WORK}/blocks" <<'PYEOF'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
for lang, body in re.findall(r"^```(\w+)\n(.*?)^```$", text, re.S | re.M):
    with open(f"{sys.argv[2]}/{lang}.block", "a", encoding="utf-8") as fh:
        fh.write(body)
PYEOF

# ---------------------------------------------------------------------------
# [1/5] Fixture
# ---------------------------------------------------------------------------
echo "  [1/5] checking the published capture ..."
python3 "${SCRIPT_DIR}/make_traffic_pcap.py" "${WORK}/regen.pcap"
if cmp -s "${WORK}/regen.pcap" "${FIXTURE}"; then
    ok "traffic.pcap is byte-identical to make_traffic_pcap.py output ($(wc -c < "${FIXTURE}") bytes)"
else
    fail "traffic.pcap differs from make_traffic_pcap.py output — regenerate it with: python3 tests/docs_onboarding/make_traffic_pcap.py docs/first-run/traffic.pcap"
fi

# ---------------------------------------------------------------------------
# [2/5] Displayed source, commands and copy controls
# ---------------------------------------------------------------------------
echo "  [2/5] checking the displayed steps against the published files ..."
for lang in bash text c; do
    [ -s "${WORK}/blocks/${lang}.block" ] || { echo "✗ ${FRAGMENT} has no \`\`\`${lang} block" >&2; exit 1; }
done
if cmp -s "${WORK}/blocks/c.block" "${SOURCE}"; then
    ok "first-example.md shows docs/first-run/hello_packet.c in full"
else
    fail "the C block in first-example.md differs from docs/first-run/hello_packet.c"
fi

# Displayed commands, one per line, with backslash continuations joined.
sed -e ':a' -e '/\\$/N; s/[[:space:]]*\\\n[[:space:]]*/ /; ta' \
    "${WORK}/blocks/bash.block" > "${WORK}/commands.txt"
if [ "$(wc -l < "${WORK}/commands.txt")" -eq 3 ] \
   && grep -qxF "curl -fsSL -O ${SITE_URL}first-run/hello_packet.c -O ${SITE_URL}first-run/traffic.pcap" "${WORK}/commands.txt" \
   && grep -qE '^gcc -o hello_packet hello_packet\.c ' "${WORK}/commands.txt" \
   && grep -qxF './hello_packet traffic.pcap' "${WORK}/commands.txt"; then
    ok "three displayed steps: fetch both files, compile, run"
else
    fail "displayed steps are not fetch/compile/run: $(tr '\n' '|' < "${WORK}/commands.txt")"
fi

# Every site URL the fragment names resolves to a published file.
while IFS= read -r url; do
    rel="${url#"${SITE_URL}"}"
    if [ -f "${SITE_DIR}/${rel}" ]; then
        ok "${url} is published (${rel})"
    else
        fail "${url} — no ${rel} under ${SITE_DIR}"
    fi
done < <(grep -oE "${SITE_URL//./\\.}[A-Za-z0-9_./-]+" "${FRAGMENT}" "${SOURCE}" | cut -d: -f2- | sort -u)

# The hero's copy controls copy exactly the displayed commands, and the
# output lines it shows are part of the displayed output.
python3 - "$INDEX" "${WORK}/commands.txt" "${WORK}/blocks/text.block" <<'PYEOF' || ERRORS=$((ERRORS + 1))
import html
import re
import sys
page = open(sys.argv[1], encoding="utf-8").read()
commands = open(sys.argv[2], encoding="utf-8").read().splitlines()
output = open(sys.argv[3], encoding="utf-8").read().splitlines()
bad = 0
def report(ok, msg):
    global bad
    print(f"    {'✓' if ok else '✗'} {msg}")
    bad += 0 if ok else 1

buttons = re.findall(r"<(\w+)([^>]*\bclass=\"copy-btn\"[^>]*)>", page)
report(buttons and all(tag == "button" for tag, _ in buttons),
       f"{len(buttons)} copy controls are native <button> elements (keyboard operable)")
report(all("aria-label=" in attrs for _, attrs in buttons),
       "every copy control has an aria-label naming what it copies")
cmds = [html.unescape(m) for _, attrs in buttons
        for m in re.findall(r'data-cmd="([^"]*)"', attrs)]
first_run = [c for c in cmds if "install.sh" not in c]
report(sorted(first_run) == sorted(commands),
       "hero copy controls copy exactly the displayed fetch/compile/run commands")
shown = [html.unescape(m) for m in re.findall(r'<span class="ok">([^<]*)</span>', page)]
report(shown and all(line in output for line in shown),
       f"hero shows {len(shown)} line(s) of the displayed output")
report(re.search(r"\.copy-btn:focus-visible[^{]*\{[^}]*outline", page, re.S) is not None,
       "copy controls keep a visible focus outline")
report("@media (prefers-reduced-motion: reduce)" in page,
       "reduced-motion preference is honoured")
for rel in ("first-run/hello_packet.c", "first-run/traffic.pcap"):
    report(f'href="{rel}"' in page, f"landing page links {rel} (checked by check-site-links.sh)")
sys.exit(1 if bad else 0)
PYEOF

# Lifecycle order and the processing loop in the published source.
code_line() { grep -nE -- "$1" "${SOURCE}" | grep -vE '^[0-9]+:[[:space:]]*(\*|//|/\*)' | cut -d: -f1 | sed -n "${2}p" || true; }
l_init="$(code_line 'init_extraction\(\)' 1)"
l_handler="$(code_line 'mmt_init_handler\(' 1)"
l_loop="$(code_line 'while \(\(rc = pcap_next_ex\(' 1)"
l_process="$(code_line 'packet_process\(' 1)"
l_close_h="$(code_line 'mmt_close_handler\(' '$')"
l_close_x="$(code_line 'close_extraction\(\)' '$')"
if [ -n "$l_init" ] && [ -n "$l_handler" ] && [ -n "$l_loop" ] && [ -n "$l_process" ] \
   && [ -n "$l_close_h" ] && [ -n "$l_close_x" ] \
   && [ "$l_init" -lt "$l_handler" ] && [ "$l_handler" -lt "$l_loop" ] \
   && [ "$l_loop" -lt "$l_process" ] && [ "$l_process" -lt "$l_close_h" ] \
   && [ "$l_close_h" -lt "$l_close_x" ]; then
    ok "hello_packet.c: init_extraction < mmt_init_handler < pcap loop { packet_process } < mmt_close_handler < close_extraction"
else
    fail "hello_packet.c lifecycle order is wrong or incomplete (lines: ${l_init:-?} ${l_handler:-?} ${l_loop:-?} ${l_process:-?} ${l_close_h:-?} ${l_close_x:-?})"
fi

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ docs_onboarding: ${ERRORS} static check(s) failed" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# [3/5] Build + install into a throwaway prefix
# ---------------------------------------------------------------------------
BUILD_LOG="${WORK}/build.log"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    set -- "BUILD=${SDK_BUILD_PROFILE}"
else
    set --
fi
echo "  [3/5] building + installing SDK into ${PREFIX} ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "$@" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "$@" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

# ---------------------------------------------------------------------------
# [4/5] The displayed steps, from an empty directory
# ---------------------------------------------------------------------------
echo "  [4/5] running the displayed steps in an empty directory ..."
RUN_DIR="${WORK}/empty"
mkdir -p "${RUN_DIR}"
python3 - "${WORK}/commands.txt" "${WORK}/steps.sh" "${SITE_URL}" "file://${SITE_DIR}/" "${PREFIX}" <<'PYEOF'
import sys
src, dst, site_url, local_url, prefix = sys.argv[1:6]
lines = []
for cmd in open(src, encoding="utf-8").read().splitlines():
    cmd = cmd.replace(site_url, local_url).replace("/opt/mmt/", prefix + "/")
    if cmd.startswith("gcc "):
        cmd = '${CC:-gcc} ${EXTRA_CFLAGS:-} ' + cmd[len("gcc "):]
    lines.append(cmd)
open(dst, "w", encoding="utf-8").write("set -e\n" + "\n".join(lines) + "\n")
PYEOF
rc=0
(cd "${RUN_DIR}" && LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" bash "${WORK}/steps.sh") \
    >"${WORK}/out.txt" 2>"${WORK}/err.txt" || rc=$?
if [ "$rc" -eq 0 ] && [ -f "${RUN_DIR}/hello_packet.c" ] && [ -f "${RUN_DIR}/traffic.pcap" ]; then
    ok "displayed steps fetched hello_packet.c + traffic.pcap, compiled and ran (exit 0)"
else
    fail "displayed steps failed (exit ${rc})"
    tail -10 "${WORK}/err.txt" >&2 || true
fi
if [ -s "${WORK}/out.txt" ] && cmp -s "${WORK}/out.txt" "${WORK}/blocks/text.block" \
   && ! grep -q "^hello_packet: " "${WORK}/err.txt"; then
    ok "output matches the displayed output ($(wc -l < "${WORK}/out.txt") lines), no errors reported"
else
    fail "output differs from the displayed output, or the program reported errors:"
    grep "^hello_packet: " "${WORK}/err.txt" >&2 || true
    diff "${WORK}/blocks/text.block" "${WORK}/out.txt" >&2 || true
fi

# ---------------------------------------------------------------------------
# [5/5] Missing fixture
# ---------------------------------------------------------------------------
echo "  [5/5] checking the missing-capture error ..."
rm -f "${RUN_DIR}/traffic.pcap"
rc=0
(cd "${RUN_DIR}" && LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" ./hello_packet traffic.pcap) \
    >"${WORK}/out.txt" 2>"${WORK}/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && [ ! -s "${WORK}/out.txt" ] \
   && grep -qF "hello_packet: cannot open capture 'traffic.pcap'" "${WORK}/err.txt" \
   && grep -qF "curl -fsSLO ${SITE_URL}first-run/traffic.pcap" "${WORK}/err.txt"; then
    ok "missing traffic.pcap exits 1, names the file and how to fetch it"
else
    fail "missing traffic.pcap: expected exit 1 with a clear message, got exit ${rc}"
    cat "${WORK}/err.txt" >&2 || true
fi

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ docs_onboarding: ${ERRORS} check(s) failed" >&2
    exit 1
fi
echo
echo "✓ documented first run verified from an empty directory against an installed SDK (issue #393)"
