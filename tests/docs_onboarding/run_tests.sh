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
#   [1/6] traffic.pcap is exactly what make_traffic_pcap.py generates, so the
#         fixture stays synthetic and redistributable;
#   [2/6] the displayed source equals the published file and follows the
#         embedding lifecycle with a processing loop; the hero's copy
#         controls copy exactly the displayed commands and stay keyboard
#         accessible (real <button>s, visible focus, reduced motion), and
#         its install control copies the quick start's hero-install command;
#   [3/6] every install command docs/_includes/quick-start.md displays
#         belongs to a known route (issue #577): the bootstrap and source
#         installer commands are exactly the ones the bootstrap-smoke and
#         install-smoke workflows run before this same first run
#         (tools/ci/smoke-bootstrap.sh, tools/ci/smoke-install.sh), the
#         bootstrap's own usage names them, and each source-installer line
#         runs from an empty directory with --dry-run added (the installer
#         fetched from this checkout), exits 0, shows the plan its options
#         ask for and leaves the directory empty;
#   [4/6] the SDK builds and installs into a throwaway MMT_BASE prefix;
#   [5/6] the displayed commands, run verbatim in an empty directory, obtain
#         both files, compile and print exactly the displayed output;
#   [6/6] a missing capture exits 1 with a clear message; the fetch hint is
#         given for the sample capture only.
#
# Only two substitutions are made to the displayed commands: the site URL
# https://montimage-projects.github.io/mmt-dpi/ becomes file://$DOCS_SITE_DIR/
# (default: the docs/ source tree, whose files the site serves verbatim — set
# DOCS_SITE_DIR=docs/_site, relative to the repository root, to verify a built
# site artifact instead; CI does, in the verify-helpers job, issue #396), and
# /opt/mmt becomes the throwaway prefix. $EXTRA_CFLAGS (sanitizer modes) is
# added to the compile line. The landing page checked in [2/6] is the one
# under $DOCS_SITE_DIR, so a built site is checked as rendered.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FRAGMENT="${REPO_ROOT}/docs/_includes/first-example.md"
QUICK_START="${REPO_ROOT}/docs/_includes/quick-start.md"
SOURCE="${REPO_ROOT}/docs/first-run/hello_packet.c"
FIXTURE="${REPO_ROOT}/docs/first-run/traffic.pcap"
SITE_URL="https://montimage-projects.github.io/mmt-dpi/"
SITE_DIR="${DOCS_SITE_DIR:-docs}"
case "${SITE_DIR}" in /*) ;; *) SITE_DIR="${REPO_ROOT}/${SITE_DIR}" ;; esac  # relative = repo root
SITE_DIR="$(cd "${SITE_DIR}" && pwd)"
INDEX="${SITE_DIR}/index.html"

ERRORS=0
ok()   { echo "    ✓ $1"; }
fail() { echo "    ✗ $1"; ERRORS=$((ERRORS + 1)); }

for tool in python3 curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "✗ docs_onboarding needs ${tool}" >&2; exit 1; }
done

WORK="$(mktemp -d)"
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    # tests/run_all_tests.sh built and installed it once (issue #654).
    PREFIX="${MMT_PREFIX:-}"
    trap 'rm -rf "${WORK}"' EXIT
else
    PREFIX="$(mktemp -d)"
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
fi

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
# [1/6] Fixture
# ---------------------------------------------------------------------------
echo "  [1/6] checking the published capture ..."
python3 "${SCRIPT_DIR}/make_traffic_pcap.py" "${WORK}/regen.pcap"
if cmp -s "${WORK}/regen.pcap" "${FIXTURE}"; then
    ok "traffic.pcap is byte-identical to make_traffic_pcap.py output ($(wc -c < "${FIXTURE}") bytes)"
else
    fail "traffic.pcap differs from make_traffic_pcap.py output — regenerate it with: python3 tests/docs_onboarding/make_traffic_pcap.py docs/first-run/traffic.pcap"
fi

# ---------------------------------------------------------------------------
# [2/6] Displayed source, commands and copy controls
# ---------------------------------------------------------------------------
echo "  [2/6] checking the displayed steps against the published files ..."
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
    if [ -f "${SITE_DIR}/${rel}" ] && cmp -s "${SITE_DIR}/${rel}" "${REPO_ROOT}/docs/${rel}"; then
        ok "${url} is published (${rel}, identical to docs/${rel})"
    elif [ -f "${SITE_DIR}/${rel}" ]; then
        fail "${url} — ${SITE_DIR}/${rel} differs from docs/${rel}"
    else
        fail "${url} — no ${rel} under ${SITE_DIR}"
    fi
done < <(grep -oE "${SITE_URL//./\\.}[A-Za-z0-9_./-]+" "${FRAGMENT}" "${SOURCE}" | cut -d: -f2- | sort -u)

# The hero's copy controls copy exactly the displayed commands, and the
# output lines it shows are part of the displayed output.
python3 - "$INDEX" "${WORK}/commands.txt" "${WORK}/blocks/text.block" "$QUICK_START" <<'PYEOF' || ERRORS=$((ERRORS + 1))
import html
import re
import sys
page = open(sys.argv[1], encoding="utf-8").read()
commands = open(sys.argv[2], encoding="utf-8").read().splitlines()
output = open(sys.argv[3], encoding="utf-8").read().splitlines()
quick_start = open(sys.argv[4], encoding="utf-8").read()
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
def data_cmds(pred):
    return [html.unescape(m) for _, attrs in buttons if pred(attrs)
            for m in re.findall(r'data-cmd="([^"]*)"', attrs)]
is_install = lambda attrs: 'aria-label="Copy the install command"' in attrs
first_run = data_cmds(lambda attrs: not is_install(attrs))
report(sorted(first_run) == sorted(commands),
       "hero copy controls copy exactly the displayed fetch/compile/run commands")
# The install control copies the quick start's hero-install block (issue
# #577): the Liquid reference in the source tree, the command once rendered.
marked = quick_start.split("<!-- hero-install", 1)[-1].split("```")
hero_cmd = marked[1].removeprefix("bash").strip() if len(marked) > 2 else None
install = data_cmds(is_install)
if "{% include" in page:
    report(install == ["{{ hero_install | escape }}"],
           "hero install control copies the quick start's hero-install command (Liquid, source tree)")
else:
    shown_cmd = [html.unescape(m) for m in re.findall(r'<span class="cmd">([^<]*)</span>', page)]
    report(hero_cmd is not None and install == [hero_cmd] and hero_cmd in shown_cmd,
           f"hero install control shows and copies the quick start's hero-install command: {hero_cmd}")
shown = [html.unescape(m) for m in re.findall(r'<span class="ok">([^<]*)</span>', page)]
report(shown and all(line in output for line in shown),
       f"hero shows {len(shown)} line(s) of the displayed output")
report(re.search(r"\.copy-btn:focus-visible[^{]*\{[^}]*outline", page, re.S) is not None,
       "copy controls keep a visible focus outline")
report("@media (prefers-reduced-motion: reduce)" in page,
       "reduced-motion preference is honoured")
for rel in ("first-run/hello_packet.c", "first-run/traffic.pcap"):
    report(f'href="{rel}"' in page, f"landing page links {rel} (checked by check-site-links.sh)")
# Copy feedback and the mobile menu (issue #396): the markup contract the
# recorded browser checks exercised (docs/DECISIONS.md).
report(re.search(r'<span id="copyStatus"[^>]*role="status"[^>]*aria-live="polite"', page)
       is not None and "status.textContent = ok ?" in page,
       "copy result is announced through a polite role=status live region")
toggle = re.search(r"<(\w+)[^>]*\bclass=\"nav-toggle\"([^>]*)>", page)
report(toggle is not None and toggle.group(1) == "button"
       and 'aria-expanded="false"' in toggle.group(2)
       and 'aria-controls="navLinks"' in toggle.group(2)
       and 'id="navLinks"' in page,
       "mobile menu toggle is a <button> with aria-expanded/aria-controls=navLinks")
report("btn.setAttribute('aria-expanded', open ? 'false' : 'true')" in page
       and "links.classList.remove('open')" in page,
       "menu toggle updates aria-expanded and a section link closes the menu")
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

# ---------------------------------------------------------------------------
# [3/6] Install routes (issue #577)
# ---------------------------------------------------------------------------
echo "  [3/6] checking the install routes the quick start displays ..."
SOURCE_URL="$(sed -n 's/^PUBLISHED_INSTALLER="\(.*\)"$/\1/p' "${REPO_ROOT}/tools/ci/smoke-install.sh")"
BOOTSTRAP_URL="$(sed -n 's/^PUBLISHED="\(.*\)"$/\1/p' "${REPO_ROOT}/tools/ci/smoke-bootstrap.sh")"
for smoke in smoke-install.sh smoke-bootstrap.sh; do
    # shellcheck disable=SC2016  # the literal assignment line, not an expansion
    grep -qF 'FRAGMENT="${REPO_DIR}/docs/_includes/first-example.md"' "${REPO_ROOT}/tools/ci/${smoke}" \
        || fail "tools/ci/${smoke} no longer runs the first run of docs/_includes/first-example.md"
done
mkdir -p "${WORK}/routes"
python3 - "$QUICK_START" "${WORK}/routes" "${SOURCE_URL}" "${BOOTSTRAP_URL}" "file://${REPO_ROOT}/install.sh" <<'PYEOF' || ERRORS=$((ERRORS + 1))
import re
import sys
import urllib.parse
fragment, out, source_url, bootstrap_url, local_url = sys.argv[1:6]
local_url = urllib.parse.quote(local_url, safe="/:")
text = open(fragment, encoding="utf-8").read()
bad = 0
def report(ok, msg):
    global bad
    print(f"    {'✓' if ok else '✗'} {msg}")
    bad += 0 if ok else 1
commands = [line.strip()
            for body in re.findall(r"^```bash\n(.*?)^```$", text, re.S | re.M)
            for line in body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
source = [c for c in commands if c.startswith(f"curl -fsSL {source_url} | ")]
wget = [c for c in commands if c.startswith(f"wget -qO- {source_url} | ")]
bootstrap = [c for c in commands if c.startswith(f"curl -fsSL {bootstrap_url} | ")]
unknown = [c for c in commands if c not in source + wget + bootstrap]
report(source_url != "" and bootstrap_url != "",
       "the smoke workflows' published installer URLs are readable")
report(not unknown, "every displayed install command belongs to a known route"
       + "".join(f"\n        unknown: {c}" for c in unknown))
marked = text.split("<!-- hero-install", 1)[-1].split("```")
hero = marked[1].removeprefix("bash").strip() if len(marked) > 2 else ""
report(hero == f"curl -fsSL {source_url} | bash",
       f"the hero-install block is the command tools/ci/smoke-install.sh runs: {hero}")
report(bootstrap[:1] == [f"curl -fsSL {bootstrap_url} | sh"],
       "the bootstrap route is the command tools/ci/smoke-bootstrap.sh runs")
report(all(c.replace("wget -qO-", "curl -fsSL", 1) in source for c in wget),
       f"{len(wget)} wget line(s) fetch the same installer as a displayed curl line")
open(f"{out}/bootstrap.txt", "w", encoding="utf-8").write("".join(c + "\n" for c in bootstrap))
# Each source-installer line as run here: the installer fetched from this
# checkout, --dry-run added, and what its plan must show.
with open(f"{out}/source.tsv", "w", encoding="utf-8") as fh:
    for c in source:
        run = c.replace(source_url, local_url, 1)
        if "--dry-run" not in run:
            run += " --dry-run" if re.search(r"\bbash -s --( |$)", run) else " -s -- --dry-run"
        expect = "Uninstall plan (dry run" if "--uninstall" in c else "Install plan (dry run"
        for var, label in (("MMT_BASE", "Prefix     : "), ("BRANCH", "Ref        : ")):
            m = re.search(rf"\b{var}=(\S+)", c)
            if m:
                expect += "\t" + label + m.group(1)
        if "SKIP_DEPS=1" in c:
            expect += "\tDeps       : skipped"
        fh.write(f"{c}\t{run}\t{expect}\n")
sys.exit(1 if bad else 0)
PYEOF
if usage="$(sh "${REPO_ROOT}/tools/ci/bootstrap-install.sh" --help 2>&1)"; then
    while IFS= read -r cmd; do
        if printf '%s\n' "$usage" | grep -qxF "  ${cmd}"; then
            ok "the bootstrap's own usage shows the displayed command: ${cmd}"
        else
            fail "tools/ci/bootstrap-install.sh --help does not show the displayed command: ${cmd}"
        fi
    done < "${WORK}/routes/bootstrap.txt"
    if grep -qF -- '-s -- --with-security' "$QUICK_START"; then
        if printf '%s\n' "$usage" | grep -qF -- 'sh -s -- --with-security'; then
            ok "the bootstrap accepts the displayed --with-security option"
        else
            fail "tools/ci/bootstrap-install.sh --help does not offer the displayed --with-security option"
        fi
    fi
else
    fail "sh tools/ci/bootstrap-install.sh --help failed"
fi
ROUTE_DIR="${WORK}/route-empty"
n_source=0
while IFS=$'\t' read -r cmd run expects; do
    n_source=$((n_source + 1))
    rm -rf "${ROUTE_DIR}" && mkdir -p "${ROUTE_DIR}"
    rc=0
    (cd "${ROUTE_DIR}" && env -u LD_LIBRARY_PATH bash -o pipefail -c "$run") \
        >"${WORK}/route.out" 2>&1 || rc=$?
    missing=""
    IFS=$'\t' read -r -a want <<< "$expects"
    for w in "${want[@]}"; do
        grep -qF -- "$w" "${WORK}/route.out" || missing="${missing} '${w}'"
    done
    if [ "$rc" -eq 0 ] && [ -z "$missing" ] && [ -z "$(find "${ROUTE_DIR}" -mindepth 1)" ]; then
        ok "dry run of: ${cmd}"
    else
        fail "dry run of: ${cmd} — exit ${rc}${missing:+, plan lacks${missing}}, $(find "${ROUTE_DIR}" -mindepth 1 | wc -l) file(s) left"
        tail -5 "${WORK}/route.out" >&2 || true
    fi
done < "${WORK}/routes/source.tsv"
[ "$n_source" -gt 0 ] || fail "docs/_includes/quick-start.md displays no source-installer command"

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ docs_onboarding: ${ERRORS} static check(s) failed" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# [4/6] Build + install into a throwaway prefix
# ---------------------------------------------------------------------------
BUILD_LOG="${WORK}/build.log"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    set -- "BUILD=${SDK_BUILD_PROFILE}"
else
    set --
fi
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    [ -e "${PREFIX}/dpi/lib/libmmt_core.so" ] || { echo "✗ MMT_SDK_PREBUILT=1 but MMT_PREFIX='${PREFIX}' holds no installed SDK" >&2; exit 1; }
    echo "  [4/6] reusing the prebuilt SDK in ${PREFIX} (MMT_SDK_PREBUILT=1) ..."
else
    echo "  [4/6] building + installing SDK into ${PREFIX} ..."
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    if ! make -C "${REPO_ROOT}/sdk" "$@" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
        echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
    fi
    if ! make -C "${REPO_ROOT}/sdk" "$@" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
        echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
    fi
fi

# ---------------------------------------------------------------------------
# [5/6] The displayed steps, from an empty directory
# ---------------------------------------------------------------------------
echo "  [5/6] running the displayed steps in an empty directory ..."
RUN_DIR="${WORK}/empty"
mkdir -p "${RUN_DIR}"
python3 - "${WORK}/commands.txt" "${WORK}/steps.sh" "${SITE_URL}" "${SITE_DIR}" "${PREFIX}" <<'PYEOF'
import shlex
import sys
import urllib.parse
src, dst, site_url, site_dir, prefix = sys.argv[1:6]
# Percent-encode the file URL and shell-quote the prefix, so checkouts and
# temp dirs whose paths contain spaces or shell metacharacters still work.
local_url = "file://" + urllib.parse.quote(site_dir) + "/"
lines = []
for cmd in open(src, encoding="utf-8").read().splitlines():
    # prefix first: a checkout under /opt/mmt/ must not have its file URL rewritten
    cmd = cmd.replace("/opt/mmt/", shlex.quote(prefix) + "/").replace(site_url, local_url)
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
# [6/6] Missing fixture
# ---------------------------------------------------------------------------
echo "  [6/6] checking the missing-capture error ..."
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
rc=0
(cd "${RUN_DIR}" && LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" ./hello_packet other.pcap) \
    >"${WORK}/out.txt" 2>"${WORK}/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -qF "hello_packet: cannot open capture 'other.pcap'" "${WORK}/err.txt" \
   && ! grep -qF "curl" "${WORK}/err.txt"; then
    ok "another missing capture exits 1 without the sample's fetch hint"
else
    fail "missing other.pcap: expected exit 1 and no traffic.pcap fetch hint, got exit ${rc}"
    cat "${WORK}/err.txt" >&2 || true
fi

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ docs_onboarding: ${ERRORS} check(s) failed" >&2
    exit 1
fi
echo
echo "✓ documented first run verified from an empty directory against an installed SDK (issue #393)"
