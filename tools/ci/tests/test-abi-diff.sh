#!/usr/bin/env bash
#
# test-abi-diff.sh — self-test for tools/ci/abi-diff.sh (issue #525).
#
# Drives the REAL script with stub tools (ABIDIFF, OBJCOPY, DPKG_DEB, MAKE)
# and dummy library files, so it builds nothing, needs no abigail-tools and no
# network, and runs in about a second. The stub abidiff exits with the code a
# map file assigns to each library (default 0).
#
# Scenario -> expected script exit / verdict:
#   all libraries exit 0                                  -> 0, NO CHANGE x5
#   abidiff 4 (change) under --fail-on none/incompat/change -> 0 / 0 / 1, CHANGED
#   abidiff 8 and 12 (incompatible) under the same          -> 0 / 1 / 1, INCOMPATIBLE
#   abidiff 1, 2, 3, 6, 9 (an error/usage bit), 16 (unknown) -> 2, ERROR
#   a library missing on the head side                      -> INCOMPATIBLE, 0 / 1
#   a library missing on both sides, two versions of one    -> 2
#   nonexistent ABIDIFF, bad --fail-on, one prebuilt dir    -> 2
#   --headers-dir1/2 reach abidiff; symlinks are skipped
#   --summary cut at ABI_SUMMARY_MAX_BYTES, --report keeps everything
#   release leg: both sides stripped, no --fail-no-debug-info
#   build mode on a fixture repo (ROOT_DIR): release-profile CC/CXX + -g,
#     --fail-no-debug-info and both header dirs, --keep-libs layout, the
#     worktrees and the scratch dir removed; a failing build and an unknown
#     ref -> 2, worktrees removed too
#
# Usage: bash tools/ci/tests/test-abi-diff.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.
# shellcheck disable=SC2015
#  The A && B || C idiom is used only as `cond && ok ... || bad ...`, where
#  ok is an echo plus a counter increment that cannot fail, so C never runs
#  when A is true — the hazard SC2015 warns about cannot occur in this file.

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/abi-diff.sh"
[ -f "${SCRIPT}" ] || { echo "✗ missing ${SCRIPT}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
LIBS=(core tcpip tmobile business_app tdicom)

pass=0
fail=0
ok()  { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

# --- stubs -------------------------------------------------------------------
STUBS="${WORK}/stubs"
mkdir -p "${STUBS}"
cat > "${STUBS}/abidiff" <<'EOF'
#!/usr/bin/env bash
# Stub abidiff: logs its argv, prints a line per library (STUB_BIG bytes
# extra), exits with the code STUB_MAP assigns to the new file's library.
printf '%s\n' "$*" >> "${STUB_LOG}"
new="${!#}"
lib="$(basename "${new}")"
lib="${lib%%.so*}"
echo "stub report for ${lib}"
if [ -n "${STUB_BIG:-}" ]; then head -c "${STUB_BIG}" /dev/zero | tr '\0' x; echo; fi
rc="$(awk -v l="${lib}" '$1 == l { print $2 }' "${STUB_MAP}" 2>/dev/null)"
exit "${rc:-0}"
EOF
cat > "${STUBS}/objcopy" <<'EOF'
#!/usr/bin/env bash
# Stub objcopy: `--strip-debug IN OUT` copies IN to OUT and logs the call.
[ "$1" = --strip-debug ] || exit 9
printf 'strip %s\n' "$2" >> "${STUB_LOG}"
cp "$2" "$3"
EOF
cat > "${STUBS}/dpkg-deb" <<'EOF'
#!/usr/bin/env bash
# Stub dpkg-deb: `-x DEB DEST` copies the fixture package tree to DEST.
[ "$1" = -x ] || exit 9
cp -R "${STUB_DEB_TREE}/." "$3/"
EOF
cat > "${STUBS}/make" <<'EOF'
#!/usr/bin/env bash
# Stub make: `-C DIR ...` creates DIR/lib/libmmt_*.so.9.9.9 and DIR/include,
# logs its argv; STUB_MAKE_FAIL=1 fails like a broken build.
printf '%s\n' "$*" >> "${STUB_LOG}"
[ "${STUB_MAKE_FAIL:-0}" = 1 ] && { echo "stub build error" >&2; exit 2; }
dir="$2"
mkdir -p "${dir}/lib" "${dir}/include"
for l in core tcpip tmobile business_app tdicom; do
    echo "${l}" > "${dir}/lib/libmmt_${l}.so.9.9.9"
    ln -sf "libmmt_${l}.so.9.9.9" "${dir}/lib/libmmt_${l}.so"
done
echo '/* stub */' > "${dir}/include/mmt_core.h"
EOF
chmod +x "${STUBS}"/*

export STUB_LOG="${WORK}/stub.log" STUB_MAP="${WORK}/map.txt"

# mklibs <dir>: the five dummy libraries plus an unversioned symlink.
mklibs() {
    mkdir -p "$1"
    for l in "${LIBS[@]}"; do echo "$l" > "$1/libmmt_${l}.so.1.9.1"; done
    ln -sf libmmt_core.so.1.9.1 "$1/libmmt_core.so"
}
OLD="${WORK}/old"; NEW="${WORK}/new"
mklibs "${OLD}"; mklibs "${NEW}"
mkdir -p "${WORK}/h1" "${WORK}/h2"

OUT="${WORK}/out.txt"
RC=0
# run [ENV=VAL ...] -- <args>: run the script with the stubs; sets RC and OUT.
run() {
    local envs=()
    while [ "$1" != -- ]; do envs+=("$1"); shift; done
    shift
    : > "${STUB_LOG}"
    env ABIDIFF="${STUBS}/abidiff" OBJCOPY="${STUBS}/objcopy" \
        DPKG_DEB="${STUBS}/dpkg-deb" MAKE="${STUBS}/make" TMPDIR="${WORK}/tmp" \
        ${envs[@]+"${envs[@]}"} bash "${SCRIPT}" "$@" > "${OUT}" 2>&1
    RC=$?
}
setmap() { printf '%s\n' "$@" > "${STUB_MAP}"; }
expect_rc() { # expect_rc <want> <label>
    if [ "${RC}" -eq "$1" ]; then ok "$2 (exit $1)"
    else bad "$2: exit ${RC}, want $1"; sed 's/^/      /' "${OUT}"; fi
}
expect_out() { # expect_out <fixed string> <label>
    if grep -qF -- "$1" "${OUT}"; then ok "$2"
    else bad "$2: no '$1' in output"; sed 's/^/      /' "${OUT}"; fi
}
mkdir -p "${WORK}/tmp"

echo "=== abi-diff self-test: verdict mapping (prebuilt mode) ==="
PRE=(--baseline-dir "${OLD}" --head-dir "${NEW}")
setmap
run -- "${PRE[@]}"
expect_rc 0 "all libraries unchanged"
n="$(grep -c '^  libmmt_.*: NO CHANGE (abidiff exit 0)$' "${OUT}")"
[ "$n" -eq 5 ] && ok "five NO CHANGE verdicts" || bad "NO CHANGE verdicts: $n, want 5"
expect_out "Result: 0 incompatible, 0 changed (--fail-on none)" "result line"
calls="$(grep -c . "${STUB_LOG}")"
[ "$calls" -eq 5 ] && ok "abidiff ran once per library (symlink skipped)" \
    || bad "abidiff calls: $calls, want 5"

for case in "4 CHANGED 0 0 1" "8 INCOMPATIBLE 0 1 1" "12 INCOMPATIBLE 0 1 1"; do
    read -r code verdict r_none r_inc r_chg <<< "$case"
    setmap "libmmt_tcpip ${code}"
    i=0
    for f in none incompatible change; do
        want=("${r_none}" "${r_inc}" "${r_chg}")
        run -- "${PRE[@]}" --fail-on "$f"
        expect_rc "${want[$i]}" "abidiff ${code} under --fail-on $f"
        i=$((i + 1))
    done
    expect_out "libmmt_tcpip: ${verdict} (abidiff exit ${code})" "abidiff ${code} -> ${verdict}"
done

for code in 1 2 3 6 9 16; do
    setmap "libmmt_core ${code}"
    run -- "${PRE[@]}"
    expect_rc 2 "abidiff ${code} is a tool error under --fail-on none"
    expect_out "libmmt_core: ERROR (abidiff exit ${code})" "abidiff ${code} -> ERROR"
done
setmap

echo "=== abi-diff self-test: library sets and usage ==="
NEW2="${WORK}/new2"; mklibs "${NEW2}"; rm -f "${NEW2}/libmmt_tdicom.so.1.9.1"
run -- --baseline-dir "${OLD}" --head-dir "${NEW2}"
expect_rc 0 "a missing head library under --fail-on none"
expect_out "libmmt_tdicom: INCOMPATIBLE" "a missing head library -> INCOMPATIBLE"
run -- --baseline-dir "${OLD}" --head-dir "${NEW2}" --report "${WORK}/missing.txt"
grep -qF "missing on the head side" "${WORK}/missing.txt" \
    && ok "the report names the side the library is missing on" \
    || bad "no 'missing on the head side' in the report"
run -- --baseline-dir "${OLD}" --head-dir "${NEW2}" --fail-on incompatible
expect_rc 1 "a missing head library under --fail-on incompatible"
OLD2="${WORK}/old2"; mklibs "${OLD2}"; rm -f "${OLD2}/libmmt_tdicom.so.1.9.1"
run -- --baseline-dir "${OLD2}" --head-dir "${NEW2}"
expect_rc 2 "a library missing on both sides"
NEW3="${WORK}/new3"; mklibs "${NEW3}"; echo x > "${NEW3}/libmmt_core.so.1.9.0"
run -- --baseline-dir "${OLD}" --head-dir "${NEW3}"
expect_rc 2 "two versions of one library"
run ABIDIFF="${WORK}/no-such-abidiff" -- "${PRE[@]}"
expect_rc 2 "nonexistent ABIDIFF"
expect_out "abidiff not found" "nonexistent ABIDIFF is named"
run -- "${PRE[@]}" --fail-on sometimes
expect_rc 2 "bad --fail-on"
run -- --baseline-dir "${OLD}"
expect_rc 2 "prebuilt mode with one directory"
run -- "${PRE[@]}" --keep-libs "${WORK}/kept"
expect_rc 2 "--keep-libs outside build mode"

run -- "${PRE[@]}" --headers-dir1 "${WORK}/h1" --headers-dir2 "${WORK}/h2"
grep -qF -- "--headers-dir1 ${WORK}/h1 --headers-dir2 ${WORK}/h2" "${STUB_LOG}" \
    && ok "--headers-dir1/2 reach abidiff" || bad "header dirs not passed to abidiff"

echo "=== abi-diff self-test: report and summary ==="
setmap "libmmt_core 4"
run STUB_BIG=5000 ABI_SUMMARY_MAX_BYTES=100 -- "${PRE[@]}" \
    --report "${WORK}/r.txt" --summary "${WORK}/s.md"
expect_rc 0 "report + summary run"
rsize="$(wc -c < "${WORK}/r.txt")"
[ "$rsize" -gt 25000 ] && ok "the report keeps every abidiff output ($rsize bytes)" \
    || bad "report is $rsize bytes, want > 25000"
grep -qF "| \`libmmt_core\` | CHANGED | 4 |" "${WORK}/s.md" \
    && ok "the summary has a verdict row per library" || bad "no CHANGED row in the summary"
grep -qF "truncated at 100 of ${rsize} bytes" "${WORK}/s.md" \
    && ok "the summary excerpt is cut at ABI_SUMMARY_MAX_BYTES" || bad "no truncation note"
ssize="$(wc -c < "${WORK}/s.md")"
[ "$ssize" -lt 2000 ] && ok "the summary stays short ($ssize bytes)" \
    || bad "summary is $ssize bytes"
run ABI_SUMMARY_MAX_BYTES=lots -- "${PRE[@]}"
expect_rc 2 "a non-numeric ABI_SUMMARY_MAX_BYTES"
setmap

echo "=== abi-diff self-test: release leg ==="
DEB_TREE="${WORK}/debtree"
mklibs "${DEB_TREE}/opt/mmt/dpi/lib"
mkdir -p "${DEB_TREE}/opt/mmt/plugins"
echo plugin > "${DEB_TREE}/opt/mmt/plugins/libmmt_tcpip.so"
touch "${WORK}/fixture.deb"
run STUB_DEB_TREE="${DEB_TREE}" -- --release-deb "${WORK}/fixture.deb" --head-dir "${NEW}"
expect_rc 0 "release leg against a prebuilt head"
n="$(grep -c '^strip ' "${STUB_LOG}")"
[ "$n" -eq 10 ] && ok "both sides of all five libraries are stripped" \
    || bad "objcopy --strip-debug calls: $n, want 10"
grep -q '/opt/mmt/dpi/lib/libmmt_core.so.1.9.1$' "${STUB_LOG}" \
    && ok "the baseline is the package's dpi/lib" || bad "the package's dpi/lib was not used"
if grep -v '^strip ' "${STUB_LOG}" | grep -q -- '--fail-no-debug-info\|--headers-dir'; then
    bad "the release leg passed debug-info or header options"
else ok "the release leg is symbol-only (no --fail-no-debug-info, no headers)"; fi
grep -v '^strip ' "${STUB_LOG}" | grep -q '/strip/old/libmmt_core.so.1.9.1 .*/strip/new/libmmt_core.so.1.9.1$' \
    && ok "abidiff compares the stripped copies" || bad "abidiff did not get the stripped copies"
run -- --release-deb "${WORK}/no-such.deb" --head-dir "${NEW}"
expect_rc 2 "a missing release package"
EMPTY_TREE="${WORK}/emptytree"; mkdir -p "${EMPTY_TREE}/usr"
run STUB_DEB_TREE="${EMPTY_TREE}" -- --release-deb "${WORK}/fixture.deb" --head-dir "${NEW}"
expect_rc 2 "a package without dpi/lib/libmmt_core.so.*"

echo "=== abi-diff self-test: build mode (fixture repository) ==="
FX="${WORK}/repo"
g() { git -C "${FX}" -c user.name=fixture -c user.email=fixture@example.invalid \
        -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }
mkdir -p "${FX}/sdk"
git init -q "${FX}" || exit 2
echo 'all:' > "${FX}/sdk/Makefile"
g add -A && g commit -q -m released || exit 2
g tag v1.9.1 || exit 2
echo '# later' >> "${FX}/sdk/Makefile"
g commit -q -am later || exit 2
TMP_BUILD="${WORK}/tmp-build"; mkdir -p "${TMP_BUILD}"
wt_count() { git -C "${FX}" worktree list --porcelain | grep -c '^worktree '; }

run ROOT_DIR="${FX}" TMPDIR="${TMP_BUILD}" -- --keep-libs "${WORK}/kept" --summary "${WORK}/b.md"
expect_rc 0 "build mode v1.9.1 -> HEAD"
expect_out "ABI diff: v1.9.1 → HEAD (" "the title names both refs"
n="$(grep -c "CC=gcc -g CXX=g++ -std=c++11 -g" "${STUB_LOG}")"
[ "$n" -eq 2 ] && ok "both refs build with the release-profile compilers plus -g" \
    || bad "release-profile CC/CXX on $n of 2 builds"
if grep -q -- 'DEBUG=' "${STUB_LOG}"; then bad "build mode passed DEBUG="
else ok "build mode never passes DEBUG= (it would drop the release profile)"; fi
grep -q -- '--fail-no-debug-info --headers-dir1 .*/baseline/sdk/include --headers-dir2 .*/head/sdk/include ' "${STUB_LOG}" \
    && ok "type-level comparison: --fail-no-debug-info and both header dirs" \
    || bad "abidiff options in build mode: $(head -n 1 "${STUB_LOG}")"
n="$(find "${WORK}/kept" -name 'libmmt_*.so.9.9.9' -type f | wc -l)"
[ "$n" -eq 10 ] && [ -f "${WORK}/kept/head/include/mmt_core.h" ] \
    && [ -f "${WORK}/kept/baseline/include/mmt_core.h" ] \
    && ok "--keep-libs copies {baseline,head}/{lib,include}" || bad "--keep-libs layout ($n libs)"
[ "$(wt_count)" -eq 1 ] && ok "the build worktrees are removed" \
    || bad "worktrees left: $(git -C "${FX}" worktree list)"
[ -z "$(ls -A "${TMP_BUILD}")" ] && ok "the scratch directory is removed" \
    || bad "scratch left: $(ls -A "${TMP_BUILD}")"

run ROOT_DIR="${FX}" TMPDIR="${TMP_BUILD}" STUB_MAKE_FAIL=1 -- --baseline-ref HEAD~1
expect_rc 2 "a failing build"
expect_out "stub build error" "the build log tail is shown"
[ "$(wt_count)" -eq 1 ] && [ -z "$(ls -A "${TMP_BUILD}")" ] \
    && ok "a failing build leaves no worktree or scratch dir" \
    || bad "leftovers after a failing build"
run ROOT_DIR="${FX}" TMPDIR="${TMP_BUILD}" -- --baseline-ref v0.0.0-no-such-tag
expect_rc 2 "an unknown baseline ref"
expect_out "unknown ref 'v0.0.0-no-such-tag'" "the unknown ref is named"
run ROOT_DIR="${FX}" TMPDIR="${TMP_BUILD}" STUB_DEB_TREE="${DEB_TREE}" -- \
    --release-deb "${WORK}/fixture.deb"
expect_rc 0 "release leg building the head ref"
[ "$(grep -c 'CC=gcc -g' "${STUB_LOG}")" -eq 1 ] && [ "$(wt_count)" -eq 1 ] \
    && ok "the release leg builds only the head ref and removes its worktree" \
    || bad "release-leg head build"

echo
echo "abi-diff self-test: ${pass} passed, ${fail} failed"
if [ "$fail" -eq 0 ]; then
    echo "Result: PASS (abi-diff self-test)"
    exit 0
fi
echo "Result: FAIL (abi-diff self-test)"
exit 1
