#!/usr/bin/env bash
#
# test-unreachable-sections.sh — self-test for
# tools/ci/report-unreachable-sections.sh (issue #541, F-DEAD-007).
#
# It copies the REAL script and tools/ci/vendor-paths-lib.sh into a throwaway
# git repository whose src/ holds fixture sources (an SDK source, a generated
# asn1c source and a vendored one) and feeds it fixture linker logs through
# --log, so the parser and the allowlist gate run in milliseconds without an
# SDK build. The build path runs once against a stub `make` on PATH that
# records its arguments and prints a fixture log.
#
# Scenario -> expected exit:
#   every unreachable section allowlisted                   -> 0
#   asn1c, vendored, anonymous and dotted sections skipped  -> 0
#   an unreachable section missing from the allowlist       -> 1
#   a stale allowlist row                                   -> 1
#   malformed allowlist row (bad tag, missing field)        -> 2
#   missing allowlist                                       -> 2
#   a log with no removed section at all                    -> 2
#   an archive member mapping to no source, or to two       -> 2
#   an untracked, non-ignored source is attributed          -> 0
#   --report-only prints the rows (no allowlist needed)     -> 0
#   --emit-allowlist keeps known tags and writes `todo`     -> 0
#   build path: -O0, -ffunction-sections, --print-gc-sections, the working
#   tree copied (an untracked file included, an ignored one not) -> 0
#   build path: the build fails                             -> 2
#
# Usage: bash tools/ci/tests/test-unreachable-sections.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
TOOL="${REPO_ROOT}/tools/ci/report-unreachable-sections.sh"
LIB="${REPO_ROOT}/tools/ci/vendor-paths-lib.sh"
for f in "${TOOL}" "${LIB}"; do
    [ -f "${f}" ] || { echo "✗ missing ${f}" >&2; exit 2; }
done
command -v git >/dev/null 2>&1 || { echo "✗ git is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FIX="${WORK}/repo"
mkdir -p "${FIX}/tools/ci" "${FIX}/src/mmt_core/src" "${FIX}/src/mmt_tcpip/lib" \
    "${FIX}/src/mmt_mobile/asn1c" "${FIX}/sdk"
cp "${TOOL}" "${LIB}" "${FIX}/tools/ci/"
echo 'int a(void) { return 0; }' > "${FIX}/src/mmt_core/src/core.c"
echo 'int b(void) { return 0; }' > "${FIX}/src/mmt_tcpip/lib/proto.c"
echo 'int g(void) { return 0; }' > "${FIX}/src/mmt_mobile/asn1c/Gen.c"
echo 'int v(void) { return 0; }' > "${FIX}/src/mmt_tcpip/lib/vendored.c"
printf '# fixture vendored-source list\nsrc/mmt_tcpip/lib/vendored.c\n' \
    > "${FIX}/tools/ci/vendor-paths.txt"
echo 'all:' > "${FIX}/sdk/Makefile"
printf 'ignored.txt\n' > "${FIX}/.gitignore"
git -C "${FIX}" init -q
git -C "${FIX}" add -A

LD="/usr/bin/ld"
# gc LINE: one --print-gc-sections line for section $1 of member $2 of lib $3.
gc() { echo "${LD}: removing unused section '$1' in file '/x/sdk/lib/$3.a($2)'"; }

# The base log: two in-scope sections, plus what the probe must skip — a
# generated asn1c section, a vendored one, an anonymous .rodata, a string
# pool, a function-local static and a section of a non-archive object.
base_log() {
    gc .text.dead_fn core.o libmmt_core
    gc .data.rel.ro.local.dead_table proto.o libmmt_tcpip
    gc .text.gen_fn Gen.o libmmt_tmobile
    gc .text.vendored_fn vendored.o libmmt_tcpip
    gc .rodata core.o libmmt_core
    gc .rodata.dead_fn.str1.8 core.o libmmt_core
    gc .bss.log_site.0 proto.o libmmt_tcpip
    echo "${LD}: removing unused section '.text' in file '/usr/lib/crti.o'"
}
base_log > "${WORK}/base.log"

pass=0
fail=0

# check NAME EXPECTED_RC OUTPUT_ERE CMD... — runs CMD in the fixture repo.
check() {
    local name="$1" want="$2" pattern="$3" rc=0
    shift 3
    (cd "${FIX}" && "$@") > "${WORK}/out.log" 2>&1 || rc=$?
    if [ "${rc}" -ne "${want}" ]; then
        echo "  ✗ ${name}: expected exit ${want}, got ${rc}"
        sed 's/^/      /' "${WORK}/out.log"
        fail=$((fail + 1))
    elif [ -n "${pattern}" ] && ! grep -Eq -- "${pattern}" "${WORK}/out.log"; then
        echo "  ✗ ${name}: output does not match /${pattern}/"
        sed 's/^/      /' "${WORK}/out.log"
        fail=$((fail + 1))
    else
        echo "  ✓ ${name} (exit ${rc})"
        pass=$((pass + 1))
    fi
}

allow() { printf '# fixture\n%s\n' "$@" > "${WORK}/allow.txt"; }
export UNREACHABLE_ALLOWLIST="${WORK}/allow.txt"
T=tools/ci/report-unreachable-sections.sh

echo "── report-unreachable-sections.sh ──"
allow "src/mmt_core/src/core.c dead_fn test" "src/mmt_tcpip/lib/proto.c dead_table config"
check "every unreachable section allowlisted passes"      0 '^✓ 0 unreachable non-public sections outside the allowlist \(2 allowlisted' \
    bash "$T" --log "${WORK}/base.log"
check "--report-only prints only the in-scope sections"   0 '^src/mmt_tcpip/lib/proto\.c dead_table libmmt_tcpip$' \
    bash "$T" --log "${WORK}/base.log" --report-only
check "generated, vendored, anonymous and dotted are skipped" 0 '' \
    bash -c "[ \"\$(bash $T --log ${WORK}/base.log --report-only 2>/dev/null | wc -l)\" -eq 2 ]"
check "--report-only counts what it skipped"              0 '2 unreachable section\(s\) in scope \(2 generated/vendored, 3 anonymous' \
    bash "$T" --log "${WORK}/base.log" --report-only
allow "src/mmt_core/src/core.c dead_fn test"
check "an unlisted section fails"                         1 'src/mmt_tcpip/lib/proto\.c dead_table' \
    bash "$T" --log "${WORK}/base.log"
check "--emit-allowlist keeps tags and writes todo"       0 '^src/mmt_tcpip/lib/proto\.c dead_table todo$' \
    bash "$T" --log "${WORK}/base.log" --emit-allowlist
check "--emit-allowlist keeps a known tag"                0 '^src/mmt_core/src/core\.c dead_fn test$' \
    bash "$T" --log "${WORK}/base.log" --emit-allowlist
allow "src/mmt_core/src/core.c dead_fn test" "src/mmt_tcpip/lib/proto.c dead_table config" \
    "src/mmt_core/src/core.c gone_fn test"
check "a stale allowlist row fails"                       1 'stale allowlist row.*' \
    bash "$T" --log "${WORK}/base.log"
check "the stale row is named"                            1 'src/mmt_core/src/core\.c gone_fn' \
    bash "$T" --log "${WORK}/base.log"
allow "src/mmt_core/src/core.c dead_fn because" "src/mmt_tcpip/lib/proto.c dead_table config"
check "an unknown tag is a malformed row"                 2 'malformed allowlist row' \
    bash "$T" --log "${WORK}/base.log"
allow "src/mmt_core/src/core.c dead_fn"
check "a missing field is a malformed row"                2 'malformed allowlist row' \
    bash "$T" --log "${WORK}/base.log"
rm -f "${WORK}/allow.txt"
check "a missing allowlist is a broken helper"            2 'allowlist not found' \
    bash "$T" --log "${WORK}/base.log"
check "--report-only needs no allowlist"                  0 'dead_fn' \
    bash "$T" --log "${WORK}/base.log" --report-only
echo "${LD}: warning: nothing removed" > "${WORK}/empty.log"
check "a log with no removed section is a broken helper"  2 'no removed section' \
    bash "$T" --log "${WORK}/empty.log" --report-only
{ base_log; gc .text.x stranger.o libmmt_core; } > "${WORK}/unmapped.log"
check "an unmapped archive member is a broken helper"     2 'object stranger\.o maps to no tracked source' \
    bash "$T" --log "${WORK}/unmapped.log" --report-only
mkdir -p "${FIX}/src/mmt_dicom"
echo 'int c(void) { return 0; }' > "${FIX}/src/mmt_dicom/core.c"
git -C "${FIX}" add -A
check "a basename shared by two sources is a broken helper" 2 'object core\.o maps to several tracked sources' \
    bash "$T" --log "${WORK}/base.log" --report-only
git -C "${FIX}" rm -q --cached src/mmt_dicom/core.c
rm -rf "${FIX}/src/mmt_dicom"
echo 'int u(void) { return 0; }' > "${FIX}/src/mmt_core/src/fresh.c"
{ base_log; gc .text.fresh_fn fresh.o libmmt_core; } > "${WORK}/untracked.log"
check "a source not yet added to the index is attributed" 0 '^src/mmt_core/src/fresh\.c fresh_fn libmmt_core$' \
    bash "$T" --log "${WORK}/untracked.log" --report-only
rm -f "${FIX}/src/mmt_core/src/fresh.c"

echo "── build path (stub make) ──"
mkdir -p "${WORK}/bin"
# The stub records its arguments and LDFLAGS, lists the copied tree, prints
# the base log, and fails when STUB_MAKE_FAIL is set.
cat > "${WORK}/bin/make" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" > "${WORK}/make.args"
printf '%s\n' "\${LDFLAGS:-}" > "${WORK}/make.ldflags"
dir=""
while [ \$# -gt 0 ]; do [ "\$1" = -C ] && dir="\$2"; shift; done
(cd "\$dir/.." && find . -type f | sort) > "${WORK}/make.tree"
[ -z "\${STUB_MAKE_FAIL:-}" ] || { echo "stub: build failed"; exit 1; }
cat "${WORK}/base.log"
EOF
chmod +x "${WORK}/bin/make"
echo 'untracked but not ignored' > "${FIX}/src/new.c"
echo 'ignored' > "${FIX}/ignored.txt"
allow "src/mmt_core/src/core.c dead_fn test" "src/mmt_tcpip/lib/proto.c dead_table config"
check "the build path gates the stub's log"               0 '^✓ 0 unreachable' \
    env PATH="${WORK}/bin:${PATH}" bash "$T"
check "the probe builds at -O0 (DEBUG=1), default profile" 0 '' \
    bash -c "grep -qx DEBUG=1 ${WORK}/make.args && grep -qx BUILD= ${WORK}/make.args && grep -qx ENABLESEC= ${WORK}/make.args"
check "objects get their own sections"                    0 '' \
    grep -q '^MMT_EXTRA_CFLAGS=.*-ffunction-sections -fdata-sections$' "${WORK}/make.args"
check "the linker prints what it collects"                0 '' \
    grep -q -- '-Wl,--gc-sections -Wl,--print-gc-sections' "${WORK}/make.ldflags"
check "the copy holds the working tree"                   0 '' \
    grep -qx './src/new.c' "${WORK}/make.tree"
check "the copy leaves ignored files out"                 0 '' \
    bash -c "! grep -q ignored.txt ${WORK}/make.tree"
check "a failed build is a broken helper"                 2 'probe build failed' \
    env PATH="${WORK}/bin:${PATH}" STUB_MAKE_FAIL=1 bash "$T"

echo "unreachable sections: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
