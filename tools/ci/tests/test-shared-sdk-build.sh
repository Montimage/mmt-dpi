#!/usr/bin/env bash
#
# test-shared-sdk-build.sh — self-test for the shared SDK builds of
# tests/run_all_tests.sh (issue #654).
#
# It copies the REAL runner into a scratch tree whose tests/ holds fake
# suites (each records the MMT_SDK_PREBUILT / MMT_PREFIX / MMT_FI_PREFIX it
# was given) and puts a stub `make` first on PATH that logs its arguments
# and, for `install`, creates <MMT_BASE>/dpi/lib/libmmt_core.so. Nothing is
# compiled, so each scenario runs in milliseconds.
#
# Scenario -> expected:
#   hashmap rule_engine memory  -> one clean, a default build and an
#                                  incremental ENABLESEC=1 build (sdk_builds=2);
#                                  hashmap gets the default prefix, rule_engine
#                                  the enablesec one, memory no MMT_SDK_PREBUILT;
#                                  both prefixes are gone after the run
#   fault_injection             -> one default build, MMT_FI_PREFIX set too
#   memory / installer          -> no shared build (installer keeps its own)
#   rule_engine                 -> one clean, full ENABLESEC=1 build
#   SANITIZE=asan fault_injection -> no build (its engine leg is skipped)
#   SANITIZE=asan hashmap       -> the build carries BUILD=asan
#   a failing build             -> runner exits non-zero, no suite runs
#
# Usage: bash tools/ci/tests/test-shared-sdk-build.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
RUNNER="${REPO_ROOT}/tests/run_all_tests.sh"
[ -f "${RUNNER}" ] || { echo "✗ missing ${RUNNER}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
T="${WORK}/tree"
mkdir -p "${T}/tests" "${T}/sdk" "${WORK}/bin"
cp "${RUNNER}" "${T}/tests/run_all_tests.sh"

for suite in hashmap fault_injection rule_engine installed_consumer memory installer; do
    mkdir -p "${T}/tests/${suite}"
    cat > "${T}/tests/${suite}/run_tests.sh" <<'SUITE'
#!/usr/bin/env bash
# Fake suite: record what the runner handed it; a prebuilt prefix must hold
# the stub install.
printf '%s|%s|%s|%s\n' "$(basename "$(dirname "$0")")" "${MMT_SDK_PREBUILT:-unset}" \
    "${MMT_PREFIX:-unset}" "${MMT_FI_PREFIX:-unset}" >> "${SUITE_LOG}"
[ "${MMT_SDK_PREBUILT:-0}" != 1 ] || [ -e "${MMT_PREFIX}/dpi/lib/libmmt_core.so" ]
SUITE
done

cat > "${WORK}/bin/make" <<'STUB'
#!/usr/bin/env bash
# Stub make: log the arguments; `install` creates the installed core library
# under MMT_BASE; STUB_MAKE_FAIL=1 fails every goal but clean.
printf '%s\n' "$*" >> "${MAKE_LOG}"
base="" goal=build
for a in "$@"; do
    case "$a" in
        MMT_BASE=*) base="${a#MMT_BASE=}" ;;
        clean|install) goal="$a" ;;
    esac
done
[ "${goal}" = clean ] && exit 0
[ -z "${STUB_MAKE_FAIL:-}" ] || { echo "stub: build failed" >&2; exit 2; }
if [ "${goal}" = install ]; then
    mkdir -p "${base}/dpi/lib" && : > "${base}/dpi/lib/libmmt_core.so"
fi
exit 0
STUB
chmod +x "${WORK}/bin/make"

pass=0
fail=0
check() {
    local name="$1"; shift
    if "$@"; then
        echo "  ✓ ${name}"
        pass=$((pass + 1))
    else
        echo "  ✗ ${name}"
        fail=$((fail + 1))
    fi
}

# run_case [VAR=value...] -- SUITE... — run the copied runner; sets RC and
# leaves out.log, make.log and suites.log in ${WORK}.
run_case() {
    local envs=()
    while [ "$1" != -- ]; do envs+=("$1"); shift; done
    shift
    : > "${WORK}/make.log"; : > "${WORK}/suites.log"
    RC=0
    # Scrub every variable the runner reads from its environment: run from
    # the coverage or sanitizer mode of the real runner, this test inherits
    # SDK_BUILD_PROFILE, EXTRA_CFLAGS, SANITIZE... which would switch the
    # copied runner's mode. A scenario sets SANITIZE itself.
    env -u SANITIZE -u SDK_BUILD_PROFILE -u EXTRA_CFLAGS -u ASAN_OPTIONS \
        -u MMT_TSAN_REEXEC -u VERBOSE_COVERAGE -u JOBS \
        -u MMT_SDK_PREBUILT -u MMT_PREFIX -u MMT_FI_PREFIX \
        PATH="${WORK}/bin:${PATH}" MAKE_LOG="${WORK}/make.log" \
        SUITE_LOG="${WORK}/suites.log" "${envs[@]}" \
        bash "${T}/tests/run_all_tests.sh" "$@" > "${WORK}/out.log" 2>&1 || RC=$?
}

# Lines of make.log: clean goals, build goals (neither clean nor install).
cleans() { grep -c -w clean "${WORK}/make.log" || true; }
builds() { grep -v -w -e clean -e install "${WORK}/make.log" | grep -c . || true; }
saw() { grep -q -x -- "$1" "${WORK}/suites.log"; }
said() { grep -q -- "$1" "${WORK}/out.log"; }
not() { ! "$@"; }
eq() { [ "$1" = "$2" ]; }
prefix_of() { awk -F'|' -v s="$1" '$1 == s { print $3 }' "${WORK}/suites.log"; }

echo "-- hashmap rule_engine memory --"
run_case -- hashmap rule_engine memory
check "runner exits 0" eq "${RC}" 0
check "one make clean" eq "$(cleans)" 1
check "two builds" eq "$(builds)" 2
check "the default build carries no ENABLESEC" \
    grep -q -- '-j.*MMT_BASE=.*/default$' "${WORK}/make.log"
check "the enablesec build is ENABLESEC=1 into its own prefix" \
    grep -q -- 'ENABLESEC=1 -j.*MMT_BASE=.*/enablesec$' "${WORK}/make.log"
check "logs the default build" said 'sdk_build 1: group=default profile=default prefix='
check "logs the enablesec build as incremental" \
    said 'sdk_build 2: group=enablesec profile=default incremental prefix='
check "logs sdk_builds=2" said '^sdk_builds=2$'
check "the results table counts 2 shared builds" said 'Shared SDK builds: 2'
pa="$(prefix_of hashmap)"; pb="$(prefix_of rule_engine)"
check "hashmap reuses the default prefix" saw "hashmap|1|${pa}|unset"
check "hashmap's prefix is the default group's" eq "${pa##*/}" default
check "rule_engine reuses the enablesec prefix" saw "rule_engine|1|${pb}|unset"
check "rule_engine's prefix is the enablesec group's" eq "${pb##*/}" enablesec
check "memory gets no prebuilt SDK" saw "memory|unset|unset|unset"
check "the shared prefixes are removed on exit" not test -e "${pa%/*}"

echo "-- fault_injection --"
run_case -- fault_injection
check "one default build" eq "$(builds)" 1
pa="$(prefix_of fault_injection)"
check "fault_injection gets MMT_FI_PREFIX = MMT_PREFIX = the default prefix" \
    saw "fault_injection|1|${pa}|${pa}"

echo "-- memory, installer --"
run_case -- memory
check "memory alone: runner exits 0" eq "${RC}" 0
check "memory alone: no make call" eq "$(wc -l < "${WORK}/make.log")" 0
check "memory alone: no sdk_build line" not said 'sdk_build'
run_case -- installer
check "installer alone: no shared build" eq "$(wc -l < "${WORK}/make.log")" 0
check "installer keeps its own build (no MMT_SDK_PREBUILT)" saw "installer|unset|unset|unset"

echo "-- rule_engine --"
run_case -- rule_engine
check "one make clean" eq "$(cleans)" 1
check "one full ENABLESEC=1 build" eq "$(builds)" 1
check "logged as a full build" said 'sdk_build 1: group=enablesec profile=default prefix='

echo "-- sanitizer profiles --"
run_case SANITIZE=asan -- fault_injection
check "asan fault_injection: no build" eq "$(wc -l < "${WORK}/make.log")" 0
check "asan fault_injection: no MMT_SDK_PREBUILT" saw "fault_injection|unset|unset|unset"
run_case SANITIZE=asan -- hashmap
check "asan hashmap: the build is BUILD=asan" grep -q -- ' BUILD=asan -j' "${WORK}/make.log"
check "asan hashmap: logged with profile=asan" said 'sdk_build 1: group=default profile=asan prefix='

echo "-- failing build --"
run_case STUB_MAKE_FAIL=1 -- hashmap memory
check "runner exits non-zero" not eq "${RC}" 0
check "names the failed group" said 'shared SDK build failed (group=default)'
check "no suite ran" eq "$(wc -l < "${WORK}/suites.log")" 0

echo ""
echo "shared SDK build self-test: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
