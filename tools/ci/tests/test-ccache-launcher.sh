#!/usr/bin/env bash
#
# test-ccache-launcher.sh — self-test of the opt-in compiler cache and of the
# cache-stable compile lines (issue #553, F-CI-008).
#
# Part 1 evaluates the makefiles (no compile) and pins MMT_CCACHE's contract
# (rules/arch-linux-gcc.mk):
#   unset                        -> CC/CXX exactly `gcc` / `g++ -std=c++11`
#   MMT_CCACHE=<launcher>        -> CC/CXX prefixed, CCACHE_BASEDIR = checkout,
#                                   the full release hardening set unchanged
#   ... with a command-line CC=  -> that CC prefixed too
#   ... with BUILD=coverage      -> not prefixed (gcov counters)
#   MMT_CCACHE=<missing program> -> the build stops naming it; clean still runs
# Part 2 dry-runs (`make -n`) object compiles: the per-prefix
# -DPLUGINS_REPOSITORY_OPT reaches plugins_engine.o only and the per-commit
# -DGIT_VERSION packet_processing.o only, so every other object's compile
# line is identical across install prefixes and commits — what lets ccache's
# direct mode hit across the suites' throwaway prefixes.
#
# Usage: bash tools/ci/tests/test-ccache-launcher.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd -P)"
command -v gcc >/dev/null 2>&1 || { echo "✗ gcc is required" >&2; exit 2; }
# The caller's own cache settings must not leak into the evaluations.
unset MMT_CCACHE CCACHE_BASEDIR

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
LAUNCHER="${WORK}/fake-ccache"
printf '#!/bin/sh\nexec "$@"\n' > "${LAUNCHER}"
chmod +x "${LAUNCHER}"

FAILED=0
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; FAILED=$((FAILED + 1)); }
# expect DESC GOT WANT
expect() {
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1"; echo "      got:  $2"; echo "      want: $3"; fi
}

# eval_vars [VAR=VALUE...] — CC, CXX, CCACHE_BASEDIR and CFLAGS after a real
# makefile evaluation, one `NAME=value` per line.
eval_vars() {
    # shellcheck disable=SC2016  # $(...) are make references, not shell
    make -s --no-print-directory -C "${REPO_ROOT}/sdk" "$@" \
        --eval 'mmt-print-cc: ; @printf "CC=%s\nCXX=%s\nBASEDIR=%s\nCFLAGS=%s\n" "$(CC)" "$(CXX)" "$(CCACHE_BASEDIR)" "$(CFLAGS)"' \
        mmt-print-cc 2>"${WORK}/err" || {
            echo "✗ make evaluation failed ($*):" >&2; cat "${WORK}/err" >&2; exit 2; }
}
field() { sed -n "s/^$1=//p" <<<"$2"; }

echo "-- MMT_CCACHE (opt-in launcher) --"
o="$(eval_vars)"
expect "unset: CC is exactly gcc" "$(field CC "$o")" "gcc"
expect "unset: CXX is exactly g++ -std=c++11" "$(field CXX "$o")" "g++ -std=c++11"
expect "unset: no CCACHE_BASEDIR" "$(field BASEDIR "$o")" ""
plain_cflags="$(field CFLAGS "$o")"

o="$(eval_vars MMT_CCACHE="${LAUNCHER}")"
expect "set: CC is the launcher + gcc" "$(field CC "$o")" "${LAUNCHER} gcc"
expect "set: CXX is the launcher + g++ -std=c++11" "$(field CXX "$o")" "${LAUNCHER} g++ -std=c++11"
expect "set: CCACHE_BASEDIR defaults to the checkout" "$(field BASEDIR "$o")" "${REPO_ROOT}"
expect "set: CFLAGS identical to the uncached build (hardening, LTO, dialect)" \
    "$(field CFLAGS "$o")" "${plain_cflags}"
case "${plain_cflags}" in
    *-D_FORTIFY_SOURCE=*-flto=auto*) pass "the compared CFLAGS carry the release hardening set" ;;
    *) fail "the compared CFLAGS carry the release hardening set"; echo "      ${plain_cflags}" ;;
esac

o="$(MMT_CCACHE="${LAUNCHER}" eval_vars)"
expect "set from the environment: CC is the launcher + gcc" "$(field CC "$o")" "${LAUNCHER} gcc"

gcc_abs="$(command -v gcc)"
o="$(eval_vars MMT_CCACHE="${LAUNCHER}" CC="${gcc_abs}")"
expect "a command-line CC= is prefixed too" "$(field CC "$o")" "${LAUNCHER} ${gcc_abs}"

o="$(eval_vars MMT_CCACHE="${LAUNCHER}" CCACHE_BASEDIR=/somewhere)"
expect "a given CCACHE_BASEDIR is kept" "$(field BASEDIR "$o")" "/somewhere"

o="$(eval_vars MMT_CCACHE="${LAUNCHER}" BUILD=coverage)"
expect "BUILD=coverage stays uncached" "$(field CC "$o")" "gcc"

if make -s --no-print-directory -C "${REPO_ROOT}/sdk" MMT_CCACHE="${WORK}/no-such-ccache" \
        --eval 'mmt-print-cc: ; @:' mmt-print-cc >"${WORK}/out" 2>&1; then
    fail "a missing launcher stops the build"
elif grep -q "no-such-ccache.*not found" "${WORK}/out"; then
    pass "a missing launcher stops the build, naming it"
else
    fail "a missing launcher stops the build, naming it"; sed 's/^/      /' "${WORK}/out"
fi
if make -n -s --no-print-directory -C "${REPO_ROOT}/sdk" MMT_CCACHE="${WORK}/no-such-ccache" \
        clean >/dev/null 2>&1; then
    pass "clean still runs with a missing launcher"
else
    fail "clean still runs with a missing launcher"
fi

echo "-- cache-stable compile lines --"
# compile_line OBJECT [VAR=VALUE...] — the dry-run compile command of one
# object (-B: as if out of date; -n: print, never run), with make's shell
# quoting: a string define prints as -DNAME=\"value\".
compile_line() {
    local obj="$1"; shift
    make -n -B --no-print-directory -C "${REPO_ROOT}/sdk" "$@" \
        "${REPO_ROOT}/src/mmt_core/src/${obj}" 2>/dev/null \
        | grep -F -- "-c ${REPO_ROOT}/src/mmt_core/src/${obj%.o}.c" || true
}
pe="$(compile_line plugins_engine.o MMT_BASE=/tmp/mmt-p1 GIT_VERSION=c0ffee1)"
pp="$(compile_line packet_processing.o MMT_BASE=/tmp/mmt-p1 GIT_VERSION=c0ffee1)"
hm1="$(compile_line hashmap.o MMT_BASE=/tmp/mmt-p1 GIT_VERSION=c0ffee1)"
hm2="$(compile_line hashmap.o MMT_BASE=/tmp/mmt-p2 GIT_VERSION=deadbee)"
if [ -z "$pe" ] || [ -z "$pp" ] || [ -z "$hm1" ]; then
    echo "✗ no compile line found (plugins_engine.o, packet_processing.o, hashmap.o)" >&2; exit 2
fi
case "$pe" in
    *'-DPLUGINS_REPOSITORY_OPT=\"/tmp/mmt-p1/plugins\"'*) pass "plugins_engine.o gets the plugin directory" ;;
    *) fail "plugins_engine.o gets the plugin directory"; echo "      $pe" ;;
esac
case "$pp" in
    *'-DGIT_VERSION=\"c0ffee1\"'*) pass "packet_processing.o gets GIT_VERSION (mmt_version())" ;;
    *) fail "packet_processing.o gets GIT_VERSION (mmt_version())"; echo "      $pp" ;;
esac
# Without git history GIT_VERSION falls back to `nogit` for the package
# revision (rules/common.mk) only after CFLAGS is set; the define keeps the
# value it had there — empty — as the global define did. CI is cleared for
# this one evaluation: under CI (every hosted runner sets it) a build without
# git history is a hard error by design.
pp0="$(CI='' GIT_DIR=/nonexistent compile_line packet_processing.o MMT_BASE=/tmp/mmt-p1)"
case "$pp0" in
    *'-DGIT_VERSION=\"\"'*) pass "without git, packet_processing.o keeps an empty GIT_VERSION (not nogit)" ;;
    *) fail "without git, packet_processing.o keeps an empty GIT_VERSION (not nogit)"; echo "      $pp0" ;;
esac
case "$hm1" in
    *PLUGINS_REPOSITORY_OPT*|*GIT_VERSION*|*mmt-p1*) fail "other objects carry neither define"; echo "      $hm1" ;;
    *) pass "other objects carry neither define" ;;
esac
expect "another object's compile line is identical across prefixes and commits" "$hm2" "$hm1"

echo ""
if [ "${FAILED}" -eq 0 ]; then
    echo "✓ ccache launcher self-test passed"
else
    echo "✗ ${FAILED} check(s) failed"
    exit 1
fi
