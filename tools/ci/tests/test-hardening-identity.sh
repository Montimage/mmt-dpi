#!/usr/bin/env bash
#
# test-hardening-identity.sh — self-test for the release-hardening gate
# (issue #508).
#
# Part 1 evaluates the REAL makefiles (sdk/Makefile -> rules/*.mk) with a
# print goal passed through `make --eval`: the preprocessor probes run, but
# no SDK source is compiled. It pins that the hardening block is keyed on the
# compiler's identity, not on how $(CC) is spelled:
#
#   CC=gcc                         -> FORTIFY, -z,now, -flto=auto, no warning
#   CC=$(command -v gcc)           -> same (was: whole block silently skipped)
#   CC=<wrapper exec'ing gcc>      -> same
#   CC=<not GCC/Clang>             -> no hardening flags + SKIPPED $(warning)
#   CXX=<g++ reporting another     -> hardening kept, LTO dropped + warning
#        GCC minor release>
#   BUILD=asan / tsan / coverage   -> no hardening flags + DISABLED warning
#   clean goal                     -> no hardening warning
#   default / CC=<absolute gcc>    -> last C -std is gnu17, none in CXXFLAGS
#   MMT_EXTRA_CFLAGS=-std=gnu2x    -> gnu2x appended after the pin (#514)
#
# Part 2 runs tools/ci/check-hardening-flags.sh --built DIR on two fixture
# shared objects compiled here: one with full RELRO and FORTIFY (must pass)
# and one with lazy binding and no FORTIFY (must fail, naming BIND_NOW and
# the _FORTIFY_SOURCE floor).
#
# Usage: bash tools/ci/tests/test-hardening-identity.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
CHECKER="${REPO_ROOT}/tools/ci/check-hardening-flags.sh"
[ -f "${CHECKER}" ] || { echo "✗ missing ${CHECKER}" >&2; exit 2; }
GCC="$(command -v gcc || true)"
GXX="$(command -v g++ || true)"
if [ -z "${GCC}" ] || [ -z "${GXX}" ]; then
    echo "✗ gcc and g++ are required" >&2; exit 2
fi
command -v readelf >/dev/null 2>&1 || { echo "✗ readelf is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILED=0
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; FAILED=$((FAILED + 1)); }

# --- fixtures: compiler wrappers ------------------------------------------
# A wrapper whose basename is not gcc/clang but which IS GCC.
cat >"${WORK}/cc-wrapper" <<EOF
#!/bin/sh
exec "${GCC}" "\$@"
EOF
# A compiler that is neither GCC nor Clang: its preprocessor defines none of
# the identity macros. It is never asked to compile anything here.
cat >"${WORK}/not-gcc" <<'EOF'
#!/bin/sh
if [ -t 0 ]; then :; else cat >/dev/null; fi
echo '#define __STDC__ 1'
EOF
# A g++ that reports a different GCC minor release from its macro dump.
cat >"${WORK}/gxx-other" <<EOF
#!/bin/sh
case " \$* " in
  *" -dM "*) "${GXX}" "\$@" | sed 's/^#define __GNUC_MINOR__ .*/#define __GNUC_MINOR__ 99/' ;;
  *) exec "${GXX}" "\$@" ;;
esac
EOF
chmod +x "${WORK}/cc-wrapper" "${WORK}/not-gcc" "${WORK}/gxx-other"

# --- part 1: makefile evaluation ------------------------------------------
# eval_make GOAL [VAR=VALUE...] — prints the effective flags of a real
# makefile evaluation (no compile), then make's stderr (warnings) prefixed
# "W:".
eval_make() {
    local goal="$1"; shift
    local out="${WORK}/make.out" err="${WORK}/make.err"
    make -s --no-print-directory -C "${REPO_ROOT}/sdk" "$@" \
        --eval "mmt-print-hardening: ; @echo CFLAGS=\$(CFLAGS) CXXFLAGS=\$(CXXFLAGS)" \
        "${goal}" >"${out}" 2>"${err}" || {
            echo "✗ make evaluation failed ($*):" >&2; cat "${err}" >&2; exit 2; }
    cat "${out}"
    sed 's/^/W:/' "${err}"
}

has()    { grep -qF -- "$2" <<<"$1"; }

# expect_hardened DESC OUTPUT [nolto]
expect_hardened() {
    local desc="$1" o="$2" lto="${3:-lto}" ok=1
    has "$o" "-D_FORTIFY_SOURCE=" || ok=0
    has "$o" "-fstack-protector-strong" || ok=0
    has "$o" "-Wl,-z,relro -Wl,-z,now" || ok=0
    if [ "$lto" = lto ]; then has "$o" "-flto=auto" || ok=0; fi
    if [ "$lto" = nolto ]; then has "$o" "-flto=auto" && ok=0; fi
    has "$o" "release hardening SKIPPED" && ok=0
    has "$o" "release hardening DISABLED" && ok=0
    if [ "$ok" -eq 1 ]; then pass "$desc"; else fail "$desc"; printf '%s\n' "$o" | sed 's/^/      /'; fi
}

# expect_unhardened DESC OUTPUT WARNING
expect_unhardened() {
    local desc="$1" o="$2" warn="$3" ok=1
    has "$o" "-D_FORTIFY_SOURCE=" && ok=0
    has "$o" "-Wl,-z,now" && ok=0
    has "$o" "-flto=auto" && ok=0
    has "$o" "W:" || ok=0
    has "$o" "$warn" || ok=0
    if [ "$ok" -eq 1 ]; then pass "$desc"; else fail "$desc"; printf '%s\n' "$o" | sed 's/^/      /'; fi
}

echo "-- hardening keyed on compiler identity --"
expect_hardened "CC=gcc gets the full hardening set" \
    "$(eval_make mmt-print-hardening CC=gcc)"
expect_hardened "CC=${GCC} (absolute path) gets the full hardening set" \
    "$(eval_make mmt-print-hardening CC="${GCC}")"
expect_hardened "CC=<wrapper around gcc> gets the full hardening set" \
    "$(eval_make mmt-print-hardening CC="${WORK}/cc-wrapper")"
expect_unhardened "an unidentified CC skips the block with a warning" \
    "$(eval_make mmt-print-hardening CC="${WORK}/not-gcc")" \
    "release hardening SKIPPED"
o="$(eval_make mmt-print-hardening CC="${GCC}" CXX="${WORK}/gxx-other")"
expect_hardened "a CXX of another GCC release keeps hardening but not LTO" "$o" nolto
if has "$o" "LTO SKIPPED"; then pass "the dropped LTO is announced"; else fail "the dropped LTO is announced"; fi

echo "-- sanitizer/coverage profiles keep hardening off --"
for b in asan tsan coverage; do
    expect_unhardened "BUILD=$b has no hardening flags and warns" \
        "$(eval_make mmt-print-hardening CC="${GCC}" BUILD="$b")" \
        "release hardening DISABLED"
done

echo "-- C dialect pin (issue #514) --"
# eval_dialect [VAR=VALUE...] — eval_make without a job-level
# MMT_EXTRA_CFLAGS leaking in from the environment.
eval_dialect() { (unset MMT_EXTRA_CFLAGS; eval_make mmt-print-hardening "$@"); }
c_flags()   { grep -m1 '^CFLAGS=' <<<"$1" | sed 's/ CXXFLAGS=.*//'; }
cxx_flags() { grep -m1 '^CFLAGS=' <<<"$1" | sed 's/^.* CXXFLAGS=//'; }
std_seq()   { grep -o -- '-std=[^ ]*' <<<"$1" | tr '\n' ' ' || true; }
last_std()  { grep -o -- '-std=[^ ]*' <<<"$1" | tail -n1 || true; }
# expect_last_std DESC OUTPUT STD
expect_last_std() {
    local got; got="$(last_std "$(c_flags "$2")")"
    if [ "$got" = "$3" ]; then pass "$1"; else fail "$1 (last C -std: '${got}')"; fi
}
o="$(eval_dialect CC=gcc)"
expect_last_std "the default GCC toolchain compiles C as gnu17" "$o" "-std=gnu17"
if has "$(cxx_flags "$o")" "-std=gnu17"; then fail "the C dialect pin does not reach CXXFLAGS"
else pass "the C dialect pin does not reach CXXFLAGS"; fi
o="$(eval_dialect CC=gcc MMT_EXTRA_CFLAGS=-std=gnu2x)"
expect_last_std "MMT_EXTRA_CFLAGS=-std=gnu2x overrides the pin (last -std)" "$o" "-std=gnu2x"
if has "$(std_seq "$(c_flags "$o")")" "-std=gnu17 -std=gnu2x "; then pass "MMT_EXTRA_CFLAGS is appended after the pin"
else fail "MMT_EXTRA_CFLAGS is appended after the pin (C -std sequence: '$(std_seq "$(c_flags "$o")")')"; fi
expect_last_std "CC=${GCC} (absolute path) keeps the gnu17 pin" \
    "$(eval_dialect CC="${GCC}")" "-std=gnu17"

echo "-- cleaning goals stay quiet --"
# Dry run (-n): the clean recipe is printed, never executed.
o="$(make -n -s --no-print-directory -C "${REPO_ROOT}/sdk" CC="${WORK}/not-gcc" clean 2>&1 >/dev/null | sed 's/^/W:/')"
if has "$o" "W:"; then fail "clean prints no hardening warning"; printf '%s\n' "$o" | sed 's/^/      /'
else pass "clean prints no hardening warning"; fi

# --- part 2: --built on fixture shared objects ----------------------------
echo "-- check-hardening-flags.sh --built DIR --"
cat >"${WORK}/fx.c" <<'EOF'
#include <string.h>
int fx_copy(const char *src, size_t n)
{
    char buf[16];
    memcpy(buf, src, n);
    return buf[0] + buf[n > 1 ? 1 : 0];
}
EOF
# The positive fixture is linked like the checker's own link probe, so it
# carries the control-flow note exactly when the checker asserts it (the
# checker gates the check on a -shared -fcf-protection link probe).
CF=""
if printf 'int main(void){return 0;}\n' | "${GCC}" -x c -fcf-protection -Werror - -o /dev/null >/dev/null 2>&1; then
    CF="-fcf-protection"
fi
mkdir -p "${WORK}/good" "${WORK}/bad"
# shellcheck disable=SC2086  # $CF is empty or one flag
"${GCC}" -shared -fPIC -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 ${CF} \
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack \
    -o "${WORK}/good/libfx.so.1" "${WORK}/fx.c"
"${GCC}" -shared -fPIC -O2 -U_FORTIFY_SOURCE -Wl,-z,lazy -Wl,-z,noexecstack \
    -o "${WORK}/bad/libfx.so.1" "${WORK}/fx.c"
ln -s libfx.so.1 "${WORK}/good/libfx.so"   # symlinks are skipped

rc=0; out="$(bash "${CHECKER}" --built "${WORK}/good" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && has "$out" "_FORTIFY_SOURCE floor:" && has "$out" "across 1 object"; then
    pass "a full-RELRO, fortified object passes"
else
    fail "a full-RELRO, fortified object passes (exit $rc)"; printf '%s\n' "$out" | sed 's/^/      /'
fi
rc=0; out="$(bash "${CHECKER}" --built "${WORK}/bad" 2>&1)" || rc=$?
if [ "$rc" -eq 1 ] && has "$out" "✗ BIND_NOW (full RELRO): libfx.so.1" \
   && has "$out" "✗ _FORTIFY_SOURCE floor"; then
    pass "a lazy-binding, unfortified object fails on BIND_NOW and the FORTIFY floor"
else
    fail "a lazy-binding, unfortified object fails on BIND_NOW and the FORTIFY floor (exit $rc)"
    printf '%s\n' "$out" | sed 's/^/      /'
fi
rc=0; out="$(bash "${CHECKER}" --built "${WORK}/missing" 2>&1)" || rc=$?
if [ "$rc" -eq 2 ]; then pass "a missing directory is a helper error (exit 2)"
else fail "a missing directory is a helper error (exit 2, got $rc)"; fi

if [ "${FAILED}" -ne 0 ]; then
    echo "✗ ${FAILED} hardening self-test check(s) failed" >&2
    exit 1
fi
echo "✓ hardening identity self-test passed"
