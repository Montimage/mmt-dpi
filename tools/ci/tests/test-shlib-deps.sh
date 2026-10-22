#!/usr/bin/env bash
#
# test-shlib-deps.sh — self-test for the soname -> package mapping of
# tools/ci/shlib-deps.sh (issues #219, #515).
#
# The real helper runs on fixture payloads: a shared object linked against a
# stub library that carries only the soname under test, so no libxml2 of any
# version needs to be installed. Needs gcc and objdump (binutils).
#
#   NEEDED libxml2.so.2   -> deb libxml2,    rpm libxml2
#   NEEDED libxml2.so.16  -> deb libxml2-16, rpm libxml2   (Ubuntu 26.04)
#   NEEDED libxml2.so.3   -> exit 2 (unmapped: never guessed)
#
# Usage: bash tools/ci/tests/test-shlib-deps.sh
# Exit: 0 = all checks pass, 1 = a check failed, 2 = the self-test broke.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HELPER="${REPO_ROOT}/tools/ci/shlib-deps.sh"
[ -f "$HELPER" ] || { echo "✗ missing $HELPER" >&2; exit 2; }
for tool in gcc objdump; do
    command -v "$tool" >/dev/null 2>&1 || { echo "✗ $tool is required" >&2; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILS=0
pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; FAILS=$((FAILS + 1)); }

# payload <soname> — a directory holding one .so whose NEEDED names <soname>.
payload() {
    local d="$WORK/$1"
    mkdir -p "$d/stub" "$d/lib"
    echo 'int stub_sym(void) { return 0; }' > "$d/stub.c"
    echo 'int stub_sym(void); int use(void) { return stub_sym(); }' > "$d/use.c"
    gcc -shared -fPIC -Wl,-soname,"$1" -o "$d/stub/$1" "$d/stub.c"
    gcc -shared -fPIC -Wl,--no-as-needed -o "$d/lib/libuse.so" "$d/use.c" \
        "$d/stub/$1"
    objdump -p "$d/lib/libuse.so" | grep -q "NEEDED *$1\$" \
        || { echo "✗ fixture for $1 has no NEEDED $1" >&2; exit 2; }
    printf '%s\n' "$d/lib"
}

# fixture <soname> — payload's directory; a broken fixture stops the self-test.
fixture() {
    FIXTURE="$(payload "$1")" || exit 2
}

# expect_entry <label> <mode> <soname> <entry> — the Depends/Requires list
# contains <entry> as a whole item.
expect_entry() {
    local out
    fixture "$3"
    if out="$(sh "$HELPER" "$2" "$FIXTURE" 2>&1)" \
        && tr ',' '\n' <<< "$out" | sed 's/^ *//' | grep -qx -- "$4"; then
        pass "$1 ($out)"
    else
        fail "$1 (got: $out)"
    fi
}

echo "shlib-deps.sh soname mapping self-test (issues #219, #515)"
expect_entry "deb: libxml2.so.2 -> libxml2" deb libxml2.so.2 libxml2
expect_entry "deb: libxml2.so.16 -> libxml2-16 (Ubuntu 26.04)" deb libxml2.so.16 libxml2-16
expect_entry "rpm: libxml2.so.2 -> libxml2" rpm libxml2.so.2 libxml2
expect_entry "rpm: libxml2.so.16 -> libxml2" rpm libxml2.so.16 libxml2

rc=0
fixture libxml2.so.3
sh "$HELPER" deb "$FIXTURE" > "$WORK/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -q "unmapped soname 'libxml2.so.3'" "$WORK/out"; then
    pass "deb: an unknown libxml2 soname is refused, not guessed (exit 2)"
else
    fail "deb: libxml2.so.3 should exit 2 as unmapped (exit $rc: $(cat "$WORK/out"))"
fi

if [ "$FAILS" -ne 0 ]; then
    echo "✗ ${FAILS} shlib-deps check(s) failed"
    exit 1
fi
echo "✓ shlib-deps.sh maps each libxml2 soname to its package"
