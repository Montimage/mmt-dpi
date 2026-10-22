#!/usr/bin/env bash
#
# check-package-split.sh — the two built packages carry their licence files
# and split the payload as declared (issue #497, F-CI-109).
#
# mmt-dpi ships the SDK under Apache-2.0 AND BSD-2-Clause AND MIT;
# mmt-dpi-security ships the ENABLESEC engines (libmmt_security is
# GPL-3.0-or-later). A path the split misses would put the GPL library back
# into mmt-dpi — and rpm generates build-id links on its own, which a
# /opt/mmt/* glob with %exclude lines once leaked into the main package — so
# this checks the built artifacts themselves:
#   - each package lists <prefix>/dpi/share/doc/<package>/LICENSE and
#     THIRD-PARTY-NOTICES, and its THIRD-PARTY-NOTICES is the committed file
#   - mmt-dpi-security holds libmmt_security, libmmt_fuzz, the fuzz headers
#     and the GPL text as COPYING
#   - mmt-dpi holds none of them, nor a build-id link pointing at one
#   - .rpm: `rpm -qp --qf '%{LICENSE}'` prints PKG_LICENSE / SEC_PKG_LICENSE
#     from sdk/Makefile
#
# Usage: check-package-split.sh <mmt-dpi.deb|.rpm> <mmt-dpi-security.deb|.rpm>
# Exit codes: 0 = holds, 1 = violation, 2 = bad usage / tool missing.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MAIN="${1:-}"
SEC="${2:-}"
if [ -z "$MAIN" ] || [ -z "$SEC" ] || [ ! -f "$MAIN" ] || [ ! -f "$SEC" ]; then
    echo "usage: $0 <mmt-dpi package> <mmt-dpi-security package>" >&2
    exit 2
fi
case "$MAIN" in *.deb) KIND=deb ;; *.rpm) KIND=rpm ;; *) echo "✗ not a .deb/.rpm: $MAIN" >&2; exit 2 ;; esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAIL=0
ok()  { echo "  ✓ $1"; }
bad() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

# list <pkg> — one payload path per line, without a leading '.'.
list() {
    if [ "$KIND" = deb ]; then
        dpkg-deb -c "$1" | awk '{print $6}' | sed 's|^\./|/|'
    else
        rpm -qlp "$1"
    fi
}

# extract <pkg> <dir>
extract() {
    mkdir -p "$2"
    if [ "$KIND" = deb ]; then
        dpkg-deb -x "$1" "$2"
    elif command -v cpio >/dev/null 2>&1; then
        rpm2cpio "$1" | (cd "$2" && cpio -idm --quiet)
    else
        # rpm2archive with no argument reads stdin and writes a tar.gz.
        rpm2archive < "$1" | tar -xz -C "$2"
    fi
}

list "$MAIN" > "$WORK/main.list"
list "$SEC" > "$WORK/sec.list"

for pair in "mmt-dpi:$MAIN:main" "mmt-dpi-security:$SEC:sec"; do
    IFS=: read -r name pkg tag <<< "$pair"
    for f in LICENSE THIRD-PARTY-NOTICES; do
        if grep -q "/dpi/share/doc/${name}/${f}\$" "$WORK/$tag.list"; then
            ok "$(basename "$pkg") lists ${name}/${f}"
        else
            bad "$(basename "$pkg") does not list dpi/share/doc/${name}/${f}"
        fi
    done
    extract "$pkg" "$WORK/$tag"
    notice="$(find "$WORK/$tag" -path "*/share/doc/${name}/THIRD-PARTY-NOTICES" -type f | head -1)"
    # sha256sum (coreutils), not cmp: minimal rpm images ship no diffutils.
    if [ -n "$notice" ] && [ "$(sha256sum < "$notice")" = "$(sha256sum < "$ROOT/THIRD-PARTY-NOTICES")" ]; then
        ok "$(basename "$pkg"): THIRD-PARTY-NOTICES is the committed file"
    else
        bad "$(basename "$pkg"): THIRD-PARTY-NOTICES missing or not the committed file"
    fi
done

for pat in '/libmmt_security\.so\.' '/libmmt_fuzz\.so\.' '/include/fuzz/' '/dpi/share/doc/mmt-dpi-security/COPYING$'; do
    if grep -Eq "$pat" "$WORK/sec.list"; then
        ok "mmt-dpi-security holds ${pat}"
    else
        bad "mmt-dpi-security lacks ${pat}"
    fi
done
if grep -Eq 'libmmt_(security|fuzz)|/include/fuzz|mmt-dpi-security|/COPYING$' "$WORK/main.list"; then
    bad "mmt-dpi still holds engine files: $(grep -E 'libmmt_(security|fuzz)|/include/fuzz|mmt-dpi-security|/COPYING$' "$WORK/main.list" | head -5 | tr '\n' ' ')"
else
    ok "mmt-dpi holds no engine file"
fi
leaked="$(find "$WORK/main" -path '*/.build-id/*' -type l -printf '%l\n' | grep -E 'libmmt_(security|fuzz)' || true)"
if [ -n "$leaked" ]; then
    bad "mmt-dpi carries build-id links to engine libraries: $(echo "$leaked" | tr '\n' ' ')"
else
    ok "mmt-dpi carries no build-id link to an engine library"
fi

if [ "$KIND" = rpm ]; then
    for pair in "PKG_LICENSE:$MAIN" "SEC_PKG_LICENSE:$SEC"; do
        var="${pair%%:*}"; pkg="${pair#*:}"
        want="$(sed -n "s/^${var}[[:space:]]*:=[[:space:]]*//p" "$ROOT/sdk/Makefile" | head -1)"
        got="$(rpm -qp --qf '%{LICENSE}' "$pkg")"
        if [ -n "$want" ] && [ "$got" = "$want" ]; then
            ok "$(basename "$pkg"): License: $got"
        else
            bad "$(basename "$pkg"): License: '$got', sdk/Makefile $var is '$want'"
        fi
    done
fi

if [ "$FAIL" -gt 0 ]; then
    echo "✗ $FAIL package-split violation(s)" >&2
    exit 1
fi
echo "✓ package split and licence files hold ($KIND)"
