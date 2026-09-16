#!/usr/bin/env bash
#
# lint-packet-path-io.sh — no unconditional printf/fprintf on packet paths
# (issue #246, F-PERF-009; helper committed under issue #190).
#
# Packet-path code reached by network-controlled input must not write to
# stdout/stderr unconditionally: stderr is unbuffered, so each call is a
# syscall and retransmission-heavy flows collapse throughput toward the
# syscall ceiling. Logging belongs behind the MMT_LOG macros, which compile
# out of release builds.
#
# Counted: lines in src/mmt_core/src and src/mmt_tcpip/lib matching a
# printf(/fprintf( call that is not inside a comment and not part of a
# logging-macro definition. Vendored sources listed in
# tools/ci/vendor-paths.txt are excluded by configuration (issue #249,
# F-CLEAN-019) — upstream code is pinned byte-verbatim and cannot be
# routed through MMT_LOG without breaking the pin; llhttp's
# llhttp__debug() fprintf pair is dead code with no call site in the
# generated release build.
#
# Exits 1 when any call site is found (the condition Task 8.7 removes).
#
# Exit codes: 0 = clean, 1 = violations found, 2 = helper broken.
#
# Usage: bash tools/ci/lint-packet-path-io.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

for d in src/mmt_core/src src/mmt_tcpip/lib; do
    [ -d "$d" ] || { echo "✗ expected source dir missing: $d" >&2; exit 2; }
done

# Vendored sources are excluded by configuration, not convention
# (issue #249, F-CLEAN-019): tools/ci/vendor-paths.txt lists them.
VENDOR_LIST="tools/ci/vendor-paths.txt"
vendor_excludes=()
[ -f "$VENDOR_LIST" ] || { echo "✗ vendored-source list not found: $VENDOR_LIST" >&2; exit 2; }
while IFS= read -r p; do
    case "$p" in ''|'#'*) continue ;; esac
    vendor_excludes+=(":!:$p")
done < "$VENDOR_LIST"

# `^[^/]*` keeps comment lines (whose first non-space char is /) out of the
# match; the second grep drops macro-definition lines. git pathspec globs
# match across directory boundaries, so lib/*.c also covers lib/protocols/.
hits="$(git ls-files 'src/mmt_core/src/*.c' 'src/mmt_tcpip/lib/*.c' \
            "${vendor_excludes[@]}" \
    | xargs grep -nE '^[^/]*\b(printf|fprintf)[[:space:]]*\(' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#[[:space:]]*define' || true)"
# `grep -c .` exits 1 on a zero count, which `set -e` would turn into a
# silent failure before the success path — keep the count, swallow the status.
count="$(printf '%s\n' "$hits" | grep -c . || true)"

if [ "$count" -ne 0 ]; then
    echo "✗ $count unconditional printf/fprintf call(s) on packet-path code:" >&2
    printf '%s\n' "$hits" | awk 'NR<=30 {print "      " $0}
                                END {if (NR>30) printf "      … (%d more)\n", NR-30}' >&2
    echo "To fix:  route the write through MMT_LOG (issue #246), or delete it" >&2
    exit 1
fi
echo "✓ no unconditional printf/fprintf on packet-path code"
