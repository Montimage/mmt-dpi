#!/usr/bin/env bash
#
# lint-packet-path-io.sh — no unconditional printf/fprintf on packet paths
# (issue #246, F-PERF-009; helper committed under issue #190).
#
# Packet-path code reached by network-controlled input must not write to
# stdout/stderr unconditionally: stderr is unbuffered, so each call is a
# syscall and retransmission-heavy flows collapse throughput toward the
# syscall ceiling. Logging belongs behind the SDK logger
# (src/mmt_core/private_include/mmt_log.h, issue #545): off by default,
# stderr only, rate-limited per call site.
#
# Counted (1): lines in the packet-path trees — src/mmt_core/src,
# src/mmt_tcpip/lib and, since issue #545, the protocol plugins
# src/mmt_mobile (minus the generated asn1c/ tree), src/mmt_business_app and
# src/mmt_dicom — matching a printf(/fprintf( call that is not inside a
# comment and not part of a logging-macro definition. Vendored sources listed
# in tools/ci/vendor-paths.txt are excluded by configuration (issue #249,
# F-CLEAN-019) — upstream code is pinned byte-verbatim and cannot be
# routed through the logger without breaking the pin; llhttp's
# llhttp__debug() fprintf pair is dead code with no call site in the
# generated release build.
#
# Counted (2), issue #545: a macro definition line, in a .c or .h file of
# the same trees or of src/mmt_core/private_include, that writes to stdout
# (printf(, puts(, putchar(, fprintf(stdout / xer_fprint(stdout, or
# fputs/fputc/putc/fwrite naming stdout). Only the #define line itself is
# read, not its continuation lines. The macro-definition
# exemption of (1) is how S1AP_ERROR/S1AP_WARN printed every malformed PDU
# to stdout; no SDK diagnostic may target stdout.
#
# Exits 1 when any call site is found (the condition Task 8.7 removes).
#
# Exit codes: 0 = clean, 1 = violations found, 2 = helper broken.
#
# Usage: bash tools/ci/lint-packet-path-io.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PACKET_PATH_DIRS=(src/mmt_core/src src/mmt_tcpip/lib src/mmt_mobile
                  src/mmt_business_app src/mmt_dicom)
for d in "${PACKET_PATH_DIRS[@]}" src/mmt_core/private_include; do
    [ -d "$d" ] || { echo "✗ expected source dir missing: $d" >&2; exit 2; }
done

# Vendored sources (tools/ci/vendor-paths.txt) are excluded by configuration.
# shellcheck source=tools/ci/vendor-paths-lib.sh
. "$ROOT/tools/ci/vendor-paths-lib.sh"
vendor_paths_load "$VENDOR_LIST" || exit 2
# The generated asn1c runtime is regenerated, never hand-edited (AGENTS.md).
vendor_excludes=(":!:src/mmt_mobile/asn1c")
for p in "${VENDOR_PATHS[@]}"; do
    vendor_excludes+=(":!:$p")
done

# `^[^/]*` keeps comment lines (whose first non-space char is /) out of the
# match; the second grep drops macro-definition lines. git pathspec globs
# match across directory boundaries, so lib/*.c also covers lib/protocols/.
c_specs=()
for d in "${PACKET_PATH_DIRS[@]}"; do c_specs+=("$d/*.c"); done
hits="$(git ls-files "${c_specs[@]}" "${vendor_excludes[@]}" \
    | xargs grep -nE '^[^/]*\b(printf|fprintf)[[:space:]]*\(' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#[[:space:]]*define' || true)"
# (2) stdout-writing macro definitions, headers included.
h_specs=("src/mmt_core/private_include/*.h")
for d in "${PACKET_PATH_DIRS[@]}"; do h_specs+=("$d/*.c" "$d/*.h"); done
stdout_macros="$(git ls-files "${h_specs[@]}" "${vendor_excludes[@]}" \
    | xargs grep -nE '^[[:space:]]*#[[:space:]]*define.*(\b(printf|puts|putchar)[[:space:]]*\(|\b(fprintf|xer_fprint)[[:space:]]*\([[:space:]]*stdout\b|\b(fputs|fputc|putc|fwrite)[[:space:]]*\(.*\bstdout\b)' \
    || true)"
if [ -n "$stdout_macros" ]; then
    hits="$(printf '%s\n%s\n' "$hits" "$stdout_macros")"
fi
# `grep -c .` exits 1 on a zero count, which `set -e` would turn into a
# silent failure before the success path — keep the count, swallow the status.
count="$(printf '%s\n' "$hits" | grep -c . || true)"

if [ "$count" -ne 0 ]; then
    echo "✗ $count unconditional printf/fprintf call(s) on packet-path code:" >&2
    printf '%s\n' "$hits" | awk 'NR<=30 {print "      " $0}
                                END {if (NR>30) printf "      … (%d more)\n", NR-30}' >&2
    echo "To fix:  route the write through mmt_log_* (mmt_log.h, issue #545), or delete it" >&2
    exit 1
fi
echo "✓ no unconditional printf/fprintf and no stdout-writing macro on packet-path code"
