#!/bin/bash
# Issue #557 (F-PERF-102): the compiled-in IPv4 attribution table is generated
# from the versioned data file data/ip_ranges.txt by tools/gen-ip-range-table.py
# as a sorted array of disjoint intervals. This check fails when the committed
# .inc is not what the generator emits, proves the generator refuses the data
# faults it guards against (missing or malformed version header, duplicate
# prefix, unknown protocol id, host bits set, prefix out of range, malformed
# line) and flags a stale .inc, and checks the flattening of nested prefixes.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GEN="$PROJECT_DIR/tools/gen-ip-range-table.py"
fails=0
checks=0

ok() { checks=$((checks + 1)); echo "  ✓ $1"; }
ko() { checks=$((checks + 1)); fails=$((fails + 1)); echo "  ✗ $1"; }

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 1; }

if python3 "$GEN" --check; then
    ok "committed .inc equals the generator output"
else
    ko "committed .inc is stale"
fi

T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT
cat > "$T/protos.h" <<'EOF'
#define PROTO_UNKNOWN 0
#define PROTO_ALPHA 10
#define PROTO_BETA  11
#define PROTO_HUGE  70000
EOF

# expect_reject NAME PATTERN: the data in $T/NAME.txt must exit 1, write
# nothing and name the fault (PATTERN, an extended regex) on stderr.
expect_reject() {
    local name="$1" pattern="$2" rc=0
    rm -f "$T/out.inc"
    python3 "$GEN" --data "$T/$name.txt" --header "$T/protos.h" \
        --output "$T/out.inc" 2> "$T/err.txt" >/dev/null || rc=$?
    if [ "$rc" -eq 1 ] && [ ! -e "$T/out.inc" ] && grep -Eq "$pattern" "$T/err.txt"; then
        ok "rejects $name"
    else
        ko "rejects $name (exit $rc): $(cat "$T/err.txt")"
    fi
}

printf '10.0.0.0/8 PROTO_ALPHA\n' > "$T/no_version.txt"
expect_reject no_version "no '# version"
printf '# version: 2026-13-01\n10.0.0.0/8 PROTO_ALPHA\n' > "$T/bad_date.txt"
expect_reject bad_date "not a YYYY-MM-DD date"
printf '10.0.0.0/8 PROTO_ALPHA\n# version: 2026-10-31\n' > "$T/late_version.txt"
expect_reject late_version "must precede the entries"
printf '# version: 2026-10-31\n10.0.0.0/8 PROTO_ALPHA\n10.0.0.0/8 PROTO_BETA\n' > "$T/duplicate.txt"
expect_reject duplicate ":3: 10.0.0.0/8 already listed at line 2"
printf '# version: 2026-10-31\n10.0.0.0/8 PROTO_GAMMA\n' > "$T/unknown_proto.txt"
expect_reject unknown_proto "'PROTO_GAMMA' is not a PROTO_\\* id"
printf '# version: 2026-10-31\n10.0.0.0/8 PROTO_UNKNOWN\n' > "$T/zero_proto.txt"
expect_reject zero_proto "'PROTO_UNKNOWN' is not a PROTO_\\* id"
printf '# version: 2026-10-31\n10.0.0.0/8 PROTO_HUGE\n' > "$T/wide_proto.txt"
expect_reject wide_proto "'PROTO_HUGE' is not a PROTO_\\* id"
printf '# version: 2026-10-31\n10.0.0.1/8 PROTO_ALPHA\n' > "$T/host_bits.txt"
expect_reject host_bits "has host bits set \\(network 10.0.0.0/8\\)"
printf '# version: 2026-10-31\n10.0.0.0/0 PROTO_ALPHA\n' > "$T/prefix_zero.txt"
expect_reject prefix_zero "outside 1..32"
printf '# version: 2026-10-31\n10.0.0.0/33 PROTO_ALPHA\n' > "$T/prefix_wide.txt"
expect_reject prefix_wide "outside 1..32"
printf '# version: 2026-10-31\n10.0.256.0/24 PROTO_ALPHA\n' > "$T/bad_octet.txt"
expect_reject bad_octet "not a dotted-quad"
printf '# version: 2026-10-31\n2001:db8::/32 PROTO_ALPHA\n' > "$T/ipv6.txt"
expect_reject ipv6 "not a dotted-quad"
printf '# version: 2026-10-31\n10.0.0.0/8 PROTO_ALPHA override\n' > "$T/three_fields.txt"
expect_reject three_fields "expected \"<network>/<prefix> <PROTO_ID>\""

# Nested prefixes flatten into disjoint intervals with the longest prefix
# inside, adjacent equal intervals merge, uncovered space is an UNKNOWN
# interval, and the table starts at 0.0.0.0; the prefix table keeps file order.
printf '%s\n' '# version: 2026-10-31' '# a comment' '' \
    '10.1.0.0/16 PROTO_BETA' '10.0.0.0/8 PROTO_ALPHA' '10.1.2.0/24 PROTO_ALPHA' \
    '10.1.3.0/24 PROTO_ALPHA' '255.255.255.255/32 PROTO_BETA' > "$T/good.txt"
cat > "$T/want.txt" <<'EOF'
    {0x00000000u, PROTO_UNKNOWN, 0},
    {0x0a000000u, PROTO_ALPHA, 8}, /* 10.0.0.0/8 */
    {0x0a010000u, PROTO_BETA, 16}, /* 10.1.0.0/16 */
    {0x0a010200u, PROTO_ALPHA, 24}, /* 10.1.2.0/24 */
    {0x0a010400u, PROTO_BETA, 16}, /* 10.1.0.0/16 */
    {0x0a020000u, PROTO_ALPHA, 8}, /* 10.0.0.0/8 */
    {0x0b000000u, PROTO_UNKNOWN, 0},
    {0xffffffffu, PROTO_BETA, 32}, /* 255.255.255.255/32 */
EOF
if python3 "$GEN" --data "$T/good.txt" --header "$T/protos.h" --output "$T/good.inc" \
        --prefix-table "$T/prefixes.inc" >/dev/null \
    && grep -q 'version 2026-10-31' "$T/good.inc" \
    && grep -q '^#define IP_RANGE_INTERVAL_COUNT 8$' "$T/good.inc" \
    && grep '^    {0x' "$T/good.inc" | diff -u "$T/want.txt" - \
    && [ "$(grep -c '^    {[0-9]' "$T/prefixes.inc")" -eq 6 ] \
    && grep '^    {[0-9]' "$T/prefixes.inc" | head -n 2 | diff -u - <(printf '%s\n' \
        '    {16, 0xffff0000u, 0x0a010000u, PROTO_BETA},' \
        '    {8, 0xff000000u, 0x0a000000u, PROTO_ALPHA},'); then
    ok "flattens nested prefixes into disjoint, merged intervals"
else
    ko "flattens nested prefixes into disjoint, merged intervals"
fi
if python3 "$GEN" --check --data "$T/good.txt" --header "$T/protos.h" --output "$T/good.inc" >/dev/null; then
    ok "--check passes on fresh output"
else
    ko "--check passes on fresh output"
fi
sed -i 's/PROTO_BETA, 16}/PROTO_ALPHA, 16}/' "$T/good.inc"
rc=0
python3 "$GEN" --check --data "$T/good.txt" --header "$T/protos.h" --output "$T/good.inc" \
    >/dev/null 2>"$T/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -q "is stale" "$T/err.txt"; then
    ok "--check flags a hand-edited .inc"
else
    ko "--check flags a hand-edited .inc (exit $rc)"
fi

if [ "$fails" -ne 0 ]; then
    echo "IP-range table generator: $fails/$checks checks failed"
    exit 1
fi
echo "IP-range table generator: all $checks checks passed"
