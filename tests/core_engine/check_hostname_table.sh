#!/bin/bash
# Issue #566 (F-BUG-310): the hostname-suffix table is generated from the
# versioned data file data/hostnames.txt by tools/gen-hostname-table.py.
# This check fails when the committed .inc is not what the generator emits,
# and proves the generator refuses the data faults it guards against
# (missing or malformed version header, duplicate suffix, unknown protocol
# id, uppercase or dotless suffix, malformed line) and flags a stale .inc.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GEN="$PROJECT_DIR/tools/gen-hostname-table.py"
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

printf '.alpha.example PROTO_ALPHA\n' > "$T/no_version.txt"
expect_reject no_version "no '# version"
printf '# version: 2026-13-01\n.alpha.example PROTO_ALPHA\n' > "$T/bad_date.txt"
expect_reject bad_date "not a YYYY-MM-DD date"
printf '# version: 20261031\n.alpha.example PROTO_ALPHA\n' > "$T/basic_date.txt"
expect_reject basic_date "not a YYYY-MM-DD date"
printf '.alpha.example PROTO_ALPHA\n# version: 2026-10-31\n' > "$T/late_version.txt"
expect_reject late_version "must precede the entries"
printf '# version: 2026-10-31\n.a.example PROTO_ALPHA\n.a.example PROTO_BETA\n' > "$T/duplicate.txt"
expect_reject duplicate ":3: suffix '.a.example' already listed at line 2"
printf '# version: 2026-10-31\n.a.example PROTO_GAMMA\n' > "$T/unknown_proto.txt"
expect_reject unknown_proto "'PROTO_GAMMA' is not a PROTO_\\* id"
printf '# version: 2026-10-31\n.a.example PROTO_UNKNOWN\n' > "$T/zero_proto.txt"
expect_reject zero_proto "'PROTO_UNKNOWN' is not a PROTO_\\* id"
printf '# version: 2026-10-31\n.A.example PROTO_ALPHA\n' > "$T/uppercase.txt"
expect_reject uppercase "must be lowercase"
printf '# version: 2026-10-31\na.example PROTO_ALPHA\n' > "$T/no_dot.txt"
expect_reject no_dot "must start with '\\.'"
printf '# version: 2026-10-31\n.a.example PROTO_ALPHA 9\n' > "$T/three_fields.txt"
expect_reject three_fields "expected \"<suffix> <PROTO_ID>\""

# A valid file: lengths are computed, order and the sentinel are kept, and
# --check passes on the fresh output and fails once the output drifts.
printf '# version: 2026-10-31\n# a comment\n\n.beta.example PROTO_BETA\n.a.example PROTO_ALPHA\n' > "$T/good.txt"
if python3 "$GEN" --data "$T/good.txt" --header "$T/protos.h" --output "$T/good.inc" >/dev/null \
    && grep -q 'version 2026-10-31' "$T/good.inc" \
    && [ "$(grep -c '^    {"' "$T/good.inc")" -eq 2 ] \
    && grep -A1 '{".beta.example", PROTO_BETA,13},' "$T/good.inc" | grep -q '{".a.example", PROTO_ALPHA,10},' \
    && grep -q '^    { NULL, 0, 0}$' "$T/good.inc"; then
    ok "generates entries in file order with computed lengths"
else
    ko "generates entries in file order with computed lengths"
fi
if python3 "$GEN" --check --data "$T/good.txt" --header "$T/protos.h" --output "$T/good.inc" >/dev/null; then
    ok "--check passes on fresh output"
else
    ko "--check passes on fresh output"
fi
sed -i 's/PROTO_ALPHA,10/PROTO_ALPHA,11/' "$T/good.inc"
rc=0
python3 "$GEN" --check --data "$T/good.txt" --header "$T/protos.h" --output "$T/good.inc" \
    >/dev/null 2>"$T/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -q "is stale" "$T/err.txt"; then
    ok "--check flags a hand-edited .inc"
else
    ko "--check flags a hand-edited .inc (exit $rc)"
fi

if [ "$fails" -ne 0 ]; then
    echo "Hostname-table generator: $fails/$checks checks failed"
    exit 1
fi
echo "Hostname-table generator: all $checks checks passed"
