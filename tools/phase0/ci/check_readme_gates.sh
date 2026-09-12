#!/usr/bin/env bash
#
# check_readme_gates.sh — keep the "CI gate" job list in tools/phase0/README.md
# truthful by generating it from .github/workflows/phase0-baseline.yml
# (issue #186, F-TEST-017).
#
# The README section used to be hand-maintained and drifted: it listed three
# gates while the workflow defined more, and said nothing about the harnesses
# gated by nothing. The block between
#   <!-- begin-generated: ci-gates -->  /  <!-- end-generated: ci-gates -->
# is produced by this script — edit the workflow, then run with --write.
#
#   default (check)  exit 1 when the committed block differs from a fresh
#                    generation (stale doc), 0 when in sync.
#   --write          rewrite the block in place, then exit 0.
#
# Exit codes: 0 = in sync / written, 1 = stale block, 2 = helper broken.
#
# Usage: bash tools/phase0/ci/check_readme_gates.sh [--write]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WORKFLOW="${ROOT}/.github/workflows/phase0-baseline.yml"
README="${ROOT}/tools/phase0/README.md"
TEST_DIR="${ROOT}/tools/phase0/tests"
BEGIN='<!-- begin-generated: ci-gates -->'
END='<!-- end-generated: ci-gates -->'

WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

for f in "$WORKFLOW" "$README"; do
    [ -f "$f" ] || { echo "✗ $f missing" >&2; exit 2; }
done
if ! grep -qF "$BEGIN" "$README" || ! grep -qF "$END" "$README"; then
    echo "✗ generated-block markers not found in README" >&2
    exit 2
fi

gen_block() {
    # Job ids are the 2-space keys inside the workflow's jobs: block; the gate
    # label is the job's `name:` (falling back to the id).
    awk '
        /^jobs:/ { injobs = 1; next }
        injobs && /^[a-zA-Z_]/ { injobs = 0 }
        injobs && match($0, /^  ([a-z0-9_-]+):[[:space:]]*$/, m) {
            id = m[1]; order[++n] = id; names[id] = id
        }
        injobs && id != "" && match($0, /^    name:[[:space:]]+(.+)/, m) {
            names[id] = m[1]; id = ""
        }
        END {
            for (i = 1; i <= n; i++) {
                id = order[i]
                label = (id == "harness") ? "harness-*" : id
                printf "- `%s` — %s\n", label, names[id]
            }
        }
    ' "$WORKFLOW"
    # The `harness` job is a matrix over every tools/phase0/tests/run_*.sh —
    # spell out the fan-out so the count is auditable from the doc alone.
    local count
    count=$(find "$TEST_DIR" -maxdepth 1 -name 'run_*.sh' | wc -l)
    printf '%s\n' "- matrix expansion: \`harness-*\` fans out to ${count} jobs, one per \`tools/phase0/tests/run_*.sh\`"
}

BLOCK="$(gen_block)" || exit 2

current() {
    awk -v b="$BEGIN" -v e="$END" '
        $0 == b { inf = 1; next }
        $0 == e { inf = 0 }
        inf { print }
    ' "$README"
}

if [ "$WRITE" -eq 1 ]; then
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    awk -v b="$BEGIN" -v e="$END" -v block="$BLOCK" '
        $0 == b { print; print block; skip = 1; next }
        skip && $0 == e { skip = 0; print; next }
        !skip { print }
    ' "$README" > "$tmp"
    cat "$tmp" > "$README"
    echo "✓ README ci-gates block regenerated"
    exit 0
fi

if [ "$(current)" = "$BLOCK" ]; then
    echo "✓ README ci-gates block is in sync with phase0-baseline.yml"
    exit 0
fi

echo "✗ README ci-gates block is stale — regenerate with:" >&2
echo "    bash tools/phase0/ci/check_readme_gates.sh --write" >&2
diff <(current) <(printf '%s\n' "$BLOCK") >&2 || true
exit 1
