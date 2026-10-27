#!/usr/bin/env bash
#
# lint-commented-code.sh — no commented-out code blocks (issue #232,
# F-DEAD-007/F-CLEAN-016; helper committed under issue #190).
#
# Runs of MIN_RUN (2) or more consecutive commented-out statement lines are real
# code that stopped compiling the day they were commented — they drift out
# of sync silently and some record decisions the code still needs. Task 5.8
# deletes them and files genuine open questions as issues.
#
# A "commented statement line" is a line that is comment text — inside a //
# line comment or a /* */ block — and whose content looks like C: it ends in
# `;` or `{`/`}`, or starts with a control keyword (if/for/while/return/
# switch/else). Banner art, prose and license headers do not match.
#
# The number of such runs is ratcheted: it must not exceed the committed
# baseline in tools/ci/commented-code-ratchet.txt (override the path with
# $COMMENTED_CODE_RATCHET). A rise fails; a drop is reported so the baseline
# can be tightened in the same change.
#
# Exit codes: 0 = within the ratchet, 1 = blocks rose above it,
#             2 = helper broken (missing tool, list or baseline).
#
# Usage: bash tools/ci/lint-commented-code.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
    echo "✗ python3 is required" >&2
    exit 2
fi

MIN_RUN=2   # consecutive commented-out statement lines that make a block
RATCHET="${COMMENTED_CODE_RATCHET:-tools/ci/commented-code-ratchet.txt}"

if [ ! -f "$RATCHET" ] || [ ! -r "$RATCHET" ]; then
    echo "✗ ratchet baseline not found: $RATCHET" >&2
    exit 2
fi
# First non-comment line of the baseline file is the recorded count.
baseline="$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "$RATCHET")"
if ! [[ "$baseline" =~ ^[0-9]+$ ]]; then
    echo "✗ ratchet baseline unreadable: $RATCHET" >&2
    echo "    expected a bare integer on the first non-comment line" >&2
    exit 2
fi

# Vendored sources (tools/ci/vendor-paths.txt) are excluded by configuration.
# shellcheck source=tools/ci/vendor-paths-lib.sh
. "$ROOT/tools/ci/vendor-paths-lib.sh"
vendor_paths_load "$VENDOR_LIST" || exit 2
vendor_excludes=()
for p in "${VENDOR_PATHS[@]}"; do
    vendor_excludes+=(":!:$p")
done

# A private mktemp file, not a predictable /tmp/<name>.$$ path (issue #508).
TRACKED="$(mktemp)"
TOTALS="$(mktemp)"
trap 'rm -f "$TRACKED" "$TOTALS"' EXIT
git ls-files -z 'src/*.[ch]' ':!:src/mmt_mobile/asn1c/*' "${vendor_excludes[@]}" > "$TRACKED"

python3 - "$TRACKED" "$MIN_RUN" "$TOTALS" <<'PYEOF' || { echo "✗ commented-code scan failed" >&2; exit 2; }
import re
import sys

MIN_RUN = int(sys.argv[2])

tracked = [p.decode("utf-8", "surrogateescape")
           for p in open(sys.argv[1], "rb").read().split(b"\0") if p]

STMT = re.compile(
    r'(;|\{|\}|\)\s*;)\s*$'                       # ends like a statement/block
    r'|^\s*(if|for|while|switch|return|else|do|case|break|continue)\b'
    r'|^\s*[\w\*]+\s+[\w\*]+\s*='                # declaration/assignment
)


def looks_like_code(text):
    text = text.strip()
    if not text:
        return False
    return bool(STMT.search(text))


def scan(path):
    """Yield (start_line, length) runs of commented-out statement lines."""
    runs = []
    in_block = False
    run_start = 0
    run = 0
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return runs
    for n, line in enumerate(lines, 1):
        s = line.strip()
        comment_text = None
        if in_block:
            end = s.find("*/")
            comment_text = s[:end] if end >= 0 else s
            if end >= 0:
                in_block = False
            comment_text = comment_text.lstrip("*").strip()
        elif s.startswith("//"):
            comment_text = s[2:].strip()
        elif s.startswith("/*"):
            end = s.find("*/", 2)
            if end >= 0:
                comment_text = s[2:end].strip()      # one-line block comment
            else:
                in_block = True
                comment_text = s[2:].lstrip("*").strip()

        if comment_text is not None and looks_like_code(comment_text):
            if run == 0:
                run_start = n
            run += 1
        else:
            if run >= MIN_RUN:
                runs.append((run_start, run))
            run = 0
    if run >= MIN_RUN:
        runs.append((run_start, run))
    return runs


total_blocks = 0
total_lines = 0
for path in tracked:
    for start, length in scan(path):
        total_blocks += 1
        total_lines += length
        print(f"      {path}:{start}  {length} commented-out statement lines")

with open(sys.argv[3], "w") as out:
    out.write(f"{total_blocks} {total_lines}\n")
PYEOF

read -r blocks lines < "$TOTALS"
echo "    commented-out code blocks of ≥$MIN_RUN lines: $blocks ($lines lines, ratchet baseline: $baseline)"

if [ "$blocks" -gt "$baseline" ]; then
    echo "✗ commented-out code blocks rose above the ratchet: $blocks > $baseline" >&2
    echo "To fix:  delete the dead code, or file an issue for the open question it" >&2
    echo "         records and reference it; raise $RATCHET only with a" >&2
    echo "         recorded justification" >&2
    exit 1
elif [ "$blocks" -lt "$baseline" ]; then
    echo "  note: commented-out code blocks dropped below the baseline ($blocks < $baseline) —"
    echo "        tighten $RATCHET in this change to bank the progress"
else
    echo "✓ commented-out code blocks of ≥$MIN_RUN lines within the ratchet ($blocks ≤ $baseline)"
fi
