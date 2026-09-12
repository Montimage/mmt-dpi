#!/usr/bin/env bash
#
# lint-commented-code.sh — no commented-out code blocks (issue #232,
# F-DEAD-007/F-CLEAN-016; helper committed under issue #190).
#
# Runs of five or more consecutive commented-out statement lines are real
# code that stopped compiling the day they were commented — they drift out
# of sync silently and some record decisions the code still needs. Task 5.8
# deletes them and files genuine open questions as issues.
#
# A "commented statement line" is a line that is comment text — inside a //
# line comment or a /* */ block — and whose content looks like C: it ends in
# `;` or `{`/`}`, or starts with a control keyword (if/for/while/return/
# switch/else). Banner art, prose and license headers do not match.
#
# Exits 1 when any run of ≥ 5 such lines exists.
#
# Exit codes: 0 = clean, 1 = blocks found, 2 = helper broken.
#
# Usage: bash tools/ci/lint-commented-code.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
    echo "✗ python3 is required" >&2
    exit 2
fi

git ls-files -z 'src/*.[ch]' ':!:src/mmt_mobile/asn1c/*' > /tmp/ccode-tracked.$$
trap 'rm -f /tmp/ccode-tracked.$$' EXIT

python3 - /tmp/ccode-tracked.$$ <<'PYEOF'
import re
import sys

MIN_RUN = 5

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

if total_blocks:
    print(f"✗ {total_blocks} commented-out code block(s) "
          f"({total_lines} lines) of ≥{MIN_RUN} lines", file=sys.stderr)
    print("To fix:  delete the dead code, or file an issue for the open", file=sys.stderr)
    print("         question it records and reference it (issue #232)", file=sys.stderr)
    sys.exit(1)

print("✓ no commented-out code blocks of ≥5 lines")
PYEOF
