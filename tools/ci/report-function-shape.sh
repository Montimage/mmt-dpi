#!/usr/bin/env bash
#
# report-function-shape.sh — per-function size and nesting-depth report
# (issue #237, F-CLEAN-004/F-CLEAN-015; helper committed under issue #190).
#
# Structural debt concentrates in a few functions: proto_irc.c holds a
# 449-line function at nesting depth 13, and verify() in mmt_tcpip is the
# god function Task 6.3 splits. This report makes "the file is too deep" a
# measurable, reviewable claim instead of folklore.
#
# For each C source file given it prints one line per top-level function:
# its name, first line, line span and maximum brace-nesting depth inside the
# body. Function starts are detected heuristically: a `{` that takes the
# brace depth 0→1 and is not preceded by a type/keyword opener (struct,
# enum, union, typedef, if/for/while/switch, =). Good enough for a report —
# deterministic, not a parser.
#
# Vendored sources (tools/ci/vendor-paths.txt) are dropped from the input
# list here — exclusion by configuration, not by the convention of never
# passing them (issue #249, F-CLEAN-019).
#
#   default          gate mode: exit 1 when any function exceeds
#                    --max-lines (default 200) or --max-depth (default 6).
#   --report-only    print the table and always exit 0.
#
# Exit codes: 0 = pass/report written, 1 = a function exceeds a threshold,
#             2 = helper broken (missing file, no functions parsed).
#
# Usage: bash tools/ci/report-function-shape.sh [--report-only]
#               [--max-lines N] [--max-depth N] FILE [FILE...]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

REPORT_ONLY=0
MAX_LINES=200
MAX_DEPTH=6
FILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --report-only) REPORT_ONLY=1 ;;
        --max-lines)   MAX_LINES="${2:?--max-lines needs a value}"; shift ;;
        --max-depth)   MAX_DEPTH="${2:?--max-depth needs a value}"; shift ;;
        -*)            echo "✗ unknown option: $1" >&2; exit 2 ;;
        *)             FILES+=("$1") ;;
    esac
    shift
done

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "✗ no input files — usage: report-function-shape.sh [--report-only] FILE..." >&2
    exit 2
fi
# Drop vendored sources listed in tools/ci/vendor-paths.txt (issue #249,
# F-CLEAN-019): upstream code is reported on upstream, so its shape is not
# this repo's debt — the exclusion lives in configuration, not convention.
VENDOR_LIST="tools/ci/vendor-paths.txt"
[ -f "$VENDOR_LIST" ] || { echo "✗ vendored-source list not found: $VENDOR_LIST" >&2; exit 2; }
kept=()
while [ "${#FILES[@]}" -gt 0 ]; do
    f="${FILES[0]}"
    FILES=("${FILES[@]:1}")
    if grep -qxF -- "$f" "$VENDOR_LIST"; then
        echo "  note: $f is vendored ($VENDOR_LIST) — skipped"
        continue
    fi
    kept+=("$f")
done
FILES=("${kept[@]}")
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "✓ nothing to check — every input file is vendored ($VENDOR_LIST)"
    exit 0
fi
for f in "${FILES[@]}"; do
    [ -f "$f" ] || { echo "✗ file not found: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "$MAX_LINES" "$MAX_DEPTH" "$REPORT_ONLY" "${FILES[@]}" <<'PYEOF'
import re
import sys

max_lines, max_depth, report_only = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "1"
files = sys.argv[4:]

# A line that can open a function definition rather than a function body.
NONFUNC = re.compile(r'^\s*(typedef|struct|enum|union|if|for|while|switch|else|do|return)\b')
NAME = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*$')


def strip_comments_strings(line, in_block):
    out = []
    i = 0
    while i < len(line):
        two = line[i:i + 2]
        if in_block:
            end = line.find("*/", i)
            if end < 0:
                return "".join(out), True
            i = end + 2
            in_block = False
        elif two == "//":
            break
        elif two == "/*":
            in_block = True
            i += 2
        elif line[i] in "\"'":
            q = line[i]
            i += 1
            while i < len(line) and line[i] != q:
                i += 2 if line[i] == "\\" else 1
            i += 1
            out.append(' ')
        else:
            out.append(line[i])
            i += 1
    return "".join(out), in_block


def functions(path):
    """Yield (name, start_line, line_count, max_inner_depth)."""
    try:
        raw = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return
    depth = 0
    in_block = False
    fn = None              # [name, start, maxdepth]
    sig = ""               # text accumulated at depth 0 since last ';'/'{'
    for n, line in enumerate(raw, 1):
        code, in_block = strip_comments_strings(line, in_block)
        # Track the pending signature while at top level.
        if depth == 0:
            sig += " " + code
        for ch in code:
            if ch == "{":
                if depth == 0:
                    cand = sig
                    sig = ""
                    m = NAME.search(cand)
                    if m and not NONFUNC.match(cand):
                        fn = [m.group(1), n, 1]
                depth += 1
                if fn is not None:
                    fn[2] = max(fn[2], depth - 1)
            elif ch == "}":
                depth = max(0, depth - 1)
                if depth == 0 and fn is not None:
                    yield fn[0], fn[1], n - fn[1] + 1, fn[2]
                    fn = None
                    sig = ""
            elif ch == ";" and depth == 0:
                sig = ""


violations = 0
parsed_any = False
for path in files:
    fns = list(functions(path))
    if not fns:
        print(f"  {path}: no functions parsed")
        continue
    parsed_any = True
    print(f"  {path}:")
    for name, start, span, d in fns:
        mark = ""
        if span > max_lines or d > max_depth:
            mark = "  <-- exceeds limits"
            violations += 1
        print(f"    {start:>6}  {name:<50} {span:>4} lines  depth {d}{mark}")

if not parsed_any:
    print("✗ no functions parsed in any input file", file=sys.stderr)
    sys.exit(2)

if report_only:
    sys.exit(0)
if violations:
    print(f"✗ {violations} function(s) exceed the shape limits "
          f"(>{max_lines} lines or depth >{max_depth})", file=sys.stderr)
    print("To fix:  split the function (issues #233–#237), or pass"
          " --report-only to just print the table", file=sys.stderr)
    sys.exit(1)
print(f"✓ all functions within shape limits (≤{max_lines} lines, depth ≤{max_depth})")
PYEOF
