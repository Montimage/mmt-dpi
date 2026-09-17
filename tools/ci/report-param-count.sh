#!/usr/bin/env bash
#
# report-param-count.sh — per-function parameter-count report
# (issue #233, F-CLEAN-002/F-CLEAN-003).
#
# Long parameter lists are the other half of the shape debt tracked by
# report-function-shape.sh: verify() held the record at 9 parameters until
# Task 6.2 threaded its invariant arguments through a context struct. This
# report makes "the signature is too wide" a measurable, reviewable claim —
# the committed snapshot for the src/mmt_security/tips*.c units lives at
# tools/ci/param-count-tips.txt and the remaining >6-parameter functions
# there are Task 6.5 scope.
#
# For each C source file given it prints one line per top-level function:
# its name, first line and parameter count. Function starts are detected
# with the same heuristic as report-function-shape.sh: a `{` that takes the
# brace depth 0→1 and is not preceded by a type/keyword opener. The count
# splits the signature's outermost parenthesised list on commas at
# parenthesis depth 1, so function-pointer parameters do not inflate it.
#
#   default          print the table and exit 0.
#   --max N          gate mode: exit 1 when any function exceeds N
#                    parameters.
#
# Exit codes: 0 = pass/report written, 1 = a function exceeds --max,
#             2 = helper broken (missing file, no functions parsed).
#
# Usage: bash tools/ci/report-param-count.sh [--max N] FILE [FILE...]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MAX=""
FILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --max)  MAX="${2:?--max needs a value}"; shift ;;
        -*)     echo "✗ unknown option: $1" >&2; exit 2 ;;
        *)      FILES+=("$1") ;;
    esac
    shift
done

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "✗ no input files — usage: report-param-count.sh [--max N] FILE..." >&2
    exit 2
fi
for f in "${FILES[@]}"; do
    [ -f "$f" ] || { echo "✗ file not found: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "${MAX:-0}" "${FILES[@]}" <<'PYEOF'
import re
import sys

max_params = int(sys.argv[1])
files = sys.argv[2:]

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


def param_count(sig):
    """Count commas at depth 1 inside the signature's last (...) group."""
    start = sig.rfind("(")
    if start < 0:
        return 0
    depth = 0
    commas = 0
    inner = ""
    for ch in sig[start:]:
        if ch == "(":
            depth += 1
            if depth > 1:
                inner += ch
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
            inner += ch
        elif ch == "," and depth == 1:
            commas += 1
        elif depth >= 1:
            inner += ch
    if not inner.strip() or inner.strip() == "void":
        return 0
    return commas + 1


def functions(path):
    """Yield (name, start_line, param_count)."""
    try:
        raw = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return
    depth = 0
    in_block = False
    sig = ""
    for n, line in enumerate(raw, 1):
        code, in_block = strip_comments_strings(line, in_block)
        if depth == 0:
            sig += " " + code
        for ch in code:
            if ch == "{":
                if depth == 0:
                    cand = sig
                    sig = ""
                    m = NAME.search(cand)
                    if m and not NONFUNC.match(cand):
                        yield m.group(1), n, param_count(cand)
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
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
    for name, start, count in fns:
        mark = ""
        if max_params and count > max_params:
            mark = "  <-- exceeds limit"
            violations += 1
        print(f"    {start:>6}  {name:<50} {count:>2} params{mark}")

if not parsed_any:
    print("✗ no functions parsed in any input file", file=sys.stderr)
    sys.exit(2)

if max_params:
    if violations:
        print(f"✗ {violations} function(s) exceed {max_params} parameters",
              file=sys.stderr)
        sys.exit(1)
    print(f"✓ all functions have at most {max_params} parameter(s)")
PYEOF
