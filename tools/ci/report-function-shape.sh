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
#   --ratchet FILE   gate against a ratchet: a function over the limits
#                    passes when FILE records it (path, name) at no fewer
#                    lines and no lower depth; an unrecorded or grown one
#                    fails, and so does a recorded row whose function is
#                    within the limits now or no longer exists (delete it)
#                    or shrank below the row (tighten it). Same-named
#                    functions of one file share its row.
#   --emit-ratchet   print the ratchet rows of today's over-limit functions
#                    and exit 0 (regenerates the ratchet file's rows).
#
# With no FILE (issue #547, F-CLEAN-008/F-CLEAN-018) the report covers every
# tracked src/ C source — generated asn1c (src/mmt_mobile/asn1c/) and the
# vendored list excluded — and gates against the committed ratchet
# tools/ci/function-shape-ratchet.txt ($FUNCTION_SHAPE_RATCHET overrides it).
#
# Exit codes: 0 = pass/report written, 1 = a function exceeds a threshold
#             (or the ratchet), 2 = helper broken (missing file or ratchet,
#             malformed ratchet row, no functions parsed).
#
# Usage: bash tools/ci/report-function-shape.sh [--report-only | --emit-ratchet]
#               [--max-lines N] [--max-depth N] [--ratchet FILE] [FILE...]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

REPORT_ONLY=0
EMIT=0
MAX_LINES=200
MAX_DEPTH=6
RATCHET=""
FILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --report-only)  REPORT_ONLY=1 ;;
        --emit-ratchet) EMIT=1 ;;
        --max-lines)    MAX_LINES="${2:?--max-lines needs a value}"; shift ;;
        --max-depth)    MAX_DEPTH="${2:?--max-depth needs a value}"; shift ;;
        --ratchet)      RATCHET="${2:?--ratchet needs a file}"; shift ;;
        -*)             echo "✗ unknown option: $1" >&2; exit 2 ;;
        *)              FILES+=("$1") ;;
    esac
    shift
done

# Drop vendored sources listed in tools/ci/vendor-paths.txt: upstream code is
# reported on upstream, so its shape is not this repo's debt.
# shellcheck source=tools/ci/vendor-paths-lib.sh
. "$ROOT/tools/ci/vendor-paths-lib.sh"
vendor_paths_load "$VENDOR_LIST" || exit 2
if [ "${#FILES[@]}" -eq 0 ]; then
    # Default scope (issue #547): every tracked src/ C source, gated against
    # the committed ratchet.
    vendor_excludes=()
    for p in "${VENDOR_PATHS[@]}"; do
        vendor_excludes+=(":!:$p")
    done
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
        || { echo "✗ no input files and no git checkout to list src/ from" >&2; exit 2; }
    while IFS= read -r -d '' f; do
        FILES+=("$f")
    done < <(git ls-files -z 'src/*.c' ':!:src/mmt_mobile/asn1c/*' "${vendor_excludes[@]}")
    if [ "${#FILES[@]}" -eq 0 ]; then
        echo "✗ no tracked src/ C sources found" >&2
        exit 2
    fi
    if [ "$REPORT_ONLY" -eq 0 ] && [ "$EMIT" -eq 0 ] && [ -z "$RATCHET" ]; then
        RATCHET="${FUNCTION_SHAPE_RATCHET:-tools/ci/function-shape-ratchet.txt}"
    fi
fi
if [ -n "$RATCHET" ] && { [ ! -f "$RATCHET" ] || [ ! -r "$RATCHET" ]; }; then
    echo "✗ ratchet not found: $RATCHET" >&2
    exit 2
fi
is_vendored() {
    local v
    for v in "${VENDOR_PATHS[@]}"; do
        [ "$v" = "$1" ] && return 0
    done
    return 1
}
kept=()
while [ "${#FILES[@]}" -gt 0 ]; do
    f="${FILES[0]}"
    FILES=("${FILES[@]:1}")
    if is_vendored "$f"; then
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

python3 - "$MAX_LINES" "$MAX_DEPTH" "$REPORT_ONLY" "$EMIT" "$RATCHET" "${FILES[@]}" <<'PYEOF'
import os
import re
import sys

max_lines, max_depth, report_only = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "1"
emit, ratchet_path = sys.argv[4] == "1", sys.argv[5]
files = sys.argv[6:]

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


def load_ratchet(path):
    """{(path, name): (lines, depth)} from 'path name lines depth' rows."""
    rows = {}
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.split("#", 1)[0].split()
        if not line:
            continue
        if len(line) != 4 or not line[2].isdigit() or not line[3].isdigit():
            print(f"✗ {path}:{n}: malformed ratchet row (want: path name lines depth)",
                  file=sys.stderr)
            sys.exit(2)
        rows[(line[0], line[1])] = (int(line[2]), int(line[3]))
    return rows


ratchet = load_ratchet(ratchet_path) if ratchet_path else None
violations = 0
parsed_any = False
offenders = []
for path in files:
    fns = list(functions(path))
    if not fns:
        if not emit:
            print(f"  {path}: no functions parsed")
        continue
    parsed_any = True
    if not emit:
        print(f"  {path}:")
    for name, start, span, d in fns:
        mark = ""
        if span > max_lines or d > max_depth:
            offenders.append((path, name, span, d))
            cap = ratchet.get((path, name)) if ratchet is not None else None
            if cap is not None and span <= cap[0] and d <= cap[1]:
                mark = "  (ratcheted)"
            else:
                mark = "  <-- exceeds limits"
                violations += 1
        if not emit:
            print(f"    {start:>6}  {name:<50} {span:>4} lines  depth {d}{mark}")

if not parsed_any:
    print("✗ no functions parsed in any input file", file=sys.stderr)
    sys.exit(2)

if emit:
    for path, name, span, d in offenders:
        print(f"{path} {name} {span} {d}")
    sys.exit(0)
if report_only:
    sys.exit(0)
stale = 0
if ratchet is not None:
    scanned = set(files)
    seen = {}
    for path, name, span, d in offenders:
        prev = seen.get((path, name), (0, 0))
        seen[(path, name)] = (max(prev[0], span), max(prev[1], d))
    for key, cap in sorted(ratchet.items()):
        if key not in seen:
            # A row of a file outside the scan stays dormant; one of a scanned
            # or deleted file is stale.
            if key[0] in scanned or not os.path.exists(key[0]):
                print(f"✗ stale ratchet row: {key[0]} {key[1]} is within the limits"
                      " or gone — delete its row", file=sys.stderr)
                stale += 1
        elif seen[key][0] <= cap[0] and seen[key][1] <= cap[1] and seen[key] != cap:
            # A ratchet only moves down: bank the progress in this change.
            print(f"✗ loose ratchet row: {key[0]} {key[1]} shrank to {seen[key][0]} lines,"
                  f" depth {seen[key][1]} — tighten its row to"
                  f" '{key[0]} {key[1]} {seen[key][0]} {seen[key][1]}'", file=sys.stderr)
            stale += 1
if violations:
    print(f"✗ {violations} function(s) exceed the shape limits "
          f"(>{max_lines} lines or depth >{max_depth})"
          + (f" beyond the ratchet {ratchet_path}" if ratchet is not None else ""),
          file=sys.stderr)
    print("To fix:  split the function (issues #233–#237, #547), or pass"
          " --report-only to just print the table", file=sys.stderr)
if violations or stale:
    sys.exit(1)
if ratchet is not None:
    print(f"✓ all functions within shape limits (≤{max_lines} lines, depth ≤{max_depth})"
          f" or within the ratchet {ratchet_path} ({len(ratchet)} rows)")
else:
    print(f"✓ all functions within shape limits (≤{max_lines} lines, depth ≤{max_depth})")
PYEOF
