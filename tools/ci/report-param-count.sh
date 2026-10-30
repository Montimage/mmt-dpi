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
#   --ratchet FILE   with --max: a function over N passes when FILE records
#                    it (path, name) at no fewer parameters; an unrecorded or
#                    grown one fails, and so does a recorded row whose
#                    function is within N now, no longer exists or has fewer
#                    parameters than the row (tighten it). Same-named
#                    functions of one file share its row.
#   --emit-ratchet   print the ratchet rows of today's functions over --max
#                    (default 6) and exit 0.
#
# With no FILE (issue #547, F-CLEAN-008/F-CLEAN-018) the report covers every
# tracked src/ C source — generated asn1c (src/mmt_mobile/asn1c/) and the
# vendored list (tools/ci/vendor-paths.txt) excluded — in gate mode at
# --max 6 against the committed ratchet tools/ci/param-count-ratchet.txt
# ($PARAM_COUNT_RATCHET overrides it).
#
# Exit codes: 0 = pass/report written, 1 = a function exceeds --max (or the
#             ratchet), 2 = helper broken (missing file or ratchet, malformed
#             ratchet row, no functions parsed).
#
# Usage: bash tools/ci/report-param-count.sh [--max N] [--ratchet FILE]
#               [--emit-ratchet] [FILE...]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MAX=""
RATCHET=""
EMIT=0
FILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --max)          MAX="${2:?--max needs a value}"; shift ;;
        --ratchet)      RATCHET="${2:?--ratchet needs a file}"; shift ;;
        --emit-ratchet) EMIT=1 ;;
        -*)             echo "✗ unknown option: $1" >&2; exit 2 ;;
        *)              FILES+=("$1") ;;
    esac
    shift
done

if [ "${#FILES[@]}" -eq 0 ]; then
    # Default scope (issue #547): every tracked src/ C source, gated at
    # --max 6 against the committed ratchet.
    # shellcheck source=tools/ci/vendor-paths-lib.sh
    . "$ROOT/tools/ci/vendor-paths-lib.sh"
    vendor_paths_load "$VENDOR_LIST" || exit 2
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
    MAX="${MAX:-6}"
    if [ "$EMIT" -eq 0 ] && [ -z "$RATCHET" ]; then
        RATCHET="${PARAM_COUNT_RATCHET:-tools/ci/param-count-ratchet.txt}"
    fi
fi
if [ "$EMIT" -eq 1 ]; then
    MAX="${MAX:-6}"
fi
if [ -n "$RATCHET" ]; then
    [ -n "$MAX" ] || { echo "✗ --ratchet needs --max" >&2; exit 2; }
    if [ ! -f "$RATCHET" ] || [ ! -r "$RATCHET" ]; then
        echo "✗ ratchet not found: $RATCHET" >&2
        exit 2
    fi
fi
for f in "${FILES[@]}"; do
    [ -f "$f" ] || { echo "✗ file not found: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "${MAX:-0}" "$EMIT" "$RATCHET" "${FILES[@]}" <<'PYEOF'
import os
import re
import sys

max_params = int(sys.argv[1])
emit, ratchet_path = sys.argv[2] == "1", sys.argv[3]
files = sys.argv[4:]

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


def load_ratchet(path):
    """{(path, name): params} from 'path name params' rows."""
    rows = {}
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.split("#", 1)[0].split()
        if not line:
            continue
        if len(line) != 3 or not line[2].isdigit():
            print(f"✗ {path}:{n}: malformed ratchet row (want: path name params)",
                  file=sys.stderr)
            sys.exit(2)
        rows[(line[0], line[1])] = int(line[2])
    return rows


ratchet = load_ratchet(ratchet_path) if ratchet_path else None
violations = 0
parsed_any = False
offenders = {}
for path in files:
    fns = list(functions(path))
    if not fns:
        if not emit:
            print(f"  {path}: no functions parsed")
        continue
    parsed_any = True
    if not emit:
        print(f"  {path}:")
    for name, start, count in fns:
        mark = ""
        if max_params and count > max_params:
            key = (path, name)
            offenders[key] = max(offenders.get(key, 0), count)
            cap = ratchet.get(key) if ratchet is not None else None
            if cap is not None and count <= cap:
                mark = "  (ratcheted)"
            else:
                mark = "  <-- exceeds limit"
                violations += 1
        if not emit:
            print(f"    {start:>6}  {name:<50} {count:>2} params{mark}")

if not parsed_any:
    print("✗ no functions parsed in any input file", file=sys.stderr)
    sys.exit(2)

if emit:
    for (path, name), count in offenders.items():
        print(f"{path} {name} {count}")
    sys.exit(0)
if max_params:
    stale = 0
    if ratchet is not None:
        scanned = set(files)
        for key, cap in sorted(ratchet.items()):
            if key not in offenders:
                # A row of a file outside the scan stays dormant; one of a
                # scanned or deleted file is stale.
                if key[0] in scanned or not os.path.exists(key[0]):
                    print(f"✗ stale ratchet row: {key[0]} {key[1]} is within {max_params}"
                          " parameters or gone — delete its row", file=sys.stderr)
                    stale += 1
            elif offenders[key] < cap:
                # A ratchet only moves down: bank the progress in this change.
                print(f"✗ loose ratchet row: {key[0]} {key[1]} dropped to {offenders[key]}"
                      f" parameters — tighten its row to '{key[0]} {key[1]} {offenders[key]}'",
                      file=sys.stderr)
                stale += 1
    if violations:
        print(f"✗ {violations} function(s) exceed {max_params} parameters"
              + (f" beyond the ratchet {ratchet_path}" if ratchet is not None else ""),
              file=sys.stderr)
    if violations or stale:
        sys.exit(1)
    if ratchet is not None:
        print(f"✓ all functions have at most {max_params} parameter(s)"
              f" or are within the ratchet {ratchet_path} ({len(ratchet)} rows)")
    else:
        print(f"✓ all functions have at most {max_params} parameter(s)")
PYEOF
