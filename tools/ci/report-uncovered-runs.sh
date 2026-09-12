#!/usr/bin/env bash
#
# report-uncovered-runs.sh — contiguous uncovered-line runs from lcov
# coverage.info (issue #243, F-TEST-018; helper committed under issue #190).
#
# Per-line coverage % hides the real signal: a file can be 90% covered and
# still carry a 40-line error path nobody ever executes. This report lists
# contiguous runs of lines whose hit count is 0 — the gaps a reviewer should
# actually look at.
#
# Input: an lcov tracefile (default tests/coverage/coverage.info, produced by
# `bash tests/run_all_tests.sh --coverage`).
#
#   default          gate mode: exit 1 when any contiguous uncovered run is
#                    longer than --max-run (default 10) lines.
#   --report-only    print the table and always exit 0.
#
# Exit codes: 0 = pass/report written, 1 = a run exceeds the limit,
#             2 = helper broken (missing/empty tracefile).
#
# Usage: bash tools/ci/report-uncovered-runs.sh [--report-only]
#               [--max-run N] [coverage.info]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

REPORT_ONLY=0
MAX_RUN=10
TRACE="tests/coverage/coverage.info"
while [ $# -gt 0 ]; do
    case "$1" in
        --report-only) REPORT_ONLY=1 ;;
        --max-run)     MAX_RUN="${2:?--max-run needs a value}"; shift ;;
        -*)            echo "✗ unknown option: $1" >&2; exit 2 ;;
        *)             TRACE="$1" ;;
    esac
    shift
done

if [ ! -s "$TRACE" ]; then
    echo "✗ lcov tracefile missing or empty: $TRACE" >&2
    echo "To fix:  run 'bash tests/run_all_tests.sh --coverage' first" >&2
    exit 2
fi
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "$TRACE" "$MAX_RUN" "$REPORT_ONLY" <<'PYEOF'
import sys

trace, max_run, report_only = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"

records = []          # (file, start, length)
cur_file = None
run_start = None
run_len = 0
saw_da = False


def flush():
    global run_start, run_len
    if run_start is not None:
        records.append((cur_file, run_start, run_len))
        run_start = None
        run_len = 0


for line in open(trace, encoding="utf-8", errors="replace"):
    line = line.strip()
    if line.startswith("SF:"):
        flush()
        cur_file = line[3:]
    elif line.startswith("DA:"):
        saw_da = True
        try:
            lineno, hits = line[3:].split(",")[:2]
            lineno = int(lineno)
            hits = int(float(hits))
        except ValueError:
            continue
        if hits == 0:
            if run_start is None:
                run_start = lineno
                run_len = 1
            elif lineno == run_start + run_len:
                run_len += 1
            else:
                flush()
                run_start = lineno
                run_len = 1
        else:
            flush()
    elif line == "end_of_record":
        flush()
        cur_file = None
flush()

if not saw_da:
    print(f"✗ no DA records in {trace} — is it an lcov tracefile?", file=sys.stderr)
    sys.exit(2)

long_runs = [r for r in records if r[2] > max_run]
for f, start, length in sorted(long_runs, key=lambda r: -r[2]):
    print(f"    {f}:{start}  {length} uncovered lines")

print(f"    {len(records)} uncovered run(s) total; "
      f"{len(long_runs)} longer than {max_run} lines")

if report_only:
    sys.exit(0)
if long_runs:
    print(f"✗ {len(long_runs)} contiguous uncovered run(s) longer than"
          f" {max_run} lines", file=sys.stderr)
    print("To fix:  cover the run, or pass --report-only to just print"
          " the table (issue #243)", file=sys.stderr)
    sys.exit(1)
print(f"✓ no contiguous uncovered run longer than {max_run} lines")
PYEOF
