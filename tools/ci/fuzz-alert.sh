#!/usr/bin/env bash
#
# fuzz-alert.sh — give a failed scheduled fuzz run an owner (issue #486).
#
# The weekly fuzz job draws a fresh seed per run, so a crash it finds is
# gone from the next run; before this script the only trace was an artifact
# that expired after 14 days with no issue filed. Run by the `fuzz-alert`
# job of .github/workflows/c-cpp.yml when the scheduled `fuzz` job fails, it
# opens an issue — or, when one with the same title is still open, comments
# on it — carrying what reproduces the finding without the artifact: the
# exact mutate.py command, the exit verdict and the head of the sanitizer
# report of every reproducer, plus the run and artifact links.
#
# Usage: bash tools/ci/fuzz-alert.sh <artifacts-dir> <run-url> [--dry-run]
#   <artifacts-dir>  the downloaded fuzz-reproducers artifact (may be empty:
#                    the job can fail before any finding, e.g. a build break)
#   <run-url>        link to the failed workflow run
#   --dry-run        print the title, the action and the body; call nothing
#
# Needs `gh` with GH_TOKEN (issues: write) and GH_REPO in the environment.
# Exit: 0 = issue opened/updated (or dry run), 2 = usage or gh failure.

set -euo pipefail

TITLE="Scheduled fuzz run failed"
LOG_LINES=40
MAX_LOGS=3
# GitHub rejects an issue or comment body over 65,536 characters; keep a
# margin so a run with many large ASan reports still files its issue.
MAX_BODY=60000

[ $# -ge 2 ] || { echo "usage: $0 <artifacts-dir> <run-url> [--dry-run]" >&2; exit 2; }
ART="$1"; RUN_URL="$2"; DRY=0
[ "${3:-}" = "--dry-run" ] && DRY=1

BODY="$(mktemp)"
trap 'rm -f "${BODY}"' EXIT

{
    echo "The scheduled fuzz job failed: ${RUN_URL}"
    echo ""
    echo "Reproducers and full logs: artifact \`fuzz-reproducers\` of that run (kept 90 days)."
    echo "Regenerate a mutant with the \`mutant\` command below, then commit it to"
    echo "\`tools/ci/fuzz/regressions/\` (add its sha256 to \`manifest.txt\`) so every"
    echo "pull request replays it: \`bash tools/ci/run-fuzz.sh --replay-only\`."
    echo ""
    if [ -f "${ART}/SUMMARY.txt" ]; then
        echo '```'
        cat "${ART}/SUMMARY.txt"
        echo '```'
        echo ""
    fi
    shopt -s nullglob
    logs=( "${ART}"/*.log )
    if [ "${#logs[@]}" -eq 0 ]; then
        echo "No reproducer was recorded: the job failed outside the mutation loop"
        echo "(build, compile or harness breakage) — see the run log."
    fi
    for log in "${logs[@]:0:${MAX_LOGS}}"; do
        echo "### \`$(basename "${log%.log}")\`"
        echo ""
        echo '```'
        head -n "${LOG_LINES}" "${log}"
        echo '```'
        echo ""
    done
    if [ "${#logs[@]}" -gt "${MAX_LOGS}" ]; then
        echo "$(( ${#logs[@]} - MAX_LOGS )) more reproducer log(s) in the artifact."
    fi
} > "${BODY}"
if [ "$(wc -c < "${BODY}")" -gt "${MAX_BODY}" ]; then
    head -c "${MAX_BODY}" "${BODY}" > "${BODY}.cut"
    printf '\n```\n\n(truncated — full logs in the artifact)\n' >> "${BODY}.cut"
    mv "${BODY}.cut" "${BODY}"
fi

existing=""
if [ "${DRY}" -eq 0 ]; then
    existing="$(gh issue list --state open --search "in:title \"${TITLE}\"" \
                    --json number,title --jq ".[] | select(.title == \"${TITLE}\") | .number" \
                | head -n 1)" || { echo "✗ gh issue list failed" >&2; exit 2; }
fi

if [ -n "${existing}" ]; then
    gh issue comment "${existing}" --body-file "${BODY}" >/dev/null \
        || { echo "✗ gh issue comment failed" >&2; exit 2; }
    echo "✓ fuzz failure recorded on open issue #${existing}"
elif [ "${DRY}" -eq 1 ]; then
    echo "title: ${TITLE}"
    cat "${BODY}"
else
    gh issue create --title "${TITLE}" --body-file "${BODY}" \
        || { echo "✗ gh issue create failed" >&2; exit 2; }
    echo "✓ fuzz failure issue opened"
fi
