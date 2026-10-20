#!/usr/bin/env bash
#
# release-alert.sh — give a failed tag-release run an owner (issue #489,
# F-CI-002).
#
# The v1.9.0 tag run failed its gates and nobody noticed for 24 days. Run by
# the `release-alert` job of .github/workflows/release-packages.yml when any
# job of a tag run fails, it opens an issue — or, when one with the same
# title is still open, comments on it — naming the tag, the run and each
# job's result (the NEEDS_RESULT_<JOB> variables the job exports).
#
# Usage: bash tools/ci/release-alert.sh <tag> <run-url> [--dry-run]
#   --dry-run  print the title, the action and the body; call nothing
#
# Needs `gh` with GH_TOKEN (issues: write) and GH_REPO in the environment.
# Exit: 0 = issue opened/updated (or dry run), 2 = usage or gh failure.

set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <tag> <run-url> [--dry-run]" >&2; exit 2; }
TAG="$1"; RUN_URL="$2"; DRY=0
[ "${3:-}" = "--dry-run" ] && DRY=1
[ -n "$TAG" ] || { echo "✗ empty tag" >&2; exit 2; }
# Git ref names may hold quotes or `$`: keep only safe characters, so the
# title (also used in the --jq filter below) always files an alert.
TAG="$(printf '%s' "$TAG" | tr -cd 'A-Za-z0-9._/+-')"
[ -n "$TAG" ] || TAG="(unprintable tag)"

TITLE="Release workflow failed for ${TAG}"
BODY="$(mktemp)"
trap 'rm -f "${BODY}"' EXIT

{
    echo "The release workflow run for tag \`${TAG}\` failed and did not publish: ${RUN_URL}"
    echo ""
    echo "| Job | Result |"
    echo "|-----|--------|"
    while IFS='=' read -r name value; do
        job="${name#NEEDS_RESULT_}"
        job="$(printf '%s' "$job" | tr 'A-Z_' 'a-z-')"
        echo "| ${job} | ${value:-unknown} |"
    done < <(env | grep '^NEEDS_RESULT_' | LC_ALL=C sort)
    echo ""
    if [ "${NEEDS_RESULT_RELEASE:-}" = "failure" ]; then
        echo "The \`release\` job itself failed: check the repository's Releases for a"
        echo "Release made by hand for this tag (the job refuses to overwrite one) or a"
        echo "draft left by this run (a re-run replaces it)."
        echo ""
    fi
    echo "Do not create the Release by hand: the \`release\` job is the only publisher"
    echo "and refuses to run when a Release for the tag already exists. Fix the cause"
    echo "(a \`verify-tag\` failure usually means the tag is not on \`main\` or does not"
    echo "equal \`v\$(VERSION)\`), then re-run the workflow or delete and re-push the tag —"
    echo "see docs/Prepare-for-a-new-released-version.md."
} > "${BODY}"

existing=""
if [ "${DRY}" -eq 0 ]; then
    existing="$(gh issue list --state open --search "in:title \"${TITLE}\"" \
                    --json number,title --jq ".[] | select(.title == \"${TITLE}\") | .number" \
                | head -n 1)" || { echo "✗ gh issue list failed" >&2; exit 2; }
fi

if [ -n "${existing}" ]; then
    gh issue comment "${existing}" --body-file "${BODY}" >/dev/null \
        || { echo "✗ gh issue comment failed" >&2; exit 2; }
    echo "✓ release failure recorded on open issue #${existing}"
elif [ "${DRY}" -eq 1 ]; then
    echo "title: ${TITLE}"
    cat "${BODY}"
else
    gh issue create --title "${TITLE}" --body-file "${BODY}" \
        || { echo "✗ gh issue create failed" >&2; exit 2; }
    echo "✓ release failure issue opened"
fi
