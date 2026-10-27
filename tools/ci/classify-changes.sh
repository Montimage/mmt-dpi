#!/usr/bin/env bash
#
# classify-changes.sh — does a pull request change anything but
# documentation? (issue #552, F-CI-009)
#
# The `changes` job of .github/workflows/c-cpp.yml and phase0-baseline.yml
# feeds it the pull request's changed paths (`git diff --name-only` of the
# merge commit against the base tip) and writes its verdict to
# $GITHUB_OUTPUT. The C jobs (build matrix, sanitizers, coverage, lint,
# phase0 gates, ...) skip themselves on `code=false`, so a docs-only pull
# request runs only the jobs that read the docs, while every required context
# still reports: a skipped job reports success, and a matrix job runs with
# its steps skipped so each leg keeps its own context.
#
# Documentation-only paths — an allowlist, everything else is code:
#   docs/...        the site sources, first-run files and the guides
#   <name>.md       Markdown at the repository root (README.md, CHANGELOG.md,
#                   CONTRIBUTING.md, AGENTS.md, ...)
# Markdown below any other directory (src/, tests/, tools/, ...) is code: a
# suite or a generator may read it.
#
# Jobs that read these paths do not skip on `code=false`: doc-validators
# (plus the docs_lifecycle suite on a docs-only change), verify-helpers,
# version-agreement, pre-commit, secret-scan, site-onboarding and `build`,
# whose runtime protocol-count check compares README.md, docs/index.html and
# docs/_config.yml with the built SDK.
#
# Fail-closed: an empty list (nothing to classify) is `code=true`.
#
# Usage:   git diff --no-renames --name-only BASE HEAD \
#              | bash tools/ci/classify-changes.sh >> "$GITHUB_OUTPUT"
# Output:  `code=true` or `code=false` on stdout; the first code path and the
#          counts on stderr.
# Exit:    0 = classified; 2 = bad usage.

set -euo pipefail

if [ $# -ne 0 ]; then
    echo "usage: <changed paths, one per line> | bash $0" >&2
    exit 2
fi

docs=0
code=0
first_code=""
while IFS= read -r path || [ -n "$path" ]; do
    [ -n "$path" ] || continue
    case "$path" in
        docs/*) docs=$((docs + 1)) ;;
        */*) code=$((code + 1)); [ -n "$first_code" ] || first_code="$path" ;;
        *.md) docs=$((docs + 1)) ;;
        *) code=$((code + 1)); [ -n "$first_code" ] || first_code="$path" ;;
    esac
done

if [ "$docs" -eq 0 ] && [ "$code" -eq 0 ]; then
    echo "no changed path to classify — running every job (fail-closed)" >&2
    echo "code=true"
elif [ "$code" -gt 0 ]; then
    echo "code change: $first_code ($code code path(s), $docs docs path(s))" >&2
    echo "code=true"
else
    echo "docs-only change ($docs docs path(s)) — the C jobs skip" >&2
    echo "code=false"
fi
