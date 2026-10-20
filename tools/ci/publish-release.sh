#!/usr/bin/env bash
#
# publish-release.sh — the release workflow is the only publisher of a
# GitHub Release (issue #489, F-CI-002).
#
# v1.9.0's tag run failed its gates, the publish job was skipped, and a
# 'Latest' Release with 0 assets was created by hand 5 s later. The `release`
# job of .github/workflows/release-packages.yml now creates the Release
# itself, through this script, after every gate passed:
#
#   1. Refuse when a Release for the tag already exists — published, or a
#      draft a person made. Only the workflow publishes; a pre-existing
#      Release means someone published by hand, and is never overwritten.
#      The one exception is a DRAFT authored by github-actions[bot]: the
#      leftover of an earlier attempt of this same job that failed between
#      create and publish, deleted and recreated so a re-run can finish.
#   2. Create the Release as a draft, with every asset attached.
#   3. Publish it (draft=false) — only after all assets uploaded,
#      so a Release is never visible with a partial asset set.
#
# Usage: bash tools/ci/publish-release.sh <tag> <assets-dir>
# Needs `gh` with GH_TOKEN (contents: write) and GH_REPO in the environment.
# Exit: 0 = published, 1 = a Release already exists (manual publication),
#       2 = usage or gh failure.

set -euo pipefail

BOT="github-actions[bot]"

[ $# -eq 2 ] || { echo "usage: $0 <tag> <assets-dir>" >&2; exit 2; }
TAG="$1"; DIR="$2"
[[ "$TAG" =~ ^v[0-9]+(\.[0-9]+)*$ ]] \
    || { echo "✗ '$TAG' is not a vX.Y.Z release tag" >&2; exit 2; }
[ -n "${GH_REPO:-}" ] || { echo "✗ GH_REPO is not set" >&2; exit 2; }

shopt -s nullglob
assets=( "$DIR"/* )
[ "${#assets[@]}" -gt 0 ] || { echo "✗ no assets in $DIR — refusing to publish an empty Release" >&2; exit 2; }

# The releases/tags/<tag> endpoint hides drafts, so list them all.
existing="$(gh api --paginate "repos/${GH_REPO}/releases" \
    --jq ".[] | select(.tag_name == \"${TAG}\") | \"\(.id) \(.draft) \(.author.login)\"")" \
    || { echo "✗ could not list the releases of ${GH_REPO}" >&2; exit 2; }

while read -r id draft author; do
    [ -n "${id:-}" ] || continue
    if [ "$draft" = "true" ] && [ "$author" = "$BOT" ]; then
        echo "○ deleting draft Release ${id} left by an earlier attempt of this workflow"
        gh api -X DELETE "repos/${GH_REPO}/releases/${id}" >/dev/null \
            || { echo "✗ could not delete draft Release ${id}" >&2; exit 2; }
        continue
    fi
    kind="published"; [ "$draft" = "true" ] && kind="draft"
    echo "✗ a ${kind} Release for ${TAG} already exists (id ${id}, by ${author})." >&2
    echo "  The release workflow is the only publisher: delete that Release" >&2
    echo "  (gh release delete ${TAG} --repo ${GH_REPO}) and re-run this job." >&2
    exit 1
done <<< "${existing}"

gh release create "$TAG" "${assets[@]}" --draft --verify-tag \
    --title "$TAG" --generate-notes \
    || { echo "✗ gh release create failed" >&2; exit 2; }

# Publish by id: a lookup by tag only reaches a draft through gh's fallback.
draft_id="$(gh api --paginate "repos/${GH_REPO}/releases" \
    --jq ".[] | select(.tag_name == \"${TAG}\" and .draft and .author.login == \"${BOT}\") | .id" \
    | head -n 1)" || { echo "✗ could not list the releases of ${GH_REPO}" >&2; exit 2; }
[ -n "$draft_id" ] || { echo "✗ the draft Release for ${TAG} was not found after create" >&2; exit 2; }
# make_latest=legacy: GitHub picks Latest by creation date and higher
# semantic version, rather than forcing this Release to be Latest.
gh api -X PATCH "repos/${GH_REPO}/releases/${draft_id}" \
    -F draft=false -f make_latest=legacy >/dev/null \
    || { echo "✗ publishing draft Release ${draft_id} failed — it stays for a re-run" >&2; exit 2; }
echo "✓ published Release ${TAG} with ${#assets[@]} asset(s)"
