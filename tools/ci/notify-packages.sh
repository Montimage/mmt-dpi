#!/usr/bin/env bash
#
# notify-packages.sh — tell Montimage/packages that a release is published
# (issue #76; design in issue #24).
#
# Montimage/packages builds and signs the APT repository from the last
# mmt-dpi Releases; mmt-dpi never holds the APT signing key. After the
# `release` job of .github/workflows/release-packages.yml has published the
# GitHub Release, this script sends one `repository_dispatch` event:
#
#   POST /repos/Montimage/packages/dispatches
#   {"event_type": "mmt-dpi-release", "client_payload": {"tag": "<tag>"}}
#
# The packages build is stateless (it rebuilds from the Releases), so a
# re-run of a published tag dispatches again harmlessly.
#
# Credential: PACKAGES_DISPATCH_TOKEN, a fine-grained token limited to
# Montimage/packages (Contents: read and write). The workflow passes it
# through the step's `env:` only; this script hands it to `gh` as GH_TOKEN
# for the one API call and never prints it.
#
# Never fails the release: the Release is already public when this runs.
# A missing token or a refused dispatch prints a `::warning::` naming the
# manual trigger and exits 0. Only a usage error (no tag) exits 2.
#
# Usage: PACKAGES_DISPATCH_TOKEN=... bash tools/ci/notify-packages.sh <tag>

# Nothing below may echo the token, even with xtrace inherited: turn it off
# before any line expands the token.
{ set +x; } 2>/dev/null
set -uo pipefail

PACKAGES_REPO="Montimage/packages"
EVENT_TYPE="mmt-dpi-release"
MANUAL="gh workflow run apt-repo.yml -R ${PACKAGES_REPO}"

tag="${1:-}"
if [ -z "$tag" ]; then
    echo "usage: notify-packages.sh <tag>" >&2
    exit 2
fi

token="${PACKAGES_DISPATCH_TOKEN:-}"
unset PACKAGES_DISPATCH_TOKEN

if [ -z "$token" ]; then
    echo "::warning title=APT repository not notified::PACKAGES_DISPATCH_TOKEN is not set, so ${PACKAGES_REPO} was not told about ${tag} and the APT repository was not rebuilt. Trigger the rebuild by hand: ${MANUAL}"
    exit 0
fi

if GH_TOKEN="$token" gh api --method POST \
        -H "Accept: application/vnd.github+json" \
        "repos/${PACKAGES_REPO}/dispatches" \
        -f "event_type=${EVENT_TYPE}" \
        -f "client_payload[tag]=${tag}" >/dev/null; then
    echo "Dispatched ${EVENT_TYPE} for ${tag} to ${PACKAGES_REPO}."
    echo "Check the run: https://github.com/${PACKAGES_REPO}/actions/workflows/apt-repo.yml"
    exit 0
fi

echo "::warning title=APT repository not notified::the ${EVENT_TYPE} dispatch to ${PACKAGES_REPO} for ${tag} failed (see the gh error above), so the APT repository was not rebuilt. Check PACKAGES_DISPATCH_TOKEN (expired, or not granted Contents: read and write on ${PACKAGES_REPO}), then trigger the rebuild by hand: ${MANUAL}"
exit 0
