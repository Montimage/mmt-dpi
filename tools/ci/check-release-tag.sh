#!/usr/bin/env bash
#
# check-release-tag.sh — the pushed v* tag must equal the declared VERSION
# (issue #220, F-CI-010).
#
# release-packages.yml publishes on ANY `v*` tag — nothing checked that the
# tag agreed with the VERSION declared in rules/common.mk, so a `v1.9.0` tag
# pushed on a tree still declaring `VERSION := 1.8.0` would ship packages
# labelled 1.8.0 under a 1.9.0 release. The verify-tag job runs this before
# any publish step; a mismatch fails the gate and the release job never runs.
#
# Usage: check-release-tag.sh [tag]     (default: $GITHUB_REF_NAME)
#
# Exit codes: 0 = tag matches declared version, 1 = mismatch, 2 = helper
# broken (no tag given, VERSION unreadable).
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

TAG="${1:-${GITHUB_REF_NAME:-}}"
if [ -z "$TAG" ]; then
  echo "✗ no tag given and GITHUB_REF_NAME is unset" >&2
  exit 2
fi

VERSION="$(sed -n 's/^VERSION[[:space:]]*:=[[:space:]]*//p' \
  "$ROOT/rules/common.mk" | head -n 1)"
if [ -z "$VERSION" ]; then
  echo "✗ could not read VERSION from rules/common.mk" >&2
  exit 2
fi

case "$TAG" in
  v*) ;;
  *)
    echo "✗ '$TAG' is not a v* release tag — refusing to publish" >&2
    exit 1
    ;;
esac

if [ "$TAG" != "v$VERSION" ]; then
  echo "✗ tag $TAG does not match the declared VERSION v$VERSION" >&2
  echo "  (rules/common.mk) — bump VERSION or retag before releasing" >&2
  exit 1
fi

echo "✓ tag $TAG matches declared VERSION $VERSION"
