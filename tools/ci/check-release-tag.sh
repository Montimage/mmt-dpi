#!/usr/bin/env bash
#
# check-release-tag.sh — release-tag gates (issues #220, #484 and #489).
#
#  1. Version gate (issue #220, F-CI-010): the pushed v* tag must equal the
#     VERSION declared in rules/common.mk. release-packages.yml publishes on
#     ANY `v*` tag — nothing checked that the tag agreed with the declared
#     VERSION, so a `v1.9.0` tag pushed on a tree still declaring
#     `VERSION := 1.8.0` would ship packages labelled 1.8.0 under a 1.9.0
#     release. The verify-tag job runs this before any publish step.
#
#  2. Ancestry gate (issue #489, F-CI-002): the tagged commit must be an
#     ancestor of the release base, origin/main — `git merge-base
#     --is-ancestor`. v1.9.0 was tagged on a stale release/v1.9.0 commit
#     that main never contained; only the version gate happened to catch it.
#     Runs when the tag is passed as an ARGUMENT (the verify-tag job does),
#     and fails closed there: a tag or base ref that is not available
#     locally, or a shallow clone (where merge-base can wrongly say "not an
#     ancestor"), is exit 2, never a skip. The GITHUB_REF_NAME default below
#     runs the version gate only — c-cpp.yml's version-agreement job calls
#     this script without an argument on tag pushes from a shallow checkout.
#
#  3. Installer pin gate (issue #484, F-UX-001): install.sh's RELEASE_TAG_SHA
#     must be the PEELED commit of its RELEASE_TAG (`git rev-parse
#     "$RELEASE_TAG^{commit}"`). install.sh aborts when the clone resolves to
#     any other commit, so a stale pin (v1.9.0 pinned to the v1.8.0 commit)
#     breaks every documented one-liner install. The gate runs whenever the
#     tag is available in the local repository; when it is not (a shallow
#     checkout without tags) it is skipped with a notice, unless
#     REQUIRE_RELEASE_TAG=1 makes a missing tag fatal.
#
# Usage:
#   check-release-tag.sh             installer pin gate only (any branch)
#   check-release-tag.sh <tag>       version + ancestry gates for <tag>, then
#                                    the installer pin gate
#   check-release-tag.sh --write-pin <tag>
#                                    rewrite install.sh's RELEASE_TAG and
#                                    RELEASE_TAG_SHA from the peeled <tag>
#                                    (the post-release follow-up step)
# With no argument on a tag-triggered GitHub Actions run (GITHUB_REF_TYPE=tag)
# the tag defaults to $GITHUB_REF_NAME for the version gate only (no
# ancestry gate). An explicitly empty argument is an error, never a silent
# skip of the version gate.
#
# Environment: ROOT_DIR overrides the checkout root (the self-test points it
# at a fixture repository). RELEASE_BASE_REF overrides the ancestry base
# (default origin/main; the verify-tag job fetches it explicitly).
#
# Exit codes: 0 = gates passed, 1 = mismatch (incl. a tag not on the base),
# 2 = helper broken (empty tag, VERSION or install.sh pin unreadable,
# required tag or base ref missing).
#
set -euo pipefail

ROOT="${ROOT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
INSTALLER="$ROOT/install.sh"

# peel <tag> — print the commit the tag resolves to, or nothing.
peel() {
  git -C "$ROOT" rev-parse -q --verify "refs/tags/$1^{commit}" 2>/dev/null || true
}

read_pin() {
  RELEASE_TAG="$(sed -n 's/^RELEASE_TAG="\([^"]*\)".*/\1/p' "$INSTALLER" | head -n 1)"
  RELEASE_TAG_SHA="$(sed -n 's/^RELEASE_TAG_SHA="\([^"]*\)".*/\1/p' "$INSTALLER" | head -n 1)"
  if [ -z "$RELEASE_TAG" ] || [ -z "$RELEASE_TAG_SHA" ]; then
    echo "✗ install.sh has no RELEASE_TAG=\"...\" / RELEASE_TAG_SHA=\"...\" lines" >&2
    exit 2
  fi
}

if [ "${1:-}" = "--write-pin" ]; then
  TAG="${2:-}"
  # Strict vX.Y.Z: the tag is substituted into a sed replacement below.
  if [[ ! "$TAG" =~ ^v[0-9]+(\.[0-9]+)*$ ]]; then
    echo "✗ usage: check-release-tag.sh --write-pin v<x.y.z>" >&2
    exit 2
  fi
  SHA="$(peel "$TAG")"
  if [ -z "$SHA" ]; then
    echo "✗ tag $TAG is not available locally — git fetch --tags first" >&2
    exit 2
  fi
  read_pin
  sed -i -e "s/^RELEASE_TAG=\"[^\"]*\"/RELEASE_TAG=\"$TAG\"/" \
         -e "s/^RELEASE_TAG_SHA=\"[^\"]*\"/RELEASE_TAG_SHA=\"$SHA\"/" "$INSTALLER"
  echo "✓ install.sh now pins $TAG to $SHA"
  echo "  update the README/site mentions too (scripts/validate-release-prep.sh)"
  exit 0
fi

# --- 1. Version gate (only when a tag is given) -------------------------------
TAG=""
ANCESTRY=0
if [ $# -ge 1 ]; then
  TAG="$1"
  ANCESTRY=1
  if [ -z "$TAG" ]; then
    echo "✗ empty tag argument (is GITHUB_REF_NAME unset?)" >&2
    exit 2
  fi
elif [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  TAG="${GITHUB_REF_NAME:-}"
  if [ -z "$TAG" ]; then
    echo "✗ tag-triggered run but GITHUB_REF_NAME is unset" >&2
    exit 2
  fi
fi

if [ -n "$TAG" ]; then
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
fi

# --- 2. Ancestry gate (explicit tag argument only) ---------------------------
if [ "$ANCESTRY" = "1" ]; then
  if [ "$(git -C "$ROOT" rev-parse --is-shallow-repository 2>/dev/null)" != "false" ]; then
    echo "✗ $ROOT is a shallow clone or not a git repository — the ancestry" >&2
    echo "  check needs the full history (actions/checkout fetch-depth: 0)" >&2
    exit 2
  fi
  BASE="${RELEASE_BASE_REF:-origin/main}"
  TAG_COMMIT="$(peel "$TAG")"
  if [ -z "$TAG_COMMIT" ]; then
    echo "✗ tag $TAG is not available locally — cannot check it is on $BASE" >&2
    echo "  (git fetch origin tag $TAG)" >&2
    exit 2
  fi
  BASE_COMMIT="$(git -C "$ROOT" rev-parse -q --verify "$BASE^{commit}" 2>/dev/null || true)"
  if [ -z "$BASE_COMMIT" ]; then
    echo "✗ release base $BASE is not available locally" >&2
    echo "  (git fetch origin +refs/heads/main:refs/remotes/origin/main)" >&2
    exit 2
  fi
  ANC=0
  git -C "$ROOT" merge-base --is-ancestor "$TAG_COMMIT" "$BASE_COMMIT" || ANC=$?
  if [ "$ANC" -gt 1 ]; then
    echo "✗ git merge-base failed (exit $ANC) for $TAG against $BASE" >&2
    exit 2
  fi
  if [ "$ANC" -eq 1 ]; then
    echo "✗ tag $TAG ($TAG_COMMIT) is not an ancestor of $BASE ($BASE_COMMIT)" >&2
    echo "  — release tags are cut from main only: delete the tag and retag" >&2
    echo "  a commit on main" >&2
    exit 1
  fi
  echo "✓ tag $TAG ($TAG_COMMIT) is on $BASE"
fi

# --- 3. Installer pin gate ----------------------------------------------------
read_pin
ACTUAL="$(peel "$RELEASE_TAG")"
if [ -z "$ACTUAL" ]; then
  if [ "${REQUIRE_RELEASE_TAG:-0}" = "1" ]; then
    echo "✗ install.sh RELEASE_TAG $RELEASE_TAG is not available locally" >&2
    echo "  (REQUIRE_RELEASE_TAG=1) — fetch the tag before running this gate" >&2
    exit 2
  fi
  echo "○ install.sh pin not checked: tag $RELEASE_TAG is not available locally"
  echo "  (git fetch origin tag $RELEASE_TAG, or set REQUIRE_RELEASE_TAG=1)"
  exit 0
fi

if [ "$ACTUAL" != "$RELEASE_TAG_SHA" ]; then
  echo "✗ install.sh RELEASE_TAG_SHA $RELEASE_TAG_SHA is not the commit" >&2
  echo "  $RELEASE_TAG resolves to ($ACTUAL) — every one-liner install would" >&2
  echo "  abort; fix it with: bash tools/ci/check-release-tag.sh --write-pin $RELEASE_TAG" >&2
  exit 1
fi

echo "✓ install.sh pins $RELEASE_TAG to its peeled commit $ACTUAL"
