#!/usr/bin/env bash
# shellcheck disable=SC2016  # sed expressions match a literal $ and backticks
# validate-release-prep.sh — Check-only validation for Prepare-for-a-new-released-version.md.
# Usage: ./validate-release-prep.sh [--check] [--run-destructive] [--root DIR]
#
# --root DIR validates the tree at DIR instead of this checkout (the
# version-agreement self-test, tools/ci/tests/test-version-agreement.sh, runs
# it on fixtures).
set -euo pipefail

MODE="--check"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
while [ $# -gt 0 ]; do
    case "$1" in
        --check|--run-destructive) MODE="$1" ;;
        --root)
            [ $# -ge 2 ] || { echo "Usage: $0 [--check] [--run-destructive] [--root DIR]"; exit 1; }
            ROOT="$(cd "$2" && pwd)"; shift ;;
        *) echo "Usage: $0 [--check] [--run-destructive] [--root DIR]"; exit 1 ;;
    esac
    shift
done
ERRORS=0

check() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "  ✓ $desc"
    else
        echo "  ✗ $desc"
        ERRORS=$((ERRORS + 1))
    fi
}

# agree DESC EXPECTED ACTUAL — one version site must carry the expected value.
agree() {
    if [ -n "$3" ] && [ "$3" = "$2" ]; then
        echo "  ✓ $1 = $2"
    else
        echo "  ✗ $1 = '${3:-<not found>}', expected '$2'"
        ERRORS=$((ERRORS + 1))
    fi
}

# first_match FILE SED_EXPR — first value the sed -n expression prints.
first_match() {
    [ -f "$1" ] || return 0
    sed -n "$2" "$1" | head -n 1
}

if [ "$MODE" = "--run-destructive" ]; then
    echo "Running in destructive mode (not implemented for this script)."
    exit 0
fi

echo "=== Prepare-for-a-new-released-version.md validation ==="

# Check 1: Version agreement (issue #483). rules/common.mk VERSION is the
# single version source; every site below is compared with it, and
# docs/Prepare-for-a-new-released-version.md lists exactly these sites.
VERSION="$(first_match "$ROOT/rules/common.mk" 's/^VERSION[[:space:]]*:=[[:space:]]*\([^[:space:]]*\).*/\1/p')"
if [ -z "$VERSION" ]; then
    echo "  ✗ rules/common.mk has no VERSION := line"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ rules/common.mk VERSION = $VERSION (single source)"
    # (a) Declared-version sites: must equal VERSION exactly.
    agree "src/mmt_core/public_include/mmt_core.h #define VERSION" "$VERSION" \
        "$(first_match "$ROOT/src/mmt_core/public_include/mmt_core.h" 's/^#define VERSION "\([^"]*\)".*/\1/p')"
    agree "dist/ZIP/mmt-install-common.sh VERSION fallback" "$VERSION" \
        "$(first_match "$ROOT/dist/ZIP/mmt-install-common.sh" 's/^VERSION="\${VERSION:-\([^}]*\)}".*/\1/p')"
    agree "CHANGELOG.md topmost 'Version' heading" "$VERSION" \
        "$(first_match "$ROOT/CHANGELOG.md" 's/^Version \([0-9][^ ]*\).*/\1/p')"
    # debian/ is not tracked on main yet (issue #475): checked only when present.
    if [ -f "$ROOT/debian/changelog" ]; then
        agree "debian/changelog upstream version" "$VERSION" \
            "$(first_match "$ROOT/debian/changelog" '1s/^[^ ]* (\([0-9]*:\)\{0,1\}\([^)]*\)).*/\2/p' | sed 's/-[^-]*$//; s/+\(dfsg\|ds\).*$//')"
    else
        echo "  ○ debian/changelog absent — skipped"
    fi
    # (b) Published-release sites: the installer pins the latest PUBLISHED tag,
    # which lags VERSION between the bump and the tag (a tagged commit cannot
    # pin its own SHA in RELEASE_TAG_SHA). They must agree with install.sh's
    # RELEASE_TAG, which must name a dated CHANGELOG release not newer than
    # VERSION.
    RELEASE_TAG="$(first_match "$ROOT/install.sh" 's/^RELEASE_TAG="\([^"]*\)".*/\1/p')"
    if [ -z "$RELEASE_TAG" ]; then
        echo "  ✗ install.sh has no RELEASE_TAG=\"v...\" line"
        ERRORS=$((ERRORS + 1))
    else
        PUBLISHED="${RELEASE_TAG#v}"
        if [ "$RELEASE_TAG" = "v$PUBLISHED" ] && \
           [ "$(printf '%s\n%s\n' "$PUBLISHED" "$VERSION" | sort -V | tail -n 1)" = "$VERSION" ]; then
            echo "  ✓ install.sh RELEASE_TAG = $RELEASE_TAG (not newer than v$VERSION)"
        else
            echo "  ✗ install.sh RELEASE_TAG = '$RELEASE_TAG' is not a v* tag at or below v$VERSION"
            ERRORS=$((ERRORS + 1))
        fi
        agree "CHANGELOG.md dated entry for $RELEASE_TAG" "$PUBLISHED" \
            "$(grep -E "^Version ${PUBLISHED//./\\.} \(" "$ROOT/CHANGELOG.md" 2>/dev/null | grep -vi unreleased | head -n 1 | sed -n 's/^Version \([^ ]*\).*/\1/p')"
        agree "README.md 'Current release'" "$RELEASE_TAG" \
            "$(first_match "$ROOT/README.md" 's/.*Current release: \[\(v[^]]*\)\].*/\1/p')"
        agree "README.md installer pinned tag" "$RELEASE_TAG" \
            "$(first_match "$ROOT/README.md" 's/.*pinned release tag (`\(v[^`]*\)`).*/\1/p')"
        agree "docs/_includes/quick-start.md installer pinned tag" "$RELEASE_TAG" \
            "$(first_match "$ROOT/docs/_includes/quick-start.md" 's/.*pinned release tag (`\(v[^`]*\)`).*/\1/p')"
        agree "docs/index.html hero version" "$RELEASE_TAG" \
            "$(first_match "$ROOT/docs/index.html" 's/.*<\/span>\(v[0-9][^ ]*\) ·.*/\1/p')"
    fi
fi
# Check 2: mmt-test directory does NOT exist (doc should note this)
if [ -d "$ROOT/mmt-test" ]; then
    echo "  ✗ mmt-test/ exists but doc was updated to not reference it"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ mmt-test/ does not exist (doc correctly updated to use src/examples/)"
fi

# Check 3: Sample pcap exists for testing
check "src/examples/google-fr.pcap exists" "test -f $ROOT/src/examples/google-fr.pcap"

# Check 4: Git tag workflow
check "git is available" "command -v git"

# Check 5: CHANGELOG.md exists
check "CHANGELOG.md exists" "test -f $ROOT/CHANGELOG.md"

# Check 6: dist/ZIP/ directory exists
check "dist/ZIP/install.sh exists" "test -f $ROOT/dist/ZIP/install.sh"
check "dist/ZIP/uninstall.sh exists" "test -f $ROOT/dist/ZIP/uninstall.sh"
check "dist/ZIP/mmt-install-common.sh exists" "test -f $ROOT/dist/ZIP/mmt-install-common.sh"

# Check 7: CI workflows exist
check ".github/workflows/c-cpp.yml exists" "test -f $ROOT/.github/workflows/c-cpp.yml"
check ".github/workflows/release-packages.yml exists" "test -f $ROOT/.github/workflows/release-packages.yml"

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
