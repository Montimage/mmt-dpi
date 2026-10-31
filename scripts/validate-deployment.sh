#!/usr/bin/env bash
# validate-deployment.sh — Check-only validation for DEPLOYMENT.md install/linking steps.
# Usage: ./validate-deployment.sh [--check] [--run-destructive]
# shellcheck disable=SC2015
#  The A && B || C idiom below is used exclusively as
#  `check && echo "  ✓ ..." || { echo "  ✗ ..."; ERRORS+=1; }`, where the
#  middle command is a plain echo that cannot fail — the hazard SC2015
#  warns about (C running when A is true) cannot occur here. Scoped to
#  this file rather than .shellcheckrc (issue #189, F-CI-019).

set -euo pipefail

MODE="${1:---check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

if [ "$MODE" = "--run-destructive" ]; then
    echo "Running in destructive mode (not implemented for this script)."
    exit 0
fi

if [ "$MODE" != "--check" ]; then
    echo "Usage: $0 [--check] [--run-destructive]"
    exit 1
fi

echo "=== DEPLOYMENT.md validation ==="

# Check 1: Build and install targets exist
check "sdk/Makefile has 'install' target" "grep -q '^install:' $ROOT/sdk/Makefile"
check "sdk/Makefile has 'deb' target" "grep -q '^deb:' $ROOT/sdk/Makefile"
check "sdk/Makefile has 'dist-clean' target" "grep -q '^dist-clean:' $ROOT/sdk/Makefile"

# Check 2: Install paths match code
grep -q 'MMT_DPI' "$ROOT/rules/common.mk" && echo "  ✓ MMT_DPI path defined" || { echo "  ✗ MMT_DPI path mismatch"; ERRORS=$((ERRORS + 1)); }
grep -q 'MMT_LIB' "$ROOT/rules/common.mk" && echo "  ✓ MMT_LIB path defined" || { echo "  ✗ MMT_LIB path mismatch"; ERRORS=$((ERRORS + 1)); }
grep -q 'MMT_INC' "$ROOT/rules/common.mk" && echo "  ✓ MMT_INC path defined" || { echo "  ✗ MMT_INC path mismatch"; ERRORS=$((ERRORS + 1)); }
grep -q 'MMT_PLUGINS' "$ROOT/rules/common.mk" && echo "  ✓ MMT_PLUGINS path defined" || { echo "  ✗ MMT_PLUGINS path mismatch"; ERRORS=$((ERRORS + 1)); }

# Check 3: ldconfig file name
grep -q 'mmt-dpi.conf' "$ROOT/sdk/Makefile" && echo "  ✓ ldconfig file is mmt-dpi.conf" || { echo "  ✗ ldconfig file name mismatch"; ERRORS=$((ERRORS + 1)); }

# Check 4: Plugin path compiled in
grep -q 'PLUGINS_REPOSITORY_OPT' "$ROOT/rules/common.mk" && echo "  ✓ PLUGINS_REPOSITORY_OPT defined" || { echo "  ✗ PLUGINS_REPOSITORY_OPT missing"; ERRORS=$((ERRORS + 1)); }

# Check 5: the build knows the shared libraries the doc says are installed —
# sdk/lib/ is a gitignored build artifact that does not exist on a clean
# checkout, so assert each library in the Makefile instead (issue #187 — the
# doc-validators CI job runs on a clean checkout).
# The names live in rules/common.mk; sdk/Makefile installs them through its
# one layout list, MMT_LAYOUT_LIBS (issue #538).
for lib in libmmt_core libmmt_tcpip; do
    check "the build names $lib and sdk/Makefile installs its layout list" \
        "grep -Eq ':= *$lib\$' $ROOT/rules/common.mk && grep -q '^MMT_LAYOUT_LIBS ' $ROOT/sdk/Makefile"
done

# Check 6: public headers exist at their source — sdk/include/ is a
# gitignored build copy populated by make; the tracked originals live in
# src/mmt_core/public_include/ (same issue #187 constraint as Check 5).
check "src/mmt_core/public_include/mmt_core.h exists" "test -f $ROOT/src/mmt_core/public_include/mmt_core.h"

# Check 7: No MMT_SEC_DTLS_CIPHER_ALLOWLIST in code (doc should not list it)
count=$(grep -r 'MMT_SEC_DTLS_CIPHER_ALLOWLIST' "$ROOT/sdk/" "$ROOT/src/" 2>/dev/null | wc -l || true)
if [ "$count" -eq 0 ]; then
    echo "  ✓ MMT_SEC_DTLS_CIPHER_ALLOWLIST not in code (doc correctly flags as unverified)"
else
    echo "  ✗ MMT_SEC_DTLS_CIPHER_ALLOWLIST found in code but doc flagged as unverified"
    ERRORS=$((ERRORS + 1))
fi

# Checks 8-12 (issue #583, F-DOCS-014/016/018/019/021/023): the content of the
# deployment-facing docs against the sources. They read tracked files only
# (`git ls-files`), so a stale local docs/_site build is never scanned.
DEPLOY_DOC="$ROOT/docs/DEPLOYMENT.md"

# Check 8: every MMT_* variable the library reads at run time is documented.
# The names come from the getenv()/secure_getenv() calls in tracked src/
# (generated asn1c code excluded); a macro argument such as PLUGINS_DIR_ENV is
# resolved through its #define. MMT_DPI_PLUGINS_DIR is pinned as a floor so a
# grep that silently finds nothing cannot pass.
env_calls=$(git -C "$ROOT" grep -hoE '(secure_)?getenv\( *("MMT_[A-Z0-9_]+"|[A-Z][A-Z0-9_]*) *\)' \
    -- src ':!src/mmt_mobile/asn1c' 2>/dev/null || true)
env_names=(MMT_DPI_PLUGINS_DIR)
unresolved=""
while IFS= read -r arg; do
    [ -n "$arg" ] || continue
    case "$arg" in
        \"*\") env_names+=("${arg//\"/}") ;;
        *)
            val=$(git -C "$ROOT" grep -hoE "^#define +$arg +\"MMT_[A-Z0-9_]+\"" -- src 2>/dev/null \
                | sed -E 's/.*"(MMT_[A-Z0-9_]+)"/\1/' | head -n 1 || true)
            if [ -n "$val" ]; then
                env_names+=("$val")
            else
                unresolved="$unresolved $arg"
            fi
            ;;
    esac
done <<EOF
$(printf '%s\n' "$env_calls" | sed -E 's/^(secure_)?getenv\( *//; s/ *\)$//')
EOF
if [ -n "$unresolved" ]; then
    echo "  ✗ getenv() argument(s) not resolved to an MMT_* name:$unresolved"
    ERRORS=$((ERRORS + 1))
fi
env_count=0
for name in $(printf '%s\n' "${env_names[@]}" | sort -u); do
    env_count=$((env_count + 1))
    if grep -qF "\`$name\`" "$DEPLOY_DOC"; then
        echo "  ✓ DEPLOYMENT.md documents $name"
    else
        echo "  ✗ DEPLOYMENT.md does not document $name (read by src/)"
        ERRORS=$((ERRORS + 1))
    fi
done
if [ "$env_count" -lt 2 ]; then
    echo "  ✗ found only $env_count run-time variable(s) in src/ — the getenv() scan is broken"
    ERRORS=$((ERRORS + 1))
fi

# Check 9: every `path:line`, `path:a-b` or `path:a,b` cite in DEPLOYMENT.md
# and ARCHITECTURE.md names a tracked file that has at least that many lines.
for doc in docs/DEPLOYMENT.md docs/ARCHITECTURE.md; do
    name=${doc##*/}
    cite_count=0
    while IFS= read -r cite; do
        [ -n "$cite" ] || continue
        cite_count=$((cite_count + 1))
        path=${cite%%:*}
        max=$(printf '%s\n' "${cite#*:}" | sed 's/[,-]/\n/g' | sort -n | tail -n 1)
        if ! git -C "$ROOT" ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
            echo "  ✗ $name cites $cite, but $path is not a tracked file"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        lines=$(awk 'END { print NR }' "$ROOT/$path")
        if [ "$max" -gt "$lines" ]; then
            echo "  ✗ $name cites $cite, but $path has $lines lines"
            ERRORS=$((ERRORS + 1))
        fi
    done <<EOF
$(grep -oE "\`[A-Za-z0-9_./-]+:[0-9]+([,-][0-9]+)*\`" "$ROOT/$doc" | tr -d "\`" || true)
EOF
    if [ "$cite_count" -gt 0 ]; then
        echo "  ✓ checked $cite_count path:line cite(s) in $name"
    else
        echo "  ✗ no path:line cite found in $name — the cite scan is broken"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check 10: no claim that the library reads no environment variables.
if grep -qiE 'no (run[- ]?time )?environment variables?' "$DEPLOY_DOC"; then
    echo "  ✗ DEPLOYMENT.md claims there are no (run-time) environment variables"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✓ DEPLOYMENT.md makes no 'no environment variables' claim"
fi

# Check 11: every libmmt_<x> a deployment-facing doc names is a library the
# build defines in rules/common.mk (the mobile plugin is libmmt_tmobile).
known_libs=$(grep -oE ':= *libmmt_[a-z_]+$' "$ROOT/rules/common.mk" | sed -E 's/:= *//' | sort -u)
for doc in docs/DEPLOYMENT.md docs/ARCHITECTURE.md README.md; do
    bad=""
    while IFS= read -r lib; do
        [ -n "$lib" ] || continue
        if ! printf '%s\n' "$known_libs" | grep -qxF "$lib"; then
            bad="$bad $lib"
        fi
    done <<EOF
$(grep -oE 'libmmt_[a-z_]+' "$ROOT/$doc" | sort -u || true)
EOF
    if [ -z "$bad" ]; then
        echo "  ✓ $doc names only libraries rules/common.mk defines"
    else
        echo "  ✗ $doc names libraries rules/common.mk does not define:$bad"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check 12: the stale install-layout label is gone, and no contributor- or
# user-facing doc names an integration branch that does not exist. The
# append-only docs/DECISIONS.md keeps its history and is not scanned for the
# branch name.
tracked_docs=$(git -C "$ROOT" ls-files -- README.md CONTRIBUTING.md install.sh docs \
    | grep -E '\.(md|html|sh)$' || true)
if [ -z "$tracked_docs" ]; then
    echo "  ✗ no tracked doc found — the git ls-files scan is broken"
    ERRORS=$((ERRORS + 1))
fi
label_hits=""
branch_hits=""
for doc in $tracked_docs; do
    if grep -qF 'Prebuilt example binaries' "$ROOT/$doc"; then
        label_hits="$label_hits $doc"
    fi
    [ "$doc" = "docs/DECISIONS.md" ] && continue
    if grep -qE "BRANCH=dev([^A-Za-z0-9_-]|\$)|--branch dev([^A-Za-z0-9_-]|\$)|\`dev\`|(^|[^A-Za-z0-9_-])dev branch" "$ROOT/$doc"; then
        branch_hits="$branch_hits $doc"
    fi
done
if [ -z "$label_hits" ]; then
    echo "  ✓ no doc labels the installed examples as prebuilt binaries"
else
    echo "  ✗ 'Prebuilt example binaries' label still in:$label_hits"
    ERRORS=$((ERRORS + 1))
fi
if [ -z "$branch_hits" ]; then
    echo "  ✓ no doc names a 'dev' branch"
else
    echo "  ✗ a 'dev' branch is named in:$branch_hits"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS
