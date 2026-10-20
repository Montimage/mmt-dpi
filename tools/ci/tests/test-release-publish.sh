#!/usr/bin/env bash
#
# test-release-publish.sh — self-test for tools/ci/publish-release.sh and
# tools/ci/release-alert.sh (issue #489, F-CI-002).
#
# Runs both REAL scripts against a stub `gh` on PATH that records every call
# and answers the release listing as the script's --jq filter would print
# it: STUB_RELEASES ("<id> <draft> <author>" lines) before `release create`,
# STUB_DRAFT_ID (the new draft's id, default 99) after it. Needs no network.
#
# Scenario -> expected exit:
#   no Release for the tag            -> 0: create --draft, then publish by id
#   the draft vanished after create   -> 2: nothing published
#   a published Release exists        -> 1: nothing created (manual upload)
#   a draft made by a person exists   -> 1: nothing created
#   a draft left by github-actions    -> 0: deleted, then recreated
#   empty assets dir / non-v* tag     -> 2
#   alert: no open issue / open issue -> 0: issue created / commented
#
# Usage: bash tools/ci/tests/test-release-publish.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
PUBLISH="${REPO_ROOT}/tools/ci/publish-release.sh"
ALERT="${REPO_ROOT}/tools/ci/release-alert.sh"
for f in "${PUBLISH}" "${ALERT}"; do
    [ -f "${f}" ] || { echo "✗ missing ${f}" >&2; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/bin" "${WORK}/assets" "${WORK}/empty"
touch "${WORK}/assets/mmt-dpi_1.2.3_amd64.deb" "${WORK}/assets/SHA256SUMS"
LOG="${WORK}/gh.log"

cat > "${WORK}/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh $*" >> "${STUB_LOG}"
case "$1 $2" in
    "api --paginate")
        if grep -q "release create" "${STUB_LOG}"; then
            printf '%s' "${STUB_DRAFT_ID-99}"
        else
            printf '%s' "${STUB_RELEASES:-}"
        fi ;;
    "issue list")     printf '%s' "${STUB_OPEN_ISSUE:-}" ;;
esac
exit 0
STUB
chmod +x "${WORK}/bin/gh"

PASS=0; FAIL=0
check() { # check <desc> <cond-exit>
    if [ "$2" -eq 0 ]; then PASS=$((PASS + 1)); echo "  ok   $1"
    else FAIL=$((FAIL + 1)); echo "  FAIL $1"; sed 's/^/      /' "${WORK}/out" "${LOG}" 2>/dev/null; fi
}
run() { # run <want-exit> <desc> <script> <args...>  (STUB_* from the caller)
    local want="$1" desc="$2" rc=0
    shift 2
    : > "${LOG}"
    PATH="${WORK}/bin:${PATH}" STUB_LOG="${LOG}" GH_REPO=owner/repo \
        bash "$@" > "${WORK}/out" 2>&1 || rc=$?
    [ "${rc}" -eq "${want}" ]; check "${desc} (exit ${rc}, want ${want})" $?
}
logged() { grep -q -- "$1" "${LOG}"; }

echo "publish-release.sh / release-alert.sh self-test (issue #489)"

STUB_RELEASES="" run 0 "no Release yet: publishes" "${PUBLISH}" v1.2.3 "${WORK}/assets"
logged "gh release create v1.2.3 .*--draft --verify-tag"; check "  creates the Release as a draft" $?
logged "gh api -X PATCH repos/owner/repo/releases/99 -F draft=false -f make_latest=legacy"
check "  then publishes that draft by id" $?
[ "$(grep -n 'release create' "${LOG}" | cut -d: -f1)" -lt "$(grep -n 'X PATCH' "${LOG}" | cut -d: -f1)" ]
check "  publish happens after create" $?
logged "SHA256SUMS"; check "  attaches every asset" $?

STUB_DRAFT_ID="" run 2 "draft not found after create: fails" "${PUBLISH}" v1.2.3 "${WORK}/assets"
! logged "X PATCH"; check "  publishes nothing" $?

export STUB_RELEASES="42 false someone"
run 1 "published Release exists (manual upload): refuses" "${PUBLISH}" v1.2.3 "${WORK}/assets"
! logged "release create"; check "  creates nothing" $?
grep -q "only publisher" "${WORK}/out"; check "  explains the workflow is the only publisher" $?

export STUB_RELEASES="43 true someone"
run 1 "draft made by a person exists: refuses" "${PUBLISH}" v1.2.3 "${WORK}/assets"
! logged "-X DELETE"; check "  deletes nothing" $?

export STUB_RELEASES="44 true github-actions[bot]"
run 0 "workflow's own leftover draft: replaced" "${PUBLISH}" v1.2.3 "${WORK}/assets"
logged "gh api -X DELETE repos/owner/repo/releases/44"; check "  deletes the leftover draft" $?
logged "gh release create v1.2.3"; check "  recreates the Release" $?
unset STUB_RELEASES

run 2 "empty assets dir: refuses" "${PUBLISH}" v1.2.3 "${WORK}/empty"
run 2 "non-vX.Y.Z tag: refuses" "${PUBLISH}" 'release/v1.2.3' "${WORK}/assets"

NEEDS_RESULT_VERIFY_TAG=failure NEEDS_RESULT_RELEASE=skipped STUB_OPEN_ISSUE="" \
    run 0 "alert: no open issue -> opens one" "${ALERT}" v1.2.3 https://example.invalid/run/1
logged 'gh issue create --title Release workflow failed for v1.2.3'; check "  issue titled after the tag" $?
NEEDS_RESULT_VERIFY_TAG=failure STUB_OPEN_ISSUE="77" \
    run 0 "alert: open issue -> comments on it" "${ALERT}" v1.2.3 https://example.invalid/run/2
logged "gh issue comment 77"; check "  comments on #77" $?
NEEDS_RESULT_VERIFY_TAG=failure run 0 "alert: --dry-run calls nothing" \
    "${ALERT}" v1.2.3 https://example.invalid/run/3 --dry-run
[ ! -s "${LOG}" ]; check "  no gh call" $?
grep -q "| verify-tag | failure |" "${WORK}/out"; check "  body lists each job's result" $?
run 2 "alert: missing arguments" "${ALERT}" v1.2.3

echo "release-publish self-test: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
