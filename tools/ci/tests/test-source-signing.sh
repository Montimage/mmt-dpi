#!/usr/bin/env bash
#
# test-source-signing.sh — self-test for tools/ci/sign-source-tarball.sh and
# its wiring (issue #538, F-SEC-010).
#
# The real script runs on fixture trees. No OpenPGP key is created or used:
# every case below is decided before gpg would run — the pairing of
# debian/upstream/signing-key.asc with debian/watch's pgpsigurlmangle, and the
# key/secret combinations the release job refuses. The fixture "key" is a
# placeholder text file, never key material.
#
#   --check: no key + no pgpsigurlmangle            -> 0 (unsigned by design)
#            key + pgpsigurlmangle                   -> 0
#            key, no pgpsigurlmangle                 -> 1
#            pgpsigurlmangle, no key                 -> 1
#            pgpsigurlmangle in a comment only       -> 0 (comments ignored)
#   sign:    no key + no secret  -> 0, ::warning, no .asc
#            key, no secret      -> 1, no .asc
#            secret, no key      -> 1, no .asc
#            key, no debian/watch -> 1 (the release job must check it out)
#            missing tarball     -> 2
# Then the committed tree: debian/watch names the release-asset tarball and
# --check passes, and release-packages.yml signs the tarball in the tag-only
# release job before SHA256SUMS and the attestation.
#
# Usage: bash tools/ci/tests/test-source-signing.sh
# Exit: 0 = all checks pass, 1 = a check failed, 2 = the self-test broke.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SIGNER="${REPO_ROOT}/tools/ci/sign-source-tarball.sh"
WF="${REPO_ROOT}/.github/workflows/release-packages.yml"
[ -f "${SIGNER}" ] || { echo "✗ missing ${SIGNER}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILS=0
pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; FAILS=$((FAILS + 1)); }

# tree <name> <key:0|1> <watch-line> — a fixture root with debian/watch
# holding <watch-line> (none when empty) and, with key=1, a placeholder
# debian/upstream/signing-key.asc. Prints the root.
tree() {
    local d="${WORK}/$1"
    mkdir -p "${d}/debian/upstream"
    if [ -n "$3" ]; then printf 'version=4\n%s\n' "$3" > "${d}/debian/watch"; fi
    if [ "$2" = 1 ]; then echo 'placeholder for the test, not key material' > "${d}/debian/upstream/signing-key.asc"; fi
    printf '%s\n' "${d}"
}

# expect <label> <exit> <cmd...> — the command exits <exit>.
expect() {
    local label="$1" want="$2" got=0
    shift 2
    "$@" >"${WORK}/out" 2>&1 || got=$?
    if [ "${got}" -eq "${want}" ]; then pass "${label} (exit ${got})"; else fail "${label}: exit ${got}, want ${want}"; sed 's/^/      /' "${WORK}/out"; fi
}

PLAIN='opts="searchmode=plain" https://example.invalid/releases https://example.invalid/mmt-dpi-(\d[\d.]*)\.tar\.gz'
SIGNED='opts="searchmode=plain, pgpsigurlmangle=s/$/.asc/" https://example.invalid/releases https://example.invalid/mmt-dpi-(\d[\d.]*)\.tar\.gz'

echo "--- --check: the key and pgpsigurlmangle come together ---"
expect "no key, no pgpsigurlmangle" 0 bash "${SIGNER}" --root "$(tree c1 0 "${PLAIN}")" --check
expect "no debian/watch at all" 0 bash "${SIGNER}" --root "$(tree c2 0 '')" --check
expect "key and pgpsigurlmangle" 0 bash "${SIGNER}" --root "$(tree c3 1 "${SIGNED}")" --check
expect "key without pgpsigurlmangle is refused" 1 bash "${SIGNER}" --root "$(tree c4 1 "${PLAIN}")" --check
expect "pgpsigurlmangle without a key is refused" 1 bash "${SIGNER}" --root "$(tree c5 0 "${SIGNED}")" --check
expect "pgpsigurlmangle in a comment does not count" 0 \
    bash "${SIGNER}" --root "$(tree c6 0 "# ${SIGNED}")" --check

echo "--- sign mode: refusals happen before gpg runs ---"
TB="${WORK}/mmt-dpi-0.0.0.tar.gz"
echo 'not a real tarball' > "${TB}"
R="$(tree s1 0 "${PLAIN}")"
expect "no key, no secret: published unsigned" 0 env -u MMT_RELEASE_SIGNING_KEY bash "${SIGNER}" --root "${R}" "${TB}"
if grep -q '^::warning::.*unsigned' "${WORK}/out" && [ ! -e "${TB}.asc" ]; then
    pass "the unsigned case warns and writes no .asc"
else
    fail "the unsigned case must warn and write no .asc"
fi
expect "key committed, no secret: refused" 1 \
    env -u MMT_RELEASE_SIGNING_KEY bash "${SIGNER}" --root "$(tree s2 1 "${SIGNED}")" "${TB}"
expect "secret set, no key committed: refused" 1 \
    env MMT_RELEASE_SIGNING_KEY='placeholder, not key material' bash "${SIGNER}" --root "$(tree s3 0 "${PLAIN}")" "${TB}"
expect "inconsistent pairing refused in sign mode too" 1 \
    env -u MMT_RELEASE_SIGNING_KEY bash "${SIGNER}" --root "$(tree s4 1 "${PLAIN}")" "${TB}"
expect "key committed but debian/watch not checked out: refused" 1 \
    env -u MMT_RELEASE_SIGNING_KEY bash "${SIGNER}" --root "$(tree s5 1 '')" "${TB}"
expect "missing tarball is a usage error" 2 bash "${SIGNER}" --root "${R}" "${WORK}/absent.tar.gz"
if [ ! -e "${TB}.asc" ]; then pass "no refusal left a .asc behind"; else fail "a refusal left ${TB}.asc"; fi

echo "--- the committed tree ---"
expect "the committed debian/ passes --check" 0 bash "${SIGNER}" --check
WATCH_LINES="$(grep -v '^[[:space:]]*#' "${REPO_ROOT}/debian/watch")"
if grep -q 'releases/download/v' <<< "${WATCH_LINES}" && grep -q 'mmt-dpi-' <<< "${WATCH_LINES}"; then
    pass "debian/watch matches the release-asset tarball (releases/download/v<ver>/mmt-dpi-<ver>)"
else
    fail "debian/watch must match the release-asset tarball, not a tag archive"
fi
if grep -Eq 'repacksuffix=\+ds' <<< "${WATCH_LINES}" && grep -q 'dversionmangle=' <<< "${WATCH_LINES}"; then
    pass "debian/watch repacks to +ds and compares versions without it"
else
    fail "debian/watch needs repacksuffix=+ds and a dversionmangle (Files-Excluded repack)"
fi

# The release job: the script is in its sparse checkout, signs before the
# SHA256SUMS manifest and the attestation (so both cover the .asc), and is
# the only step that receives the secret.
REL="$(awk '/^  release:/{on=1} /^  release-alert:/{on=0} on' "${WF}")"
sign_at="$(grep -n 'name: Sign the source tarball' <<< "${REL}" | cut -d: -f1)"
sums_at="$(grep -n 'name: Generate SHA256SUMS manifest' <<< "${REL}" | cut -d: -f1)"
attest_at="$(grep -n 'name: Attest build provenance' <<< "${REL}" | cut -d: -f1)"
if grep -q '^ *tools/ci/sign-source-tarball.sh$' <<< "${REL}" && grep -q '^ *debian/watch$' <<< "${REL}" \
    && grep -q '^ *debian/upstream/$' <<< "${REL}"; then
    pass "the release job's sparse checkout holds the signer, debian/watch and debian/upstream/"
else
    fail "the release job's sparse checkout must hold tools/ci/sign-source-tarball.sh, debian/watch and debian/upstream/ (sign mode re-checks their pairing)"
fi
if [ -n "${sign_at}" ] && [ -n "${sums_at}" ] && [ -n "${attest_at}" ] \
    && [ "${sign_at}" -lt "${sums_at}" ] && [ "${sign_at}" -lt "${attest_at}" ]; then
    pass "the tarball is signed before SHA256SUMS and the attestation"
else
    fail "the release job must run sign-source-tarball.sh before SHA256SUMS and the attestation"
fi
if [ "$(grep -c 'secrets.MMT_RELEASE_SIGNING_KEY' "${WF}")" -eq 1 ] \
    && grep -q 'secrets.MMT_RELEASE_SIGNING_KEY' <<< "${REL}"; then
    pass "only the tag-only release job receives MMT_RELEASE_SIGNING_KEY"
else
    fail "MMT_RELEASE_SIGNING_KEY must reach the release job only"
fi

echo
if [ "${FAILS}" -gt 0 ]; then
    echo "✗ source-signing self-test: ${FAILS} check(s) failed" >&2
    exit 1
fi
echo "✓ source-signing self-test: all checks passed"
