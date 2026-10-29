#!/usr/bin/env bash
#
# sign-source-tarball.sh — the detached OpenPGP signature of the upstream
# source tarball, and the check that keeps the signing pieces consistent
# (issue #538, F-SEC-010).
#
# Three pieces only work together: the public key a distribution verifies
# with (debian/upstream/signing-key.asc), the debian/watch option that asks
# uscan for the signature (pgpsigurlmangle), and the <tarball>.asc the
# release job publishes next to mmt-dpi-<VERSION>.tar.gz. The secret key is
# held by the maintainer and reaches the release job as the repository
# secret MMT_RELEASE_SIGNING_KEY (ASCII-armoured; an optional
# MMT_RELEASE_SIGNING_PASSPHRASE unlocks it). Until the maintainer commits the
# public key and provisions the secret, releases stay unsigned, as before.
#
# Usage:
#   sign-source-tarball.sh [--root DIR] --check
#       Pull-request check (scripts/validate-release-prep.sh): exit 1 unless
#       debian/upstream/signing-key.asc exists exactly when a non-comment line
#       of debian/watch uses pgpsigurlmangle.
#   sign-source-tarball.sh [--root DIR] <tarball>
#       Release job, before SHA256SUMS and the attestation:
#         no key committed, no secret -> warning, nothing signed (exit 0)
#         key committed, no secret    -> exit 1: uscan would reject the release
#         secret, no key committed    -> exit 1: nothing could verify the .asc
#         both                        -> writes <tarball>.asc, then verifies it
#                                        with gpgv against the committed key
#                                        alone (a secret that does not match
#                                        the committed key fails, .asc removed)
#
# --root DIR reads debian/ under DIR instead of this checkout (the self-test,
# tools/ci/tests/test-source-signing.sh, runs it on fixtures).
#
# The secret is imported on stdin into a throwaway GNUPGHOME under
# $RUNNER_TEMP, removed (and its gpg-agent stopped) on exit; it is never
# written to the checkout, put on a command line or printed. debian/watch and
# debian/upstream/ must both be in the release job's sparse checkout: sign
# mode re-checks their pairing.
#
# Exit: 0 consistent / signed / unsigned by design, 1 inconsistent or a
# signature that does not verify, 2 usage or tool error.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODE=sign
TARBALL=

while [ $# -gt 0 ]; do
    case "$1" in
        --root)  ROOT="${2:?--root needs a directory}"; shift 2 ;;
        --check) MODE=check; shift ;;
        -h|--help) sed -n '2,37p' "$0"; exit 0 ;;
        -*) echo "✗ unknown option: $1" >&2; exit 2 ;;
        *)  [ -z "${TARBALL}" ] || { echo "✗ one tarball only" >&2; exit 2; }
            TARBALL="$1"; shift ;;
    esac
done

KEY="${ROOT}/debian/upstream/signing-key.asc"
WATCH="${ROOT}/debian/watch"

# watch_signed — debian/watch asks uscan for a signature (comments excluded).
watch_signed() {
    [ -f "${WATCH}" ] && grep -v '^[[:space:]]*#' "${WATCH}" | grep -q 'pgpsigurlmangle'
}

# check_pairing — the committed key and the watch option come together.
check_pairing() {
    if [ -f "${KEY}" ] && ! watch_signed; then
        echo "✗ debian/upstream/signing-key.asc is committed but debian/watch does not use pgpsigurlmangle — add pgpsigurlmangle=s/\$/.asc/ to its opts" >&2
        return 1
    fi
    if [ ! -f "${KEY}" ] && watch_signed; then
        echo "✗ debian/watch uses pgpsigurlmangle but debian/upstream/signing-key.asc is missing — uscan could not verify the signature" >&2
        return 1
    fi
}

if [ "${MODE}" = check ]; then
    [ -z "${TARBALL}" ] || { echo "✗ --check takes no tarball" >&2; exit 2; }
    check_pairing || exit 1
    if [ -f "${KEY}" ]; then
        echo "✓ release signing configured: debian/upstream/signing-key.asc + pgpsigurlmangle in debian/watch"
    else
        echo "○ release signing not configured: no debian/upstream/signing-key.asc (maintainer action, issue #538)"
    fi
    exit 0
fi

[ -n "${TARBALL}" ] || { echo "✗ usage: $0 [--root DIR] (--check | <tarball>)" >&2; exit 2; }
[ -f "${TARBALL}" ] || { echo "✗ no such tarball: ${TARBALL}" >&2; exit 2; }
check_pairing || exit 1

if [ ! -f "${KEY}" ] && [ -z "${MMT_RELEASE_SIGNING_KEY:-}" ]; then
    echo "::warning::${TARBALL##*/} is published unsigned: no debian/upstream/signing-key.asc and no MMT_RELEASE_SIGNING_KEY secret (maintainer action, issue #538)"
    exit 0
fi
if [ -z "${MMT_RELEASE_SIGNING_KEY:-}" ]; then
    echo "✗ debian/upstream/signing-key.asc is committed but the MMT_RELEASE_SIGNING_KEY secret is not set — refusing to publish an unsigned tarball" >&2
    exit 1
fi
if [ ! -f "${KEY}" ]; then
    echo "✗ MMT_RELEASE_SIGNING_KEY is set but debian/upstream/signing-key.asc is not committed — nothing could verify the signature" >&2
    exit 1
fi
for tool in gpg gpgv; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "✗ ${tool} is required to sign" >&2; exit 2; }
done

# Outside the workspace (and so outside release/, which is published whole);
# the agent gpg starts is stopped with it, so no process keeps the unlocked
# key while the later release steps run.
GNUPGHOME="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gnupg.XXXXXX")"
export GNUPGHOME
chmod 0700 "${GNUPGHOME}"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf -- "${GNUPGHOME}"' EXIT

printf '%s\n' "${MMT_RELEASE_SIGNING_KEY}" | gpg --batch --quiet --import
SIG="${TARBALL}.asc"
rm -f -- "${SIG}"
if [ -n "${MMT_RELEASE_SIGNING_PASSPHRASE:-}" ]; then
    printf '%s' "${MMT_RELEASE_SIGNING_PASSPHRASE}" \
        | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
              --armor --detach-sign --output "${SIG}" "${TARBALL}"
else
    gpg --batch --yes --armor --detach-sign --output "${SIG}" "${TARBALL}"
fi

# Verify with the committed public key only — the keyring that signed is not
# trusted here, so a secret that is not the published key fails the release.
gpg --batch --quiet --dearmor --output "${GNUPGHOME}/upstream.gpg" "${KEY}"
if ! gpgv --keyring "${GNUPGHOME}/upstream.gpg" "${SIG}" "${TARBALL}"; then
    rm -f -- "${SIG}"
    echo "✗ ${SIG##*/} does not verify against debian/upstream/signing-key.asc — the secret is not the published key" >&2
    exit 1
fi
echo "✓ ${SIG##*/} verifies against debian/upstream/signing-key.asc"
