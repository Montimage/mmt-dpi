#!/usr/bin/env bash
#
# smoke-apt.sh — mmt-dpi installs from the signed APT repository, and apt
# refuses tampered repository metadata (issue #78; repository design in #24).
#
# Runs as root inside a fresh Debian/Ubuntu container (the `apt` and
# `apt-tamper` jobs of .github/workflows/install-smoke.yml), with this
# checkout mounted read-only:
#   [1/4] install the tools the documented APT setup and the consumer check
#         need (curl, ca-certificates, gnupg, gcc, libpcap-dev, pkg-config);
#   [2/4] fetch the published keyring and check that its primary key is the
#         one committed in debian/upstream/signing-key.asc — the keyring is
#         served by the same site as the metadata it vouches for, so it is
#         never trusted on its own; install it under /etc/apt/keyrings and
#         write the deb822 source (Signed-By) for this release's codename;
# positive leg (default):
#   [3/4] apt-get update, then install mmt-dpi and mmt-dpi-security at the
#         wanted upstream version (--version; the newest candidate without it)
#         and check what dpkg installed;
#   [4/4] run the installed-consumer check (run-installed-consumer.sh
#         --root-install) on the packaged SDK, with LD_LIBRARY_PATH unset;
# negative leg (--expect-reject):
#   [3/4] copy this codename's InRelease and Packages files into a local
#         directory served over file://, and run an apt-get update scoped to
#         that one source: it must succeed and offer mmt-dpi (the control);
#   [4/4] change one byte of the signed body of the local InRelease, drop the
#         lists the control wrote, and update again: apt-get update must exit
#         non-zero on the signature and mmt-dpi must have no candidate.
#
# Resolve mode (--resolve, the `apt-ready` job; runs on the runner, not as
# root): print the upstream version X.Y.Z every suite x architecture of the
# repository lists for mmt-dpi. With --tag vX.Y.Z (a post-release run) it
# polls the Packages indexes until all of them hold that version — the tag
# run dispatches the repository rebuild (tools/ci/notify-packages.sh), which
# finishes minutes after it — and fails after --wait seconds (default 2700).
# Without --tag it takes the newest version and fails unless every index
# holds it.
#
# Usage: bash tools/ci/smoke-apt.sh [--version X.Y.Z] [--consumer-dir DIR]
#                                   [--expect-reject]
#        bash tools/ci/smoke-apt.sh --resolve [--tag vX.Y.Z] [--wait SECONDS]
#   --version X.Y.Z     install this upstream version (the repository version
#                       is X.Y.Z-<commit>); default: the newest candidate
#   --consumer-dir DIR  directory holding run-installed-consumer.sh and its
#                       inputs (default: tools/ci/tests of this checkout);
#                       the workflow passes the installed release's own copy
#   APT_SUITES / APT_ARCHS  what --resolve checks (default: the five
#                       codenames and two architectures the repository serves)
#   REPO_DIR=<dir>      checkout to read (default: this script's repository)
#   APT_REPO_URL=<url>  repository (default https://montimage.github.io/packages)
# Exit: 0 = as expected, 1 = a step failed, 2 = usage error.

set -euo pipefail

WANT_VERSION=""; CONSUMER_DIR=""; EXPECT_REJECT=0
RESOLVE=0; TAG=""; WAIT=2700
while [ $# -gt 0 ]; do
    case "$1" in
        --version)       WANT_VERSION="${2:-}"; shift ;;
        --consumer-dir)  CONSUMER_DIR="${2:-}"; shift ;;
        --expect-reject) EXPECT_REJECT=1 ;;
        --resolve)       RESOLVE=1 ;;
        --tag)           TAG="${2:-}"; shift ;;
        --wait)          WAIT="${2:-}"; shift ;;
        -h|--help) sed -n '2,55p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ -n "$WANT_VERSION" ] && ! [[ $WANT_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "✗ --version must be X.Y.Z, not '${WANT_VERSION}'" >&2; exit 2
fi

APT_REPO_URL="${APT_REPO_URL:-https://montimage.github.io/packages}"

if [ "$RESOLVE" -eq 1 ]; then
    [[ $WAIT =~ ^[0-9]+$ ]] || { echo "✗ --wait needs a number of seconds" >&2; exit 2; }
    want=""
    if [ -n "$TAG" ]; then
        [[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "✗ --tag must be vX.Y.Z" >&2; exit 2; }
        want="${TAG#v}"
    fi
    read -r -a suites <<< "${APT_SUITES:-jammy noble resolute bookworm trixie}"
    read -r -a archs <<< "${APT_ARCHS:-amd64 arm64}"
    # Every mmt-dpi upstream version one Packages index lists, one per line.
    upstreams() {
        curl -fsSL "${APT_REPO_URL}/dists/$1/main/binary-$2/Packages" \
            | awk '/^Package: /{p=($2=="mmt-dpi")} p&&/^Version: /{v=$2; sub(/-[^-]*$/,"",v); print v}'
    }
    if [ -z "$want" ]; then
        want="$(upstreams "${suites[0]}" "${archs[0]}" | sort -V | tail -n1 || true)"
        [ -n "$want" ] || { echo "✗ ${APT_REPO_URL} ${suites[0]}/${archs[0]} lists no mmt-dpi" >&2; exit 1; }
        WAIT=0
    fi
    deadline=$(( $(date +%s) + WAIT ))
    while :; do
        missing=""
        for s in "${suites[@]}"; do
            for a in "${archs[@]}"; do
                upstreams "$s" "$a" 2>/dev/null | grep -qxF "$want" || missing="${missing} ${s}/${a}"
            done
        done
        [ -n "$missing" ] || break
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "✗ ${APT_REPO_URL} does not list mmt-dpi ${want} for:${missing}" >&2; exit 1
        fi
        echo "  waiting for mmt-dpi ${want} in:${missing}" >&2
        sleep 60
    done
    echo "✓ every suite and architecture lists mmt-dpi ${want}" >&2
    echo "$want"
    exit 0
fi
[ -z "$TAG" ] || { echo "✗ --tag needs --resolve" >&2; exit 2; }

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
CONSUMER_DIR="${CONSUMER_DIR:-${REPO_DIR}/tools/ci/tests}"
COMMITTED_KEY="${REPO_DIR}/debian/upstream/signing-key.asc"
KEYRING=/etc/apt/keyrings/montimage-archive-keyring.gpg
[ -f "$COMMITTED_KEY" ] || { echo "✗ no ${COMMITTED_KEY}" >&2; exit 2; }
[ "$EXPECT_REJECT" -eq 1 ] || [ -f "${CONSUMER_DIR}/run-installed-consumer.sh" ] \
    || { echo "✗ no run-installed-consumer.sh in ${CONSUMER_DIR}" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "✗ run as root in a throwaway container" >&2; exit 2; }
command -v apt-get >/dev/null 2>&1 || { echo "✗ the APT smoke needs a Debian/Ubuntu image" >&2; exit 2; }

# shellcheck disable=SC1091  # runtime file
. /etc/os-release
codename="${VERSION_CODENAME:?/etc/os-release has no VERSION_CODENAME}"
distro="${PRETTY_NAME:-${ID:-unknown}}"
arch="$(dpkg --print-architecture)"
mode="install${WANT_VERSION:+ ${WANT_VERSION}}"
[ "$EXPECT_REJECT" -eq 0 ] || mode="expect-reject"
echo "==> APT smoke on ${distro} (${codename}/${arch}, ${mode})"

export DEBIAN_FRONTEND=noninteractive
fail() { echo "✗ ${distro} (${arch}): $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
echo "  [1/4] installing curl, gnupg and the consumer's build tools"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    curl ca-certificates gnupg gcc libc6-dev libpcap-dev pkg-config >/dev/null

# ---------------------------------------------------------------------------
echo "  [2/4] keyring ${APT_REPO_URL}/montimage-archive-keyring.gpg"
primary_fpr() { gpg --batch --quiet --show-keys --with-colons "$1" | awk -F: '$1=="pub"{p=1;next} p&&$1=="fpr"{print $10;exit}'; }
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
export GNUPGHOME="${work}/gnupg"
install -d -m 0700 "$GNUPGHOME"
curl -fsSL -o "${work}/keyring.gpg" "${APT_REPO_URL}/montimage-archive-keyring.gpg"
want="$(primary_fpr "$COMMITTED_KEY")"
got="$(primary_fpr "${work}/keyring.gpg")"
[ -n "$want" ] || fail "no primary key in ${COMMITTED_KEY}"
[ "$got" = "$want" ] || fail "the published keyring's primary key is ${got:-none}, the committed one ${want}"
echo "        primary key ${got} (matches debian/upstream/signing-key.asc)"
install -d -m 0755 /etc/apt/keyrings
install -m 0644 "${work}/keyring.gpg" "$KEYRING"

# Every repository apt-get call below reads only the sources in this
# directory: the image's own mirrors can neither satisfy nor break a check.
sources="${work}/sources"
install -d -m 0755 "$sources"
apt_scoped() { apt-get -o Dir::Etc::SourceList=/dev/null -o "Dir::Etc::SourceParts=${sources}" "$@"; }
write_source() {
    printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: main\nSigned-By: %s\n' \
        "$1" "$codename" "$KEYRING" > "${sources}/montimage.sources"
}
candidate() { apt-cache -o Dir::Etc::SourceList=/dev/null -o "Dir::Etc::SourceParts=${sources}" \
                  policy "$1" | awk '$1=="Candidate:"{print $2}'; }

if [ "$EXPECT_REJECT" -eq 0 ]; then
    write_source "$APT_REPO_URL"
    # The documented setup: the same file in sources.list.d.
    install -m 0644 "${sources}/montimage.sources" /etc/apt/sources.list.d/montimage.sources

    # -----------------------------------------------------------------------
    echo "  [3/4] apt-get update; apt-get install mmt-dpi mmt-dpi-security"
    # Unscoped: the packages' Depends (libc6, libxml2…) come from the image's
    # own mirrors. A source apt cannot verify fails the update (exit 100).
    apt-get update -q || fail "apt-get update failed"
    if [ -n "$WANT_VERSION" ]; then
        pkgver="$(apt-cache madison mmt-dpi | awk -v v="$WANT_VERSION" '$3 ~ "^" v "-" {print $3; exit}')"
        [ -n "$pkgver" ] || fail "${APT_REPO_URL} ${codename} has no mmt-dpi ${WANT_VERSION}-*"
    else
        pkgver="$(candidate mmt-dpi)"
        { [ -n "$pkgver" ] && [ "$pkgver" != "(none)" ]; } || fail "${APT_REPO_URL} ${codename} offers no mmt-dpi"
    fi
    apt-get install -y -q "mmt-dpi=${pkgver}" "mmt-dpi-security=${pkgver}"
    for p in mmt-dpi mmt-dpi-security; do
        have="$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null || true)"
        [ "$have" = "$pkgver" ] || fail "${p} is ${have:-not installed}, expected ${pkgver}"
    done
    echo "        installed ${pkgver}"

    # -----------------------------------------------------------------------
    echo "  [4/4] installed-consumer check (loader registration, LD_LIBRARY_PATH unset)"
    env -u LD_LIBRARY_PATH bash "${CONSUMER_DIR}/run-installed-consumer.sh" --root-install \
        --package "-" --distro "${ID}-${VERSION_ID:-}-apt" --arch "$arch" \
        || fail "the installed-consumer check failed on mmt-dpi ${pkgver}"
    echo "✓ ${distro} (${arch}): mmt-dpi ${pkgver} from ${APT_REPO_URL} passes the installed-consumer check"
    exit 0
fi

# ---------------------------------------------------------------------------
echo "  [3/4] local copy of ${codename}'s metadata; control update"
mirror="${work}/mirror"
bin="dists/${codename}/main/binary-${arch}"
install -d -m 0755 "${mirror}/${bin}"
curl -fsSL -o "${mirror}/dists/${codename}/InRelease" "${APT_REPO_URL}/dists/${codename}/InRelease"
for f in Packages Packages.gz; do
    curl -fsSL -o "${mirror}/${bin}/${f}" "${APT_REPO_URL}/${bin}/${f}"
done
# apt's file method reads as the unprivileged _apt user.
chmod -R a+rX "$work"
write_source "file://${mirror}"
rm -rf /var/lib/apt/lists/*
log="${work}/update.log"
rc=0; apt_scoped update >"$log" 2>&1 || rc=$?
cat "$log"
[ "$rc" -eq 0 ] || fail "the control update of the untampered copy failed (exit ${rc})"
c="$(candidate mmt-dpi)"
{ [ -n "$c" ] && [ "$c" != "(none)" ]; } || fail "the control update offers no mmt-dpi"
echo "        control: exit 0, mmt-dpi candidate ${c}"

# ---------------------------------------------------------------------------
echo "  [4/4] one byte changed in the signed body of InRelease; update must fail"
inrel="${mirror}/dists/${codename}/InRelease"
before_sum="$(sha256sum "$inrel" | cut -d' ' -f1)"; before_size="$(stat -c %s "$inrel")"
grep -q '^Date: [A-W]' "$inrel" || fail "InRelease has no Date: field to change"
# The first letter of the Date: value (a weekday), inside the cleartext the
# signature covers: Mon -> Xon. One byte, same size.
sed -i '0,/^Date: /s/^Date: [A-W]/Date: X/' "$inrel"
after_sum="$(sha256sum "$inrel" | cut -d' ' -f1)"; after_size="$(stat -c %s "$inrel")"
{ [ "$after_sum" != "$before_sum" ] && [ "$after_size" = "$before_size" ]; } \
    || fail "the InRelease edit did not change exactly one byte"
grep '^Date: ' "$inrel" | sed 's/^/        /'
rm -rf /var/lib/apt/lists/*
rc=0; apt_scoped update >"$log" 2>&1 || rc=$?
cat "$log"
[ "$rc" -ne 0 ] || fail "apt-get update accepted a tampered InRelease"
# gpgv (BADSIG) or sqv (Debian 13: "Message has been manipulated").
grep -qE 'BADSIG|signatures were invalid|Message has been manipulated' "$log" \
    || fail "apt-get update failed (exit ${rc}) without a signature error"
c="$(candidate mmt-dpi)"
{ [ -z "$c" ] || [ "$c" = "(none)" ]; } || fail "mmt-dpi still has a candidate (${c}) after the rejected update"
echo "✓ ${distro} (${arch}): apt-get update refused the tampered InRelease (exit ${rc}), mmt-dpi not offered"
