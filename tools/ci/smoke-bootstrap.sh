#!/usr/bin/env bash
#
# smoke-bootstrap.sh — the release bootstrap installs the native package, and
# refuses a tampered one (issue #498, F-CI-112).
#
# Runs as root inside a fresh distribution container (the `smoke` job of
# .github/workflows/bootstrap-smoke.yml):
#   [1/4] install curl (the one-liner's only prerequisite) natively;
#   [2/4] run the one-liner: `curl -fsSL <install.sh> | sh`;
#   [3/4] the package registered libmmt_core with the loader
#         (`ldconfig -p | grep -c libmmt_core` >= 1);
#   [4/4] install the first-run prerequisites docs/_includes/first-example.md
#         names (gcc + libpcap-dev / libpcap-devel) and run its displayed
#         steps in an empty directory with LD_LIBRARY_PATH unset, comparing
#         the output with the displayed one.
# With --expect-reject sha256|attestation, step [2/4] must exit non-zero
# with that check's refusal message and leave no mmt-dpi package installed;
# steps [3/4] and [4/4] are skipped.
#
# Sources:
#   --source published     the README one-liner verbatim:
#                          releases/latest/download/install.sh, first-run
#                          files from the documentation site
#   --fixture <dir>        a directory made by tools/ci/make-bootstrap-fixture.sh
#                          (real published packages + attestation, bootstrap
#                          rendered by the release-job generator), served over
#                          file:// via MMT_BOOTSTRAP_BASE_URL; first-run files
#                          from docs/ in this checkout
#
# Usage: bash tools/ci/smoke-bootstrap.sh (--source published | --fixture <dir>)
#                                         [--expect-reject sha256|attestation]
#   REPO_DIR=<dir>  checkout to read (default: this script's repository)
# Exit: 0 = as expected, 1 = a step failed, 2 = usage error.

set -euo pipefail

SOURCE=""; FIXTURE=""; EXPECT_REJECT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --source)  SOURCE="${2:-}"; shift ;;
        --fixture) FIXTURE="${2:-}"; shift ;;
        --expect-reject)
            case "${2:-}" in
                sha256) EXPECT_REJECT="sha256 mismatch" ;;
                attestation) EXPECT_REJECT="provenance attestation does not match" ;;
                *) echo "✗ --expect-reject needs sha256 or attestation" >&2; exit 2 ;;
            esac
            shift ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if [ -n "$FIXTURE" ]; then
    [ -z "$SOURCE" ] || { echo "✗ --source and --fixture are exclusive" >&2; exit 2; }
    FIXTURE="$(cd "$FIXTURE" && pwd)"
    [ -f "$FIXTURE/install.sh" ] || { echo "✗ no install.sh in $FIXTURE" >&2; exit 2; }
elif [ "$SOURCE" != published ]; then
    echo "✗ use --source published or --fixture <dir>" >&2; exit 2
fi

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
FRAGMENT="${REPO_DIR}/docs/_includes/first-example.md"
SITE_URL="https://montimage-projects.github.io/mmt-dpi/"
PUBLISHED="https://github.com/montimage-projects/mmt-dpi/releases/latest/download/install.sh"
[ -f "$FRAGMENT" ] || { echo "✗ no ${FRAGMENT}" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "✗ run as root in a throwaway container" >&2; exit 2; }

distro="unknown"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091  # runtime file
    distro="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${ID:-unknown}}")"
fi
echo "==> bootstrap smoke on ${distro} (${FIXTURE:-published}${EXPECT_REJECT:+, expect: ${EXPECT_REJECT}})"

pkg_installed() {
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Status}' mmt-dpi 2>/dev/null | grep -q 'install ok installed'
    else
        rpm -q mmt-dpi >/dev/null 2>&1
    fi
}

# ---------------------------------------------------------------------------
echo "  [1/4] installing curl"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates >/dev/null
    # Cold package metadata, as on a host or an image that dropped its lists:
    # the bootstrap itself must refresh it to resolve the package's Depends.
    rm -rf /var/lib/apt/lists/*
elif command -v dnf >/dev/null 2>&1; then
    command -v curl >/dev/null 2>&1 || dnf install -y -q curl ca-certificates
    dnf clean all >/dev/null
else
    echo "✗ the bootstrap smoke covers apt-get and dnf images only" >&2; exit 1
fi

# ---------------------------------------------------------------------------
rc=0
log="$(mktemp)"
if [ -n "$FIXTURE" ]; then
    echo "  [2/4] curl -fsSL file://${FIXTURE}/install.sh | MMT_BOOTSTRAP_BASE_URL=file://${FIXTURE} sh"
    # shellcheck disable=SC2016  # expanded by the inner bash, from its arguments
    env -u LD_LIBRARY_PATH bash -o pipefail -c \
        'curl -fsSL "file://$1/install.sh" | MMT_BOOTSTRAP_BASE_URL="file://$1" sh' _ "$FIXTURE" \
        >"$log" 2>&1 || rc=$?
else
    echo "  [2/4] curl -fsSL ${PUBLISHED} | sh"
    # shellcheck disable=SC2016  # expanded by the inner bash, from its arguments
    env -u LD_LIBRARY_PATH bash -o pipefail -c 'curl -fsSL "$1" | sh' _ "$PUBLISHED" \
        >"$log" 2>&1 || rc=$?
fi
cat "$log"

if [ -n "$EXPECT_REJECT" ]; then
    if [ "$rc" -eq 0 ]; then
        echo "✗ ${distro}: the bootstrap accepted a tampered asset" >&2; exit 1
    fi
    if ! grep -qF "$EXPECT_REJECT" "$log"; then
        echo "✗ ${distro}: the bootstrap failed (exit ${rc}) without '${EXPECT_REJECT}'" >&2; exit 1
    fi
    if pkg_installed; then
        echo "✗ ${distro}: the bootstrap failed (exit ${rc}) but mmt-dpi is installed" >&2; exit 1
    fi
    echo "✓ ${distro}: refused (${EXPECT_REJECT}, exit ${rc}), nothing installed"
    exit 0
fi
[ "$rc" -eq 0 ] || { echo "✗ ${distro}: the bootstrap failed (exit ${rc})" >&2; exit 1; }

# ---------------------------------------------------------------------------
echo "  [3/4] ldconfig -p | grep -c libmmt_core"
count="$(ldconfig -p | grep -c libmmt_core || true)"
[ "$count" -ge 1 ] || { echo "✗ ${distro}: libmmt_core is not in the loader cache" >&2; exit 1; }
echo "        ${count}"

# ---------------------------------------------------------------------------
echo "  [4/4] first-run prerequisites, then the landing-page steps with LD_LIBRARY_PATH unset"
if ! grep -qF 'sudo apt-get install gcc libpcap-dev' "$FRAGMENT" \
   || ! grep -qF 'sudo dnf --enablerepo=crb install gcc libpcap-devel' "$FRAGMENT"; then
    echo "✗ ${FRAGMENT} no longer displays the gcc + libpcap prerequisite commands" >&2; exit 1
fi
if command -v apt-get >/dev/null 2>&1; then
    # The commands first-example.md displays, minus sudo (this runs as root).
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc libpcap-dev >/dev/null
else
    dnf --enablerepo=crb install -y -q gcc libpcap-devel
fi
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
# shellcheck disable=SC2016  # literal Markdown fences, not expansions
sed -n '/^```bash$/,/^```$/{/^```/d;p}' "$FRAGMENT" > "${work}/steps.sh"
# shellcheck disable=SC2016  # literal Markdown fences, not expansions
sed -n '/^```text$/,/^```$/{/^```/d;p}' "$FRAGMENT" > "${work}/expected.txt"
if [ ! -s "${work}/steps.sh" ] || [ ! -s "${work}/expected.txt" ]; then
    echo "✗ ${FRAGMENT} lost its bash or text block" >&2; exit 1
fi
[ -z "$FIXTURE" ] || sed -i "s#${SITE_URL}#file://${REPO_DIR}/docs/#g" "${work}/steps.sh"
mkdir "${work}/run"
(cd "${work}/run" && env -u LD_LIBRARY_PATH bash -e "${work}/steps.sh") > "${work}/actual.txt"
if [ "$(cat "${work}/actual.txt")" = "$(cat "${work}/expected.txt")" ]; then
    echo "✓ ${distro}: verified package install + first run without LD_LIBRARY_PATH"
else
    echo "✗ ${distro}: the first run's output differs from the displayed output" >&2
    echo "--- displayed" >&2; cat "${work}/expected.txt" >&2
    echo "+++ actual" >&2; cat "${work}/actual.txt" >&2
    exit 1
fi
