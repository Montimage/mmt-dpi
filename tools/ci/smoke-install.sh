#!/usr/bin/env bash
#
# smoke-install.sh — the documented one-command install and first run work
# end to end on one distribution (issue #493, F-CI-113).
#
# Runs as root inside a fresh distribution container (the matrix of
# .github/workflows/install-smoke.yml), the way a new user meets the docs:
#   [1/4] install the two tools the one-liner itself needs (curl, plus bash
#         where the image lacks it — Alpine) with the native package manager;
#   [2/4] run the README one-liner `curl -fsSL <install.sh> | bash`;
#   [3/4] in an empty directory, run the three landing-page steps displayed
#         in docs/_includes/first-example.md (fetch hello_packet.c and
#         traffic.pcap, compile, run) with LD_LIBRARY_PATH unset — the root
#         install must have registered the loader (issue #485);
#   [4/4] compare the program's output with the output the page displays.
#
# Sources (--source):
#   published  the installer at its published URL (main/install.sh on
#              raw.githubusercontent.com), which clones and verifies the
#              pinned release tag, and the first-run files from the
#              documentation site — exactly what a user runs.
#   local      this checkout: the installer is fetched with curl from a
#              file:// URL (no network fetch of the published script), its
#              clone of the canonical repository is redirected to this
#              checkout with a git `insteadOf` rule, and it builds the ref
#              given by --ref (a branch the caller created at the commit under
#              test) through --branch/--unverified-branch. The first-run files
#              come from docs/first-run/ in the checkout. Used on pull
#              requests, so the PR's installer and SDK are what is tested.
#
# The displayed steps are run verbatim; the only substitution is the site URL
# -> file://<checkout>/docs/ under --source local.
#
# Usage: bash tools/ci/smoke-install.sh --source published|local [--ref <branch>]
#   REPO_DIR=<dir>  checkout to read (default: this script's repository)
# Exit: 0 = installed and the first run printed the displayed output,
#       1 = a step failed, 2 = usage error.

set -euo pipefail

SOURCE=""
REF=""
while [ $# -gt 0 ]; do
    case "$1" in
        --source) SOURCE="${2:-}"; shift ;;
        --ref)    REF="${2:-}"; shift ;;
        -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
case "$SOURCE" in
    published) ;;
    local) [ -n "$REF" ] || { echo "✗ --source local needs --ref <branch>" >&2; exit 2; } ;;
    *) echo "✗ --source must be published or local" >&2; exit 2 ;;
esac

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
FRAGMENT="${REPO_DIR}/docs/_includes/first-example.md"
SITE_URL="https://montimage-projects.github.io/mmt-dpi/"
CANONICAL_REPO="https://github.com/montimage-projects/mmt-dpi.git"
PUBLISHED_INSTALLER="https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh"
[ -f "$FRAGMENT" ] || { echo "✗ no ${FRAGMENT}" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "✗ run as root in a throwaway container" >&2; exit 2; }

distro="unknown"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091  # runtime file
    distro="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${ID:-unknown}}")"
fi
echo "==> install smoke on ${distro} (source: ${SOURCE})"

# ---------------------------------------------------------------------------
echo "  [1/4] installing the one-liner's own prerequisites (curl, bash)"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    command -v curl >/dev/null 2>&1 || dnf install -y -q curl ca-certificates
elif command -v yum >/dev/null 2>&1; then
    command -v curl >/dev/null 2>&1 || yum install -y -q curl ca-certificates
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed curl ca-certificates >/dev/null
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache bash curl ca-certificates >/dev/null
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install -y curl ca-certificates >/dev/null
else
    echo "✗ no supported package manager in this image" >&2; exit 1
fi

# ---------------------------------------------------------------------------
installer_args=()
if [ "$SOURCE" = "local" ]; then
    installer_url="file://${REPO_DIR}/install.sh"
    site_base="file://${REPO_DIR}/docs/"
    # The installer clones the canonical URL; send that clone to this
    # checkout. git is not installed yet (the installer installs it), so the
    # rule is written as a plain gitconfig file. safe.directory: the checkout
    # is owned by the runner's uid, not by root.
    cat > "${HOME}/.gitconfig" <<EOF
[url "file://${REPO_DIR}"]
	insteadOf = ${CANONICAL_REPO}
[safe]
	directory = *
EOF
    installer_args=(-s -- --branch "$REF" --unverified-branch)
else
    installer_url="$PUBLISHED_INSTALLER"
    site_base="$SITE_URL"
fi

echo "  [2/4] curl -fsSL ${installer_url} | bash ${installer_args[*]}"
# shellcheck disable=SC2016  # expanded by the inner bash, from its arguments
env -u LD_LIBRARY_PATH bash -o pipefail -c \
    'curl -fsSL "$1" | bash "${@:2}"' _ "$installer_url" "${installer_args[@]}"

# ---------------------------------------------------------------------------
echo "  [3/4] running the landing-page first run with LD_LIBRARY_PATH unset"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
# The fragment's ```bash and ```text blocks: the displayed commands and the
# displayed output (backslash continuations are kept; bash joins them).
# shellcheck disable=SC2016  # literal Markdown fences, not expansions
sed -n '/^```bash$/,/^```$/{/^```/d;p}' "$FRAGMENT" > "${work}/steps.sh"
# shellcheck disable=SC2016  # literal Markdown fences, not expansions
sed -n '/^```text$/,/^```$/{/^```/d;p}' "$FRAGMENT" > "${work}/expected.txt"
if [ ! -s "${work}/steps.sh" ] || [ ! -s "${work}/expected.txt" ]; then
    echo "✗ ${FRAGMENT} lost its bash or text block" >&2; exit 1
fi
if [ "$site_base" != "$SITE_URL" ]; then
    sed -i "s#${SITE_URL}#${site_base}#g" "${work}/steps.sh"
fi
mkdir "${work}/run"
sed 's/^/        /' "${work}/steps.sh"
(cd "${work}/run" && env -u LD_LIBRARY_PATH bash -e "${work}/steps.sh") > "${work}/actual.txt"

# ---------------------------------------------------------------------------
echo "  [4/4] comparing with the displayed output"
# Plain shell comparison: diff/cmp (diffutils) are absent from minimal images.
if [ "$(cat "${work}/actual.txt")" = "$(cat "${work}/expected.txt")" ]; then
    echo "✓ ${distro}: one-command install + first run without LD_LIBRARY_PATH"
else
    echo "✗ ${distro}: the first run's output differs from the displayed output" >&2
    echo "--- displayed" >&2; cat "${work}/expected.txt" >&2
    echo "+++ actual" >&2; cat "${work}/actual.txt" >&2
    exit 1
fi
