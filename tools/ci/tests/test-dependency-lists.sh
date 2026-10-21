#!/usr/bin/env bash
#
# test-dependency-lists.sh — self-test for tools/ci/check-dependency-lists.sh
# (issue #495).
#
# The REAL lint runs against fixture trees (ROOT_DIR): a copy of the six files
# it reads, then that copy with exactly one list or manifest row changed.
#
#   this checkout                                              -> 0
#   unchanged fixture copy                                     -> 0
#   install.sh apt branch gains a package                      -> 1
#   install-build-deps.sh rpm list loses a package             -> 1
#   sdk/Makefile BuildRequires gains a package                 -> 1
#   AGENT_ENVIRONMENT.md toolchain line loses a package        -> 1
#   bootstrap-deps repeats a package                           -> 1
#   install.sh grows a second apt-get install in the function  -> 1
#   the best-effort `|| true` helper loses its `|| true`       -> 1
#   manifest adds a package to a role: every list naming it    -> 1
#   manifest lists an id no extractor knows                    -> 1
#   manifest list names a role undefined for its manager       -> 1
#   manifest row malformed                                     -> 2
#   a source file missing                                      -> 2
#
# Usage: bash tools/ci/tests/test-dependency-lists.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
LINT="${REPO_ROOT}/tools/ci/check-dependency-lists.sh"
[ -f "${LINT}" ] || { echo "✗ missing ${LINT}" >&2; exit 2; }

FILES=(tools/ci/build-deps.txt install.sh tools/ci/install-build-deps.sh
       sdk/Makefile .github/actions/bootstrap-deps/action.yml
       docs/AGENT_ENVIRONMENT.md)

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FX="${WORK}/repo"

failures=0
expect() { # expect <exit> <label> [ROOT_DIR]
    local want="$1" label="$2" root="${3:-${FX}}" got=0
    ROOT_DIR="${root}" bash "${LINT}" > "${WORK}/out" 2>&1 || got=$?
    if [ "${got}" = "${want}" ]; then
        echo "  ✓ ${label} (exit ${got})"
    else
        echo "  ✗ ${label}: expected exit ${want}, got ${got}"
        sed 's/^/      /' "${WORK}/out"
        failures=$((failures + 1))
    fi
}
expect_out() { # expect_out <label> <grep -E pattern>  (on the last run)
    if grep -Eq -- "$2" "${WORK}/out"; then
        echo "  ✓ $1"
    else
        echo "  ✗ $1: output lacks /$2/"
        sed 's/^/      /' "${WORK}/out"
        failures=$((failures + 1))
    fi
}
reset_fixture() {
    rm -rf "${FX}"
    local f
    for f in "${FILES[@]}"; do
        mkdir -p "${FX}/$(dirname "${f}")"
        cp "${REPO_ROOT}/${f}" "${FX}/${f}"
    done
}
# edit <file> <sed script> — the edit must change the file, or the self-test
# is broken (a no-op mutation would make a "must fail" case vacuous).
edit() {
    local f="${FX}/$1"
    cp "${f}" "${WORK}/before"
    sed -i "$2" "${f}"
    if cmp -s "${f}" "${WORK}/before"; then
        echo "✗ self-test broken: '$2' did not change $1" >&2
        exit 2
    fi
}

echo "--- check-dependency-lists.sh ---"
expect 0 "this checkout" "${REPO_ROOT}"

reset_fixture
expect 0 "unchanged fixture copy"

reset_fixture
edit install.sh '/^install_deps_linux()/,/^}/{s/^\( *\)libpcap-dev$/\1libpcap-dev \\\n\1libfoo-dev/;}'
expect 1 "install.sh apt branch gains a package"
expect_out "  ... and the lint names the package" "install\.sh:apt .*not in .*libfoo-dev"

reset_fixture
edit tools/ci/install-build-deps.sh 's/ libpcap-devel rpm-build / rpm-build /'
expect 1 "install-build-deps.sh rpm list loses a package"
expect_out "  ... and the lint names the missing package" "install-build-deps\.sh:rpm .*missing .*libpcap-devel"

reset_fixture
edit sdk/Makefile 's/libxml2-devel, rpm-build/libxml2-devel, libpcap-devel, rpm-build/'
expect 1 "sdk/Makefile BuildRequires gains a package"
expect_out "  ... and the lint names the package" "BuildRequires .*libpcap-devel"

reset_fixture
edit docs/AGENT_ENVIRONMENT.md '/apt-get install -y build-essential/s/ jq$//'
expect 1 "AGENT_ENVIRONMENT.md toolchain line loses a package"
expect_out "  ... and the lint names the missing package" "AGENT_ENVIRONMENT\.md .*missing .*jq"

reset_fixture
edit .github/actions/bootstrap-deps/action.yml 's/install -y libxml2-dev libpcap-dev /install -y libxml2-dev libpcap-dev libpcap-dev /'
expect 1 "bootstrap-deps repeats a package"
expect_out "  ... and the lint reports the repetition" "bootstrap-deps .*repeated"

reset_fixture
# shellcheck disable=SC2016  # a literal $SUDO in the sed script, not an expansion
edit install.sh '/^install_deps_linux()/,/^}/{s/^\( *\)\$SUDO apt-get update -qq$/&\n\1$SUDO apt-get install -y extra-tool/;}'
expect 1 "install.sh grows a second apt-get install in the function"
expect_out "  ... and the lint says it found two" "install\.sh:apt: expected one install command .* found 2"

reset_fixture
edit tools/ci/install-build-deps.sh 's/install -y dnf-plugins-core || true/install -y dnf-plugins-core/'
expect 1 "the best-effort '|| true' helper loses its '|| true'"

reset_fixture
edit tools/ci/build-deps.txt 's/^\(role  *build  *apt  *.*\)$/\1 cmake/'
expect 1 "manifest adds a package to a role"
expect_out "  ... install.sh:apt falls behind" "install\.sh:apt .*missing .*cmake"
expect_out "  ... install-build-deps.sh:deb falls behind" "install-build-deps\.sh:deb .*missing .*cmake"
expect_out "  ... AGENT_ENVIRONMENT.md falls behind" "AGENT_ENVIRONMENT\.md .*missing .*cmake"

reset_fixture
printf 'list  Dockerfile  apt  build\n' >> "${FX}/tools/ci/build-deps.txt"
expect 1 "manifest lists an id no extractor knows"
expect_out "  ... and the lint names it" "Dockerfile: listed in .* no extractor"

reset_fixture
edit tools/ci/build-deps.txt 's/^\(list  *install\.sh:dnf  *dnf  *build examples\)$/\1 devtools/'
expect 1 "manifest list names a role undefined for its manager"
expect_out "  ... and the lint names the role" "install\.sh:dnf: role 'devtools' has no"

reset_fixture
printf 'role  build\n' >> "${FX}/tools/ci/build-deps.txt"
expect 2 "manifest row malformed"

reset_fixture
rm "${FX}/docs/AGENT_ENVIRONMENT.md"
expect 2 "a source file missing"

if [ "${failures}" -gt 0 ]; then
    echo "✗ ${failures} dependency-list self-test check(s) failed"
    exit 1
fi
echo "✓ dependency-list self-test passed"
