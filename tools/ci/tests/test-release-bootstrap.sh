#!/usr/bin/env bash
#
# test-release-bootstrap.sh — self-test for tools/ci/make-release-bootstrap.sh
# and the bootstrap template tools/ci/bootstrap-install.sh (issue #498).
#
# Offline, no docker, no root: the generator runs on fixture release
# directories (stand-in package files with the real naming scheme), and the
# rendered bootstrap is sourced with MMT_BOOTSTRAP_SOURCE_ONLY=1 to drive its
# distribution detection, row lookup and digest check. The full chain —
# download, sha256, Sigstore attestation, native install — runs against a
# published release in the `smoke` job of .github/workflows/bootstrap-smoke.yml
# (tools/ci/smoke-bootstrap.sh), including the tampered-asset legs.
#
# Usage: bash tools/ci/tests/test-release-bootstrap.sh
# Exit: 0 = all checks pass, 1 = a check failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GEN="${REPO_ROOT}/tools/ci/make-release-bootstrap.sh"
TEMPLATE="${REPO_ROOT}/tools/ci/bootstrap-install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILS=0
pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; FAILS=$((FAILS + 1)); }
check() { # <label> <command>... — passes when the command succeeds
    local label="$1"; shift
    if "$@"; then pass "$label"; else fail "$label"; fi
}
# expect_refusal <label> <dir> [tag] — the generator must exit 1 and write nothing.
expect_refusal() {
    local rc=0
    bash "$GEN" "${3:-v1.2.3}" "$2" >"$WORK/out" 2>&1 || rc=$?
    if [ "$rc" -eq 1 ] && [ ! -e "$2/install.sh" ] && [ ! -e "$2/manifest.json" ]; then
        pass "refuses: $1 ($(tail -n1 "$WORK/out" | sed 's/^✗ //'))"
    else
        fail "refuses: $1 (exit ${rc})"
    fi
}
# release_dir <name> <file>... — a fixture release directory.
release_dir() {
    local d="$WORK/$1" f; shift
    mkdir -p "$d"
    for f in "$@"; do printf '%s payload\n' "$f" > "$d/$f"; done
    printf '%s\n' "$d"
}

echo "make-release-bootstrap.sh / bootstrap-install.sh self-test (issue #498)"

# --- the generator's table matches the release matrix -------------------------
# FORMAT in the generator and the build job's distro matrix list the same
# distributions with the same format (issue #515): a matrix leg the table
# lacks makes the release job refuse the tag, and a table entry no leg
# builds advertises a package that never ships.
matrix_legs() { # "<name> <pkg>" per row of the build job's distro matrix
    sed -n '/^  build:$/,/^  [a-z-]*:$/p' "${REPO_ROOT}/.github/workflows/release-packages.yml" \
        | sed -n 's/^ *- { *name: *\([a-z0-9.-]*\),.*pkg: *\([a-z]*\) *}.*/\1 \2/p' | LC_ALL=C sort
}
format_table() { # "<distro> <ext>" per FORMAT entry of the generator
    sed -n '/^declare -A FORMAT=($/,/^)$/p' "$GEN" \
        | grep -o '\[[a-z0-9.-]*\]=[a-z]*' | sed 's/^\[\(.*\)\]=\(.*\)$/\1 \2/' | LC_ALL=C sort
}
legs="$(matrix_legs)"
check "the build matrix has legs" test -n "$legs"
check "the generator's FORMAT table names exactly the build-matrix legs and formats" \
    test "$legs" = "$(format_table)"
for leg in "ubuntu-26.04 deb" "debian-13 deb" "rocky-10 rpm" "centos-stream10 rpm"; do
    check "the build matrix carries the current-generation leg ${leg% *} (.${leg#* })" \
        grep -qx "$leg" <<< "$legs"
done

# --- a well-formed release ----------------------------------------------------
good="$(release_dir good \
    mmt-dpi_1.2.3_abc123_ubuntu-24.04_x86_64.deb \
    mmt-dpi_1.2.3_abc123_ubuntu-24.04_aarch64.deb \
    mmt-dpi-security_1.2.3_abc123_ubuntu-24.04_x86_64.deb \
    mmt-dpi_1.2.3_abc123_rocky-9_x86_64.rpm \
    mmt-dpi_1.2.3_abc123_ubuntu-24.04_x86_64.deb.sbom.json)"
check "renders a release directory" bash "$GEN" v1.2.3 "$good" >/dev/null
for a in mmt-dpi_ubuntu-24.04_amd64.deb mmt-dpi_ubuntu-24.04_arm64.deb \
         mmt-dpi-security_ubuntu-24.04_amd64.deb mmt-dpi_rocky-9_amd64.rpm; do
    check "  alias $a" test -f "$good/$a"
done
check "an alias is a byte copy of its versioned package" \
    cmp -s "$good/mmt-dpi_rocky-9_amd64.rpm" "$good/mmt-dpi_1.2.3_abc123_rocky-9_x86_64.rpm"
check "the versioned packages stay" test -f "$good/mmt-dpi_1.2.3_abc123_rocky-9_x86_64.rpm"

manifest_ok() {
python3 - "$good" <<'PYEOF'
import hashlib, json, os, sys
d = sys.argv[1]
m = json.load(open(os.path.join(d, "manifest.json")))
assert m["tag"] == "v1.2.3" and m["version"] == "1.2.3", m
assert m["attestation_bundle"] == "mmt-dpi.intoto.jsonl"
assert len(m["packages"]) == 4, m["packages"]
for p in m["packages"]:
    assert set(p) == {"distro", "arch", "package", "format", "file", "source", "sha256"}, p
    for f in (p["file"], p["source"]):
        assert hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() == p["sha256"], f
    assert p["file"] == f'{p["package"]}_{p["distro"]}_{p["arch"]}.{p["format"]}', p
PYEOF
}
check "manifest.json is valid JSON and every sha256 matches the alias and its source" manifest_ok
check "rendered install.sh is valid sh" sh -n "$good/install.sh"
if grep -q '@[A-Z_]*@' "$good/install.sh"; then
    fail "rendered install.sh has a placeholder left"
else
    pass "rendered install.sh has no placeholder left"
fi
check "rendered install.sh is pinned to the tag" grep -qx 'RELEASE_TAG="v1.2.3"' "$good/install.sh"

# The embedded table equals manifest.json.
python3 - "$good" > "$WORK/manifest.rows" <<'PYEOF'
import json, os, sys
m = json.load(open(os.path.join(sys.argv[1], "manifest.json")))
for p in m["packages"]:
    print(p["distro"], p["arch"], p["package"], p["file"], p["sha256"])
PYEOF
# Sources the rendered bootstrap without running it, then runs "$@" in it.
in_bootstrap() {
    # shellcheck disable=SC1090,SC1091  # the rendered fixture script
    (MMT_BOOTSTRAP_SOURCE_ONLY=1 . "$good/install.sh" && "$@")
}
in_bootstrap manifest_rows > "$WORK/embedded.rows"
check "install.sh embeds exactly the manifest.json rows" cmp -s "$WORK/manifest.rows" "$WORK/embedded.rows"

# --- refusals -------------------------------------------------------------------
expect_refusal "version other than the tag's" \
    "$(release_dir badver mmt-dpi_1.2.4_abc_ubuntu-24.04_x86_64.deb)"
expect_refusal "unmapped distribution" \
    "$(release_dir baddistro mmt-dpi_1.2.3_abc_fedora-44_x86_64.rpm)"
expect_refusal "format not shipped by the distribution" \
    "$(release_dir badfmt mmt-dpi_1.2.3_abc_ubuntu-24.04_x86_64.rpm)"
expect_refusal "unrecognised package name" \
    "$(release_dir badname mmt-dpi_ubuntu-24.04_amd64.deb)"
expect_refusal "security package without its mmt-dpi package" \
    "$(release_dir nomain mmt-dpi_1.2.3_abc_debian-12_x86_64.deb mmt-dpi-security_1.2.3_abc_debian-12_aarch64.deb)"
expect_refusal "two packages for one alias" \
    "$(release_dir dup mmt-dpi_1.2.3_abc_debian-12_x86_64.deb mmt-dpi_1.2.3_def_debian-12_x86_64.deb)"
expect_refusal "no package at all" "$(release_dir empty SHA256SUMS)"
pre="$(release_dir pre mmt-dpi_1.2.3_abc_debian-12_x86_64.deb)"
touch "$pre/install.sh"
rc=0; bash "$GEN" v1.2.3 "$pre" >/dev/null 2>&1 || rc=$?
check "refuses: an existing install.sh is never overwritten (exit ${rc})" \
    test "$rc" -eq 1 -a ! -s "$pre/install.sh" -a ! -e "$pre/manifest.json"
rc=0; bash "$GEN" 1.2.3 "$good" >/dev/null 2>&1 || rc=$?
check "refuses: a tag that is not vX.Y.Z (exit ${rc})" test "$rc" -eq 2

# --- the bootstrap itself ---------------------------------------------------------
# exits_with <code> <pattern> <command>... — exit code and message.
exits_with() {
    local want="$1" pattern="$2" rc=0; shift 2
    "$@" >"$WORK/out" 2>&1 || rc=$?
    [ "$rc" -eq "$want" ] && grep -q -- "$pattern" "$WORK/out"
}
check "the unrendered template refuses to run" exits_with 2 unrendered sh "$TEMPLATE"
check "there is no option to skip a check" \
    exits_with 2 'unknown option' sh "$good/install.sh" --skip-attestation

# The attestation check is bound to this repository, its release workflow and
# this exact tag, on GitHub-hosted runners, with a scrubbed gh environment.
# shellcheck disable=SC2016  # literal text of the rendered script
for want in '--repo "$REPO"' '--signer-workflow "$SIGNER_WORKFLOW"' \
            '--source-ref "refs/tags/${RELEASE_TAG}"' '--deny-self-hosted-runners' \
            '-u GH_TOKEN' '-u GITHUB_TOKEN' '-u GH_HOST' '-u GH_REPO' \
            'SIGNER_WORKFLOW="${REPO}/.github/workflows/release-packages.yml"' \
            'REPO="montimage-projects/mmt-dpi"'; do
    check "install.sh verifies with ${want}" grep -qF -- "$want" "$good/install.sh"
done
check "the signer workflow it names exists" \
    test -f "${REPO_ROOT}/.github/workflows/release-packages.yml"
check "a custom MMT_BASE is refused with a pointer to the source installer" \
    exits_with 2 '/opt/mmt only' env MMT_BASE=/usr/local sh "$good/install.sh"

# detect_distro on os-release fixtures.
distro_of() { # <ID> <VERSION_ID>
    printf 'ID=%s\nVERSION_ID="%s"\nPRETTY_NAME="%s %s"\n' "$1" "$2" "$1" "$2" > "$WORK/os-release"
    in_bootstrap distro_from "$WORK/os-release"
}
# shellcheck disable=SC2034  # read by the sourced detect_distro
distro_from() { OS_RELEASE="$1"; detect_distro; }
while read -r id ver want; do
    got="$(distro_of "$id" "$ver")"
    check "os-release ${id} ${ver} -> ${want}" test "$got" = "$want"
done <<'EOF'
ubuntu 22.04 ubuntu-22.04
ubuntu 24.04 ubuntu-24.04
debian 12 debian-12
rocky 9.4 rocky-9
almalinux 9.6 rocky-9
rhel 9.5 rocky-9
centos 9 centos-stream9
ubuntu 26.04 ubuntu-26.04
debian 13 debian-13
rocky 10.0 rocky-10
almalinux 10.1 rocky-10
rhel 10.0 rocky-10
centos 10 centos-stream10
debian 11 unsupported:debian 11
debian 14 unsupported:debian 14
centos 8 unsupported:centos 8
fedora 44 unsupported:fedora 44
ubuntu 25.10 unsupported:ubuntu 25.10
EOF

# Row lookup: one row, or failure.
lookup_ok() {
    [ "$(row_field ubuntu-24.04 arm64 mmt-dpi 4)" = mmt-dpi_ubuntu-24.04_arm64.deb ] \
        && ! row_field rocky-9 arm64 mmt-dpi 4 >/dev/null \
        && ! row_field debian-12 amd64 mmt-dpi 4 >/dev/null
}
check "row lookup finds the published row and fails for an unpublished one" in_bootstrap lookup_ok

# Digest check over a file:// download: a matching file passes, one changed
# byte is refused with exit 1 before anything else runs.
digest_ok() {
    local d f sum rc=0
    d="$(mktemp -d "${WORK}/dl.XXXXXX")"
    f="$(row_field ubuntu-24.04 amd64 mmt-dpi 4)"; sum="$(row_field ubuntu-24.04 amd64 mmt-dpi 5)"
    fetch "file://${good}/${f}" "$d/$f" || return 1
    (check_sha256 "$d/$f" "$sum" "$f") >/dev/null || return 1
    printf 'x' >> "$d/$f"
    (check_sha256 "$d/$f" "$sum" "$f") 2>/dev/null || rc=$?
    [ "$rc" -eq 1 ]
}
check "sha256: the released file passes, a tampered copy exits 1" in_bootstrap digest_ok

if [ "$FAILS" -ne 0 ]; then
    echo "✗ ${FAILS} bootstrap check(s) failed"
    exit 1
fi
echo "✓ release bootstrap generator and template behave"
