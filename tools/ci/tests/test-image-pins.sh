#!/usr/bin/env bash
#
# test-image-pins.sh — self-test for tools/ci/check-image-digests.sh and
# tools/ci/refresh-base-images.sh (issue #491).
#
# Both REAL scripts run against a throwaway fixture repository (ROOT_DIR);
# the registry is a stub inspector (IMAGE_INSPECT) that serves manifests from
# a fixture directory, so no docker and no network are needed.
#
# check-image-digests.sh (no argument = full scan) -> expected exit:
#   pinned + recorded fixture                                  -> 0
#   floating `container: <ref>` shorthand                      -> 1
#   floating `container:` block with `image:`                  -> 1
#   floating `docker run` operand                              -> 1
#   floating `uses: docker://` step                            -> 1
#   pinned but unrecorded image                                -> 1
#   recorded entry no workflow uses                            -> 1
#   explicit file argument skips the unused-entry check        -> 0
#   baseline with comments only                                -> 1
#   action input `cache-image:` is not an image                -> 0
#   docker run value options (--restart no) are skipped        -> 1, real image named
#   this checkout                                              -> 0
# refresh-base-images.sh -> expected exit:
#   every tag still at its pin                                 -> 0
#   tag moved, old digest still served (drift)                 -> 1
#   tag moved, old digest gone (missing — the quay.io case)    -> 1
#   new digest lacks linux/arm64                               -> 1, not written
#   ... unless the entry says `# platforms: linux/amd64`       -> 0, written
#   tag does not resolve at all                                -> 2
#   registry error on the pinned digest (not "not found")      -> 2, not missing
#   --write repins baseline + workflow, then both gates pass   -> 0
#
# Usage: bash tools/ci/tests/test-image-pins.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
DIGESTS="${REPO_ROOT}/tools/ci/check-image-digests.sh"
REFRESH="${REPO_ROOT}/tools/ci/refresh-base-images.sh"
for f in "${DIGESTS}" "${REFRESH}"; do
    [ -f "${f}" ] || { echo "✗ missing ${f}" >&2; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FX="${WORK}/repo"
REG="${WORK}/registry"

A="sha256:$(printf 'a%.0s' {1..64})"
B="sha256:$(printf 'b%.0s' {1..64})"
C="sha256:$(printf 'c%.0s' {1..64})"

failures=0
expect() { # expect <exit> <label> <cmd...>
    local want="$1" label="$2" got=0
    shift 2
    "$@" > "${WORK}/out" 2>&1 || got=$?
    if [ "${got}" = "${want}" ]; then
        echo "  ✓ ${label} (exit ${got})"
    else
        echo "  ✗ ${label}: expected exit ${want}, got ${got}"
        sed 's/^/      /' "${WORK}/out"
        failures=$((failures + 1))
    fi
}
expect_out() { # expect_out <label> <grep-pattern>  (on the last command)
    if grep -q -- "$2" "${WORK}/out"; then
        echo "  ✓ $1"
    else
        echo "  ✗ $1: output lacks '$2'"
        sed 's/^/      /' "${WORK}/out"
        failures=$((failures + 1))
    fi
}

# --- fixture repository -----------------------------------------------------
reset_fixture() {
    rm -rf "${FX}"
    mkdir -p "${FX}/.github/workflows" "${FX}/tools/ci"
    cat > "${FX}/tools/ci/base-images.txt" <<EOF
# fixture baseline
digest-source: docker buildx imagetools inspect <image>:<tag>
ubuntu:24.04@${A}
quay.io/centos/centos:stream9@${B}
EOF
    cat > "${FX}/.github/workflows/release-packages.yml" <<EOF
jobs:
  build:
    strategy:
      matrix:
        distro:
          - { name: u, image: "ubuntu:24.04@${A}", pkg: deb }
          - { name: c, image: "quay.io/centos/centos:stream9@${B}", pkg: rpm }
    steps:
      - run: grep -Fx "\${{ matrix.distro.image }}" tools/ci/base-images.txt
      - run: |
          docker run --rm --platform "linux/amd64" -e CI \\
            -v "\$PWD":/work -w /work \\
            "\${{ matrix.distro.image }}" bash build.sh
EOF
    cat > "${FX}/.github/workflows/other.yml" <<EOF
jobs:
  root:
    # a comment naming ubuntu:24.04 is not an image reference
    container: ubuntu:24.04@${A}
    steps:
      - run: docker run --rm -v "\$PWD":/w "ubuntu:24.04@${A}" true
EOF
}

digests() { ROOT_DIR="${FX}" bash "${DIGESTS}" "$@"; }

echo "check-image-digests.sh:"
reset_fixture
expect 0 "pinned + recorded fixture passes" digests
expect_out "both workflows are scanned" "in 2 file(s)"

reset_fixture
printf 'jobs:\n  x:\n    container: buildpack-deps:bookworm\n' > "${FX}/.github/workflows/asn1c.yml"
expect 1 "floating container: shorthand fails" digests
expect_out "names the floating reference and its line" "buildpack-deps:bookworm  (.github/workflows/asn1c.yml:3)"

reset_fixture
printf 'jobs:\n  x:\n    container:\n      image: debian:12\n' > "${FX}/.github/workflows/block.yml"
expect 1 "floating container: block image fails" digests
expect_out "names the block image" "floating image reference: debian:12"

reset_fixture
# shellcheck disable=SC2016  # $PWD is fixture text, not expanded here
printf 'jobs:\n  x:\n    steps:\n      - run: |\n          docker run --rm \\\n            -v "$PWD":/w -w /w \\\n            rockylinux:9 true\n' \
    > "${FX}/.github/workflows/run.yml"
expect 1 "floating docker run operand fails" digests
expect_out "names the docker run image" "floating image reference: rockylinux:9"

reset_fixture
printf 'jobs:\n  x:\n    steps:\n      - uses: docker://alpine:3.20\n' > "${FX}/.github/workflows/uses.yml"
expect 1 "floating uses: docker:// fails" digests

reset_fixture
printf 'jobs:\n  x:\n    container: "debian:12@%s"\n' "${C}" > "${FX}/.github/workflows/unrec.yml"
expect 1 "pinned but unrecorded image fails" digests
expect_out "names the unrecorded pin" "missing from tools/ci/base-images.txt: debian:12@${C}"

reset_fixture
echo "debian:12@${C}" >> "${FX}/tools/ci/base-images.txt"
expect 1 "recorded entry no workflow uses fails" digests
expect 0 "explicit file argument skips the unused-entry check" \
    digests .github/workflows/release-packages.yml

reset_fixture
printf '# comments only\ndigest-source: x\n' > "${FX}/tools/ci/base-images.txt"
expect 1 "baseline with no entries records nothing" digests

reset_fixture
printf 'jobs:\n  x:\n    steps:\n      - uses: some/action@v1\n        with:\n          cache-image: foo\n' \
    > "${FX}/.github/workflows/input.yml"
expect 0 "an action input named *-image is not an image" digests

reset_fixture
printf 'jobs:\n  x:\n    steps:\n      - run: docker run --rm --restart no --stop-timeout 5 debian:12 true\n' \
    > "${FX}/.github/workflows/opts.yml"
expect 1 "docker run value options are skipped" digests
expect_out "names the real image, not an option value" "floating image reference: debian:12"

expect 0 "this checkout passes" bash "${DIGESTS}"

# --- refresh-base-images.sh with a stub registry ----------------------------
# A manifest file named after the ref (/ and : replaced) means it resolves.
cat > "${WORK}/inspect" <<'EOF'
#!/usr/bin/env bash
f="${REGISTRY}/$(printf '%s' "$1" | tr '/:@' '___')"
[ -f "$f" ] || { echo "ERROR: $1: not found" >&2; exit 1; }
if [ "$(cat "$f")" = TRANSIENT ]; then echo "ERROR: 429 Too Many Requests" >&2; exit 1; fi
cat "$f"
EOF
chmod +x "${WORK}/inspect"

regfile() { printf '%s/%s' "${REG}" "$(printf '%s' "$1" | tr '/:@' '___')"; }
serve() { # serve <ref> <digest> [platform...]  (default: amd64 + arm64)
    local ref="$1" digest="$2" plats="" sep="" p
    shift 2
    [ "$#" -gt 0 ] || set -- linux/amd64 linux/arm64
    for p in "$@"; do
        plats="${plats}${sep}{\"platform\":{\"os\":\"${p%%/*}\",\"architecture\":\"${p#*/}\"}}"
        sep=","
    done
    printf '{"digest":"%s","manifests":[%s,{"platform":{"os":"unknown","architecture":"unknown"}}]}\n' \
        "${digest}" "${plats}" > "$(regfile "${ref}")"
}
reset_registry() {
    rm -rf "${REG}"; mkdir -p "${REG}"
    serve "ubuntu:24.04" "${A}"
    serve "ubuntu@${A}" "${A}"
    serve "quay.io/centos/centos:stream9" "${B}"
    serve "quay.io/centos/centos@${B}" "${B}"
}
refresh() { ROOT_DIR="${FX}" IMAGE_INSPECT="${WORK}/inspect" REGISTRY="${REG}" \
              bash "${REFRESH}" "$@"; }

echo "refresh-base-images.sh:"
reset_fixture
reset_registry
expect 0 "every tag still at its pin" refresh --check
cp "${FX}/tools/ci/base-images.txt" "${WORK}/baseline.orig"
expect 0 "--write with nothing to repin" refresh --write
expect 0 "nothing rewritten" cmp -s "${WORK}/baseline.orig" "${FX}/tools/ci/base-images.txt"

serve "ubuntu:24.04" "${C}"
serve "ubuntu@${C}" "${C}"
expect 1 "tag moved, old digest still served: drift" refresh --check
expect_out "reports drift" "drift    ubuntu:24.04"

rm "$(regfile "ubuntu@${A}")"
expect 1 "tag moved, old digest gone: missing" refresh
expect_out "reports the missing digest" "missing  ubuntu:24.04"

reset_registry
serve "quay.io/centos/centos:stream9" "${C}" "linux/amd64"
expect 1 "repin target without linux/arm64 is refused" refresh --write
expect_out "names the missing platform" "lacks linux/arm64"
expect 1 "refused repin left the baseline untouched" \
    grep -q "centos:stream9@${C}" "${FX}/tools/ci/base-images.txt"

# An amd64-only entry (archlinux, issue #493) narrows its own requirement.
sed -i "s|^\(quay.io/centos/centos:stream9@${B}\)\$|\1  # platforms: linux/amd64|" \
    "${FX}/tools/ci/base-images.txt"
expect 0 "an entry annotated platforms: linux/amd64 repins an amd64-only index" \
    refresh --write
expect 0 "the annotated entry carries the new pin" \
    grep -q "^quay.io/centos/centos:stream9@${C}  # platforms: linux/amd64\$" \
    "${FX}/tools/ci/base-images.txt"
reset_fixture

reset_registry
rm "$(regfile "ubuntu:24.04")"
expect 2 "unresolvable tag is inconclusive" refresh --check

reset_registry
serve "ubuntu:24.04" "${C}"
echo TRANSIENT > "$(regfile "ubuntu@${A}")"
expect 2 "registry error on the pinned digest is inconclusive, not missing" refresh --check
expect_out "reports the registry error" "unreachable  ubuntu:24.04 — registry error"

reset_fixture
reset_registry
rm "$(regfile "quay.io/centos/centos@${B}")"
serve "quay.io/centos/centos:stream9" "${C}"
expect 0 "--write repins the garbage-collected pin" refresh --write
expect 0 "baseline carries the new pin" \
    grep -qx "quay.io/centos/centos:stream9@${C}" "${FX}/tools/ci/base-images.txt"
expect 0 "workflow carries the new pin" \
    grep -q "quay.io/centos/centos:stream9@${C}" "${FX}/.github/workflows/release-packages.yml"
serve "quay.io/centos/centos@${C}" "${C}"
expect 0 "--check passes after the repin" refresh --check
expect 0 "digest gate passes after the repin" digests

expect 2 "unknown argument" refresh --bogus

if [ "${failures}" -ne 0 ]; then
    echo "✗ ${failures} image-pin self-test check(s) failed"
    exit 1
fi
echo "✓ image-pin self-test passed"
