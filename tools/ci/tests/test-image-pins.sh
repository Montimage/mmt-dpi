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
#   retire-by date more than 60 days ahead                     -> 0
#   retire-by date within 60 days                              -> 0, warning
#   retire-by date reached / passed                            -> 1, entry + legs named
#   malformed retire-by date / IMAGE_TODAY                     -> 1 / 2
#   this checkout                                              -> 0
# this checkout's schedule (issue #516): no workflow runs on the
# ubuntu-22.04 runner or a bookworm image, toolchain-floor runs in the
# pinned ubuntu:22.04 container on ubuntu-24.04, the asn1c gate on a pinned
# trixie image, and ubuntu:22.04 / centos:stream9 retire before their EOL
# refresh-base-images.sh -> expected exit:
#   every tag still at its pin                                 -> 0
#   tag moved, old digest still served (drift)                 -> 1
#   tag moved, old digest gone (missing — the quay.io case)    -> 1
#   new digest lacks linux/arm64                               -> 1, not written
#   ... unless the entry says `# platforms: linux/amd64`       -> 0, written
#   tag does not resolve at all                                -> 2
#   registry error on the pinned digest (not "not found")      -> 2, not missing
#   --write repins baseline + workflow, then both gates pass   -> 0
#   --write keeps a trailing retire-by comment                 -> 0
#   --registry quay.io ignores a drifted Docker Hub pin        -> 0, not resolved
#   --registry quay.io reports a missing quay.io pin           -> 1
#   --write --registry quay.io leaves the Docker Hub pin       -> 0
#   --registry with a host no entry uses / no / a bad host     -> 2
# this checkout's base-image-refresh.yml (issue #641): the hourly cron, the
# QUAY_HOURLY scope selector and the concurrency key name one string, and the
# repin issue lookup does not rely on `--author app/github-actions`
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

# Dated retirement (issue #516): `# retire-by: YYYY-MM-DD` on a baseline entry.
retire_fixture() { # retire_fixture <date>
    reset_fixture
    sed -i "s|^\(quay.io/centos/centos:stream9@${B}\)\$|\1  # retire-by: $1 (#516)|" \
        "${FX}/tools/ci/base-images.txt"
}
retire_fixture 2027-04-30
IMAGE_TODAY=2026-10-22 expect 0 "retire-by more than 60 days ahead passes" digests
expect_out "reports the days left" "retires on 2027-04-30 (190 day(s) left)"
IMAGE_TODAY=2027-03-15 expect 0 "retire-by within 60 days still passes" digests
expect_out "warns ahead of the date and names the legs" \
    "⚠ quay.io/centos/centos:stream9@${B} retires on 2027-04-30 (46 day(s) left) — remove its legs (.github/workflows/release-packages.yml:"
IMAGE_TODAY=2027-04-30 expect 1 "retire-by date reached fails" digests
expect_out "names the retired entry and its legs" \
    "✗ quay.io/centos/centos:stream9@${B} reached its retire-by date 2027-04-30 — remove its legs (.github/workflows/release-packages.yml:"
expect_out "says how to fix it" "never by moving the date"
IMAGE_TODAY=2028-01-01 expect 1 "retire-by date passed fails" digests
IMAGE_TODAY=2028-01-01 expect 0 "an explicit file using no retiring image passes" \
    digests .github/workflows/other.yml
IMAGE_TODAY=2028-01-01 expect 1 "an explicit file using the retired image fails" \
    digests .github/workflows/release-packages.yml
retire_fixture 2027-4-30
expect 1 "malformed retire-by date fails" digests
expect_out "names the malformed date" "malformed retire-by date for quay.io/centos/centos:stream9@${B}: 2027-4-30"
reset_fixture
IMAGE_TODAY=tomorrow expect 2 "malformed IMAGE_TODAY is a usage error" digests

expect 0 "this checkout passes" bash "${DIGESTS}"

# This checkout's runner and image schedule (issue #516).
WF="${REPO_ROOT}/.github/workflows"
job_block() { # job_block <workflow> <job> — the job's lines up to the next job
    sed -n "/^  $2:\$/,/^  [a-z0-9_-]*:\$/p" "${WF}/$1" | sed '$d'
}
expect 1 "no workflow runs on the deprecated ubuntu-22.04 runner" \
    grep -rnE 'runs-on:[[:space:]]*ubuntu-22\.04' "${WF}"
expect 1 "no workflow pulls a bookworm image" grep -rn 'bookworm' "${WF}"
floor="$(job_block c-cpp.yml toolchain-floor)"
expect 0 "toolchain-floor keeps its job name (the required context)" test -n "${floor}"
expect 0 "toolchain-floor runs on ubuntu-24.04" \
    grep -qE '^    runs-on: ubuntu-24\.04$' <<< "${floor}"
expect 0 "toolchain-floor runs in the pinned ubuntu:22.04 container" \
    grep -qE '^      image: "ubuntu:22\.04@sha256:[0-9a-f]{64}"$' <<< "${floor}"
# shellcheck disable=SC2016  # the literal workflow line, not an expansion
expect 0 "toolchain-floor still asserts GCC 11" \
    grep -qF 'test "$(gcc -dumpfullversion | cut -d. -f1)" -eq 11' <<< "${floor}"
expect 0 "the asn1c gate runs on the pinned trixie image" \
    grep -qE '^    container: buildpack-deps:trixie@sha256:[0-9a-f]{64}$' "${WF}/asn1c-regen.yml"
retire_by() { # retire_by <image name:tag> — its retire-by date in the real baseline
    sed -n "s|^$1@sha256:[0-9a-f]*[[:space:]]*#.*retire-by:[[:space:]]*\([0-9-]*\).*|\1|p" \
        "${REPO_ROOT}/tools/ci/base-images.txt"
}
before() { [ -n "$1" ] && [[ "$1" < "$2" ]]; }
# The release jobs' "Verify pinned base image is recorded" step matches each
# matrix image as a whole baseline line once trailing comments are stripped,
# so a `# retire-by:` comment never fails a leg (issue #516).
recorded_cmd="sed 's/[[:space:]]*#.*\$//' tools/ci/base-images.txt | grep -Fx -- \"\$IMAGE\""
expect 0 "both release-packages verify steps strip comments before matching" \
    test "$(grep -cF -- "run: ${recorded_cmd}" "${WF}/release-packages.yml")" -eq 2
matrix_images() {
    sed -n 's/^ *- {.*image: *"\([^"]*\)".*/\1/p' "${WF}/release-packages.yml" | sort -u
}
all_recorded() {
    local img n=0
    while read -r img; do
        n=$((n + 1))
        (cd "${REPO_ROOT}" && IMAGE="${img}" bash -c "${recorded_cmd}") >/dev/null \
            || { echo "not recorded: ${img}"; return 1; }
    done < <(matrix_images)
    [ "${n}" -ge 9 ]
}
expect 0 "every release matrix image passes that step, retiring ones included" all_recorded
expect 0 "ubuntu:22.04 retires before its standard support ends (2027-06-01)" \
    before "$(retire_by 'ubuntu:22\.04')" 2027-06-01
expect 0 "centos:stream9 retires before its EOL (2027-05-31)" \
    before "$(retire_by 'quay\.io/centos/centos:stream9')" 2027-05-31

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

retire_fixture 2027-04-30
reset_registry
rm "$(regfile "quay.io/centos/centos@${B}")"
serve "quay.io/centos/centos:stream9" "${C}"
expect 0 "--write repins an entry that carries retire-by" refresh --write
expect 0 "the repinned entry keeps its retire-by comment" \
    grep -qx "quay.io/centos/centos:stream9@${C}  # retire-by: 2027-04-30 (#516)" \
    "${FX}/tools/ci/base-images.txt"

expect 2 "unknown argument" refresh --bogus

# --- --registry: the hourly quay.io-only scope (issue #641) ------------------
reset_fixture
reset_registry
serve "ubuntu:24.04" "${C}"          # Docker Hub drift, old digest still served
expect 0 "--registry quay.io ignores a drifted Docker Hub pin" \
    refresh --check --registry quay.io
expect_out "reports the scope" "pin(s) hosted on quay.io match"
if grep -q "ubuntu" "${WORK}/out"; then
    echo "  ✗ --registry quay.io resolved a Docker Hub entry"
    sed 's/^/      /' "${WORK}/out"
    failures=$((failures + 1))
else
    echo "  ✓ --registry quay.io resolves no Docker Hub entry"
fi
expect 1 "without --registry the same drift fails" refresh --check

rm "$(regfile "quay.io/centos/centos@${B}")"
serve "quay.io/centos/centos:stream9" "${C}"
expect 1 "--registry quay.io reports a garbage-collected quay.io pin" \
    refresh --check --registry quay.io
expect_out "names it missing" "missing  quay.io/centos/centos:stream9"
expect 0 "--write --registry quay.io repins it" refresh --write --registry quay.io
expect 0 "the quay.io pin is rewritten" \
    grep -qx "quay.io/centos/centos:stream9@${C}" "${FX}/tools/ci/base-images.txt"
expect 0 "the drifted Docker Hub pin is left as it was" \
    grep -qx "ubuntu:24.04@${A}" "${FX}/tools/ci/base-images.txt"
expect 2 "--registry with a host no entry uses" refresh --check --registry ghcr.io
expect 2 "--registry without a host" refresh --check --registry
expect 2 "--registry with a path, not a host" refresh --check --registry quay.io/centos

echo "base-image-refresh.yml:"
WF="${REPO_ROOT}/.github/workflows/base-image-refresh.yml"
hourly="$(sed -n "s/^    - cron: '\([^']*\)'.*quay\.io.*/\1/p" "${WF}")"
expect 0 "an hourly quay.io cron exists" test -n "${hourly}"
expect 0 "QUAY_HOURLY names that cron" grep -qF "QUAY_HOURLY: '${hourly}'" "${WF}"
expect 0 "the concurrency key names that cron" \
    grep -qF "github.event.schedule == '${hourly}'" "${WF}"
expect 0 "the hourly scope runs --registry quay.io" \
    grep -qF 'scope=(--registry quay.io)' "${WF}"
expect 1 "the repin issue lookup does not filter on --author app/github-actions" \
    grep -qE -- 'gh issue list .*--author' "${WF}"

if [ "${failures}" -ne 0 ]; then
    echo "✗ ${failures} image-pin self-test check(s) failed"
    exit 1
fi
echo "✓ image-pin self-test passed"
