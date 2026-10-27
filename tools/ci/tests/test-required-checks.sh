#!/usr/bin/env bash
# test-required-checks.sh — self-test for tools/ci/check-required-checks.sh
# (issue #490, F-CI-004/F-CI-014).
#
# Drives the real helper on (1) the repository's own committed context list
# against the repository's workflows — it must pass, hold at least 25
# contexts and include the fuzz-replay, secret-scan and packages-gate
# contexts — and (2) fixture workflow trees, where a context that names no
# job, a context only a path-filtered / schedule-only / tag-gated job
# reports, and a duplicate context must each fail, while matrix-name
# expansion (include legs, empty values, axis products, `${{ matrix.* }}`
# names, run-time fromJSON matrices) must resolve, and a matrix leg whose job
# has a skippable job-level `if:` must fail while `!cancelled()` resolves
# (issue #552). `--live` runs against a
# stub `gh` on PATH, so the suite needs no network and no token.
#
# Needs python3 with PyYAML. Without PyYAML the test reports SKIP and exits 0,
# so the suites tests/run_all_tests.sh runs never depend on the runner image
# shipping python3-yaml; the enforced run is c-cpp.yml's verify-helpers job,
# which installs python3-yaml first and runs this test with
# REQUIRE_PYYAML=1, under which a missing PyYAML fails.
#
# Usage: bash tools/ci/tests/test-required-checks.sh
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HELPER="${REPO_ROOT}/tools/ci/check-required-checks.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

pass=0
fail=0
ok()  { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

echo "=== check-required-checks self-test ==="

if ! python3 -c 'import yaml' 2>/dev/null; then
    if [ "${REQUIRE_PYYAML:-0}" = "1" ]; then
        echo "  FAIL PyYAML (python3-yaml) is missing and REQUIRE_PYYAML=1"
        exit 1
    fi
    echo "  SKIP PyYAML (python3-yaml) not installed — install it to run this test"
    exit 0
fi

# expect <want-rc> <label> <output-grep|""> -- <helper args...>
expect() {
    local want="$1" label="$2" needle="$3"
    shift 4
    local out rc
    out="$(bash "$HELPER" "$@" 2>&1)"
    rc=$?
    if [ "$rc" -ne "$want" ]; then
        bad "$label (exit $rc, want $want)"
        printf '%s\n' "$out" | sed 's/^/      /'
        return
    fi
    if [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF -- "$needle"; then
        bad "$label (output lacks: $needle)"
        printf '%s\n' "$out" | sed 's/^/      /'
        return
    fi
    ok "$label"
}

# --- 1. the repository's own list ----------------------------------------
LIST="${REPO_ROOT}/.github/required-checks.txt"
expect 0 "committed list names only pull-request jobs" "Result: PASS" -- \
    --contexts "$LIST" --workflows "${REPO_ROOT}/.github/workflows"
n=$(grep -cvE '^[[:space:]]*(#|$)' "$LIST")
if [ "$n" -ge 25 ]; then ok "committed list holds $n >= 25 contexts"
else bad "committed list holds $n contexts, want >= 25"; fi
for ctx in fuzz secret-scan packages-gate harness-gate; do
    if grep -qxF -- "$ctx" "$LIST"; then ok "committed list requires $ctx"
    else bad "committed list lacks $ctx"; fi
done

# --- 2. fixture workflows ------------------------------------------------
FX="${WORK}/wf"
mkdir -p "$FX"
cat > "${FX}/ci.yml" <<'EOF'
name: CI
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  unit:
    strategy:
      matrix:
        include:
          - { cflags: "", suites: "" }
          - { cflags: "-O0", suites: "a b" }
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  budgets:
    strategy:
      matrix:
        runner: [ x64, arm ]
        mode: [ fast ]
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  named:
    name: Gate (M9, issue #74)
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  pkg:
    name: ${{ matrix.distro.name }} (${{ matrix.arch }})
    strategy:
      matrix:
        arch: [ amd64 ]
        distro:
          - { name: deb-12, pkg: deb }
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  list:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  shard:
    name: shard-${{ matrix.h }}
    needs: list
    strategy:
      matrix:
        h: ${{ fromJSON(needs.list.outputs.h) }}
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  tag-only:
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  skippable-matrix:
    needs: build
    if: ${{ !cancelled() && needs.build.outputs.code != 'false' }}
    strategy:
      matrix:
        profile: [ asan ]
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  live-matrix:
    needs: build
    if: ${{ !cancelled() }}
    strategy:
      matrix:
        profile: [ asan ]
    runs-on: ubuntu-24.04
    steps:
      - if: needs.build.outputs.code != 'false'
        run: "true"
  gated-single:
    needs: build
    if: ${{ !cancelled() && needs.build.outputs.code != 'false' }}
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
cat > "${FX}/filtered.yml" <<'EOF'
on:
  pull_request:
    paths: [ "sdk/**" ]
jobs:
  filtered-job:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
cat > "${FX}/nightly.yml" <<'EOF'
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  build:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  nightly-job:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF

ctx() { printf '%s\n' "$@" > "${WORK}/ctx.txt"; echo "${WORK}/ctx.txt"; }

expect 0 "fixture: names that report on pull requests resolve" "Result: PASS" -- \
    --workflows "$FX" --contexts "$(ctx \
        '# comment lines and blank lines are ignored' '' \
        build unit 'unit (-O0, a b)' 'budgets (x64, fast)' 'budgets (arm, fast)' \
        'Gate (M9, issue' 'deb-12 (amd64)' 'shard-run_a.sh')"
expect 1 "fixture: a context that names no job fails" \
    "'no-such-job' names no workflow job" -- \
    --workflows "$FX" --contexts "$(ctx build no-such-job)"
expect 1 "fixture: a renamed matrix leg fails" "names no workflow job" -- \
    --workflows "$FX" --contexts "$(ctx 'unit (-O2, a b)')"
expect 1 "fixture: a quoted '#' name differs from the truncated context" \
    "names no workflow job" -- \
    --workflows "$FX" --contexts "$(ctx 'Gate (M9, issue #74)')"
expect 1 "fixture: a path-filtered workflow's job fails" \
    "filtered by \`paths\`" -- \
    --workflows "$FX" --contexts "$(ctx filtered-job)"
expect 1 "fixture: a schedule-only workflow's job fails" \
    "no pull_request trigger" -- \
    --workflows "$FX" --contexts "$(ctx nightly-job)"
# `build` is also a job of the schedule-only nightly.yml: one pull-request
# job reporting the name is enough.
expect 0 "fixture: a name shared with a non-PR job resolves to the PR job" \
    "ok   build  <- ci.yml:build" -- \
    --workflows "$FX" --contexts "$(ctx build)"
expect 1 "fixture: a tag-gated job fails" "keeps it off pull requests" -- \
    --workflows "$FX" --contexts "$(ctx tag-only)"
expect 1 "fixture: a matrix leg behind a skippable job-level if: fails" \
    "matrix job has a job-level \`if:\` that can skip it" -- \
    --workflows "$FX" --contexts "$(ctx 'skippable-matrix (asan)')"
expect 0 "fixture: a matrix job gated by !cancelled() and step if: resolves" \
    "ok   live-matrix (asan)" -- \
    --workflows "$FX" --contexts "$(ctx 'live-matrix (asan)')"
expect 0 "fixture: a single-context job may skip at job level" \
    "ok   gated-single" -- \
    --workflows "$FX" --contexts "$(ctx gated-single)"
expect 1 "fixture: a duplicate context fails" "duplicate context" -- \
    --workflows "$FX" --contexts "$(ctx build build)"
expect 1 "fixture: an empty list fails" "list is empty" -- \
    --workflows "$FX" --contexts "$(ctx '# nothing')"
expect 2 "fixture: a missing list is a broken helper" "" -- \
    --workflows "$FX" --contexts "${WORK}/absent.txt"
mkdir -p "${WORK}/broken"
printf 'jobs: [unclosed\n' > "${WORK}/broken/bad.yml"
expect 2 "fixture: an unparsable workflow is a broken helper" "cannot parse" -- \
    --workflows "${WORK}/broken" --contexts "$(ctx build)"

# --- 3. --live against a stub gh ------------------------------------------
STUB="${WORK}/bin"
mkdir -p "$STUB"
cat > "${STUB}/gh" <<'EOF'
#!/usr/bin/env bash
# stub: `gh api repos/<r>/branches/main/protection --jq ...`
[ "$1" = api ] || exit 9
case "$2" in */branches/main/protection) ;; *) exit 9 ;; esac
cat "$STUB_LIVE"
EOF
chmod +x "${STUB}/gh"
printf '%s\n' build unit > "${WORK}/live-ok.txt"
printf '%s\n' build 'Old Job Name' > "${WORK}/live-bad.txt"
PATH="${STUB}:${PATH}" STUB_LIVE="${WORK}/live-ok.txt" \
    expect 0 "--live: drift is reported, not failed" \
    "drift: committed but not yet required: unit (-O0, a b)" -- \
    --workflows "$FX" --contexts "$(ctx build unit 'unit (-O0, a b)')" \
    --live example/repo
PATH="${STUB}:${PATH}" STUB_LIVE="${WORK}/live-bad.txt" \
    expect 1 "--live: a live context that names no job fails" \
    "FAIL live: 'Old Job Name' names no workflow job" -- \
    --workflows "$FX" --contexts "$(ctx build)" --live example/repo
PATH="${STUB}:${PATH}" STUB_LIVE="${WORK}/absent.txt" \
    expect 2 "--live: an unreadable protection is a broken helper" "" -- \
    --workflows "$FX" --contexts "$(ctx build)" --live example/repo

echo
echo "check-required-checks self-test: ${pass} passed, ${fail} failed"
if [ "$fail" -eq 0 ]; then
    echo "Result: PASS (check-required-checks self-test)"
    exit 0
fi
echo "Result: FAIL (check-required-checks self-test)"
exit 1
