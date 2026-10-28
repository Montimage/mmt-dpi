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
# (issue #552), and (the merge queue, issue #657) a context whose workflow has
# no `merge_group` trigger, or whose job-level `if:` keeps it off merge-group
# runs (an event_name pin, `!= 'merge_group'`, a pull-request-only value),
# must fail while an `if:` naming both events resolves. Queue-only jobs (issue
# #658), skipped on pull requests, must be gated by a required context (their
# own or an aggregate's) in a workflow with a merge_group trigger — an
# aggregate only when its job-level `if:` is exactly always() or !cancelled()
# and it reads the need's result — while a path-filtered workflow's job is
# exempt; retired contexts (issue #659) must
# name `if: false` stubs and never also be required. `--live` runs against a
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
RETIRED_LIST="${REPO_ROOT}/.github/retired-checks.txt"
expect 0 "repository retired contexts are reported by if: false stubs" \
    "ok   ASan/UBSan profile compiles  <- c-cpp.yml:asan-build" -- \
    --contexts "$LIST" --workflows "${REPO_ROOT}/.github/workflows" \
    --retired "$RETIRED_LIST"
expect 0 "repository queue-only legs are gated by required contexts" \
    "ok   c-cpp.yml:unit-tests-unsigned-char  gated by unit-tests-unsigned-char" -- \
    --contexts "$LIST" --workflows "${REPO_ROOT}/.github/workflows"
expect 0 "repository variant-build legs are gated through the build aggregate" \
    "ok   c-cpp.yml:assertions-live  gated by build" -- \
    --contexts "$LIST" --workflows "${REPO_ROOT}/.github/workflows"
for ctx in enablesec 'ASan/UBSan profile compiles'; do
    if grep -qxF -- "$ctx" "$LIST"; then bad "committed list still requires retired $ctx"
    elif grep -qxF -- "$ctx" "$RETIRED_LIST"; then ok "$ctx is retired, not required"
    else bad "$ctx is in neither list (live protection still requires it)"; fi
done
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
  merge_group:
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
  pr-pinned:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  not-group:
    if: ${{ github.event_name != 'merge_group' }}
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  head-ref:
    if: github.head_ref != ''
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  both-events:
    if: github.event_name == 'pull_request' || github.event_name == 'merge_group'
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
cat > "${FX}/pr-only.yml" <<'EOF'
on:
  pull_request:
    branches: [ main ]
jobs:
  pr-only-job:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
cat > "${FX}/group-typed.yml" <<'EOF'
on:
  pull_request:
  merge_group:
    types: [ destroyed ]
jobs:
  group-typed-job:
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
expect 1 "fixture: a workflow without a merge_group trigger fails" \
    "no merge_group trigger" -- \
    --workflows "$FX" --contexts "$(ctx pr-only-job)"
expect 1 "fixture: a merge_group trigger without checks_requested fails" \
    "omits \`checks_requested\`" -- \
    --workflows "$FX" --contexts "$(ctx group-typed-job)"
expect 1 "fixture: a job pinned to pull_request events fails" \
    "keeps it off merge-group runs: pins event_name to 'pull_request'" -- \
    --workflows "$FX" --contexts "$(ctx pr-pinned)"
expect 1 "fixture: a job excluding merge_group fails" \
    "keeps it off merge-group runs: excludes merge_group" -- \
    --workflows "$FX" --contexts "$(ctx not-group)"
expect 1 "fixture: a job reading a pull-request-only value fails" \
    "reads a value only pull requests carry" -- \
    --workflows "$FX" --contexts "$(ctx head-ref)"
expect 0 "fixture: an if: naming pull_request and merge_group resolves" \
    "ok   both-events" -- \
    --workflows "$FX" --contexts "$(ctx both-events)"
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

# --- 2b. queue-only jobs (issue #658) and retired stubs (issue #659) ------
QX="${WORK}/queue"
mkdir -p "$QX"
cat > "${QX}/ci.yml" <<'EOF'
on:
  pull_request:
    branches: [ main ]
  merge_group:
jobs:
  base:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  gated:
    if: ${{ !cancelled() && github.event_name != 'pull_request' }}
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  leg:
    runs-on: ubuntu-24.04
    steps:
      - if: github.event_name != 'pull_request'
        run: "true"
  agg:
    needs: leg
    if: always()
    runs-on: ubuntu-24.04
    steps:
      - env: { R: "${{ needs.leg.result }}" }
        run: test "$R" != failure
  legs:
    strategy:
      matrix:
        include:
          - { flag: "" }
          - { flag: "-x" }
    runs-on: ubuntu-24.04
    steps:
      - if: matrix.flag == '' || github.event_name != 'pull_request'
        run: "true"
  stub:
    name: Old Gate
    if: false
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
# A path-filtered workflow's `report` job (install-smoke.yml's shape) may
# skip on pull requests: the workflow never gates one.
cat > "${QX}/smoke.yml" <<'EOF'
on:
  pull_request:
    paths: [ "install.sh" ]
  schedule:
    - cron: '0 0 * * *'
jobs:
  report:
    if: failure() && github.event_name != 'pull_request'
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
expect 0 "queue: a skipped-on-PR job reporting a required context resolves" \
    "ok   ci.yml:gated  gated by gated" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)')"
expect 0 "queue: a step skipped on PRs is gated through the aggregate needing it" \
    "ok   ci.yml:leg  gated by agg" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)')"
expect 1 "queue: a skipped-on-PR job no required context gates fails" \
    "ci.yml:gated skips on pull requests, and no required context" -- \
    --workflows "$QX" --contexts "$(ctx base agg legs 'legs (-x)')"
expect 1 "queue: a step skipped on PRs whose aggregate is not required fails" \
    "ci.yml:leg skips on pull requests, and no required context" -- \
    --workflows "$QX" --contexts "$(ctx base gated legs 'legs (-x)')"
if bash "$HELPER" --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)')" 2>&1 \
        | grep -q 'smoke.yml'; then
    bad "queue: a path-filtered workflow's report job is checked"
else
    ok "queue: a path-filtered workflow's report job is not checked"
fi
expect 1 "queue: a matrix leg that skips on PRs must itself be required" \
    "ci.yml:legs skips on pull requests, and no required context reports 'legs (-x)'" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs)"
# An aggregate that a failed need would skip (no always()/!cancelled()), or
# that never reads the need's result, passes whatever the need did.
QA="${WORK}/queue-agg"
mkdir -p "$QA"
cat > "${QA}/ci.yml" <<'EOF'
on:
  pull_request:
    branches: [ main ]
  merge_group:
jobs:
  leg:
    if: ${{ !cancelled() && github.event_name != 'pull_request' }}
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  skips:
    needs: leg
    runs-on: ubuntu-24.04
    steps:
      - env: { R: "${{ needs.leg.result }}" }
        run: test "$R" != failure
  blind:
    needs: [leg]
    if: ${{ !cancelled() }}
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
  star:
    needs: [leg]
    if: ${{ !cancelled() }}
    runs-on: ubuntu-24.04
    steps:
      - if: contains(needs.*.result, 'failure')
        run: exit 1
  bracket:
    needs: [leg]
    if: always()
    runs-on: ubuntu-24.04
    steps:
      - env: { R: "${{ needs['leg'].result }}" }
        run: test "$R" = success
  either:
    needs: [leg]
    if: success() || failure()
    runs-on: ubuntu-24.04
    steps:
      - env: { R: "${{ needs.leg.result }}" }
        run: test "$R" = success
  onfail:
    needs: [leg]
    if: failure()
    runs-on: ubuntu-24.04
    steps:
      - env: { R: "${{ needs.leg.result }}" }
        run: test "$R" = success
  conj:
    needs: [leg]
    if: ${{ !cancelled() && needs.leg.result == 'success' }}
    runs-on: ubuntu-24.04
    steps:
      - env: { R: "${{ needs.leg.result }}" }
        run: test "$R" = success
  never:
    needs: [leg]
    if: ${{ ! always() || !failure() }}
    runs-on: ubuntu-24.04
    steps:
      - env: { R: "${{ needs.leg.result }}" }
        run: test "$R" = success
EOF
expect 1 "queue: an aggregate a failed need would skip does not gate it" \
    "gated through the aggregate ci.yml:skips, which has a job-level \`if:\` other than" -- \
    --workflows "$QA" --contexts "$(ctx skips)"
expect 1 "queue: an aggregate that never reads the need's result does not gate it" \
    "gated through the aggregate ci.yml:blind, which reads neither needs.leg.result" -- \
    --workflows "$QA" --contexts "$(ctx blind)"
# skips and blind need leg too, but report no required context: not checked.
expect 0 "queue: an aggregate reading needs.*.result under !cancelled() gates it" \
    "ok   ci.yml:leg  gated by star" -- \
    --workflows "$QA" --contexts "$(ctx star)"
expect 0 "queue: always() and needs['leg'].result also gate it" \
    "ok   ci.yml:leg  gated by bracket" -- \
    --workflows "$QA" --contexts "$(ctx bracket)"
# Any job-level `if:` but always() / !cancelled() can be false on a failed,
# cancelled or skipped need, and the skipped aggregate reports success.
expect 1 "queue: an aggregate under success() || failure() does not gate it" \
    "gated through the aggregate ci.yml:either, which has a job-level \`if:\` other than" -- \
    --workflows "$QA" --contexts "$(ctx either)"
expect 1 "queue: an aggregate under failure() does not gate it" \
    "gated through the aggregate ci.yml:onfail, which has a job-level \`if:\` other than" -- \
    --workflows "$QA" --contexts "$(ctx onfail)"
expect 1 "queue: an aggregate under !cancelled() && a need's success does not gate it" \
    "gated through the aggregate ci.yml:conj, which has a job-level \`if:\` other than" -- \
    --workflows "$QA" --contexts "$(ctx conj)"
expect 1 "queue: an aggregate under negated always()/failure() does not gate it" \
    "gated through the aggregate ci.yml:never, which has a job-level \`if:\` other than" -- \
    --workflows "$QA" --contexts "$(ctx never)"

QN="${WORK}/queue-nogroup"
mkdir -p "$QN"
cat > "${QN}/ci.yml" <<'EOF'
on:
  pull_request:
  merge_group:
jobs:
  base:
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
cat > "${QN}/pr.yml" <<'EOF'
on:
  pull_request:
    branches: [ main ]
jobs:
  later:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-24.04
    steps: [ { run: "true" } ]
EOF
expect 1 "queue: a skipped-on-PR job in a workflow without merge_group fails" \
    "pr.yml:later skips on pull requests, but its workflow has no merge_group" -- \
    --workflows "$QN" --contexts "$(ctx base)"

printf '%s\n' '# retired' 'Old Gate' > "${WORK}/retired.txt"
expect 0 "retired: a context reported by an if: false stub resolves" \
    "ok   Old Gate  <- ci.yml:stub" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)')" --retired "${WORK}/retired.txt"
printf '%s\n' base > "${WORK}/retired-real.txt"
expect 1 "retired: a context whose job still runs fails" \
    "is retired but its job is not a stub" -- \
    --workflows "$QX" --contexts "$(ctx gated agg legs 'legs (-x)')" --retired "${WORK}/retired-real.txt"
expect 1 "retired: a context both required and retired fails" \
    "is also in the committed list" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)' 'Old Gate')" --retired "${WORK}/retired.txt"
expect 1 "committed: a context only a stub reports fails" \
    "names only a retired stub" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)' 'Old Gate')"
expect 2 "retired: a missing --retired file is a broken helper" "" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)')" --retired "${WORK}/absent.txt"
mkdir -p "${WORK}/lists"
printf '%s\n' base gated agg legs 'legs (-x)' > "${WORK}/lists/required-checks.txt"
printf '%s\n' base > "${WORK}/lists/retired-checks.txt"
expect 1 "retired: retired-checks.txt beside the context list is read by default" \
    "is retired but its job is not a stub" -- \
    --workflows "$QX" --contexts "${WORK}/lists/required-checks.txt"

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
printf '%s\n' base gated agg legs 'legs (-x)' 'Old Gate' > "${WORK}/live-queue.txt"
PATH="${STUB}:${PATH}" STUB_LIVE="${WORK}/live-queue.txt" \
    expect 0 "--live: a retired context still required live is reported" \
    "retired: Old Gate is still required live" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)')" \
    --retired "${WORK}/retired.txt" --live example/repo
printf '%s\n' base agg legs 'legs (-x)' > "${WORK}/live-noqueue.txt"
PATH="${STUB}:${PATH}" STUB_LIVE="${WORK}/live-noqueue.txt" \
    expect 1 "--live: a queue-only job's context that is not live-required fails" \
    "FAIL live: 'gated' gates queue-only ci.yml:gated" -- \
    --workflows "$QX" --contexts "$(ctx base gated agg legs 'legs (-x)')" --live example/repo
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
