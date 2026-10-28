#!/usr/bin/env bash
#
# test-local-gates.sh — self-test of tools/ci/local-gates.sh (issue #553,
# F-CI-010).
#
# Part 1 (no PyYAML needed): argument errors and a missing container runtime
# exit 2; with a fake runtime, the gates image is built FROM the lint job's
# digest-pinned image and the run mounts the checkout at its own path, runs
# as the caller (podman: --userns=keep-id) and re-enters the script with
# --in-container and the tier; from a linked worktree it also mounts the
# main checkout's git directory, which lies outside the checkout.
# Part 2 (PyYAML; skipped without it unless REQUIRE_PYYAML=1, as the
# verify-helpers job runs it): the step list read from the real
# .github/workflows/c-cpp.yml is every `run:` step of the lint,
# verify-helpers and doc-validators jobs except the named set-up steps and
# the docs-only step, and --full adds the pre-push steps. On fixture
# workflows: a set-up step name that is gone, an unknown `${{ }}` expression
# and an unknown step `if:` each exit 2; steps run in order with their env,
# set-up steps never run, a failing step exits 1 and stops the run, and
# --keep-going runs the rest.
#
# Usage: bash tools/ci/tests/test-local-gates.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
GATES="${REPO_ROOT}/tools/ci/local-gates.sh"
[ -f "${GATES}" ] || { echo "✗ missing ${GATES}" >&2; exit 2; }
unset MMT_CCACHE MMT_GATES_WORKFLOW

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILED=0
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; FAILED=$((FAILED + 1)); }
# run_gates OUT_PREFIX ARGS... — runs local-gates.sh, stores stdout+stderr in
# OUT_PREFIX.out and the exit status in RC.
run_gates() {
    local out="$1"; shift
    set +e
    bash "${GATES}" "$@" >"${out}.out" 2>&1
    RC=$?
    set -e
}

echo "-- arguments and the container runtime --"
run_gates "${WORK}/bad" --frobnicate
if [ "$RC" -eq 2 ]; then pass "an unknown argument exits 2"; else fail "an unknown argument exits 2 (got $RC)"; fi

MMT_CONTAINER_RUNTIME="${WORK}/no-such-runtime" run_gates "${WORK}/nort" --fast
if [ "$RC" -eq 2 ] && grep -q "no container runtime" "${WORK}/nort.out"; then
    pass "no container runtime exits 2 and says so"
else
    fail "no container runtime exits 2 and says so (got $RC)"; sed 's/^/      /' "${WORK}/nort.out"
fi

# A fake runtime: no image yet (inspect fails), build keeps the context's
# Dockerfile, run records its arguments.
mkdir -p "${WORK}/rt"
for rt in docker podman; do
    cat > "${WORK}/rt/${rt}" <<EOF
#!/bin/sh
case "\$1" in
  image) exit 1 ;;
  build) for a; do ctx="\$a"; done; cp "\$ctx/Dockerfile" "${WORK}/${rt}.Dockerfile"; exit 0 ;;
  run) shift; printf '%s\n' "\$@" > "${WORK}/${rt}.run"; exit 0 ;;
esac
exit 64
EOF
    chmod +x "${WORK}/rt/${rt}"
done
lint_image="$(grep -A40 '^  lint:' "${REPO_ROOT}/.github/workflows/c-cpp.yml" \
    | grep -m1 'image:' | sed 's/.*image: *"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/')"
MMT_CONTAINER_RUNTIME="${WORK}/rt/docker" run_gates "${WORK}/fake" --full --keep-going
if [ "$RC" -eq 0 ] && [ -f "${WORK}/docker.Dockerfile" ] && [ -f "${WORK}/docker.run" ]; then
    pass "a missing image is built, then the gates run in it"
else
    fail "a missing image is built, then the gates run in it (got $RC)"; sed 's/^/      /' "${WORK}/fake.out"
fi
if [ "$(head -1 "${WORK}/docker.Dockerfile" 2>/dev/null)" = "FROM ${lint_image}" ] \
   && [ "${lint_image#*@sha256:}" != "${lint_image}" ]; then
    pass "the image is built FROM the lint job's digest-pinned image"
else
    fail "the image is built FROM the lint job's digest-pinned image (${lint_image})"
fi
if grep -q 'install-cppcheck.sh' "${WORK}/docker.Dockerfile" 2>/dev/null; then
    pass "the image builds the pinned cppcheck with install-cppcheck.sh"
else
    fail "the image builds the pinned cppcheck with install-cppcheck.sh"
fi
run_args="$(tr '\n' ' ' < "${WORK}/docker.run" 2>/dev/null || true)"
for want in "-v ${REPO_ROOT}:${REPO_ROOT}" "-w ${REPO_ROOT}" "-u $(id -u):$(id -g)" \
            "--tmpfs ${REPO_ROOT}/docs/.jekyll-cache:mode=1777" \
            "--in-container --full --keep-going" "mmt-dpi-local-gates:"; do
    case " ${run_args}" in
        *" ${want}"*) pass "docker run: ${want}" ;;
        *) fail "docker run: ${want}"; echo "      ${run_args}" ;;
    esac
done
MMT_CONTAINER_RUNTIME="${WORK}/rt/podman" run_gates "${WORK}/fakep" --fast
case " $(tr '\n' ' ' < "${WORK}/podman.run" 2>/dev/null || true)" in
    *" --userns=keep-id "*) pass "podman runs with --userns=keep-id" ;;
    *) fail "podman runs with --userns=keep-id" ;;
esac

# A linked worktree: its git directory lives in the main checkout's .git,
# outside the bind mount, so that directory is mounted too.
fx="${WORK}/fx-main"
mkdir -p "${fx}/tools/ci" "${fx}/docs" "${fx}/.github/workflows"
cp "${GATES}" "${REPO_ROOT}/tools/ci/install-build-deps.sh" \
   "${REPO_ROOT}/tools/ci/install-cppcheck.sh" "${fx}/tools/ci/"
cp "${REPO_ROOT}/docs/Gemfile" "${REPO_ROOT}/docs/Gemfile.lock" "${fx}/docs/"
cp "${REPO_ROOT}/.github/workflows/c-cpp.yml" "${fx}/.github/workflows/"
git -C "${fx}" init -q
git -C "${fx}" add -A
git -C "${fx}" -c user.name=t -c user.email=t@example.invalid commit -q -m fixture
git -C "${fx}" worktree add -q "${WORK}/fx-wt" 2>/dev/null
rm -f "${WORK}/docker.run"
set +e
MMT_CONTAINER_RUNTIME="${WORK}/rt/docker" bash "${WORK}/fx-wt/tools/ci/local-gates.sh" --fast \
    >"${WORK}/wt.out" 2>&1
RC=$?
set -e
common="$(cd "${fx}/.git" && pwd)"
case " $(tr '\n' ' ' < "${WORK}/docker.run" 2>/dev/null || true)" in
    *" -v ${WORK}/fx-wt:${WORK}/fx-wt "*" -v ${common}:${common} "*)
        pass "a linked worktree also mounts the main checkout's git directory" ;;
    *) fail "a linked worktree also mounts the main checkout's git directory (rc $RC)"
       sed 's/^/      /' "${WORK}/wt.out" ;;
esac

echo "-- the steps (read from the workflow) --"
if ! python3 -c 'import yaml' 2>/dev/null; then
    if [ "${REQUIRE_PYYAML:-0}" = 1 ]; then
        echo "✗ PyYAML is required (REQUIRE_PYYAML=1)" >&2; exit 2
    fi
    echo "  ○ PyYAML not installed: workflow-reading checks skipped"
else
    run_gates "${WORK}/list" --host --list
    expected="$(python3 - "${REPO_ROOT}/.github/workflows/c-cpp.yml" <<'PYEOF'
import sys, yaml
jobs = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))["jobs"]
setup = {"Install git, shellcheck and the cppcheck build prerequisites",
         "Mark the checkout as a safe git directory",
         "Build the pinned cppcheck release from source"}
for job in ("lint", "verify-helpers", "doc-validators"):
    for st in jobs[job]["steps"]:
        if "run" not in st or st.get("name") in setup:
            continue
        if "needs.changes.outputs.code == 'false'" in str(st.get("if", "")):
            continue
        print(f"{job} :: {st['name']}")
PYEOF
)"
    if [ "$RC" -eq 0 ] && [ "$(cat "${WORK}/list.out")" = "${expected}" ]; then
        pass "--list is every gate step of lint, verify-helpers and doc-validators, in order"
    else
        fail "--list is every gate step of lint, verify-helpers and doc-validators, in order (rc $RC)"
        diff <(echo "${expected}") "${WORK}/list.out" | sed 's/^/      /' || true
    fi
    for want in "lint :: shellcheck" "lint :: cppcheck" "verify-helpers :: Advisory helpers" \
                "doc-validators :: Run every scripts/validate-"; do
        if grep -qF -- "${want}" "${WORK}/list.out"; then pass "--list names '${want}'"; else fail "--list names '${want}'"; fi
    done
    if grep -q "Build the pinned cppcheck\|safe git directory\|Install git" "${WORK}/list.out"; then
        fail "runner set-up steps are not listed"
    else
        pass "runner set-up steps are not listed"
    fi
    run_gates "${WORK}/listfull" --host --list --full
    if [ "$RC" -eq 0 ] && [ "$(head -n "$(wc -l < "${WORK}/list.out")" "${WORK}/listfull.out")" = "$(cat "${WORK}/list.out")" ] \
       && [ "$(tail -n 3 "${WORK}/listfull.out" | cut -d' ' -f1 | sort -u)" = "pre-push" ] \
       && grep -q "pre-push :: unit-test suites" "${WORK}/listfull.out"; then
        pass "--full is --fast plus the suites and the two phase0 gates"
    else
        fail "--full is --fast plus the suites and the two phase0 gates"; sed 's/^/      /' "${WORK}/listfull.out"
    fi

    # Fixture workflows.
    fixture() {  # fixture FILE LINT_SETUP_NAME VH_EXTRA
        cat > "$1" <<EOF
jobs:
  lint:
    env:
      MODE: \${{ github.event_name == 'pull_request' && 'pr' || 'full' }}
    steps:
    - uses: actions/checkout@0000000000000000000000000000000000000000
    - name: $2
      run: exit 99
    - name: Mark the checkout as a safe git directory
      run: exit 99
    - name: Build the pinned cppcheck release from source
      run: exit 99
    - name: first
      run: echo "first \$MODE" >> "${WORK}/trace"
  verify-helpers:
    steps:
    - name: second
      env:
        GREETING: hello world
      run: |
        echo "second \$GREETING" >> "${WORK}/trace"
        exit \${FIX_SECOND_RC:-0}
$3
  doc-validators:
    steps:
    - name: docs-only
      if: needs.changes.outputs.code == 'false'
      run: exit 99
    - name: third
      run: echo third >> "${WORK}/trace"
EOF
    }
    good="Install git, shellcheck and the cppcheck build prerequisites"
    fixture "${WORK}/ok.yml" "$good" ""
    : > "${WORK}/trace"
    MMT_GATES_WORKFLOW="${WORK}/ok.yml" run_gates "${WORK}/ok" --host
    if [ "$RC" -eq 0 ] && [ "$(cat "${WORK}/trace")" = "$(printf 'first pr\nsecond hello world\nthird')" ]; then
        pass "the steps run in order with their env; set-up and docs-only steps never run"
    else
        fail "the steps run in order with their env; set-up and docs-only steps never run (rc $RC)"
        sed 's/^/      /' "${WORK}/trace" "${WORK}/ok.out"
    fi
    : > "${WORK}/trace"
    FIX_SECOND_RC=3 MMT_GATES_WORKFLOW="${WORK}/ok.yml" run_gates "${WORK}/stop" --host
    if [ "$RC" -eq 1 ] && ! grep -q third "${WORK}/trace" && grep -q "verify-helpers :: second (exit 3" "${WORK}/stop.out"; then
        pass "a failing step exits 1, names the step and stops the run"
    else
        fail "a failing step exits 1, names the step and stops the run (rc $RC)"; sed 's/^/      /' "${WORK}/stop.out"
    fi
    : > "${WORK}/trace"
    FIX_SECOND_RC=3 MMT_GATES_WORKFLOW="${WORK}/ok.yml" run_gates "${WORK}/kg" --host --keep-going
    if [ "$RC" -eq 1 ] && grep -q third "${WORK}/trace"; then
        pass "--keep-going runs the remaining steps and still exits 1"
    else
        fail "--keep-going runs the remaining steps and still exits 1 (rc $RC)"
    fi
    fixture "${WORK}/stale.yml" "Install the cppcheck prerequisites" ""
    MMT_GATES_WORKFLOW="${WORK}/stale.yml" run_gates "${WORK}/stale" --host --list
    if [ "$RC" -eq 2 ] && grep -q "SETUP_STEPS" "${WORK}/stale.out"; then
        pass "a set-up step name gone from the workflow exits 2"
    else
        fail "a set-up step name gone from the workflow exits 2 (rc $RC)"; sed 's/^/      /' "${WORK}/stale.out"
    fi
    fixture "${WORK}/expr.yml" "$good" "    - name: actor
      run: echo \${{ github.actor }}"
    MMT_GATES_WORKFLOW="${WORK}/expr.yml" run_gates "${WORK}/expr" --host --list
    if [ "$RC" -eq 2 ] && grep -q "unknown expression" "${WORK}/expr.out"; then
        pass "an unknown \${{ }} expression exits 2"
    else
        fail "an unknown \${{ }} expression exits 2 (rc $RC)"; sed 's/^/      /' "${WORK}/expr.out"
    fi
    fixture "${WORK}/cond.yml" "$good" "    - name: pushes only
      if: github.event_name == 'push'
      run: exit 99"
    MMT_GATES_WORKFLOW="${WORK}/cond.yml" run_gates "${WORK}/cond" --host --list
    if [ "$RC" -eq 2 ] && grep -q "unknown step condition" "${WORK}/cond.out"; then
        pass "an unknown step if: exits 2"
    else
        fail "an unknown step if: exits 2 (rc $RC)"; sed 's/^/      /' "${WORK}/cond.out"
    fi
fi

echo ""
if [ "${FAILED}" -eq 0 ]; then
    echo "✓ local-gates self-test passed"
else
    echo "✗ ${FAILED} check(s) failed"
    exit 1
fi
