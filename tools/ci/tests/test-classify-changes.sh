#!/usr/bin/env bash
# test-classify-changes.sh — self-test for the docs-only filter
# (tools/ci/classify-changes.sh, issue #552) and for the CI job set it feeds
# (issues #528, #552).
#
# (1) Drives the real classifier on path lists: docs/ and root-level
#     Markdown are docs; anything else — Markdown under src/ or tests/
#     included — is code; an empty list is code (fail-closed).
# (2) Reads .github/workflows/c-cpp.yml and phase0-baseline.yml and pins the
#     wiring that keeps every required context reporting on a docs-only pull
#     request:
#       - each workflow has a `changes` job running the classifier;
#       - every job that needs `changes` and has a job-level `if:` keeps
#         !cancelled() or always() in it, so a failed `changes` runs the job
#         instead of skipping it (a skipped job reports success: fail-open);
#       - single-context C jobs skip at job level on code=false;
#       - matrix C jobs never skip at job level (a skipped matrix reports only
#         its bare name) and skip every step instead;
#       - the docs jobs never skip, and doc-validators runs docs_lifecycle on
#         a docs-only change;
#       - every c-cpp.yml job is in exactly one of those sets, so a new job
#         has to be classified;
#     plus the issue #528 jobs (native ARM full suite, x86 -funsigned-char
#     full suite, both required) and the issue #552 enablesec change (it
#     builds ENABLESEC=1 and no longer re-runs a suite unit-tests runs).
#
# Part (2) needs python3 with PyYAML: without it, it reports SKIP, unless
# REQUIRE_PYYAML=1 (the verify-helpers job), under which that fails.
#
# Usage: bash tools/ci/tests/test-classify-changes.sh
# Exit: 0 = all checks passed, 1 = at least one failed.
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CLASSIFIER="${REPO_ROOT}/tools/ci/classify-changes.sh"

pass=0
fail=0
ok()  { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

echo "=== classify-changes self-test ==="

# expect_class <want: true|false> <label> <path>...
expect_class() {
    local want="$1" label="$2" out rc
    shift 2
    out="$(printf '%s\n' "$@" | bash "$CLASSIFIER" 2>/dev/null)"
    rc=$?
    if [ "$rc" -eq 0 ] && [ "$out" = "code=${want}" ]; then
        ok "$label -> code=${want}"
    else
        bad "$label: got '${out}' (exit ${rc}), want code=${want}"
    fi
}

expect_class false "docs/ tree only" docs/USER_GUIDE.md docs/index.html \
    docs/first-run/hello_packet.c docs/_config.yml
expect_class false "root-level Markdown only" README.md CHANGELOG.md AGENTS.md
expect_class false "docs/ plus root Markdown" docs/DECISIONS.md CONTRIBUTING.md
expect_class true  "a source file among docs" docs/USER_GUIDE.md src/mmt_core/src/packet_processing.c
expect_class true  "Markdown under src/ is code" src/mmt_mobile/asn1c/support/DELTA-r16.1.0.md
expect_class true  "Markdown under tests/ is code" tests/docs_onboarding/README.md
expect_class true  "a workflow change is code" .github/workflows/c-cpp.yml
expect_class true  "a root file that is not Markdown is code" LICENSE
expect_class true  "a tool script is code" tools/ci/classify-changes.sh
expect_class true  "an empty list is code (fail-closed)" ""
out="$(printf 'README.md' | bash "$CLASSIFIER" 2>/dev/null)"
if [ "$out" = "code=false" ]; then ok "a last line without a newline is read"
else bad "a last line without a newline: got '${out}'"; fi
if bash "$CLASSIFIER" unexpected-arg </dev/null >/dev/null 2>&1; then
    bad "an argument is bad usage (exit 2)"
else
    rc=$?
    if [ "$rc" -eq 2 ]; then ok "an argument is bad usage (exit 2)"
    else bad "an argument: exit ${rc}, want 2"; fi
fi

echo "=== CI job wiring (c-cpp.yml, phase0-baseline.yml) ==="
if ! python3 -c 'import yaml' 2>/dev/null; then
    if [ "${REQUIRE_PYYAML:-0}" = "1" ]; then
        bad "PyYAML (python3-yaml) is missing and REQUIRE_PYYAML=1"
    else
        echo "  SKIP PyYAML (python3-yaml) not installed — install it to run the wiring checks"
    fi
else
    wiring="$(python3 - "$REPO_ROOT" <<'PY'
import os
import sys

import yaml

root = sys.argv[1]
GATE = "needs.changes.outputs.code != 'false'"
results = []


def check(label, cond):
    results.append(("PASS" if cond else "FAIL", label))


def load(name):
    with open(os.path.join(root, ".github", "workflows", name),
              encoding="utf-8") as fh:
        return yaml.safe_load(fh)["jobs"]


def needs(job):
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else list(n)


def is_matrix(job):
    return (job.get("strategy") or {}).get("matrix") is not None


def cond(job):
    return str(job.get("if", ""))


def skips_at_job_level(job):
    return GATE in cond(job)


def steps_all_gated(job):
    steps = job.get("steps") or []
    return bool(steps) and all(GATE in str(s.get("if", "")) for s in steps)


WORKFLOWS = {
    "c-cpp.yml": {
        "single": ["unit-tests-arm", "unit-tests-unsigned-char",
                   "toolchain-floor", "toolchain-ceiling", "coverage", "lint",
                   "codeql", "root-install", "assertions-live", "enablesec",
                   "fuzz", "abi-diff"],
        "matrix": ["unit-tests", "sanitizer-tests", "resource-budgets"],
        "docs": ["build", "verify-helpers", "pre-commit", "doc-validators",
                 "version-agreement", "secret-scan", "site-onboarding"],
        "other": ["changes", "fuzz-alert"],
    },
    "phase0-baseline.yml": {
        "single": ["asan-build", "list-harnesses", "classification-gate",
                   "leak-gate", "precision-gate"],
        "matrix": [],
        "docs": [],
        "other": ["changes", "harness", "harness-gate"],
    },
}

for wf, sets in WORKFLOWS.items():
    jobs = load(wf)
    ch = jobs.get("changes") or {}
    run = " ".join(str(s.get("run", "")) for s in ch.get("steps") or [])
    check(f"{wf}: a `changes` job runs tools/ci/classify-changes.sh",
          "tools/ci/classify-changes.sh" in run
          and "code" in (ch.get("outputs") or {}))
    listed = [j for k in ("single", "matrix", "docs", "other") for j in sets[k]]
    if wf == "c-cpp.yml":
        unclassified = sorted(set(jobs) - set(listed))
        check(f"{wf}: every job is classified as a C or a docs job"
              + (f" (unclassified: {', '.join(unclassified)})"
                 if unclassified else ""), not unclassified)
    for name in listed:
        check(f"{wf}: job {name} exists", name in jobs)
    for name, job in jobs.items():
        if "changes" in needs(job) and job.get("if") is not None:
            c = cond(job)
            check(f"{wf}: {name} keeps !cancelled()/always() in its if: "
                  f"(fail-closed when `changes` fails)",
                  "!cancelled()" in c or "always()" in c)
    for name in sets["single"]:
        job = jobs.get(name) or {}
        check(f"{wf}: {name} needs changes and skips at job level on "
              f"code=false", "changes" in needs(job) and not is_matrix(job)
              and skips_at_job_level(job))
    for name in sets["matrix"]:
        job = jobs.get(name) or {}
        check(f"{wf}: matrix job {name} never skips at job level and skips "
              f"every step on code=false",
              "changes" in needs(job) and is_matrix(job)
              and not skips_at_job_level(job) and steps_all_gated(job))
    for name in sets["docs"]:
        job = jobs.get(name) or {}
        check(f"{wf}: docs job {name} never skips on code=false",
              not skips_at_job_level(job))

cc = load("c-cpp.yml")
dv = cc.get("doc-validators") or {}
check("c-cpp.yml: doc-validators runs docs_lifecycle on a docs-only change",
      any("docs_lifecycle" in str(s.get("run", ""))
          and "needs.changes.outputs.code == 'false'" in str(s.get("if", ""))
          for s in dv.get("steps") or []))

# Issue #528: unsigned plain char on native ARM, mirrored on x86.
arm = cc.get("unit-tests-arm") or {}
arm_runs = [str(s.get("run", "")).strip() for s in arm.get("steps") or []]
check("c-cpp.yml: unit-tests-arm runs the full suite set on ubuntu-24.04-arm",
      arm.get("runs-on") == "ubuntu-24.04-arm"
      and "bash tests/run_all_tests.sh" in arm_runs)
uc = cc.get("unit-tests-unsigned-char") or {}
env = uc.get("env") or {}
uc_runs = [str(s.get("run", "")).strip() for s in uc.get("steps") or []]
check("c-cpp.yml: unit-tests-unsigned-char runs the full suite set with "
      "-funsigned-char on the suites and the SDK",
      "-funsigned-char" in str(env.get("EXTRA_CFLAGS", ""))
      and "-funsigned-char" in str(env.get("MMT_EXTRA_CFLAGS", ""))
      and "bash tests/run_all_tests.sh" in uc_runs)
with open(os.path.join(root, ".github", "required-checks.txt"),
          encoding="utf-8") as fh:
    required = {ln.strip() for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")}
for ctx in ("unit-tests-arm", "unit-tests-unsigned-char"):
    check(f"required-checks.txt requires {ctx}", ctx in required)

# Issue #552: enablesec proves the engines compile; rule_engine runs in
# unit-tests (DEFAULT_SUITES), not a second time here.
es_runs = " ".join(str(s.get("run", ""))
                   for s in (cc.get("enablesec") or {}).get("steps") or [])
check("c-cpp.yml: enablesec builds ENABLESEC=1 and re-runs no suite",
      "ENABLESEC=1" in es_runs and "run_all_tests.sh" not in es_runs)

for status, label in results:
    print(f"  {status} {label}")
PY
)"
    rc=$?
    printf '%s\n' "$wiring"
    if [ "$rc" -ne 0 ]; then
        bad "wiring check crashed (exit ${rc})"
    fi
    n_pass=$(printf '%s\n' "$wiring" | grep -c '^  PASS ' || true)
    n_fail=$(printf '%s\n' "$wiring" | grep -c '^  FAIL ' || true)
    pass=$((pass + n_pass))
    fail=$((fail + n_fail))
fi

echo
echo "classify-changes self-test: ${pass} passed, ${fail} failed"
if [ "$fail" -eq 0 ]; then
    echo "Result: PASS (classify-changes self-test)"
    exit 0
fi
echo "Result: FAIL (classify-changes self-test)"
exit 1
