#!/usr/bin/env python3
"""test-release-gates.py -- self-test for the exact-release-SHA publish gate
(issue #371, F-CI-001).

Drives the REAL gate (tools/ci/check-release-gates.sh) in --check-runs mode
with synthetic check-run payloads and same-run env evidence, asserting both
the positive contract and every negative the acceptance criteria name:

  - all required gates green at the candidate SHA -> eligible (exit 0)
  - a failed / skipped / cancelled / neutral required check -> exit 1
  - a required check missing entirely at the SHA -> exit 1
  - evidence recorded for a DIFFERENT SHA -> exit 1
  - evidence only queued/in_progress (nothing completed) -> exit 1
  - re-run semantics: failure then success -> eligible; success then a
    NEWER failure -> exit 1
  - same-run needs result failed / cancelled / skipped / missing -> exit 1
  - malformed evidence / bad arguments -> exit 2

Usage: python3 tools/ci/tests/test-release-gates.py
Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.
"""

import json
import os
import subprocess
import sys
import tempfile

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SELF_DIR, "..", "..", ".."))
GATE = os.path.join(REPO_ROOT, "tools", "ci", "check-release-gates.sh")

SHA = "a" * 40
OTHER_SHA = "b" * 40

PASS = 0
FAIL = 0
TESTED = 0

T1 = "2026-09-22T15:27:05Z"
T2 = "2026-09-22T15:27:51Z"
T3 = "2026-09-22T15:32:32Z"


def run(name, status="completed", conclusion="success", head_sha=SHA,
        completed_at=T1, run_id=1):
    return {"name": name, "status": status, "conclusion": conclusion,
            "head_sha": head_sha, "completed_at": completed_at, "id": run_id}


# A fully green evidence set: every required group present at the SHA.
GREEN_RUNS = [
    run("unit-tests", completed_at=T2),
    run("unit-tests (-fsigned-char, hashmap memory hexdump mmt_utils mmt_inet_ntop)",
        completed_at=T1),
    run("sanitizer-tests (BUILD=asan, asan)", completed_at=T3),
    run("sanitizer-tests (BUILD=tsan, tsan)", completed_at=T3),
    run("ASan/UBSan profile compiles", completed_at=T1),
    run("Golden classification fingerprint unchanged", completed_at=T1),
    # Unrelated checks sharing the SHA must not matter.
    run("lint", completed_at=T1),
    run("coverage", status="in_progress", conclusion=None, completed_at=None),
]

GREEN_ENV = {
    "NEEDS_RESULT_BUILD": "success",
    "NEEDS_RESULT_REPRODUCIBILITY": "success",
    "NEEDS_RESULT_VERIFY_TAG": "success",
}


def invoke(runs, env=None, extra_args=(), sha=SHA, raw=None):
    """Run the real gate. `runs` is a list of check-run dicts (or None to
    write `raw` verbatim); `env` overrides GREEN_ENV keys (None -> use it,
    {} -> no needs vars). Returns (rc, stdout+stderr)."""
    with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False) as f:
        if raw is not None:
            f.write(raw)
        else:
            json.dump({"check_runs": runs or []}, f)
        path = f.name
    try:
        e = dict(os.environ)
        for k in GREEN_ENV:
            e.pop(k, None)
        e.update(GREEN_ENV if env is None else env)
        args = ["bash", GATE, "--check-runs", path, *extra_args, sha]
        proc = subprocess.run(args, capture_output=True, text=True, env=e)
        return proc.returncode, proc.stdout + proc.stderr
    finally:
        os.unlink(path)


def check(name, cond, detail=""):
    global PASS, FAIL, TESTED
    TESTED += 1
    if cond:
        PASS += 1
        print("  ok   %-62s" % name)
    else:
        FAIL += 1
        print("  FAIL %-62s %s" % (name, detail))


def expect(name, want_rc, runs, env=None, extra_args=(), needle=None, **kw):
    rc, out = invoke(runs, env=env, extra_args=extra_args, **kw)
    check(name, rc == want_rc, f"(rc={rc})\n{out[-800:]}")
    if needle is not None:
        check(f"{name} -- reports /{needle}/", needle in out, out[-400:])


if not os.path.isfile(GATE):
    print(f"missing {GATE}", file=sys.stderr)
    sys.exit(2)

print("check-release-gates.sh exact-SHA self-test (issue #371, F-CI-001)")
print()

# --- positive: everything green at the candidate SHA -------------------------
expect("all gates green at SHA -> eligible", 0, GREEN_RUNS,
       needle="exact-release-SHA evidence green")

# A lone in-flight tag-push re-run does not void completed green evidence.
expect("green completed + in-flight re-run -> eligible", 0,
       GREEN_RUNS + [run("unit-tests", status="in_progress",
                         conclusion=None, completed_at=None, run_id=99)])

# Re-run semantics: an older failure repaired by a newer success.
expect("failure then newer success re-run -> eligible", 0,
       GREEN_RUNS + [run("unit-tests", conclusion="failure", completed_at=T1,
                         run_id=50),
                     run("unit-tests", conclusion="success", completed_at=T3,
                         run_id=60)])

# --- negatives: required check not green --------------------------------------
expect("unit-tests leg failed -> not eligible", 1,
       [r if r["name"] != "unit-tests" else
        run("unit-tests", conclusion="failure") for r in GREEN_RUNS],
       needle="latest completed run = failure")

expect("sanitizer-tests leg skipped -> not eligible", 1,
       [r if not r["name"].startswith("sanitizer-tests (BUILD=tsan") else
        run(r["name"], conclusion="skipped") for r in GREEN_RUNS])

expect("classification cancelled -> not eligible", 1,
       [r if r["name"] != "Golden classification fingerprint unchanged" else
        run(r["name"], conclusion="cancelled") for r in GREEN_RUNS],
       needle="latest completed run = cancelled")

expect("classification neutral -> not eligible", 1,
       [r if r["name"] != "Golden classification fingerprint unchanged" else
        run(r["name"], conclusion="neutral") for r in GREEN_RUNS])

expect("newer failure voids an older success -> not eligible", 1,
       GREEN_RUNS + [run("unit-tests", conclusion="success", completed_at=T1,
                         run_id=50),
                     run("unit-tests", conclusion="failure", completed_at=T3,
                         run_id=60)])

expect("required check missing entirely -> not eligible", 1,
       [r for r in GREEN_RUNS
        if r["name"] != "Golden classification fingerprint unchanged"],
       needle="no check-run evidence")

expect("no evidence at all -> not eligible", 1, [],
       needle="no check-run evidence")

expect("only queued/in_progress evidence -> not eligible", 1,
       [run("unit-tests", status="in_progress", conclusion=None,
            completed_at=None),
        run("sanitizer-tests (BUILD=asan, asan)", status="queued",
            conclusion=None, completed_at=None),
        run("sanitizer-tests (BUILD=tsan, tsan)", completed_at=T1),
        run("ASan/UBSan profile compiles", completed_at=T1),
        run("Golden classification fingerprint unchanged", completed_at=T1)],
       needle="no completed run")

expect("wrong-SHA check run in payload -> not eligible", 1,
       GREEN_RUNS + [run("some-other-check", head_sha=OTHER_SHA)],
       needle="wrong-SHA evidence")

expect("classification via bare job id also satisfies the group", 0,
       [r if r["name"] != "Golden classification fingerprint unchanged" else
        run("classification-gate") for r in GREEN_RUNS])

# An abbreviated candidate resolves through the local clone: check runs
# always record the full 40-char head_sha, so a literal compare would
# condemn every run as wrong-SHA (the gate normalizes via git rev-parse).
full_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                           capture_output=True, text=True).stdout.strip()
short_head = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                            cwd=REPO_ROOT,
                            capture_output=True, text=True).stdout.strip()
if len(full_head) == 40 and 0 < len(short_head) < 40:
    expect("abbreviated candidate SHA resolves via local clone -> eligible",
           0, [dict(r, head_sha=full_head) for r in GREEN_RUNS],
           sha=short_head)
else:
    check("abbreviated candidate SHA resolves via local clone -> eligible",
          False, "git HEAD unavailable in this clone")

# --- negatives: same-run prerequisite results ----------------------------------
expect("same-run build=failure -> not eligible", 1, GREEN_RUNS,
       env={**GREEN_ENV, "NEEDS_RESULT_BUILD": "failure"},
       needle="NEEDS_RESULT_BUILD=failure")

expect("same-run reproducibility=cancelled -> not eligible", 1, GREEN_RUNS,
       env={**GREEN_ENV, "NEEDS_RESULT_REPRODUCIBILITY": "cancelled"})

expect("same-run verify-tag=skipped -> not eligible", 1, GREEN_RUNS,
       env={**GREEN_ENV, "NEEDS_RESULT_VERIFY_TAG": "skipped"})

expect("same-run env unset -> not eligible", 1, GREEN_RUNS,
       env={}, needle="unset")

expect("--skip-same-run ignores missing needs env", 0, GREEN_RUNS,
       env={}, extra_args=("--skip-same-run",))

expect("--skip-same-run still enforces commit evidence", 1, [],
       env={}, extra_args=("--skip-same-run",))

# --- evidence file ------------------------------------------------------------
with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
    epath = f.name
rc, out = invoke(GREEN_RUNS, extra_args=("--evidence", epath))
try:
    doc = json.load(open(epath, encoding="utf-8"))
    check("--evidence records the verdict", rc == 0 and doc["eligible"]
          and doc["sha"] == SHA and len(doc["checks"]) >= 6
          and len(doc["same_run"]) == 3, out[-400:])
except Exception as e:
    check("--evidence records the verdict", False, str(e))
finally:
    os.unlink(epath)

# --- helper-broken paths -------------------------------------------------------
rc, out = invoke(None, raw="{not json")
check("malformed evidence -> helper broken (2)", rc == 2, f"rc={rc}")

rc, out = invoke(GREEN_RUNS, sha="not-a-sha")
check("non-hex candidate -> helper broken (2)", rc == 2, f"rc={rc}")

proc = subprocess.run(["bash", GATE, "--check-runs", "/nonexistent.json", SHA],
                      capture_output=True, text=True)
check("missing evidence file -> helper broken (2)", proc.returncode == 2,
      f"rc={proc.returncode}")

print()
print(f"release-gates self-test: {PASS} passed, {FAIL} failed ({TESTED} checks)")
sys.exit(0 if FAIL == 0 else 1)
