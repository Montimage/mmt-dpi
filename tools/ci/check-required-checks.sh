#!/usr/bin/env bash
# check-required-checks.sh — required status-check contexts vs workflow jobs
# (issue #490, F-CI-004/F-CI-014).
#
# Branch protection requires status-check contexts by exact check-run name.
# A context that names no job, or names a job that never reports on a pull
# request into main (a path-filtered workflow, a tag- or schedule-only job),
# is never satisfied, so every pull request waits on it forever; a job
# renamed without updating protection drops its gate silently. This helper
# derives the check-run name every workflow job reports and fails when a
# listed context matches none of them, or matches only jobs that do not
# report on pull requests.
#
# Merge queue (issue #657): main merges through a merge queue, which runs the
# workflows again on a `merge_group` event and waits for every required
# context on the queued merge commit. A required context must therefore also
# be reported on merge-group runs: its workflow needs a `merge_group` trigger,
# and its job-level `if:` may not keep it off them — an event_name pin that
# does not name merge_group (`== 'pull_request'`, `!= 'merge_group'`) or a
# value only pull requests carry (`github.event.pull_request`,
# `github.head_ref`, `github.base_ref`). Such a job would leave the queue
# waiting, or skip and report success without running.
#
# A matrix job with a job-level `if:` that can skip it is one of those
# (issue #552): GitHub evaluates that `if:` before expanding the matrix, so a
# skipped matrix job reports a single check run under its bare job name and
# every leg's context stays pending. Only `always()` and `!cancelled()`
# (which never skip a live run) are accepted there; a matrix job that must
# not run on some pull requests skips its steps instead.
#
# The list it checks is .github/required-checks.txt — the committed,
# reviewed record of the contexts branch protection on main must require
# (one context per line; blank lines and lines starting with `#` ignored).
#
# Check-run names, as GitHub Actions reports them:
#   - a job's `name:`, with `${{ matrix.<key> }}` expressions substituted per
#     matrix leg, else the job id;
#   - a matrix job whose name has no matrix expression gets the leg's values
#     appended as ` (v1, v2)` — empty-string values are dropped, and a leg
#     whose values are all empty reports the bare name (`unit-tests`);
#   - a matrix computed at run time (`fromJSON(...)`) cannot be expanded
#     statically, so its legs match as a glob (`harness-*`).
#
# Usage:
#   bash tools/ci/check-required-checks.sh [--contexts FILE] [--workflows DIR]
#                                          [--live OWNER/REPO]
#     --contexts FILE   context list (default .github/required-checks.txt)
#     --workflows DIR   workflow directory (default .github/workflows)
#     --live REPO       also read the contexts branch protection on main
#                       requires now (read-only `gh api` GET; needs a token
#                       with admin read access, so not run in CI), fail on a
#                       live context that names no pull-request job, and
#                       report the drift between the live and committed lists
#
# Exit codes (verify-helpers contract): 0 = every context names a job that
# reports on pull requests and merge-group runs; 1 = a context does not;
# 2 = helper broken
# (missing file, unparsable workflow, no python3/PyYAML, gh failure).
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
CONTEXTS="${ROOT}/.github/required-checks.txt"
WORKFLOWS="${ROOT}/.github/workflows"
LIVE_REPO=""

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --contexts)  CONTEXTS="${2:?--contexts needs a file}"; shift 2 ;;
        --workflows) WORKFLOWS="${2:?--workflows needs a directory}"; shift 2 ;;
        --live)      LIVE_REPO="${2:?--live needs OWNER/REPO}"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "check-required-checks: unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -f "$CONTEXTS" ]  || { echo "check-required-checks: no context list: $CONTEXTS" >&2; exit 2; }
[ -d "$WORKFLOWS" ] || { echo "check-required-checks: no workflow directory: $WORKFLOWS" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "check-required-checks: python3 not found" >&2; exit 2; }

LIVE_FILE=""
if [ -n "$LIVE_REPO" ]; then
    LIVE_FILE=$(mktemp)
    trap 'rm -f "$LIVE_FILE"' EXIT
    if ! gh api "repos/${LIVE_REPO}/branches/main/protection" \
            --jq '.required_status_checks.contexts[]' > "$LIVE_FILE"; then
        echo "check-required-checks: cannot read branch protection of ${LIVE_REPO}" >&2
        exit 2
    fi
fi

python3 - "$CONTEXTS" "$WORKFLOWS" "$LIVE_FILE" <<'PY'
import glob
import itertools
import os
import re
import sys
from fnmatch import fnmatchcase

try:
    import yaml
except ImportError:
    print("check-required-checks: PyYAML (python3-yaml) is not installed",
          file=sys.stderr)
    sys.exit(2)

contexts_path, workflows_dir, live_path = sys.argv[1:4]
EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
MATRIX_REF = re.compile(r"^matrix((?:\.[A-Za-z0-9_-]+)+)$")
# `if:` conditions that keep a job off pull_request events entirely.
NON_PR_IF = re.compile(
    r"refs/tags/|github\.event_name\s*==\s*'(?:schedule|push|workflow_dispatch"
    r"|release|workflow_run)'")
# Job-level `if:` values only pull requests carry: empty on merge_group runs.
PR_ONLY_VALUE = re.compile(
    r"github\.(?:event\.pull_request\b|head_ref\b|base_ref\b)")
EVENT_PIN = re.compile(r"github\.event_name\s*(==|!=)\s*'([A-Za-z_]+)'")
# Job-level `if:` conditions that never skip a matrix job in a live run.
NEVER_SKIPS_IF = re.compile(
    r"^\s*(?:\$\{\{\s*)?(?:always\(\)|!\s*cancelled\(\))(?:\s*\}\})?\s*$")


def read_list(path):
    items = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n").strip()
            if line and not line.startswith("#"):
                items.append(line)
    return items


def render(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def lookup(leg, dotted):
    cur = leg
    for part in dotted.strip(".").split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def legs_of(matrix):
    """Static matrix legs as ordered dicts, or None when computed at run time."""
    if matrix is None:
        return [None]
    if not isinstance(matrix, dict):
        return None                      # `matrix: ${{ fromJSON(...) }}`
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    for v in axes.values():
        if not isinstance(v, list):
            return None                  # `axis: ${{ fromJSON(...) }}`
    legs = []
    if axes:
        keys = list(axes)
        for combo in itertools.product(*(axes[k] for k in keys)):
            legs.append(dict(zip(keys, combo)))
    for ex in matrix.get("exclude") or []:
        legs = [leg for leg in legs
                if not all(leg.get(k) == v for k, v in ex.items())]
    include = matrix.get("include") or []
    if not isinstance(include, list):
        return None
    for inc in include:
        if not isinstance(inc, dict):
            return None
        # An entry that matches an existing leg on every original axis it
        # names extends that leg; otherwise it is a leg of its own.
        extends = [leg for leg in legs
                   if all(k not in axes or leg.get(k) == v
                          for k, v in inc.items())
                   and any(k in axes for k in inc)]
        if extends:
            for leg in extends:
                for k, v in inc.items():
                    leg.setdefault(k, v)
        else:
            legs.append(dict(inc))
    return legs or [None]


def check_names(job_id, job):
    """[(name, is_glob)] for every check run the job reports."""
    name = job.get("name")
    name = None if name is None else str(name)
    matrix = (job.get("strategy") or {}).get("matrix")
    legs = legs_of(matrix)
    uses_matrix = bool(name and any(MATRIX_REF.match(e)
                                    for e in EXPR.findall(name)))
    if legs is None:                     # dynamic matrix: glob per leg
        if name and uses_matrix:
            parts = EXPR.split(name)
            pat = "".join(glob.escape(p) if i % 2 == 0 else "*"
                          for i, p in enumerate(parts))
            return [(pat, True)]
        return [(glob.escape(name or job_id) + " (*)", True)]
    out = []
    for leg in legs:
        if name is not None:
            if leg is not None and uses_matrix:
                def sub(m):
                    ref = MATRIX_REF.match(m.group(1))
                    val = lookup(leg, ref.group(1)) if ref else None
                    return m.group(0) if val is None else render(val)
                out.append((EXPR.sub(sub, name), False))
                continue
            base = name
        else:
            base = job_id
        if leg is None:
            out.append((base, False))
            continue
        vals = [render(v) for v in leg.values()
                if not isinstance(v, (dict, list)) and render(v) != ""]
        out.append((f"{base} ({', '.join(vals)})" if vals else base, False))
    return out


def triggers(doc):
    """The workflow's `on:` as a dict, or None."""
    on = doc.get("on", doc.get(True))    # PyYAML reads a bare `on` as True
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return on if isinstance(on, dict) else None


def pr_trigger(on):
    """(runs_on_pull_requests_into_main, reason)"""
    if on is None:
        return False, "no trigger"
    if "pull_request" not in on:
        return False, "no pull_request trigger"
    pr = on["pull_request"] or {}
    for key in ("paths", "paths-ignore"):
        if key in pr:
            return False, f"pull_request trigger is filtered by `{key}`"
    branches = pr.get("branches")
    if branches is not None and not any(fnmatchcase("main", b)
                                        for b in branches):
        return False, "pull_request trigger excludes main"
    if "branches-ignore" in pr and any(fnmatchcase("main", b)
                                       for b in pr["branches-ignore"]):
        return False, "pull_request trigger ignores main"
    return True, ""


def group_trigger(on):
    """(runs_on_merge_group_into_main, reason) — the merge queue (#657)."""
    if on is None or "merge_group" not in on:
        return False, ("no merge_group trigger, so merge-queue runs never "
                       "report it")
    mg = on["merge_group"] or {}
    if not isinstance(mg, dict):
        return True, ""
    types = mg.get("types")
    if types is not None and "checks_requested" not in types:
        return False, "merge_group trigger omits `checks_requested`"
    branches = mg.get("branches")
    if branches is not None and not any(fnmatchcase("main", b)
                                        for b in branches):
        return False, "merge_group trigger excludes main"
    if "branches-ignore" in mg and any(fnmatchcase("main", b)
                                       for b in mg["branches-ignore"]):
        return False, "merge_group trigger ignores main"
    return True, ""


def off_group_if(cond):
    """Why a job-level `if:` keeps the job off merge-group runs, or ''."""
    names_group = "merge_group" in cond
    if PR_ONLY_VALUE.search(cond) and not names_group:
        return "reads a value only pull requests carry"
    for op, event in EVENT_PIN.findall(cond):
        if op == "!=" and event == "merge_group":
            return "excludes merge_group"
        if op == "==" and event != "merge_group" and not names_group:
            return f"pins event_name to '{event}'"
    return ""


# Every check run any workflow job reports: (name, is_glob, where, why_not_pr)
reported = []
files = sorted(glob.glob(os.path.join(workflows_dir, "*.yml"))
               + glob.glob(os.path.join(workflows_dir, "*.yaml")))
if not files:
    print(f"check-required-checks: no workflow under {workflows_dir}",
          file=sys.stderr)
    sys.exit(2)
for path in files:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        print(f"check-required-checks: cannot parse {path}: {exc}",
              file=sys.stderr)
        sys.exit(2)
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        continue
    on = triggers(doc)
    on_pr, why = pr_trigger(on)
    if on_pr:
        on_pr, why = group_trigger(on)
    wf = os.path.basename(path)
    for job_id, job in doc["jobs"].items():
        if not isinstance(job, dict):
            continue
        job_why = why
        cond = str(job.get("if", ""))
        if on_pr and NON_PR_IF.search(cond):
            job_why = f"job `if:` keeps it off pull requests ({cond})"
        elif on_pr and off_group_if(cond):
            job_why = (f"job `if:` keeps it off merge-group runs: "
                       f"{off_group_if(cond)} ({cond})")
        elif (on_pr and cond and (job.get("strategy") or {}).get("matrix")
              is not None and not NEVER_SKIPS_IF.match(cond)):
            job_why = (f"matrix job has a job-level `if:` that can skip it "
                       f"({cond}); a skipped matrix job reports only its "
                       f"bare name, so its legs never report — skip the "
                       f"steps instead")
        for cname, is_glob in check_names(str(job_id), job):
            reported.append((cname, is_glob, f"{wf}:{job_id}", job_why))


def resolve(ctx):
    # An exact name wins over a run-time-matrix glob: `harness-gate` must
    # resolve to its own job, not hide behind `harness-*`.
    hits = [r for r in reported if not r[1] and ctx == r[0]]
    if not hits:
        hits = [r for r in reported if r[1] and fnmatchcase(ctx, r[0])]
    if not hits:
        return False, "names no workflow job"
    pr_hits = [r for r in hits if not r[3]]
    if pr_hits:
        return True, ", ".join(sorted({r[2] for r in pr_hits}))
    return False, "; ".join(sorted({f"{r[2]}: {r[3]}" for r in hits}))


def check(label, items):
    bad = 0
    seen = set()
    for ctx in items:
        if ctx in seen:
            print(f"  FAIL {label}: duplicate context {ctx!r}")
            bad += 1
            continue
        seen.add(ctx)
        ok, detail = resolve(ctx)
        if ok:
            print(f"  ok   {ctx}  <- {detail}")
        else:
            print(f"  FAIL {label}: {ctx!r} {detail}")
            bad += 1
    return bad


committed = read_list(contexts_path)
print(f"=== required contexts ({len(committed)}) in {contexts_path} ===")
if not committed:
    print("  FAIL committed list is empty")
    sys.exit(1)
failures = check("committed", committed)

if live_path:
    live = read_list(live_path)
    print(f"=== live required contexts ({len(live)}) on main ===")
    failures += check("live", live)
    missing = [c for c in committed if c not in live]
    extra = [c for c in live if c not in committed]
    for c in missing:
        print(f"  drift: committed but not yet required: {c}")
    for c in extra:
        print(f"  drift: required but not committed: {c}")
    if not missing and not extra:
        print("  live protection matches the committed list")

if failures:
    print(f"Result: FAIL ({failures} context(s) no pull-request and "
          f"merge-group job reports)")
    sys.exit(1)
print("Result: PASS (every required context names a job that reports on "
      "pull requests and merge-group runs)")
PY
