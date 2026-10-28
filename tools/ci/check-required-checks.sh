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
# Queue-only jobs (issue #658): a job that skips on pull requests and runs in
# the merge queue — a job- or step-level `if:` that tests
# `github.event_name != 'pull_request'` — in a workflow that runs on every
# pull request into main (no path filter) is gated only if the queue waits
# for it. So its workflow needs a `merge_group` trigger, and the job must
# report a context of the committed list, or be in the `needs` of a job that
# does (an aggregate). Path-filtered workflows (install-smoke, bootstrap-smoke)
# are not checked: their jobs never gate a pull request.
#
# Retired contexts (issue #659): .github/retired-checks.txt, same format, lists
# contexts folded into other jobs that protection may still require. Each must
# be reported by a stub — a job whose job-level `if:` is `false`, which skips
# and so reports success on every event — on pull requests and merge-group
# runs, and must not also be in the committed list.
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
#                                          [--retired FILE] [--live OWNER/REPO]
#     --contexts FILE   context list (default .github/required-checks.txt)
#     --retired FILE    retired contexts (default retired-checks.txt beside
#                       the context list; optional when that default is absent)
#     --workflows DIR   workflow directory (default .github/workflows)
#     --live REPO       also read the contexts branch protection on main
#                       requires now (read-only `gh api` GET; needs a token
#                       with admin read access, so not run in CI), fail on a
#                       live context that names no pull-request job or on a
#                       queue-only job's context that is not live-required,
#                       report the drift between the live and committed lists,
#                       and list the retired contexts protection still requires
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
RETIRED=""

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --contexts)  CONTEXTS="${2:?--contexts needs a file}"; shift 2 ;;
        --workflows) WORKFLOWS="${2:?--workflows needs a directory}"; shift 2 ;;
        --retired)   RETIRED="${2:?--retired needs a file}"; shift 2 ;;
        --live)      LIVE_REPO="${2:?--live needs OWNER/REPO}"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "check-required-checks: unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -f "$CONTEXTS" ]  || { echo "check-required-checks: no context list: $CONTEXTS" >&2; exit 2; }
[ -d "$WORKFLOWS" ] || { echo "check-required-checks: no workflow directory: $WORKFLOWS" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "check-required-checks: python3 not found" >&2; exit 2; }
if [ -z "$RETIRED" ]; then
    RETIRED="$(dirname "$CONTEXTS")/retired-checks.txt"
    [ -f "$RETIRED" ] || RETIRED=""
elif [ ! -f "$RETIRED" ]; then
    echo "check-required-checks: no retired list: $RETIRED" >&2; exit 2
fi

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

python3 - "$CONTEXTS" "$WORKFLOWS" "$LIVE_FILE" "$RETIRED" <<'PY'
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

contexts_path, workflows_dir, live_path, retired_path = sys.argv[1:5]
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
# An `if:` that skips on pull requests: the job (or step) runs in the queue.
OFF_PR_IF = re.compile(r"github\.event_name\s*!=\s*'pull_request'")
# A stub's job-level `if:` (PyYAML reads a bare `false` as the boolean).
STUB_IF = re.compile(r"^\s*(?:\$\{\{\s*)?false(?:\s*\}\})?\s*$")


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


# Every check run any workflow job reports:
# (name, is_glob, where, why_not_pr, is_stub)
reported = []
# Every job of a workflow that runs on every pull request into main, for the
# queue-only rule: dicts with wf, job_id, names, off_pr, group, needs.
pr_jobs = []
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
    always_on_pr, why = pr_trigger(on)
    on_pr = always_on_pr
    on_group, group_why = group_trigger(on)
    if on_pr and not on_group:
        on_pr, why = False, group_why
    wf = os.path.basename(path)
    for job_id, job in doc["jobs"].items():
        if not isinstance(job, dict):
            continue
        job_why = why
        raw_if = job.get("if", "")
        stub = raw_if is False or (isinstance(raw_if, str)
                                   and bool(STUB_IF.match(raw_if)))
        cond = "" if stub else str(raw_if)
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
        names = check_names(str(job_id), job)
        for cname, is_glob in names:
            reported.append((cname, is_glob, f"{wf}:{job_id}", job_why, stub))
        if always_on_pr:
            step_ifs = [str(st.get("if", "")) for st in job.get("steps") or []
                        if isinstance(st, dict)]
            needs = job.get("needs") or []
            pr_jobs.append({
                "wf": wf, "job_id": str(job_id), "names": names,
                "off_pr": any(OFF_PR_IF.search(c) for c in [cond] + step_ifs),
                "group": on_group,
                "needs": [needs] if isinstance(needs, str) else list(needs)})


def resolve(ctx, stubs):
    """(ok, detail). stubs=False: a real job must report ctx; True: a stub."""
    # An exact name wins over a run-time-matrix glob: `harness-gate` must
    # resolve to its own job, not hide behind `harness-*`.
    hits = [r for r in reported if not r[1] and ctx == r[0]]
    if not hits:
        hits = [r for r in reported if r[1] and fnmatchcase(ctx, r[0])]
    if not hits:
        return False, "names no workflow job"
    pr_hits = [r for r in hits if not r[3]]
    if not pr_hits:
        return False, "; ".join(sorted({f"{r[2]}: {r[3]}" for r in hits}))
    kind = [r for r in pr_hits if r[4] == stubs]
    if not kind:
        where = ", ".join(sorted({r[2] for r in pr_hits}))
        if stubs:
            return False, (f"is retired but its job is not a stub with "
                           f"`if: false` ({where})")
        return False, (f"names only a retired stub (`if: false`, {where}), "
                       f"which never runs — list it in the retired file")
    return True, ", ".join(sorted({r[2] for r in kind}))


def check(label, items, stubs=False):
    bad = 0
    seen = set()
    for ctx in items:
        if ctx in seen:
            print(f"  FAIL {label}: duplicate context {ctx!r}")
            bad += 1
            continue
        seen.add(ctx)
        ok, detail = resolve(ctx, stubs)
        if ok:
            print(f"  ok   {ctx}  <- {detail}")
        else:
            print(f"  FAIL {label}: {ctx!r} {detail}")
            bad += 1
    return bad


def matches_ctx(names, ctx):
    return any((fnmatchcase(ctx, n) if g else ctx == n) for n, g in names)


committed = read_list(contexts_path)
print(f"=== required contexts ({len(committed)}) in {contexts_path} ===")
if not committed:
    print("  FAIL committed list is empty")
    sys.exit(1)
failures = check("committed", committed)

retired = read_list(retired_path) if retired_path else []
if retired_path:
    print(f"=== retired contexts ({len(retired)}) in {retired_path} ===")
    for ctx in retired:
        if ctx in committed:
            print(f"  FAIL retired: {ctx!r} is also in the committed list")
            failures += 1
    failures += check("retired", retired, stubs=True)

# Queue-only jobs (issue #658): skipped on pull requests, so only a required
# context the merge queue waits for gates them.
print("=== queue-only jobs (skipped on pull requests) ===")
queue_ctx = {}       # governing required context -> [wf:job]
n_queue = 0
for j in pr_jobs:
    if not j["off_pr"]:
        continue
    n_queue += 1
    where = f"{j['wf']}:{j['job_id']}"
    if not j["group"]:
        print(f"  FAIL queue-only: {where} skips on pull requests, but its "
              f"workflow has no merge_group trigger, so nothing runs it "
              f"before merge")
        failures += 1
        continue
    gov = []
    for k in pr_jobs:
        if k["wf"] == j["wf"] and j["job_id"] in k["needs"]:
            gov += [c for c in committed if matches_ctx(k["names"], c)]
    if not gov:
        # Gated by its own contexts: every one of them — each matrix leg —
        # must be required, since any leg may be the one that skips.
        ungated = [n for n, g in j["names"]
                   if not any((fnmatchcase(c, n) if g else c == n)
                              for c in committed)]
        if ungated:
            print(f"  FAIL queue-only: {where} skips on pull requests, and "
                  f"no required context reports {', '.join(map(repr, ungated))}"
                  f" or needs the job, so the merge queue would not wait for it")
            failures += 1
            continue
        gov = [c for c in committed if matches_ctx(j["names"], c)]
    if not gov:
        print(f"  FAIL queue-only: {where} skips on pull requests, and no "
              f"required context reports it or needs it, so the merge queue "
              f"would not wait for it")
        failures += 1
        continue
    for c in gov:
        queue_ctx.setdefault(c, []).append(where)
    print(f"  ok   {where}  gated by {', '.join(sorted(set(gov)))}")
if not n_queue:
    print("  (none)")

if live_path:
    live = read_list(live_path)
    print(f"=== live required contexts ({len(live)}) on main ===")
    failures += check("live", [c for c in live if c not in retired])
    for c in [c for c in live if c in retired]:
        print(f"  retired: {c} is still required live — a maintainer drops "
              f"it from protection, then its stub is deleted")
    for c in [c for c in retired if c not in live]:
        print(f"  retired: {c} is no longer required live — delete its stub "
              f"and its line in the retired file")
    for c, where in sorted(queue_ctx.items()):
        if c not in live:
            print(f"  FAIL live: {c!r} gates queue-only {', '.join(where)} "
                  f"but is not live-required, so the merge queue does not "
                  f"wait for it")
            failures += 1
    missing = [c for c in committed if c not in live]
    extra = [c for c in live if c not in committed and c not in retired]
    for c in missing:
        print(f"  drift: committed but not yet required: {c}")
    for c in extra:
        print(f"  drift: required but not committed: {c}")
    if not missing and not extra:
        print("  live protection matches the committed list")

if failures:
    print(f"Result: FAIL ({failures} problem(s): a context no pull-request "
          f"and merge-group job reports, or an ungated queue-only job)")
    sys.exit(1)
print("Result: PASS (every required context names a job that reports on "
      "pull requests and merge-group runs)")
PY
