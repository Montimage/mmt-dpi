#!/usr/bin/env python3
"""check-resource-budgets.py -- CI gate over the resource_bounds results
(issue #395, M4; consumes the issue #394 results.json).

tests/resource_bounds/run_tests.sh writes results.json from the fixtures'
"@rb" lines and its own budget evaluation. This gate does not trust that
evaluation: it

  1. validates budgets.json (every check names a known op and a usable
     limit -- an integer `limit`, a `limit_metric`, or non-empty `parts`
     for "sum"), reporting the offending field instead of a later
     "missing metric";
  2. validates results.json against results.schema.json;
  3. requires every budgeted fixture (resource dimension) to have run, with
     exit status 0, its workload record and a non-empty metric set
     (--partial accepts a subset, for single-fixture runner invocations);
  4. re-evaluates every budget from the recorded metrics and fails on a
     breach, a missing metric, or a runner check that is missing, extra or
     disagrees with the re-evaluation;
  5. fails on any runner-reported error and on an inconsistent summary.

Budgets are deterministic counts and bytes. The optional `observations`
block (platform, per-fixture wall-clock) is printed labelled as an
observation and is never compared against anything: a budget can only
resolve against `metrics`.

Usage:
  check-resource-budgets.py [--budgets PATH] [--schema PATH] [--partial] RESULTS
  check-resource-budgets.py --self-test
Exit: 0 = every budget holds, 1 = gate failed, 2 = usage or I/O error.
"""

import argparse
import copy
import json
import os
import re
import sys

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SELF_DIR, "..", ".."))
RB_DIR = os.path.join(REPO_ROOT, "tests", "resource_bounds")
DEFAULT_BUDGETS = os.path.join(RB_DIR, "budgets.json")
DEFAULT_SCHEMA = os.path.join(RB_DIR, "results.schema.json")

BUDGETS_SCHEMA_ID = "mmt-dpi/resource-bounds-budgets/v1"
OPS = ("eq", "le", "lt", "sum")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ---- minimal JSON Schema validator (the subset results.schema.json uses) ----

def _type_ok(value, t):
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "integer":
        return is_int(value)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "null":
        return value is None
    raise ValueError("unsupported schema type %r" % t)


def schema_errors(value, schema, path="$"):
    errs = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, t) for t in types):
            return ["%s: expected %s, got %s" % (path, "|".join(types), json.dumps(value))]
    if "const" in schema and value != schema["const"]:
        errs.append("%s: must be %s" % (path, json.dumps(schema["const"])))
    if "enum" in schema and value not in schema["enum"]:
        errs.append("%s: %s not in %s" % (path, json.dumps(value), schema["enum"]))
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        errs.append("%s: %r does not match %s" % (path, value, schema["pattern"]))
    if "minimum" in schema and is_int(value) and value < schema["minimum"]:
        errs.append("%s: %d below minimum %d" % (path, value, schema["minimum"]))
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errs.append("%s: missing required property %r" % (path, key))
        extra = schema.get("additionalProperties", True)
        for key, sub in value.items():
            sub_path = "%s.%s" % (path, key)
            if key in props:
                errs += schema_errors(sub, props[key], sub_path)
            elif extra is False:
                errs.append("%s: unexpected property" % sub_path)
            elif isinstance(extra, dict):
                errs += schema_errors(sub, extra, sub_path)
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errs += schema_errors(item, schema["items"], "%s[%d]" % (path, i))
    return errs


# ---- budgets.json -----------------------------------------------------------

def budget_errors(budgets):
    """Structural errors in budgets.json, naming the offending check."""
    if not isinstance(budgets, dict) or budgets.get("schema") != BUDGETS_SCHEMA_ID:
        return ["budgets: schema must be %r" % BUDGETS_SCHEMA_ID]
    fixtures = budgets.get("fixtures")
    if not isinstance(fixtures, dict) or not fixtures:
        return ["budgets: 'fixtures' must be a non-empty object"]
    errs = []
    for fx, spec in fixtures.items():
        checks = spec.get("checks") if isinstance(spec, dict) else None
        if not isinstance(checks, list) or not checks:
            errs.append("budget %s: no checks" % fx)
            continue
        seen = set()
        for i, c in enumerate(checks):
            where = "budget %s/%s" % (fx, c.get("id", "#%d" % i) if isinstance(c, dict) else "#%d" % i)
            if not isinstance(c, dict):
                errs.append("%s: check must be an object" % where)
                continue
            if not isinstance(c.get("id"), str) or not c["id"]:
                errs.append("%s: missing 'id'" % where)
            elif c["id"] in seen:
                errs.append("%s: duplicate id" % where)
            else:
                seen.add(c["id"])
            if not isinstance(c.get("metric"), str) or not c["metric"]:
                errs.append("%s: missing 'metric'" % where)
            op = c.get("op")
            if op not in OPS:
                errs.append("%s: unknown op %s (known: %s)" % (where, json.dumps(op), ", ".join(OPS)))
                continue
            if op == "sum":
                parts = c.get("parts")
                if (not isinstance(parts, list) or not parts
                        or not all(isinstance(p, str) and p for p in parts)):
                    errs.append("%s: op 'sum' needs a non-empty 'parts' list of metric names" % where)
                continue
            has_limit, has_lm = "limit" in c, "limit_metric" in c
            if not has_limit and not has_lm:
                errs.append("%s: has neither 'limit' nor 'limit_metric'" % where)
            elif has_limit and has_lm:
                errs.append("%s: has both 'limit' and 'limit_metric'" % where)
            elif has_limit and not is_int(c["limit"]):
                errs.append("%s: 'limit' must be an integer, got %s" % (where, json.dumps(c["limit"])))
            elif has_lm and (not isinstance(c["limit_metric"], str) or not c["limit_metric"]):
                errs.append("%s: 'limit_metric' must be a metric name" % where)
            if "factor" in c and (not is_int(c["factor"]) or c["factor"] <= 0):
                errs.append("%s: 'factor' must be a positive integer, got %s" % (where, json.dumps(c["factor"])))
            if "factor" in c and not has_lm:
                errs.append("%s: 'factor' needs 'limit_metric'" % where)
    return errs


def evaluate(check, metrics):
    """(value, limit, pass, error) for one budget over a fixture's metrics."""
    value = metrics.get(check["metric"])
    if check["op"] == "sum":
        missing = [p for p in check["parts"] if p not in metrics]
        limit = None if missing else sum(metrics[p] for p in check["parts"])
        missing_names = missing
    elif "limit_metric" in check:
        lm = metrics.get(check["limit_metric"])
        limit = None if lm is None else lm * check.get("factor", 1)
        missing_names = [] if lm is not None else [check["limit_metric"]]
    else:
        limit = check["limit"]
        missing_names = []
    if value is None:
        missing_names = [check["metric"]] + missing_names
    if missing_names:
        return value, limit, False, "missing metric %s" % ", ".join(missing_names)
    ok = {"eq": value == limit, "sum": value == limit,
          "le": value <= limit, "lt": value < limit}[check["op"]]
    return value, limit, ok, None


# ---- the gate ---------------------------------------------------------------

def gate(results, budgets, schema, partial=False):
    """Return (failures, report_lines)."""
    fails = budget_errors(budgets)
    if fails:
        return fails, []
    fails = ["results.json %s" % e for e in schema_errors(results, schema)]
    if fails:
        return fails, []

    report = []
    bfx = budgets["fixtures"]
    ran = results["fixtures"]
    for fx in sorted(set(ran) - set(bfx)):
        fails.append("fixture %s: in results.json but has no budgets" % fx)
    not_run = sorted(set(bfx) - set(ran))
    if not_run and not partial:
        fails += ["fixture %s: resource dimension not run (no results record)" % fx for fx in not_run]
    if partial and not ran:
        fails.append("results.json: no fixture ran")

    runner = {}
    for c in results["checks"]:
        key = (c["fixture"], c["id"])
        if key in runner:
            fails.append("check %s/%s: reported twice by the runner" % key)
        runner[key] = c

    expected = set()
    for fx in sorted(set(ran) & set(bfx)):
        rec, spec = ran[fx], bfx[fx]
        if rec["exit_status"] != 0:
            fails.append("fixture %s: exited %d (in-fixture checks failed)" % (fx, rec["exit_status"]))
        if not isinstance(rec["workload"], str) or not rec["workload"]:
            fails.append("fixture %s: missing workload record" % fx)
        elif rec["workload"] != spec.get("workload"):
            fails.append("fixture %s: workload record differs from budgets.json" % fx)
        if rec["issue"] != spec.get("issue") or rec["finding"] != spec.get("finding"):
            fails.append("fixture %s: issue/finding differ from budgets.json" % fx)
        if not rec["metrics"]:
            fails.append("fixture %s: no metrics recorded" % fx)
        # The workload record the fixture itself emits: its fixed seeds
        # (the description above is copied from budgets.json by the runner).
        if not rec["seeds"]:
            fails.append("fixture %s: no seed recorded (workload record missing)" % fx)
        held = 0
        for check in spec["checks"]:
            key = (fx, check["id"])
            expected.add(key)
            value, limit, ok, err = evaluate(check, rec["metrics"])
            if err:
                fails.append("budget %s/%s: %s" % (fx, check["id"], err))
            elif not ok:
                fails.append("budget %s/%s: %s = %d breaks %s %d"
                             % (fx, check["id"], check["metric"], value, check["op"], limit))
            else:
                held += 1
            r = runner.get(key)
            if r is None:
                fails.append("check %s/%s: not evaluated by the runner" % key)
            elif r["pass"] != ok or r["value"] != value or r["limit"] != limit:
                fails.append("check %s/%s: runner reported pass=%s value=%s limit=%s, re-evaluated pass=%s value=%s limit=%s"
                             % (fx, check["id"], r["pass"], r["value"], r["limit"], ok, value, limit))
        report.append("  %s: %d/%d budgets hold (%d counters, %d seed(s))"
                      % (fx, held, len(spec["checks"]), len(rec["metrics"]), len(rec["seeds"])))
    budgeted = {(fx, c["id"]) for fx, spec in bfx.items() for c in spec["checks"]}
    for key in sorted(set(runner) - expected):
        if key in budgeted:
            fails.append("check %s/%s: reported by the runner but fixture %s has no results record"
                         % (key[0], key[1], key[0]))
        else:
            fails.append("check %s/%s: reported by the runner but not in budgets.json" % key)

    fails += ["runner error: %s" % e for e in results["errors"]]
    s = results["summary"]
    real = {"fixtures": len(ran),
            "failed_fixtures": sum(1 for r in ran.values() if r["exit_status"] != 0),
            "checks": len(results["checks"]),
            "failed_checks": sum(1 for c in results["checks"] if not c["pass"])}
    for k, v in real.items():
        if s[k] != v:
            fails.append("summary.%s = %d, results.json holds %d" % (k, s[k], v))
    if not s["pass"]:
        fails.append("summary.pass is false")

    obs = results.get("observations")
    if obs:
        walls = ", ".join("%s %d ms" % (k, v) for k, v in sorted(obs.get("wall_ms", {}).items()))
        report.append("  observation (not a budget, never compared): platform %s%s"
                      % (obs.get("platform", "?"), "; wall-clock " + walls if walls else ""))
    return fails, report


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        print("✗ cannot read %s: %s" % (path, exc), file=sys.stderr)
        sys.exit(2)


# ---- self-test --------------------------------------------------------------

def _runner_results(budgets, metrics, workloads=None):
    """A results.json as run_tests.sh writes it, for synthetic metrics."""
    checks, fixtures = [], {}
    for fx, spec in budgets["fixtures"].items():
        m = metrics[fx]
        fixtures[fx] = {"issue": spec["issue"], "finding": spec["finding"],
                        "workload": (workloads or {}).get(fx, spec["workload"]),
                        "exit_status": 0, "seeds": {"seed": "0x" + "0" * 15 + "1"},
                        "metrics": dict(m)}
        for c in spec["checks"]:
            value, limit, ok, err = evaluate(c, m)
            entry = {"fixture": fx, "id": c["id"], "metric": c["metric"], "op": c["op"],
                     "value": value, "limit": limit, "baseline": c.get("baseline"), "pass": ok}
            if err:
                entry["error"] = "missing metric"
            checks.append(entry)
    failed = sum(1 for c in checks if not c["pass"])
    return {"schema": "mmt-dpi/resource-bounds-result/v1",
            "budgets": "tests/resource_bounds/budgets.json", "timing_asserted": False,
            "fixtures": fixtures, "checks": checks, "errors": [],
            "summary": {"fixtures": len(fixtures), "failed_fixtures": 0,
                        "checks": len(checks), "failed_checks": failed, "pass": failed == 0},
            "observations": {"platform": "x86_64", "wall_ms": {"mem": 12, "cpu": 7}}}


def self_test():
    schema = load_json(DEFAULT_SCHEMA)
    budgets = {
        "schema": BUDGETS_SCHEMA_ID,
        "fixtures": {
            "mem": {"issue": 1, "finding": "F-1", "workload": "fill to exhaustion",
                    "checks": [
                        {"id": "reserved", "metric": "reserved_bytes", "op": "le", "limit": 4096},
                        {"id": "accounted", "metric": "offers", "op": "sum", "parts": ["accepted", "refused"]},
                        {"id": "checks", "metric": "checks.failed", "op": "eq", "limit": 0}]},
            "cpu": {"issue": 2, "finding": "F-2", "workload": "adversarial inserts",
                    "checks": [
                        {"id": "visits", "metric": "visits", "op": "lt", "limit": 1000},
                        {"id": "growth", "metric": "large.visits", "op": "le", "factor": 24,
                         "limit_metric": "small.visits"}]},
        },
    }
    metrics = {"mem": {"reserved_bytes": 4096, "offers": 10, "accepted": 7, "refused": 3,
                       "checks.failed": 0},
               "cpu": {"visits": 999, "small.visits": 100, "large.visits": 2400}}
    base = _runner_results(budgets, metrics)
    results = {"pass": 0, "fail": 0}

    def case(name, res, bud=None, partial=False, expect=None):
        fails, _ = gate(res, bud or budgets, schema, partial)
        ok = (not fails) if expect is None else any(expect in f for f in fails)
        results["pass" if ok else "fail"] += 1
        print("  %s %s%s" % ("✓" if ok else "✗", name,
                            "" if ok else " -- got %s" % (fails or "no failure")))

    def mutated(fn, bud=None):
        # Re-derive the runner's view from mutated metrics, as run_tests.sh would.
        m = copy.deepcopy(metrics)
        fn(m)
        return _runner_results(bud or budgets, m)

    def edited(fn):
        r = copy.deepcopy(base)
        fn(r)
        return r

    def bud_edit(fn):
        b = copy.deepcopy(budgets)
        fn(b)
        return b

    case("in-budget results pass (limits are inclusive where op allows)", base)
    case("observations are reported but never compared", edited(
        lambda r: r["observations"]["wall_ms"].update(mem=10 ** 9)))
    case("over-budget le fails", mutated(lambda m: m["mem"].update(reserved_bytes=4097)),
         expect="budget mem/reserved: reserved_bytes = 4097 breaks le 4096")
    case("over-budget lt at the limit fails", mutated(lambda m: m["cpu"].update(visits=1000)),
         expect="budget cpu/visits: visits = 1000 breaks lt 1000")
    case("eq breach fails", mutated(lambda m: m["mem"].update({"checks.failed": 1})),
         expect="budget mem/checks")
    case("unaccounted refusal fails", mutated(lambda m: m["mem"].update(refused=2)),
         expect="budget mem/accounted: offers = 10 breaks sum 9")
    case("factor-scaled growth breach fails", mutated(lambda m: m["cpu"].update({"large.visits": 2401})),
         expect="budget cpu/growth")
    case("missing metric fails", mutated(lambda m: m["mem"].pop("reserved_bytes")),
         expect="budget mem/reserved: missing metric reserved_bytes")
    case("missing limit_metric fails", mutated(lambda m: m["cpu"].pop("small.visits")),
         expect="budget cpu/growth: missing metric small.visits")
    case("missing sum part fails", mutated(lambda m: m["mem"].pop("refused")),
         expect="budget mem/accounted: missing metric refused")
    case("budget on a timing observation fails (not a metric)", base,
         bud=bud_edit(lambda b: b["fixtures"]["cpu"]["checks"].append(
             {"id": "wall", "metric": "wall_ms", "op": "le", "limit": 100})),
         expect="budget cpu/wall: missing metric wall_ms")
    case("unrun resource dimension fails", edited(lambda r: r["fixtures"].pop("cpu")),
         expect="fixture cpu: resource dimension not run")
    case("checks of an unrun fixture name the missing record (issue #433)",
         edited(lambda r: r["fixtures"].pop("cpu")),
         expect="check cpu/visits: reported by the runner but fixture cpu has no results record")
    single = _runner_results({"schema": BUDGETS_SCHEMA_ID,
                              "fixtures": {"mem": budgets["fixtures"]["mem"]}}, metrics)
    case("--partial accepts a single-fixture run", single, partial=True)
    case("missing workload record fails", edited(lambda r: r["fixtures"]["mem"].update(workload=None)),
         expect="fixture mem: missing workload record")
    case("missing seed (fixture-emitted workload record) fails",
         edited(lambda r: r["fixtures"]["mem"].update(seeds={})),
         expect="fixture mem: no seed recorded")
    case("empty metric record fails", edited(lambda r: r["fixtures"]["cpu"].update(metrics={})),
         expect="fixture cpu: no metrics recorded")
    case("failed fixture exit status fails", edited(lambda r: r["fixtures"]["mem"].update(exit_status=1)),
         expect="fixture mem: exited 1")
    case("runner claiming pass on a breach fails", edited(
        lambda r: r["fixtures"]["mem"]["metrics"].update(reserved_bytes=5000)),
         expect="budget mem/reserved: reserved_bytes = 5000 breaks le 4096")
    case("runner check missing fails", edited(lambda r: r["checks"].pop(0)),
         expect="check mem/reserved: not evaluated by the runner")
    case("runner check not in budgets fails", edited(lambda r: r["checks"].append(
        dict(r["checks"][0], id="ghost"))), expect="check mem/ghost: reported by the runner")
    case("runner error fails", edited(lambda r: r["errors"].append("duplicate key: mem metric x")),
         expect="runner error: duplicate key")
    case("inconsistent summary fails", edited(lambda r: r["summary"].update(failed_checks=0, checks=1)),
         expect="summary.checks = 1")
    case("results schema: timing_asserted must stay false",
         edited(lambda r: r.update(timing_asserted=True)), expect="$.timing_asserted")
    case("results schema: non-integer metric fails",
         edited(lambda r: r["fixtures"]["mem"]["metrics"].update(reserved_bytes="12")),
         expect="$.fixtures.mem.metrics.reserved_bytes")
    case("results schema: unknown top-level key fails",
         edited(lambda r: r.update(timings={})), expect="$.timings: unexpected property")
    case("budget without limit names the field", base,
         bud=bud_edit(lambda b: b["fixtures"]["mem"]["checks"][0].pop("limit")),
         expect="budget mem/reserved: has neither 'limit' nor 'limit_metric'")
    case("string limit names the field", base,
         bud=bud_edit(lambda b: b["fixtures"]["mem"]["checks"][0].update(limit="4096")),
         expect="budget mem/reserved: 'limit' must be an integer, got \"4096\"")
    case("unknown op names the field", base,
         bud=bud_edit(lambda b: b["fixtures"]["cpu"]["checks"][0].update(op="ge")),
         expect="budget cpu/visits: unknown op \"ge\"")
    case("sum without parts names the field", base,
         bud=bud_edit(lambda b: b["fixtures"]["mem"]["checks"][1].pop("parts")),
         expect="budget mem/accounted: op 'sum' needs a non-empty 'parts'")

    committed = budget_errors(load_json(DEFAULT_BUDGETS))
    ok = not committed
    results["pass" if ok else "fail"] += 1
    print("  %s committed budgets.json is well-formed%s"
          % ("✓" if ok else "✗", "" if ok else " -- %s" % committed))

    total = results["pass"] + results["fail"]
    if results["fail"]:
        print("✗ check-resource-budgets self-test: %d/%d failed" % (results["fail"], total))
        return 1
    print("✓ check-resource-budgets self-test: %d/%d passed" % (total, total))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("results", nargs="?", help="results.json written by tests/resource_bounds/run_tests.sh")
    ap.add_argument("--budgets", default=DEFAULT_BUDGETS)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--partial", action="store_true",
                    help="accept a run of a subset of the budgeted fixtures")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.results:
        ap.error("RESULTS is required (or --self-test)")
    fails, report = gate(load_json(args.results), load_json(args.budgets),
                         load_json(args.schema), args.partial)
    for line in report:
        print(line)
    for f in fails:
        print("  ✗ %s" % f, file=sys.stderr)
    if fails:
        print("✗ resource budgets: %d failure(s) in %s" % (len(fails), args.results), file=sys.stderr)
        return 1
    print("✓ resource budgets: every budget holds (%s)" % os.path.relpath(args.results, REPO_ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
