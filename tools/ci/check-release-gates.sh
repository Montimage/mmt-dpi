#!/usr/bin/env bash
#
# check-release-gates.sh — exact-release-SHA prerequisite evidence
# (issue #371, F-CI-001 — plan task 0.2).
#
# Publishing used to depend only on jobs inside the release run itself
# (build matrix, reproducibility, verify-tag): nothing proved the unit,
# sanitizer and golden-classification gates had passed AT the tagged
# commit — a tag could ship a commit whose CI failed, was cancelled, was
# skipped or never ran. This gate closes that hole: before the release
# job runs it requires, for the candidate SHA itself,
#
#   same-run evidence (needs context of the release-gates job):
#     - build            — the distro/arch package matrix, including the
#                          installed-consumer check (issue #374)
#     - reproducibility  — the double-build byte-identity guard (issue #220)
#     - verify-tag       — the tag == declared VERSION guard (issue #220)
#
#   commit evidence (check runs recorded on the candidate SHA by earlier
#   workflow runs — the tag push re-runs c-cpp.yml but those legs are
#   still in flight when this gate executes, so the decisive evidence is
#   the latest COMPLETED run of each required check):
#     - unit-tests                — every matrix leg (name or `name (...)`)
#     - sanitizer-tests           — every matrix leg (ASan + TSan suites)
#     - ASan/UBSan profile compiles — the phase0 SDK sanitizer gate
#     - Golden classification fingerprint unchanged (or its job id
#       `classification-gate` if the display name is ever dropped)
#
# Verdict rules (all fail-closed):
#   - a required check with NO matching check run at the SHA -> not eligible
#   - a check run whose head_sha differs from the candidate -> not eligible
#   - a check name whose latest completed run is not `success`
#     (failure/cancelled/skipped/neutral/timed_out/...) -> not eligible
#   - a check name seen only queued/in_progress -> not eligible
#   - several completed runs of one name: the newest wins, so a green
#     re-run repairs an older failure (and a newer failure voids a pass)
#   - any same-run needs result other than `success` -> not eligible
#
# Usage:
#   check-release-gates.sh [options] <candidate-sha>
#
#   --check-runs FILE   evaluate check-run JSON from FILE instead of the
#                       GitHub API (offline/self-test mode). Accepts the
#                       API shape {"check_runs": [...]}, a bare [...], or
#                       one check-run object per line (NDJSON).
#   --evidence FILE     write the recorded evidence as JSON to FILE
#   --skip-same-run     do not require the NEEDS_RESULT_* env evidence
#                       (local pre-flight of a not-yet-tagged commit)
#
# Env:
#   NEEDS_RESULT_BUILD / NEEDS_RESULT_REPRODUCIBILITY / NEEDS_RESULT_VERIFY_TAG
#                       result (success|failure|cancelled|skipped) of the
#                       same-run prerequisite job — required unless
#                       --skip-same-run is given
#   GH_TOKEN / GITHUB_TOKEN   token for the check-runs API (live mode)
#   GITHUB_REPOSITORY       owner/repo slug (live mode; default: the
#                           `origin` remote)
#   GITHUB_STEP_SUMMARY     when set, the evidence table is also appended
#                           to the job summary
#
# Exit codes: 0 = every required check is green at the candidate SHA,
# 1 = publication not eligible, 2 = helper broken (bad args, missing
# tools, unreadable/malformed evidence).
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

CHECK_RUNS_FILE=""
EVIDENCE_FILE=""
SKIP_SAME_RUN=0
SHA=""

usage() { sed -n '39,63p' "$0"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --check-runs)    CHECK_RUNS_FILE="${2:?--check-runs needs a file}"; shift 2 ;;
        --evidence)      EVIDENCE_FILE="${2:?--evidence needs a file}"; shift 2 ;;
        --skip-same-run) SKIP_SAME_RUN=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        -*)              echo "✗ unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)               if [ -z "$SHA" ]; then SHA="$1"; shift
                         else echo "✗ unexpected argument: $1" >&2; usage >&2; exit 2; fi ;;
    esac
done

case "$SHA" in
    ''|*[!0-9a-fA-F]*) echo "✗ candidate SHA missing or not hex: '$SHA'" >&2
                       exit 2 ;;
esac

# Abbreviated candidates resolve through the local clone: check runs record
# the full 40-char head_sha, so comparing an abbreviated candidate literally
# would condemn every run as wrong-SHA (fail-closed, but misleading). The
# release-gates job always passes a full SHA (`git rev-parse HEAD^{commit}`).
if [ "${#SHA}" -ne 40 ]; then
    resolved="$(git rev-parse --verify --quiet "${SHA}^{commit}" 2>/dev/null || true)"
    if [ "${#resolved}" -eq 40 ]; then
        SHA="$resolved"
    else
        echo "✗ candidate '$SHA' is not a full 40-char commit SHA and does" >&2
        echo "  not resolve in this clone — pass the full commit id" >&2
        exit 2
    fi
fi

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

# --- obtain the check-run evidence ------------------------------------------
if [ -n "$CHECK_RUNS_FILE" ]; then
    [ -f "$CHECK_RUNS_FILE" ] \
        || { echo "✗ check-runs file not found: $CHECK_RUNS_FILE" >&2; exit 2; }
else
    REPO="${GITHUB_REPOSITORY:-}"
    if [ -z "$REPO" ]; then
        REPO="$(git remote get-url origin 2>/dev/null \
            | sed -E 's#^(git@[^:]+:|https?://[^/]+/)([^/]+/[^/]+?)(\.git)?$#\2#')"
    fi
    case "$REPO" in
        */*) ;;
        *) echo "✗ cannot resolve owner/repo (set GITHUB_REPOSITORY)" >&2
           exit 2 ;;
    esac
    command -v gh >/dev/null 2>&1 \
        || { echo "✗ gh CLI is required for live mode (or use --check-runs)" >&2
             exit 2; }
    if [ -z "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
        echo "✗ GH_TOKEN/GITHUB_TOKEN is required for live mode" >&2
        exit 2
    fi
    CHECK_RUNS_FILE="$(mktemp)"
    trap 'rm -f "$CHECK_RUNS_FILE"' EXIT
    # --paginate follows the Link headers (100/page); --jq emits one check-run
    # object per line, which the evaluator reads as NDJSON.
    if ! gh api --paginate \
            "repos/${REPO}/commits/${SHA}/check-runs?per_page=100" \
            --jq '.check_runs[]' > "$CHECK_RUNS_FILE"; then
        echo "✗ check-runs API query failed for ${REPO}@${SHA}" >&2
        exit 2
    fi
fi

export GATE_SHA="$SHA" \
       GATE_SKIP_SAME_RUN="$SKIP_SAME_RUN" \
       GATE_EVIDENCE_FILE="$EVIDENCE_FILE"

python3 - "$CHECK_RUNS_FILE" <<'PYEOF'
import json
import os
import sys

path = sys.argv[1]
sha = os.environ["GATE_SHA"].lower()
skip_same_run = os.environ.get("GATE_SKIP_SAME_RUN") == "1"
evidence_file = os.environ.get("GATE_EVIDENCE_FILE") or ""

raw = open(path, encoding="utf-8").read().strip()
try:
    doc = json.loads(raw) if raw else {"check_runs": []}
except json.JSONDecodeError:
    # NDJSON: one check-run object per line (gh api --paginate --jq output).
    try:
        doc = {"check_runs": [json.loads(l) for l in raw.splitlines()
                              if l.strip()]}
    except json.JSONDecodeError as e:
        print(f"✗ check-run evidence is neither JSON nor NDJSON: {e}",
              file=sys.stderr)
        sys.exit(2)

if isinstance(doc, dict) and "check_runs" in doc:
    runs = doc["check_runs"]
elif isinstance(doc, dict) and "name" in doc and "status" in doc:
    runs = [doc]          # a single-line NDJSON payload is one check run
elif isinstance(doc, list):
    runs = doc
else:
    runs = None
if not isinstance(runs, list) or any(not isinstance(r, dict) for r in runs):
    print("✗ check-run evidence has an unexpected shape "
          "(want {\"check_runs\": [...]}, [...], or NDJSON)", file=sys.stderr)
    sys.exit(2)

# Required commit evidence: group label -> accepted check-run names. A check
# run matches a name when it IS the name or carries a matrix suffix
# `name (...)` — matrix legs are separate check runs and each must pass.
REQUIRED = [
    ("unit tests", ["unit-tests"]),
    ("sanitizer tests", ["sanitizer-tests"]),
    ("sanitizer SDK profile", ["ASan/UBSan profile compiles"]),
    ("golden classification",
     ["Golden classification fingerprint unchanged", "classification-gate"]),
]

# Same-run evidence: env var -> needs-context job the release-gates job must
# see succeed (the package matrix carries the installed-consumer check).
SAME_RUN = [
    ("NEEDS_RESULT_BUILD", "build (package matrix + installed consumer)"),
    ("NEEDS_RESULT_REPRODUCIBILITY", "reproducibility (byte-identity guard)"),
    ("NEEDS_RESULT_VERIFY_TAG", "verify-tag (tag == declared VERSION)"),
]

errors = 0
lines = []          # human-readable evidence table
record = {"sha": sha, "checks": [], "same_run": []}


def fail(msg):
    global errors
    errors += 1
    print(f"  ✗ {msg}")


def emit(msg):
    lines.append(msg)
    print(f"  {msg}")


def matches(name, alt):
    return name == alt or name.startswith(alt + " (")


# --- wrong-SHA evidence is fatal anywhere in the payload ---------------------
for r in runs:
    rsha = r.get("head_sha")
    if isinstance(rsha, str) and rsha.lower() != sha:
        fail(f"wrong-SHA evidence: check run '{r.get('name')}' belongs to "
             f"{rsha[:12]}, not the candidate {sha[:12]}")

# --- commit check-run evidence ----------------------------------------------
for label, alts in REQUIRED:
    matched = {}   # exact check-run name -> list of runs
    for r in runs:
        name = r.get("name") or ""
        if any(matches(name, a) for a in alts):
            matched.setdefault(name, []).append(r)
    if not matched:
        fail(f"{label}: no check-run evidence at {sha[:12]} "
             f"(looked for {', '.join(alts)})")
        continue
    for name, rs in sorted(matched.items()):
        done = [r for r in rs if r.get("status") == "completed"]
        if not done:
            fail(f"{label}: '{name}' has no completed run at {sha[:12]} "
                 f"(queued/in-progress only)")
            continue
        # Newest completed run wins: sort by completed_at, then id — a green
        # re-run repairs an older failure; a newer failure voids a pass.
        latest = max(done, key=lambda r: (r.get("completed_at") or "",
                                          r.get("id") or 0))
        concl = latest.get("conclusion")
        record["checks"].append({
            "group": label, "name": name, "conclusion": concl,
            "completed_at": latest.get("completed_at"),
            "run_id": latest.get("id")})
        if concl == "success":
            emit(f"✓ {label}: {name} = success "
                 f"({(latest.get('completed_at') or '?')})")
        else:
            fail(f"{label}: '{name}' latest completed run = {concl} "
                 f"at {sha[:12]}")

# --- same-run prerequisite evidence ------------------------------------------
if skip_same_run:
    emit("○ same-run prerequisite results not required (--skip-same-run)")
else:
    for env, label in SAME_RUN:
        val = os.environ.get(env)
        record["same_run"].append({"job": env, "result": val})
        if val is None:
            fail(f"same-run evidence missing: {env} unset "
                 f"({label} did not report a result)")
        elif val != "success":
            fail(f"same-run evidence not green: {env}={val} "
                 f"({label})")
        else:
            emit(f"✓ same-run: {label} = success")

# --- verdict -----------------------------------------------------------------
record["eligible"] = (errors == 0)
if evidence_file:
    with open(evidence_file, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.write("\n")

summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    try:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### Release evidence @ `{sha[:12]}`\n\n")
            f.writelines(f"{l}\n" for l in lines)
            f.write(f"\n**{'ELIGIBLE' if not errors else 'NOT ELIGIBLE'}**\n")
    except OSError:
        pass

if errors:
    print(f"✗ {errors} release-gate violation(s): publication not eligible "
          f"at {sha[:12]}", file=sys.stderr)
    sys.exit(1)
print(f"✓ exact-release-SHA evidence green at {sha}: "
      "unit, sanitizer, classification and package-matrix checks all passed")
PYEOF
