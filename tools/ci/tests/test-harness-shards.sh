#!/usr/bin/env bash
# test-harness-shards.sh — self-test for the sharded phase0 harness legs
# (issue #655): tools/phase0/run_all_harnesses.sh's selectors and the
# `harness` matrix of .github/workflows/phase0-baseline.yml that uses them.
#
# (1) Drives the real runner without building anything:
#       - argument validation (bad --group, --shard, --profile: exit 2);
#       - --list with no selector prints every tools/phase0/tests/run_*.sh;
#       - the K/N shards of a selection are disjoint, cover it and differ in
#         size by at most one; the four --group selections cover everything;
#       - --profile coverage --list leaves out the COVERAGE_SKIP harnesses;
#       - --only (issue #656) keeps exactly the named harnesses before
#         --group/--shard, an empty list keeps none, an unknown name is
#         exit 2.
# (2) Runs a copy of the runner on a fixture tests/ directory whose harnesses
#     build no SDK (profile group "none"): a harness added to the directory
#     is picked up by a shard with no other change; a failing harness exits
#     1, is named in verdicts.tsv, in an ::error annotation and in the job
#     summary table, and keeps its own log; MMT_SDK_PREBUILT=1 reaches it.
# (3) Reads phase0-baseline.yml and pins the wiring: no list-harnesses job;
#     the `harness` job has at most 5 legs, each running run_all_harnesses.sh
#     with its matrix `select` and uploading its log directory; the union of
#     the legs' --list output is every harness, each in exactly one leg; and
#     harness-gate needs both `changes` and `harness`; the legs skip on the
#     docs and tooling tiers (gates=false), which harness-gate accepts, and
#     pass --only the `changes` harness list unless full (issue #656).
#
# Part (3) needs python3 with PyYAML: without it, it reports SKIP, unless
# REQUIRE_PYYAML=1 (the verify-helpers job), under which that fails.
#
# Usage: bash tools/ci/tests/test-harness-shards.sh
# Exit: 0 = all checks passed, 1 = at least one failed.
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNNER="${REPO_ROOT}/tools/phase0/run_all_harnesses.sh"
TEST_DIR="${REPO_ROOT}/tools/phase0/tests"

pass=0
fail=0
ok()  { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }

# The fixture runs must not write to a real CI job's summary or log.
unset GITHUB_ACTIONS GITHUB_STEP_SUMMARY

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "== (1) selectors on the real runner (no build)"
for args in "--group foo" "--group" "--group asan,,tsan" "--shard 0/2" \
            "--shard 3/2" "--shard x" "--shard 1/0" "--profile tsan" "--bogus" \
            "--log-dir"; do
    # shellcheck disable=SC2086  # word-split on purpose: one option list
    bash "${RUNNER}" ${args} --list >/dev/null 2>&1
    expect "run_all_harnesses.sh ${args} --list exits 2" "$?" 2
done

find "${TEST_DIR}" -maxdepth 1 -name 'run_*.sh' -printf '%f\n' | sort > "${TMP}/all.txt"
bash "${RUNNER}" --list | awk '{print $2}' | sort > "${TMP}/list.txt"
if [ -s "${TMP}/all.txt" ] && cmp -s "${TMP}/all.txt" "${TMP}/list.txt"; then
    ok "--list with no selector prints all $(wc -l < "${TMP}/all.txt") run_*.sh"
else
    bad "--list with no selector differs from the run_*.sh enumeration"
fi

for n in 2 3; do
    : > "${TMP}/union.txt"
    sizes=()
    for k in $(seq 1 "${n}"); do
        bash "${RUNNER}" --shard "${k}/${n}" --list | awk '{print $2}' > "${TMP}/shard.txt"
        sizes+=("$(wc -l < "${TMP}/shard.txt")")
        cat "${TMP}/shard.txt" >> "${TMP}/union.txt"
    done
    if [ "$(sort "${TMP}/union.txt")" = "$(cat "${TMP}/all.txt")" ]; then
        ok "the ${n} shards of all harnesses are disjoint and cover them"
    else
        bad "the ${n} shards of all harnesses overlap or miss one"
    fi
    spread=$(printf '%s\n' "${sizes[@]}" | sort -n | sed -n '1p;$p' | paste -sd' ' | awk '{print $2 - $1}')
    expect "the ${n} shard sizes (${sizes[*]}) differ by at most one" "$((spread <= 1))" 1
done

: > "${TMP}/union.txt"
groups_ok=1
for g in none default asan tsan; do
    bash "${RUNNER}" --group "${g}" --list > "${TMP}/group.txt"
    awk -v g="${g}" '$1 != g { exit 1 }' "${TMP}/group.txt" || groups_ok=0
    awk '{print $2}' "${TMP}/group.txt" >> "${TMP}/union.txt"
done
expect "--group G lists only group G" "${groups_ok}" 1
if [ "$(sort "${TMP}/union.txt")" = "$(cat "${TMP}/all.txt")" ]; then
    ok "the four groups partition the harnesses"
else
    bad "the four groups overlap or miss a harness"
fi
expect "--group none,default lists the same as --group none plus --group default" \
    "$(bash "${RUNNER}" --group none,default --list | sort)" \
    "$( (bash "${RUNNER}" --group none --list; bash "${RUNNER}" --group default --list) | sort)"

# The group is read from each script's own build line, never a comment:
# an independent re-derivation from the non-comment BUILD=/make lines.
misrouted=""
while read -r group h; do
    code="$(grep -v '^[[:space:]]*#' "${TEST_DIR}/${h}")"
    want=none
    if grep -q 'BUILD=tsan' <<< "${code}"; then want=tsan
    elif grep -q 'BUILD=asan' <<< "${code}"; then want=asan
    elif grep -q 'make .*sdk' <<< "${code}"; then want=default
    fi
    [ "${group}" = "${want}" ] || misrouted="${misrouted} ${h}(${group}!=${want})"
done < <(bash "${RUNNER}" --list)
expect "every harness's group matches its own build line${misrouted}" "${misrouted}" ""
expect "run_tcp_reassembly_perf_test.sh (BUILD=asan only in a comment) groups default" \
    "$(bash "${RUNNER}" --list | awk '$2 == "run_tcp_reassembly_perf_test.sh" {print $1}')" default

bash "${RUNNER}" --profile coverage --list > "${TMP}/cov.txt"
expect "--profile coverage --list runs every harness in group coverage" \
    "$(awk '$1 != "coverage"' "${TMP}/cov.txt" | wc -l)" 0
if grep -q 'run_mt_tsan_test.sh' "${TMP}/cov.txt"; then
    bad "--profile coverage --list includes a COVERAGE_SKIP harness"
else
    ok "--profile coverage --list leaves out the COVERAGE_SKIP harnesses"
fi

# --only (issue #656): names are run_<stem>.sh stems, taken from the
# enumeration so this file names no harness script.
mapfile -t stems < <(sed 's/^run_//; s/\.sh$//' "${TMP}/all.txt")
for args in "--only bogus_harness" "--only a,,b" "--only Bad" "--only"; do
    # shellcheck disable=SC2086  # word-split on purpose: one option list
    bash "${RUNNER}" ${args} --list >/dev/null 2>&1
    expect "run_all_harnesses.sh ${args} --list exits 2" "$?" 2
done
expect "--only <one stem> --list prints that harness alone" \
    "$(bash "${RUNNER}" --only "${stems[0]}" --list | awk '{print $2}')" "run_${stems[0]}.sh"
out="$(bash "${RUNNER}" --only "" --list)"
expect "--only '' --list exits 0" "$?" 0
expect "--only '' --list selects nothing" "${out}" ""
pick="${stems[1]},${stems[3]},${stems[5]},${stems[7]},${stems[9]}"
want="$(printf 'run_%s.sh\n' "${stems[1]}" "${stems[3]}" "${stems[5]}" "${stems[7]}" "${stems[9]}" | sort)"
expect "--only <five stems> --list prints those five" \
    "$(bash "${RUNNER}" --only "${pick}" --list | awk '{print $2}' | sort)" "${want}"
expect "--only is repeatable" \
    "$(bash "${RUNNER}" --only "${stems[1]},${stems[3]}" --only "${stems[5]},${stems[7]},${stems[9]}" --list \
       | awk '{print $2}' | sort)" "${want}"
expect "the 2 shards of an --only selection partition it" \
    "$( (bash "${RUNNER}" --only "${pick}" --shard 1/2 --list
         bash "${RUNNER}" --only "${pick}" --shard 2/2 --list) | awk '{print $2}' | sort)" "${want}"
: > "${TMP}/union.txt"
for g in none default asan tsan; do
    bash "${RUNNER}" --only "${pick}" --group "${g}" --list | awk '{print $2}' >> "${TMP}/union.txt"
done
expect "the four groups of an --only selection partition it" "$(sort "${TMP}/union.txt")" "${want}"

echo "== (2) fixture run (group none: no SDK build)"
FIX="${TMP}/fixture"
mkdir -p "${FIX}/tools/phase0/tests"
cp "${RUNNER}" "${FIX}/tools/phase0/"
for c in classified_flow_fastpath position_unknown_guard session_lookup_perf mt_tsan; do
    # COVERAGE_SKIP must name existing harnesses; these never run here.
    printf '#!/usr/bin/env bash\nexit 0\n' > "${FIX}/tools/phase0/tests/run_${c}_test.sh"
done
# shellcheck disable=SC2016  # the fixture expands it, not this script
printf '#!/usr/bin/env bash\necho "fixture pass prebuilt=${MMT_SDK_PREBUILT:-unset}"\n' \
    > "${FIX}/tools/phase0/tests/run_zz_pass.sh"
printf '#!/usr/bin/env bash\necho "fixture fail output"\nexit 3\n' \
    > "${FIX}/tools/phase0/tests/run_zz_fail.sh"
FRUN="${FIX}/tools/phase0/run_all_harnesses.sh"

before=$( (bash "${FRUN}" --shard 1/2 --list; bash "${FRUN}" --shard 2/2 --list) | wc -l)
printf '#!/usr/bin/env bash\n# not built with BUILD=asan\nexit 0\n' > "${FIX}/tools/phase0/tests/run_zz_new.sh"
after=$( (bash "${FRUN}" --shard 1/2 --list; bash "${FRUN}" --shard 2/2 --list) \
         | grep -c ' run_zz_new.sh$')
expect "a newly added harness lands in exactly one shard" "${after}" 1
expect "a BUILD= marker in a comment does not set the group" \
    "$(bash "${FRUN}" --list | awk '$2 == "run_zz_new.sh" {print $1}')" none
expect "the shards grew by one harness" \
    "$( (bash "${FRUN}" --shard 1/2 --list; bash "${FRUN}" --shard 2/2 --list) | wc -l)" \
    "$((before + 1))"
rm -f "${FIX}/tools/phase0/tests/run_zz_new.sh"

LOGS="${TMP}/logs"
: > "${TMP}/summary.md"
GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY="${TMP}/summary.md" \
    bash "${FRUN}" --group none --log-dir "${LOGS}" > "${TMP}/run.out" 2>&1
expect "a run with a failing harness exits 1" "$?" 1
expect "verdicts.tsv names the failing harness" \
    "$(awk -F'\t' '$4 == "run_zz_fail.sh" {print $1}' "${LOGS}/verdicts.tsv" 2>/dev/null)" FAIL
expect "verdicts.tsv names the passing harness" \
    "$(awk -F'\t' '$4 == "run_zz_pass.sh" {print $1}' "${LOGS}/verdicts.tsv" 2>/dev/null)" PASS
expect "the failing harness keeps its own log" \
    "$(cat "${LOGS}/run_zz_fail.sh.log" 2>/dev/null)" "fixture fail output"
expect "MMT_SDK_PREBUILT=1 reaches the harness" \
    "$(cat "${LOGS}/run_zz_pass.sh.log" 2>/dev/null)" "fixture pass prebuilt=1"
expect "the failure is an ::error annotation naming the harness" \
    "$(grep -c '^::error title=phase0 harness failed::run_zz_fail.sh' "${TMP}/run.out")" 1
expect "each harness is a collapsed log group" \
    "$(grep -c '^::group::' "${TMP}/run.out")" "$(grep -c '^::endgroup::' "${TMP}/run.out")"
# shellcheck disable=SC2016  # literal backticks of the Markdown table
expect "the job summary has a FAIL row for the harness" \
    "$(grep -c '^| FAIL | [0-9]* | none | `run_zz_fail.sh` |$' "${TMP}/summary.md")" 1

bash "${FRUN}" --group none --shard 2/2 --log-dir "${TMP}/logs2" > "${TMP}/run2.out" 2>&1
rc=$?
if grep -q 'run_zz_fail.sh' "${TMP}/run2.out"; then
    expect "a shard without the failing harness exits 1" "${rc}" 1
else
    expect "a shard without the failing harness exits 0" "${rc}" 0
fi
bash "${FRUN}" --group tsan --log-dir "${TMP}/logs3" > "${TMP}/run3.out" 2>&1
expect "an empty selection runs nothing and exits 0" "$?" 0
bash "${FRUN}" --only "" --log-dir "${TMP}/logs4" > "${TMP}/run4.out" 2>&1
expect "an empty --only list runs nothing and exits 0" "$?" 0
expect "an empty --only list runs no harness" "$(grep -c '^--- Running' "${TMP}/run4.out")" 0
bash "${FRUN}" --only zz_fail --log-dir "${TMP}/logs5" > "${TMP}/run5.out" 2>&1
expect "--only runs the named failing harness alone and exits 1" "$?" 1
expect "--only ran exactly one harness" "$(grep -c '^--- Running' "${TMP}/run5.out")" 1

echo "== (3) phase0-baseline.yml wiring"
if ! python3 -c 'import yaml' 2>/dev/null; then
    if [ "${REQUIRE_PYYAML:-0}" = 1 ]; then
        bad "PyYAML is required (REQUIRE_PYYAML=1) but not importable"
    else
        echo "  SKIP workflow wiring (no PyYAML)"
    fi
else
    wiring="$(python3 - "${REPO_ROOT}" <<'PY'
import os, subprocess, sys
import yaml

root = sys.argv[1]
runner = os.path.join(root, "tools", "phase0", "run_all_harnesses.sh")
with open(os.path.join(root, ".github", "workflows", "phase0-baseline.yml"),
          encoding="utf-8") as fh:
    jobs = yaml.safe_load(fh)["jobs"]

def check(label, cond):
    print(f"  {'PASS' if cond else 'FAIL'} {label}")

def needs(job):
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else list(n)

check("no list-harnesses job (issue #655)", "list-harnesses" not in jobs)
h = jobs.get("harness") or {}
legs = ((h.get("strategy") or {}).get("matrix") or {}).get("include") or []
check(f"the harness job has 1-5 legs (has {len(legs)})", 1 <= len(legs) <= 5)
check("every leg has a distinct shard name",
      len({leg.get("shard") for leg in legs}) == len(legs)
      and all(leg.get("shard") for leg in legs))
steps = h.get("steps") or []
run_steps = [s for s in steps if "run_all_harnesses.sh" in str(s.get("run", ""))]
check("one step runs run_all_harnesses.sh with the leg's select and a log dir",
      len(run_steps) == 1
      and (run_steps[0].get("env") or {}).get("SELECT") == "${{ matrix.select }}"
      and "$SELECT" in run_steps[0]["run"]
      and "--log-dir" in run_steps[0]["run"])
check("the log directory is uploaded even when a harness fails",
      any("upload-artifact" in str(s.get("uses", ""))
          and "cancelled()" in str(s.get("if", "")) for s in steps))
check("fail-fast is off", (h.get("strategy") or {}).get("fail-fast") is False)

all_h = sorted(f for f in os.listdir(os.path.join(root, "tools", "phase0", "tests"))
               if f.startswith("run_") and f.endswith(".sh"))
seen = []
for leg in legs:
    out = subprocess.run(["bash", runner, *str(leg.get("select", "")).split(), "--list"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        check(f"leg {leg.get('shard')}: --list accepts its select", False)
        continue
    seen += [ln.split()[1] for ln in out.stdout.splitlines() if ln.strip()]
dups = sorted({x for x in seen if seen.count(x) > 1})
missing = sorted(set(all_h) - set(seen))
check(f"the legs run every harness ({len(all_h)})"
      + (f" — missing: {', '.join(missing)}" if missing else ""), not missing)
check("no harness runs in two legs"
      + (f" — {', '.join(dups)}" if dups else ""), not dups)

gate = jobs.get("harness-gate") or {}
check("harness-gate needs changes and harness and always runs",
      {"changes", "harness"} <= set(needs(gate))
      and "always()" in str(gate.get("if", "")))

# Issue #656: the legs skip on the docs and tooling tiers, and narrow to the
# named harnesses on the tests and family tiers only.
check("the harness legs skip on docs and tooling changes, fail-closed",
      "needs.changes.outputs.gates != 'false'" in str(h.get("if", ""))
      and "!cancelled()" in str(h.get("if", "")))
env = (run_steps[0].get("env") or {}) if run_steps else {}
check("the legs read full and harnesses from `changes`",
      env.get("FULL") == "${{ needs.changes.outputs.full }}"
      and env.get("HARNESSES") == "${{ needs.changes.outputs.harnesses }}")
r = str(run_steps[0].get("run", "")) if run_steps else ""
check("--only is passed only on an explicit full=false",
      'if [ "$FULL" = false ]; then only=(--only "$HARNESSES"); fi' in r
      and '$SELECT "${only[@]}"' in r)
grun = " ".join(str(st.get("run", "")) for st in gate.get("steps") or [])
genv = {}
for st in gate.get("steps") or []:
    genv.update(st.get("env") or {})
check("harness-gate accepts skipped legs on code=false or gates=false only",
      genv.get("GATES") == "${{ needs.changes.outputs.gates }}"
      and '[ "${RESULT}" = "skipped" ] && [ "${CHANGES}" = "success" ]' in grun
      and '{ [ "${CODE}" = "false" ] || [ "${GATES}" = "false" ]; }' in grun)
PY
)"
    rc=$?
    printf '%s\n' "${wiring}"
    [ "${rc}" -eq 0 ] || bad "wiring check crashed (exit ${rc})"
    pass=$((pass + $(printf '%s\n' "${wiring}" | grep -c '^  PASS ' || true)))
    fail=$((fail + $(printf '%s\n' "${wiring}" | grep -c '^  FAIL ' || true)))
fi

echo
echo "harness-shards self-test: ${pass} passed, ${fail} failed"
if [ "${fail}" -eq 0 ]; then
    echo "Result: PASS (harness-shards self-test)"
    exit 0
fi
echo "Result: FAIL (harness-shards self-test)"
exit 1
