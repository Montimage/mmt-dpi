---
layout: default
title: "CI Time and Test-Selection Audit (2026-10)"
---

# CI Time and Test-Selection Audit (2026-10)

Audit of the GitHub Actions CI of `montimage-projects/mmt-dpi` at commit
`8f0bd704` (2026-10-27); #651, merged later the same day, is noted where it
changes a finding. Goal: cut pull-request wall-clock time and the number
of tests a pull request runs, so that a PR mostly runs the tests covering the
code it changes, without weakening what protects `main`.

Read-only analysis: no workflow, branch protection or required check was
changed. Every number below comes from the GitHub API (`gh run list`,
`gh api …/runs/<id>/attempts/<n>/jobs`), from job logs, or from a local
measurement named as such. Builds on #552 (merged in PR #649: `changes` job,
docs-only filter, single cppcheck pass with a results cache) and open issue
#553 (ccache, one local command for the gates).

## 1. Summary

- **A PR runs 101 jobs and 234 job-minutes (median)**. The median wall clock
  is 33 min and p90 is 60 min, across the 29 complete PRs measured
  (2026-10-21 → 10-27). `lint` was the last job to finish in 25 of 29.
- **Since #649, `lint` is fast only when its cache is warm.** Warm runs take
  2–4 min. Cold runs take 28–30 min: the first run after a cppcheck-script
  change, a header change that reaches most files, or a missing `main` cache.
  The cold time is cppcheck checking up to 12 preprocessor configurations of
  every protocol file. Locally, a single-configuration scan of the same tree
  was 10× faster (39 s vs 394 s, §4.1).
- **95% of every unit-suite leg is the same SDK rebuilt 13 times.** 13 suites
  each run `make -C sdk clean` and rebuild (≈44 s each, 600 of 673 s in
  `unit-tests`). Nine legs do this, so a PR rebuilds the SDK ≈120 times, plus
  50 more in the harness matrix.
- **The 50-leg harness matrix is queue-bound.** A leg runs for 1.2 min
  (median), mostly an SDK build, but waits 8.5 min (median) and 24.7 min (p90)
  for a runner. A Free-plan organisation has a 20-concurrent-job cap, and one
  PR asks for ≈101 jobs.
- **Only 33% of recent PRs need the full suite.** Of the last 100 merged PRs,
  3% were docs-only, 20% CI/tooling-only, 22% tests/harness-only, 22% touched
  a single dissector family and 33% touched core/build/shared code.
- **Strict "up to date before merge" multiplies everything.** Since
  2026-10-01, 49 PR branches produced 84 `C/C++ CI` runs (1.7 per PR); 23 of
  them were cancelled by a newer push.

Target: **≈10 min** for a typical single-dissector PR (from 33 min median),
**≈12–15 min** for a full-suite PR, with the full matrix running once per
merge in a merge queue rather than on every PR update (§6).

## 2. Method and data

| Source | Scope |
|--------|-------|
| `gh run list --event pull_request --limit 40` per workflow | `c-cpp.yml`, `phase0-baseline.yml`, `release-packages.yml`: 40 runs each (2026-10-21 → 10-27); `install-smoke.yml` 13, `bootstrap-smoke.yml` 8, `asn1c-regen.yml` 13 (path-filtered, so fewer) |
| `gh api …/attempts/<n>/jobs` | every attempt of every run above (198 job lists) — durations, queue time, first-attempt failures |
| `gh run list --event push --branch main --limit 20` | the same workflows on `main` |
| `gh pr list --state merged --limit 100 --json files` | PR path mix, 2026-09-22 → 10-27 |
| job logs | per-suite timing (`unit-tests`, run 40513495242), cppcheck progress and cache lines (`lint`), apt cache post-step |
| `gh api …/actions/caches` | cache keys, sizes, refs |
| local, 20-core host, cppcheck 2.22.0 built with `tools/ci/install-cppcheck.sh` | single- vs multi-configuration scan time |

Definitions: *duration* = job `started_at` → `completed_at`; *queue* = job
`created_at` → `started_at`; *wall* = earliest run `createdAt` → latest job
`completed_at` across the three always-on workflows of one head SHA; durations
use attempt 1. Cancelled runs (superseded pushes) are excluded from wall-clock
figures. "Flake" = failed on attempt 1, passed on a re-run.

The data has a regime change at 2026-10-27 11:35Z, when PR #649 merged
(`lint` went from two cppcheck passes to one pass with a results cache), and
another earlier on 10-27 when cppcheck moved to 2.22 (#518). Only two complete
PR runs postdate #649, so warm/cold `lint` times below are read from the
individual post-#649 `lint` jobs and their logs, not from the medians.

## 3. Current state

### 3.1 Per-PR totals (29 complete PRs, all three always-on workflows)

| Metric | Median | p90 |
|--------|-------:|----:|
| Wall clock, first push → last job | 33.3 min | 60.2 min |
| Jobs that ran | 101 | 106 |
| Job-minutes | 234 | 275 |
| Last job to finish | `lint` (25/29), `packages-gate`, `toolchain-ceiling`, `unit-tests-unsigned-char`, `sanitizer-tests (asan)` (1 each) | |

Post-#649: the two complete PRs took 35.9 min (cold `lint` cache) and
15.4 min (warm; the critical path became `sanitizer-tests (asan)`).

### 3.2 `C/C++ CI` (`c-cpp.yml`, 25 jobs on a code PR)

| Job | Required | Duration med / p90 (min) | Queue med / p90 (min) | Notes |
|-----|:-------:|------:|------:|-------|
| `lint` | yes | 30.2 / 59.0 | 1.0 / 10.0 | cppcheck build 1 min; scan 2–4 warm, 28–30 cold (post-#649), 56–59 before #649 (two passes) |
| `toolchain-ceiling` | — | 12.9 / 15.5 | 0.4 / 2.1 | ENABLESEC build + all 30 suites on GCC 15 |
| `sanitizer-tests (asan)` | yes | 11.7 / 13.1 | 0.6 / 8.3 | all 30 suites |
| `unit-tests-unsigned-char` | — | 11.5 / 11.6 | 2.6 / 7.0 | new in #649 (5 runs) |
| `assertions-live` | — | 11.1 / 12.4 | 0.6 / 15.6 | NDEBUG=1 build + all suites |
| `toolchain-floor` | — | 10.2 / 12.1 | 0.3 / 4.9 | GCC 11 container + all suites |
| `unit-tests` | yes | 9.8 / 11.5 | 1.1 / 10.9 | all 30 suites |
| `sanitizer-tests (tsan)` | yes | 9.5 / 10.7 | 1.5 / 10.6 | |
| `coverage` | yes | 9.3 / 10.6 | 0.7 / 8.0 | |
| `unit-tests-arm` | — | 7.7 / 8.6 | 0.3 / 0.6 | native arm64 runner (5 runs) |
| `codeql` | — | 6.7 / 7.5 | 1.1 / 9.4 | ENABLESEC build traced |
| `fuzz` | — | 2.9 / 3.1 | 1.5 / 9.5 | 300 s / 1200 mutants on PRs |
| `build` | yes | 1.2 / 1.5 | 1.1 / 9.6 | |
| `site-onboarding`, `root-install`, `unit-tests (-fsigned-char …)` | 1 of 3 | 1.1–1.2 | ≈1.2 / 11–13 | |
| `secret-scan`, `enablesec`, `verify-helpers`, `pre-commit` | yes | 0.9–1.0 | ≈1.1 / ≈10 | |
| `doc-validators`, `version-agreement`, `resource-budgets` ×2 | 1 of 4 | 0.1–0.5 | | |

Failures over 39 PR runs: 1 rerun (`toolchain-floor`, apt fetch in
"Install git for the checkout"); single first-attempt failures in
`verify-helpers`, `pre-commit` and `lint` were real (fixed by a push).

### 3.3 `Phase 0 baseline gate` (`phase0-baseline.yml`, 57 jobs)

| Job | Required | Duration med / p90 | Queue med / p90 |
|-----|:-------:|------:|------:|
| `harness-run_*.sh` × 50 | via `harness-gate` | 1.2 / 1.8 | **8.5 / 24.7** |
| ASan/UBSan profile compiles | yes | 1.3 / 1.6 | 1.0 / 2.4 |
| `leak-gate` | — | 1.2 / 2.4 | 0.2 / 3.8 |
| Precision/recall | yes | 1.1 / 1.3 | 1.1 / 3.2 |
| Golden classification fingerprint | yes | 1.0 / 1.4 | 1.2 / 4.5 |
| `changes`, enumerate, `harness-gate` | gate | 0.1 | |

Workflow wall clock 20.6 / 38.8 min (med/p90); `harness-gate` closes it in
every complete run. The 50 legs spend ≈60 job-min per PR, almost all of it on
50 identical SDK builds (each harness script builds and installs the SDK into
its own prefix). The slowest harness averages 87 s. Two harness legs failed in
`bootstrap-deps` (apt), which is infrastructure, not code: 50 legs means 50
chances to hit an apt mirror hiccup.

### 3.4 `Build & release packages` (`release-packages.yml`)

Any `src/`, `sdk/` or `rules/` change matches the packaging filter, so a code
PR builds **18 package legs** (9 distributions × amd64/arm64) and **3
reproducibility legs**. Legs take 1.4–2.9 min (median); queue median 2–5 min,
p90 ≈10 min; workflow wall 10.7 / 21.8 min. `packages-gate` was the last job
of a PR once. First-attempt failures: `centos-stream10 (amd64)` 5/24 (3 passed
on re-run), `rocky-10 (amd64)` 1 flake, `rocky-9 (arm64)` 1 flake;
`packages-gate` failed 8/39, each time downstream of a leg failure.
`packages-gate` is in `.github/required-checks.txt` but not in branch
protection (§7).

### 3.5 Path-filtered workflows

`install-smoke` (wall 4.3 / 10.5 min), `bootstrap-smoke` (2.8 / 6.4) and
`asn1c-regen` (1.0 / 1.8) already run only when their paths change and are not
required. No change proposed.

### 3.6 Concurrency, caches and `main`

- Every workflow cancels a superseded PR run (`cancel-in-progress`). `c-cpp`
  and `phase0` also cancel on `main` pushes (group `workflow-ref`), so a quick
  second merge cancels the first merge's `main` run before `lint` can save
  its cache (2 of 20 `main` runs cancelled).
- Each merge starts ≈100 `main` jobs that compete with open PRs for the same
  20 concurrent job slots.
- **The apt cache never saves.** `bootstrap-deps` restores nothing ("Cache not
  found" — no `apt-*` key exists), and its post step fails with
  `tar: …/var/cache/apt/archives/partial: Cannot open: Permission denied` →
  `Failed to save`. The step takes 11 s median / 30 s p90 and runs ≈75 times
  per PR (≈12 job-min). F-CI-008, which #553 targets, is not delivered by the
  current action.
- **CodeQL TRAP caches use about half the 10 GB repository cache budget.** 60
  caches total 5.2 GB, almost all `codeql-trap-*` entries of 92–160 MB, one
  per `main` commit. The `cppcheck-*` entries are 0.5 MB each. When the
  budget overflows, GitHub evicts the least recently used entries, and the
  small caches go too.

## 4. Why `lint` is slow and how to shorten it

### 4.1 Measurements

| Scan | Where | Time | Findings |
|------|-------|-----:|---------:|
| two passes, no cache (before #649) | CI, 4 vCPU | 56–59 min | 0 |
| one pass, cold cache (after #649) | CI, 4 vCPU | 28–30 min | 0 |
| one pass, warm cache | CI, 4 vCPU | 2–4 min | 0 |
| one pass, default `--max-configs` (12), `-j8`, no build dir | local, 20-core host | 394 s | 2 (see below) |
| one pass, `--max-configs=1`, `-j8`, no build dir | local, 20-core host | 39 s | 0 |

The two local scans ran concurrently with the same flags and exclusions as
`tools/ci/run-cppcheck.sh`. Only `--max-configs` differed, and it gave a
**10× speed-up**. Scaled to the CI cold scan (28–30 min), a single-configuration
scan would take ≈3 min on a 4-vCPU runner. The local default scan reported 2
`nullPointerOutOfMemory` warnings in `src/mmt_tcpip/lib/llhttp_api.c:47-48`.
That file is vendored and passed to `-i`, but it is still reached through an
include. CI's scan of the same tree (with `--cppcheck-build-dir`) reports 0.
So re-measure the ratchet in CI, not locally, as part of R1.

The log shows why: for each protocol file cppcheck reports
`Checking …/proto_X.c: PROTO_AIMINI=PROTO_AIMINI...`, `PROTOCOL_HISTORY_SIZE=2...`,
and so on. It checks every `#ifdef` combination it finds, up to 12 per file,
across 722 files. The ratchet baseline is 0 findings, so the gate is really
"no warning or error in any configuration".

### 4.2 Options

1. **Scan the built configuration on PRs.** Use `--max-configs=1` with the
   build's `-D` set, or `--project=compile_commands.json` from a
   `make -C sdk` run. Measured locally: 10× faster than the default, so
   ≈3 min cold on a 4-vCPU runner; the cache stays useful on top. Re-measure
   the ratchet in the same change.
2. **Keep the full multi-configuration scan,** off the PR path: in the merge
   queue (§5.5) or weekly. It then guards the `#ifdef` branches the build
   never compiles without sitting on every PR's critical path.
3. **Changed files only** (`git diff --name-only … -- 'src/*.c'` passed to
   cppcheck) is not needed once option 1 lands: the cache already skips
   unchanged files, and a header change has to rescan the files including it
   anyway.
4. **Keep the cache warm on `main`:** do not cancel `main` push runs (§3.6),
   and keep CodeQL TRAP caches from evicting it.

Effect: `lint` drops from 28–30 min cold to ≈3–4 min (≈1 min of it the
cppcheck build), and stays 2–4 min warm.
On the measured PRs that removes the critical path's largest term: −25 min on
a cold run, which is the current p90.

## 5. Recommendations

Each item names its measured basis, expected saving, coverage risk and what
must stay required. Priorities: **high** = changes the critical path or more
than 25% of job-minutes; **medium** = a sizeable share of job-minutes or a
precondition for a high item; **low** = hygiene.

### 5.1 R1 — cppcheck: scan one configuration on PRs, all configurations in the merge queue — high (#653)

- **Extends #552** (single pass + `--cppcheck-build-dir` cache).
- **Basis:** §4.1. CI cold scan 28–30 min; locally, a single configuration
  was 10× faster than the default (39 s vs 394 s).
- **Saving:** ≈−25 min wall on every cold-cache PR; no change on warm.
- **Coverage risk:** PRs no longer check `#ifdef` branches outside the
  build; the merge-queue (or weekly) full scan still does, before merge if a
  queue exists.
- **Stays required:** `lint` (shellcheck + cppcheck, error gate + ratchet).

### 5.2 R2 — Build the SDK once per job and share it across suites — high (#654)

- **Extends #553:** ccache speeds a rebuild, sharing removes it. Do both.
- **Basis:** `unit-tests` log, run 40513495242. 13 SDK-building suites
  (`hashmap`, `citrix_ica_detection`, `http_header_case`, `s1ap_ngap_decode`,
  `rule_engine`, `nas_ies_tail`, `installer`, `installed_consumer`,
  `parser_boundaries`, `sdk_coverage`, `docs_lifecycle`, `docs_onboarding`,
  `fault_injection`) take 43–93 s each, 600 of 673 s in total. The other 17
  suites take 30 s together.
- **Change:** `tests/run_all_tests.sh` builds and installs once per profile
  into a run-scoped prefix and exports it. Suites that only consume the SDK
  use it; suites that test the build itself (`installer`, `sdk_coverage`, the
  install leg of `docs_onboarding`) keep their own. This is the pattern
  `tools/phase0/run_all_harnesses.sh` already uses.
- **Saving:** each full-suite leg goes from ≈10–12 min to ≈3–4 min. Nine legs
  cost ≈100 job-min today; ≈60–70 job-min saved per full-suite PR. Wall: the
  suite legs leave the critical path once R1 lands.
- **Coverage risk:** low, if the suites that test install/build mechanics keep
  their own builds. `--coverage` must still harvest per suite; with one shared
  build the counters accumulate, so harvest once per run or reset them with
  `GCOV_PREFIX` per suite.
- **Stays required:** every suite leg that is required today.

### 5.3 R3 — Replace the 50-leg harness matrix with profile shards — high (#655)

- **Basis:** §3.3. 50 legs × 1.2 min ≈ 60 job-min; queue 8.5 / 24.7 min;
  `harness-gate` ends `phase0` in every run.
- **Change:** run `tools/phase0/run_all_harnesses.sh`, which builds one SDK
  per profile, sharded into 3–4 jobs: asan in 2 halves, tsan, and
  default/valgrind. Enumerate dynamically as today, so a new
  `run_*.sh` is picked up; `harness-gate` stays the one stable required
  context. Upload each harness log as an artifact, and print the aggregate's
  pass/fail table, so a failure is still attributable to one harness.
- **Saving:** ≈60 → ≈10–12 job-min; −46 jobs per PR. Phase0 wall 20.6 /
  38.8 → ≈6–8 min. Freeing 46 of a PR's ≈101 jobs under the 20-job cap also
  cuts queue time for every other job.
- **Coverage risk:** none in content; the same scripts run against the same
  profiles. Debugging gets one level coarser (shard, then the log line).
- **Stays required:** `harness-gate`; `leak-gate` (Valgrind oracle) as today.

### 5.4 R4 — Path-to-test selection: extend `changes` from docs/code to five tiers — high (#656)

- **Extends #552** (`tools/ci/classify-changes.sh`, `test-classify-changes.sh`).
- **Basis:** §6.1, the PR mix of the last 100 merged PRs.
- **Change:** the classifier emits `scope` (`docs` | `tooling` | `tests` |
  `family` | `full`), the families, and the suite and harness lists, from a
  committed map (`tools/ci/test-map.txt`, §6.2). Jobs and the suite runner
  read those outputs. Required contexts keep reporting through the existing
  pattern: skip the job when it is single-context, skip its steps when it is
  a matrix.
- **Safety rules:**
  - fail-closed: an unmatched path, a `.h` outside a family's private
    directory, `rules/`, `sdk/`, `src/mmt_core/`, shared `src/mmt_tcpip`
    infrastructure, the runner or classifier, a workflow or composite action,
    or the phase0 corpora → `full`;
  - pushes, tags, the schedule and `merge_group` → `full`;
  - the map's self-test fails when a suite or harness is missing from the map;
  - read the diff with `git -c core.quotePath=false diff -z` — #601 item 1
    found that a quoted path fails open in the packaging filter.
- **Saving:** by tier, §6.3. Weighted over the measured PR mix: ≈234 → ≈95
  job-min per PR (−60%); median wall ≈10 min.
- **Coverage risk:** a test whose dependency is not in the map is skipped on
  the PR. Mitigations: fail-closed defaults, core smoke suites and the
  golden/precision gates on every `src/` change, and the full set in the
  merge queue, so nothing merges untested.
- **Stays required:** every required context still reports on every PR.

### 5.5 R5 — Adopt a merge queue and drop strict "up to date before merge" — high (#657) (human decision)

- **Basis:** 84 `C/C++ CI` PR runs for 49 branches since 10-01 (1.7 per PR);
  23 cancelled by a newer push, mostly a "Update branch" merge forced by
  strict mode. A PR that had to be updated re-ran 15–60 min of CI with no
  change of its own.
- **Change:** a ruleset or branch-protection merge queue on `main`; add
  `merge_group:` to `c-cpp.yml`, `phase0-baseline.yml` and
  `release-packages.yml`. `changes` already treats any non-`pull_request`
  event as `code=true`, so it needs no change; the release `changes` job needs
  `merge_group` → `packaging=true`. Queue builds run the full set: every tier,
  every variant leg, the full package matrix and the full cppcheck scan.
  Merge queues are available to public repositories owned by an organisation,
  so this plan qualifies.
- **Saving:** removes the re-run-after-every-merge cost (one full run per
  merge instead of one per open PR per merge), and enables R6. Batching (group
  size 2–3) amortises the full run further.
- **Coverage risk:** none; the queue tests the exact merge result, which is
  stronger than strict mode testing the PR head after a manual update.
- **Stays required:** the same contexts, now reported for both `pull_request`
  and `merge_group`. Reconcile `.github/required-checks.txt` with the applied
  protection at the same time (§7).

### 5.6 R6 — Move variant and duplicate legs from every PR to the merge queue — medium (#658) (depends on R5)

- **Basis:** §3.2 and §3.4.

| Leg | Duration (min) | Why the merge queue suffices |
|-----|------:|---------------------|
| `unit-tests-unsigned-char` | 11.5 | x86 mirror of `unit-tests-arm`, which stays on PRs |
| `unit-tests (-fsigned-char …)` | 1.1 | `-fsigned-char` is x86's default, so this leg repeats `unit-tests` for 5 suites; #601 item 3 proposes renaming it — removing it supersedes that |
| `toolchain-floor` | 10.2 | GCC 11 floor; regressions are rare and caught pre-merge in the queue |
| `toolchain-ceiling` | 12.9 | GCC 15 / C23; ditto |
| `assertions-live` | 11.1 | NDEBUG=1 variant of the suites |
| `coverage` | 9.3 (before #651) | the floor is a whole-repo metric; checking it once per merge suffices. Since #651 (merged after this window) a full `--coverage` run also replays the phase0 harnesses against one `BUILD=coverage` SDK, so this leg will grow; re-measure |
| package matrix | 16 of 18 legs ≈27 job-min, 2 of 3 repro legs ≈5 | keep `ubuntu-24.04 (amd64)` deb, `rocky-9 (arm64)` rpm and one reproducibility leg on PRs; the full matrix in the queue and on tags |

- **Saving:** 6 jobs and ≈56 job-min from the variant legs, plus 18 jobs and
  ≈32 job-min from packaging, per code PR.
- **Coverage risk:** none before merge if R5 is in place. Without R5, these
  legs would move to `main` push + weekly, and a regression would surface
  after merge. Do not do that.
- **Stays required:** whichever contexts are required today, reported by the
  queue run. On PRs they report a skip, as docs-only PRs already do.

### 5.7 R7 — Fold redundant jobs — medium (#659)

| Job | Covered by | Duration (min) |
|-----|-----------|------:|
| ASan/UBSan profile compiles | `sanitizer-tests (asan)`, whose SDK-building suites build `BUILD=asan`, and every asan harness | 1.3 |
| `enablesec` | `codeql`, which traces an ENABLESEC=1 build; `toolchain-ceiling`; `rule_engine`, `installer` | 1.0 |
| `harness-run_leak_regression_test.sh` | `leak-gate` runs the same script under Valgrind | 1.3 |
| Docs-site build in `site-onboarding` | `verify-helpers` builds the same site (`tools/ci/build-docs-site.sh`) — upload it once, reuse it | ≈0.5 |
| `resource-budgets (ubuntu-24.04)` | `resource_bounds` is in `DEFAULT_SUITES`; keep the arm64 leg and the budget re-check | 0.2 |

- **Saving:** ≈5 job-min and 5 jobs per PR. Worth more under the 20-job cap
  than the minutes suggest.
- **Coverage risk:** none, if each folded assertion moves into its covering
  job. The ASan `nm -D … __asan_init` check moves into
  `sanitizer-tests (asan)`.
- **Stays required:** the covering jobs. Each removed required context needs
  a branch-protection update (human decision).

### 5.8 R8 — Make the caches work: apt, `main` runs, CodeQL budget — low (#660)

- **Extends #553** (F-CI-008).
- **Changes:**
  1. `bootstrap-deps`: exclude `partial/` and `lock` from the cache path, or
     `chown` after the install, so the post step can save. Saves ≈12 job-min
     per PR and one source of the apt flakes in §3.2–§3.3.
  2. `cancel-in-progress: ${{ github.event_name == 'pull_request' }}` in
     `c-cpp.yml` and `phase0-baseline.yml`, as `release-packages.yml` already
     does, so `main` runs finish and save the `lint` cache.
  3. Stop the CodeQL TRAP caches from taking half the budget. Disable TRAP
     caching, or delete `codeql-trap-*` keys older than the newest few in a
     scheduled job.
- **Coverage risk:** none.

## 6. Test-to-code map and selection scheme

### 6.1 Where PRs change code (last 100 merged PRs)

| Tier | Rule (any path in the PR) | PRs |
|------|---------------------------|----:|
| `full` | `src/mmt_core/`, `rules/`, `sdk/`, `src/mmt_tcpip/include/`, `src/mmt_tcpip/lib/*` (not `protocols/`), other `src/` | 33 |
| `family` | only `src/mmt_tcpip/lib/protocols/` (10), `src/mmt_mobile/` (6), `src/mmt_security/` + `src/mmt_fuzz_engine/` (5), security + tcpip (1) | 22 |
| `tests` | only `tests/` and/or `tools/phase0/` (plus docs) | 22 |
| `tooling` | only `.github/`, `tools/ci/`, `scripts/`, packaging, dotfiles (plus docs) | 20 |
| `docs` | only `docs/` and root `*.md` (already handled by #552) | 3 |

### 6.2 What each test exercises

**Unit suites** (`tests/run_all_tests.sh`, `DEFAULT_SUITES`). "SDK" marks the
suites that rebuild the SDK (R2):

| Family | Suites |
|--------|--------|
| core (`src/mmt_core`, shared `src/mmt_tcpip/lib`) | `hashmap` (SDK), `memory`, `fault_injection` (SDK), `core_engine`, `hexdump`, `mmt_utils`, `mmt_inet_ntop`, `avltree`, `dpi_profiles`, `tcp_pending_order`, `resource_bounds` |
| tcpip (`src/mmt_tcpip/lib/protocols`) | `citrix_ica_detection` (SDK), `http_header_case` (SDK), `radius_hardening`, `ndn_dissector`, `proto_classifiers`, `parser_boundaries` (SDK) |
| mobile (`src/mmt_mobile`) | `s1ap_ngap_decode` (SDK), `nas_ies_tail` (SDK), `proto_classifiers` (diameter), `parser_boundaries` (s1ap) |
| security (`src/mmt_security`, `src/mmt_fuzz_engine`) | `rule_engine` (SDK, ENABLESEC) |
| dicom / business_app | `dicom_dissector`, `business_app` |
| build / install / packaging (`sdk/`, `rules/`, `install.sh`) | `installer` (SDK, ENABLESEC), `installed_consumer` (SDK, ENABLESEC), `sdk_coverage` (SDK, coverage profile) |
| CI tooling (`tools/ci/`) | `fuzz_verdicts`, `precision_metrics`, `release_gates` (delegate to `tools/ci/tests/`) |
| docs (`docs/USER_GUIDE.md`, `docs/MMT-Handler.md`, `docs/first-run/`) | `docs_lifecycle` (SDK), `docs_onboarding` (SDK) |

**Phase0 harnesses** (`tools/phase0/tests/run_*.sh`, 50; asan unless noted):

| Family | Harnesses |
|--------|-----------|
| core / session / memory | `arena_alloc`, `oom_no_abort` (default), `session_scale` (default), `session_lookup_perf`, `session_timeout_jump`, `memory_ceiling` (default), `classifier_init`, `ext_attribution`, `extraction_caplen_prologue`, `position_unknown_guard`, `caplen_clamp`, `classified_flow_fastpath`, `hostname_trie_mem` (default), `tunnel_parent_lifetime`, `bitmask_oob`, `leak_regression` (asan + Valgrind), `mt_tsan` (tsan) |
| tcpip L3/L4 | `ip_frag_bounds`, `ip_session_frag_key`, `ip_unaligned_header`, `tcp_doff_min`, `tcp_reassembly_perf`, `port_confirm`, `tcpip_pcap_harness` |
| tcpip application protocols | `dns_parser`, `dtls_classify_guard`, `dtls_registration`, `ftp_data_session_uaf`, `ftp_lprt_eprt`, `http2_bounds`, `http2_parser`, `http_method_classification`, `proto_http_method_classification`, `http_scanner`, `http_session`, `ndn`, `ndn_tlv_bounds`, `quic_dtls_extractor`, `quic_min_len`, `redis_resp`, `rtp_bounds`, `sip_methods`, `skype_removal`, `smb_bounds`, `sni_tlv_parse`, `ssl_record`, `ssl_tls12_version`, `tls_ext_walk` |
| mobile | `mobile_pcap_harness` |
| dicom | `dicom_test` |

**Gates and legs:**

| Gate / leg | Exercises | Runs on (proposed) |
|------------|-----------|--------------------|
| Golden classification fingerprint, precision/recall + accuracy corpus | all classification: core, tcpip, mobile, business_app, dicom | every `src/`, `rules/`, `sdk/`, `tools/phase0/ci/` change (≈1 min each — cheap insurance) |
| `fuzz` | core + tcpip + fuzz engine (ENABLESEC, asan) | `family` and `full` |
| `codeql` | all `src/` (ENABLESEC build) | `family` and `full` |
| `lint` | cppcheck: `src/` minus asn1c and vendored; shellcheck: tracked `*.sh` | cppcheck on any `src/` change; shellcheck on any `.sh` change |
| sanitizer legs, `coverage`, variant legs | whatever suites they run | the tier's suite list on PRs (R4); all in the queue (R5/R6) |
| package build / reproducibility | `src/`, `sdk/`, `rules/`, packaging scripts, `dist/`, licences | 2+1 legs on PRs when the packaging filter matches; full matrix in the queue and on tags |
| `install-smoke`, `bootstrap-smoke`, `asn1c-regen` | their path filters | unchanged |
| `verify-helpers`, `pre-commit`, `doc-validators`, `version-agreement`, `secret-scan` | repo-wide hygiene | every PR (≈1 min each) |

### 6.3 Proposed tiers

The classifier returns the **highest** tier any changed path reaches
(`docs` < `tooling` < `tests` < `family` < `full`); `merge_group`, `push`,
`schedule` and tags are always `full`.

| Tier | Runs on the PR | Est. jobs / job-min | Est. wall |
|------|---------------|-----------:|----------:|
| `docs` | unchanged from #552 | ≈10 / ≈6 | ≈5 min |
| `tooling` | `verify-helpers`, `pre-commit`, `doc-validators`, `version-agreement`, `secret-scan`, `build`, shellcheck; the `tools/ci/tests` delegate suites; any job whose workflow step names the changed `tools/ci` file (found by grepping the workflows); package PR-tier legs if the packaging filter matches | ≈14 / ≈15 | ≈5 min |
| `tests` | the changed suites (all PR legs: default, asan, tsan, arm) and the changed harnesses; core smoke | ≈18 / ≈25 | ≈6 min |
| `family` | `build`, `codeql`, `fuzz`, golden + precision, `leak-gate`, `lint` (R1); suites = core smoke ∪ family suites on the PR legs; harnesses = the family's harnesses ∪ `tcpip_pcap_harness`, `mobile_pcap_harness`, `mt_tsan`; `enablesec`-covering build if security; package PR-tier legs | ≈25 / ≈50 | **≈10 min** |
| `full` | every PR job after R1–R3, R6, R7 | ≈45 / ≈110 | ≈12–15 min |
| queue (`merge_group`) | everything, including variant legs, full package matrix and full cppcheck scan | ≈75 / ≈190 | ≈15–18 min |

Core smoke = `hashmap memory core_engine mmt_utils proto_classifiers
parser_boundaries` plus golden and precision. Together they exercise
registration of every protocol, the parser bounds and the classification
fingerprint.

The map (`tools/ci/test-map.txt`) records `path-glob → family` and
`suite|harness → families`. Its seed is the source references in each
`run_tests.sh` and harness `.c`/`.sh`, the same references §6.2 lists. A
self-test fails when a suite in `DEFAULT_SUITES` or a `run_*.sh` is missing
from the map. Fail-closed default: an unmapped suite or harness runs in every
tier.

Weighted over §6.1 (33% full, 22% family, 22% tests, 20% tooling, 3% docs):
≈95 job-min and ≈32 jobs per PR, against 234 job-min and 101 jobs today.

## 7. Target PR critical path

Typical single-dissector change (`src/mmt_tcpip/lib/protocols/proto_X.c` +
its test), after R1–R4 and R8:

| Step | Today (min) | Target (min) | Basis |
|------|------:|------:|-------|
| `changes` | 0.1 | 0.2 | measured |
| queue for a runner | 1–25 | ≈1 | ≈25 jobs instead of ≈101 under the 20-job cap |
| `lint` | 2–4 warm / 28–30 cold | 2–4 | R1, §4.1 |
| unit / asan / tsan legs (family subset) | 9.5–11.7 | ≈3 | R2: one shared build + ≈12 suites |
| harness shard(s) | 1.2 + queue 8.5–24.7 | ≈4–5 | R3: one SDK build + the family harnesses |
| `codeql` | 6.7 | 6.7 | unchanged — becomes the longest job |
| golden + precision | 1.0–1.1 | 1.0–1.1 | unchanged |
| packages (PR tier) | 1.4–2.9 + queue | ≈3 | R6: 3 legs |
| **End to end** | **33 median / 60 p90** (15 warm-cache best case post-#649) | **≈8–10** | longest chain: queue + `codeql` |

A full-suite PR stays under 15 min: codeql 7 + legs ≈4 + harness shards
≈6–8 + queue. The merge-queue run adds ≈15–18 min once per merge (or per
batch), and nobody waits on it.

Total estimated saving per PR: **≈23 min median wall** (33 → ≈10 for a
dissector PR) and **≈140 job-min** (234 → ≈95 weighted), plus the eliminated
re-run after every merge (R5): today one 15–60 min run per open PR per merge.

## 8. Needs a human decision

1. **Merge queue + dropping strict "up to date before merge"** (R5):
   repository ruleset / branch-protection change, admin only.
2. **Required-check set.** Branch protection requires 16 contexts;
   `.github/required-checks.txt` lists 31, among them `packages-gate`,
   `codeql`, `fuzz`, `leak-gate`, `toolchain-*`, `assertions-live` and
   `root-install`. Decide which list is right before R5–R7, which rename or
   remove contexts (#601 tracks two fragile names).
3. **What may leave the PR path.** R6 moves 6 variant legs and 16 package
   legs to the queue; R1 moves the multi-configuration cppcheck scan there.
   This is acceptable only together with R5.
4. **Coverage floor cadence.** Is checking `tests/coverage/floor.json` once
   per merge, not per PR push, acceptable?

## 9. Not changed / out of scope

- No workflow, action, script, branch protection or required check was
  edited. This document is the only change.
- Path-filtered workflows (`install-smoke`, `bootstrap-smoke`,
  `asn1c-regen`, `pages`) are already proportionate.
- Larger or self-hosted runners would raise the 20-job cap but are not on the
  Free plan; the recommendations above reduce demand instead.
