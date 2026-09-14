# Phase 0 — baseline & sanitizer harness

This directory is the **verification vehicle** for the MMT-DPI Master Improvement
Plan (`MASTER_IMPROVEMENT_PLAN.md`, Phase 0). It establishes the regression
baselines that every later phase is gated on, plus the `BUILD=asan` sanitizer
profile used to validate the Phase 2 memory-safety work.

Phase 0 changes **no production code** — it adds tooling and captured baselines.

## What's here

| File | Purpose |
|---|---|
| `phase0_classify.c` | Deterministic protocol-classification fingerprint tool. Prints, per pcap, sorted `count<TAB>protocol.path` lines — free of timestamps/addresses/ordering, so it diffs cleanly. |
| `phase0_throughput.c` | Throughput baseline tool (packets/second), in-memory replay with a fresh handler per iteration. |
| `phase0_precision.c` | Labelled-pcap precision/recall harness (Phase 7, M9, issue #74). Given a pcap and the application protocol it is known to carry, prints `label<TAB>total<TAB>tp<TAB>fp<TAB>app_unknown` from the classifier's deterministic decisions. The unlabelled fingerprint proves decisions don't *change*; this measures whether they are *correct*. |
| `golden_pcaps.txt` | The fixed golden pcap set (paths relative to the mmt-test `data-sets/` root). |
| `capture_baseline.sh` | Orchestrator: build+install at `-O3`, compile the drivers, capture all baselines into `baseline/`. |
| `run_all_harnesses.sh` | Aggregate runner (issue #183): enumerates `tests/run_*.sh`, builds the SDK once per required profile into a shared prefix, and replays every harness against it. Reachable from the suite runner via `bash tests/run_all_tests.sh --with-harnesses`. |
| `baseline/classification.txt` | **The golden classification baseline.** The asserted regression oracle. |
| `baseline/classification/` | Per-pcap fingerprints (one file each), for granular diffs. |
| `baseline/throughput.txt` | Throughput reference snapshot (environment-dependent — compare relative deltas). |
| `baseline/valgrind.txt` | Valgrind leak baseline, or a SKIPPED note + exact command when valgrind is absent. |

## The ASan/UBSan build profile (`BUILD=asan`)

Added to `rules/common.mk`. Builds the libraries with
`-fsanitize=address,undefined -fno-sanitize-recover=all -O1 -g`. This is the
verification vehicle for Phase 2 (run crafted edge-case pcaps through an
ASan-built library to catch OOB reads/writes and UB).

The leading `clean` is mandatory — see
[Agent Environment Notes §5 Sanitizer Build Profiles](../../docs/AGENT_ENVIRONMENT.md#5-sanitizer-build-profiles)
for why.

```bash
make -C sdk clean
make -C sdk BUILD=asan MMT_BASE=/tmp/mmt-asan
make -C sdk BUILD=asan MMT_BASE=/tmp/mmt-asan install
```

The shared objects leave the sanitizer runtime undefined; resolve it at run time
by preloading it (the SDK is loaded via `dlopen`, so the runtime can't be pulled
in from the executable alone):

```bash
gcc -O1 -g -o extract_all extract_all.c \
    -I /tmp/mmt-asan/dpi/include -L /tmp/mmt-asan/dpi/lib -lmmt_core -ldl -lpcap
LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=/tmp/mmt-asan/dpi/lib \
    ./extract_all -t crafted.pcap
```

(Leak detection is left to Valgrind; ASan here targets memory-safety and UB on
untrusted packet input.)

## Capturing / refreshing the baseline

```bash
# from the repo root
tools/phase0/capture_baseline.sh                 # defaults: prefix /tmp/mmt, 300 iters
tools/phase0/capture_baseline.sh --prefix /tmp/mmt --iterations 500 --jobs 8
```

If the mmt-test repo is not at `../mmt-test`, point the script at the data-sets:

```bash
MMT_TEST_DATASETS=/path/to/mmt-test/data-sets tools/phase0/capture_baseline.sh
```

## Using the baseline to gate a later phase

After implementing a phase, re-run the capture and diff the classification
fingerprint. **Any diff is a classification regression to explain.**

```bash
tools/phase0/capture_baseline.sh
git diff --stat tools/phase0/baseline/
git diff tools/phase0/baseline/classification.txt   # must be empty for phases 1-3,5,6
```

- `classification.txt` — **asserted**: must be unchanged unless the phase
  intentionally changes classification (then update the golden in the same PR
  and call it out in the PR body).
- `throughput.txt` — **informational**: pps is environment-dependent; read it as
  a relative trend (expect gains after Phase 4 LTO and Phase 5 hot-path work).
- `valgrind.txt` — **asserted** where valgrind is available: leak summary should
  show no growth (Phase 3 gate).

## CI gate

`.github/workflows/phase0-baseline.yml` enforces these gates on every push
and PR to `main`. The job list below is **generated from the workflow** —
run `bash tools/phase0/ci/check_readme_gates.sh --write` after editing the
workflow (the check mode runs in the `verify-helpers` CI job, so a stale
list fails the build):

<!-- begin-generated: ci-gates -->
- `asan-build` — ASan/UBSan profile compiles
- `list-harnesses` — Enumerate phase0 harnesses
- `harness-*` — harness-${{ matrix.harness }}
- `harness-gate` — harness-gate
- `classification-gate` — Golden classification fingerprint unchanged
- `precision-gate` — Labelled-pcap precision/recall holds or improves (M9, issue #74)
- matrix expansion: `harness-*` fans out to 39 jobs, one per `tools/phase0/tests/run_*.sh`
<!-- end-generated: ci-gates -->

What each gate asserts:

- **`asan-build`** — `make BUILD=asan` must compile and the resulting library
  must carry ASan instrumentation (`__asan_init`). Architecture-independent;
  protects the Phase 2 verification vehicle.
- **`classification-gate`** — runs `tools/phase0/ci/check_classification.sh`,
  which builds+installs the library, classifies a small **self-contained** pcap
  subset (vendored under `ci/pcaps/`, ~0.6 MB, no dependency on the mmt-test
  repo) and diffs the fingerprint against the committed
  `ci/baseline/classification.txt`. Any diff fails the job.
- **`precision-gate`** — runs `tools/phase0/ci/check_precision.sh`, which runs
  the labelled-pcap precision/recall harness (`phase0_precision`) over the
  labelled subset (`ci/labels.txt`) and diffs the micro-averaged metrics
  against the committed `ci/baseline/precision.txt`. Enforces the Phase 7 (M9,
  issue #74) acceptance criterion that precision/recall **holds or improves**.
  Refresh `ci/baseline/precision.txt` (artifact: `phase0-precision-actual`) in
  the same PR when an improvement is intentional.
- **`list-harnesses` / `harness-*` matrix** — the setup job enumerates
  `tools/phase0/tests/run_*.sh` and fans out one `harness-<script>` job per
  file (issue #182), so a newly added harness is gated with no workflow
  edit. Each script builds+installs the SDK under its declared profile into
  a fresh `mktemp -d` prefix (removed by an exit trap) and fails the job on
  a non-zero exit. Locally the same enumeration is driven by
  `run_all_harnesses.sh` (or `tests/run_all_tests.sh --with-harnesses`),
  sharing one SDK build per profile instead of one per harness.

### Not enforced by CI

Equally deliberate — these signals exist but nothing fails on them
(issue #186, F-TEST-017):

- `baseline/` (the full all-golden-pcaps tree under `tools/phase0/baseline/`)
  — needs the external mmt-test data-sets; only the `ci/baseline/` subset is
  gated. Re-run `capture_baseline.sh` manually to refresh it.
- `baseline/throughput.txt` — informational trend, environment-dependent.
- `baseline/valgrind.txt` — asserted only where valgrind is installed; the
  capture records SKIPPED otherwise.
- `tools/phase0/run_all_harnesses.sh` and
  `tests/run_all_tests.sh --with-harnesses` — local aggregate runners; the
  CI gate is the per-harness `harness-*` matrix, not these.
- The `tests/run_all_tests.sh` suites themselves are gated by the
  `unit-tests`/`sanitizer-tests`/`coverage` jobs in `c-cpp.yml`, not by this
  workflow.

When a phase **intentionally** changes classification, refresh the CI baseline in
the same PR. The failing job uploads the freshly-captured fingerprint as the
`phase0-classification-actual` artifact; download it (or run the check locally)
and copy it over the committed baseline:

```bash
tools/phase0/ci/check_classification.sh          # writes ci/baseline/classification.actual.txt on mismatch
cp tools/phase0/ci/baseline/classification.actual.txt \
   tools/phase0/ci/baseline/classification.txt
```

The committed CI baseline must match the CI runner (`ubuntu-24.04`, x86_64).
Protocol classification is expected to be architecture-independent, so the same
fingerprint holds across hosts; if the runner ever disagrees, the gate fails on
the first run and the uploaded artifact is the authoritative runner baseline to
commit. The full local baseline under `baseline/` is the exhaustive,
all-golden-pcaps reference and is **not** enforced by CI (it needs the mmt-test
data-sets).

## Notes & known boundaries

- Plugin loading is **CWD-relative**: the SDK scans `./plugins/` first and only
  falls back to the installed prefix when the working directory has no
  `plugins/` directory (`src/mmt_core/src/plugins_engine.c`). The capture script
  runs the drivers from a neutral temp directory for this reason.
- Pcaps whose link-type `mmt_init_handler` does not support (e.g. DLT_RAW —
  `tcp_segmented_fpm.pcap`) are recorded as `<unclassified: ...>` /
  `<unsupported link-type>` rather than dropped, so the boundary itself is part
  of the stable baseline.
- `phase0_throughput` creates a **fresh handler per iteration** on purpose:
  replaying identical packets through one persistent handler drives stateful
  parsers and the reassembly/session tables into states never seen in real
  capture and can crash. Per-handler init is ~0.01 ms, so this costs nothing
  measurable.
