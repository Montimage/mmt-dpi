# MMT-DPI Agent Guide

C deep-packet-inspection SDK (plain Make, no autotools/cmake). Linux only;
GCC is the supported toolchain. Environment, install and test-runner details:
[docs/AGENT_ENVIRONMENT.md](docs/AGENT_ENVIRONMENT.md) — the single source for
the toolchain line, the `MMT_BASE` prefix contract and the sanitizer rules.

## Commands

- Build (there is no top-level Makefile): `make -C sdk -j$(nproc)` — exit 0 = green; warnings are informational (never `-Werror`)
- Test: `bash tests/run_all_tests.sh` — 30/30 suites pass; standalone (no prior build or install); the runner runs `make -C sdk clean` and builds the SDK once per group for the suites that consume it (`installer` and `sdk_coverage` build their own), so a run discards an existing `sdk/` build. Count, runtime band and exit codes: [docs/AGENT_ENVIRONMENT.md §3](docs/AGENT_ENVIRONMENT.md#3-testing)
- One suite or a subset: `bash tests/run_all_tests.sh hashmap memory`
- Sanitized suites: `SANITIZE=asan|tsan bash tests/run_all_tests.sh` (mirrors `BUILD=asan`/`BUILD=tsan`; tsan re-execs under `setarch -R`)
- Coverage: `bash tests/run_all_tests.sh --coverage` — line coverage of the instrumented `src/` subset, not the whole SDK; whole-SDK per-family numbers: `bash tools/ci/check-sdk-coverage.sh` after that run
- Phase0 gates (golden fingerprint, precision/recall): `MMT_PREFIX=$(mktemp -d) bash tools/phase0/ci/check_classification.sh` and `MMT_PREFIX=$(mktemp -d) bash tools/phase0/ci/check_precision.sh`
- Pre-push tier (minutes): `bash tests/run_all_tests.sh --with-harnesses`
- Lint: `shellcheck $(git ls-files '*.sh')`; cppcheck via `bash tools/ci/run-cppcheck.sh` (pinned version, see [docs/AGENT_ENVIRONMENT.md §1](docs/AGENT_ENVIRONMENT.md#1-toolchain-requirements))
- Doc validators: `for s in scripts/validate-*.sh; do bash "$s" || exit 1; done`
- Optional security engines: `make -C sdk ENABLESEC=1 -j$(nproc)` (requires libxml2-dev)
- Clean: `make -C sdk clean`

## Layout

| Path | Contents |
|------|----------|
| `sdk/Makefile` | Build entry point; `install` and `test` targets |
| `src/mmt_core`, `src/mmt_tcpip` | Core engine and TCP/IP protocol detection |
| `src/mmt_mobile` | Mobile protocol dissectors; `asn1c/` subtree is generated code |
| `src/mmt_business_app`, `src/mmt_dicom` | Business-app and DICOM dissectors |
| `src/mmt_security`, `src/mmt_fuzz_engine` | Compiled only with `ENABLESEC=1` |
| `rules/*.mk` | Every build flag: `MMT_BASE`, `BUILD=asan\|tsan\|coverage`, `ENABLESEC`, `DEBUG`, `SHOWLOG` |
| `tests/` | Standalone unit suites (list in `DEFAULT_SUITES` of `tests/run_all_tests.sh`) |
| `tools/phase0/` | CI baseline gates: golden-pcap classification fingerprint, precision/recall, ASan/TSan harnesses |
| `dist/ZIP/` | Hand-maintained installer sources for the prebuilt ZIP — tracked, edit like any source |

## Constraints

### Never

- Hand-edit the asn1c-generated sources under `src/mmt_mobile/asn1c/` — they are regenerated from ASN.1 specs, so manual edits are silently lost.
- Switch `BUILD=` profiles without the clean step of [docs/AGENT_ENVIRONMENT.md §5](docs/AGENT_ENVIRONMENT.md#5-sanitizer-build-profiles).
- Build or install outside the `MMT_BASE` prefix contract of [docs/AGENT_ENVIRONMENT.md §4](docs/AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior).
- Use `make -C sdk test` as a smoke test: it compiles examples from the installed prefix and fails without a prior `sudo make install`.
- Commit generated artifacts: `sdk/lib/`, `sdk/include/`, `sdk/examples/`, `sdk/bin/`, `build/`, `dist/packages/`.
- Change the phase0 golden-pcap fingerprint silently. The `classification-gate` job ("Golden classification fingerprint unchanged", `.github/workflows/phase0-baseline.yml`) is a required check on `main` (issue #184), so a mismatch blocks the merge.
- Overwrite, reset, clean or drop work you did not create — uncommitted changes or stash entries (see [docs/AGENT_ENVIRONMENT.md §8](docs/AGENT_ENVIRONMENT.md#8-working-tree-gate-and-access-notes)).

### Ask first

- Any golden-fingerprint change: stop and flag the diff. An intentional behavior change regenerates the baselines per `tools/phase0/README.md`.
- Release or branch-protection work: it needs `gh` with admin access ([docs/AGENT_ENVIRONMENT.md §8](docs/AGENT_ENVIRONMENT.md#8-working-tree-gate-and-access-notes)).

## Conventions

- Branches `<type>/<issue>-<short-desc>`; commits follow Conventional Commits with a trailing `(#N)`.
- Minimal diffs: change only what the task requires; never reformat or mass-rename unrelated code.
- Docs are reconciled to code: cite `file:line` when documenting behavior; record resolved ambiguities append-only in `docs/DECISIONS.md`.

## Done when

- `bash tests/run_all_tests.sh` exits 0 after any source change; new behavior gets a test in the matching `tests/` suite.
- After touching `rules/*.mk` or core sources, `make -C sdk -j$(nproc)` (default profile) also exits 0 before pushing.
- A classification-logic change leaves `bash tools/phase0/ci/check_classification.sh` passing.
- A docs change leaves every `scripts/validate-*.sh` passing (the `doc-validators` job runs them as a required `main` check).

## Roles

These are **role briefs, not loadable agent definitions**. `.gitignore` keeps
`.claude/` untracked — `CLAUDE.md` and `AGENTS.md` are the only agent files this
repo tracks — so there is no `.claude/agents/*.md` to load and none is intended.
Adopt a brief by reading it.

### protocol-classifier — protocol detection and classification

Scope: `src/mmt_tcpip`, `src/mmt_mobile`, `src/mmt_business_app`, `src/mmt_dicom`.

- Model new signatures on existing dissectors; reuse match-condition helpers instead of ad-hoc byte scans.
- After every change run the test command of record (*Commands* above) plus the phase0 gates.
- Report: files changed, suites run, fingerprint impact. If the golden fingerprint changes, stop — flag it as an intentional behavior change needing baseline regeneration.

### doc-reconciler — documentation verified against code

Scope: `docs/`, root Markdown, `docs/DECISIONS.md`.

- Verify each doc claim against sources (`rules/*.mk`, `sdk/Makefile`, `src/`, `tests/`); fix or flag unverifiable claims.
- Every non-trivial resolution gets one append-only entry in `docs/DECISIONS.md`: question, answer, source.
- Facts that have a single home stay there: link to [docs/AGENT_ENVIRONMENT.md](docs/AGENT_ENVIRONMENT.md) rather than restating it, and keep `scripts/validate-agent-environment.sh` green.
- Report: files fixed, claims verified, entries appended. Do not reformat docs beyond what the fix requires.

### sanitizer-verifier — memory- and thread-safety verification

Scope: the sanitizer build profiles and the phase0 harnesses.

- Use the recipes in [docs/AGENT_ENVIRONMENT.md](docs/AGENT_ENVIRONMENT.md) §5–§7 and the TSan harness `tools/phase0/tests/run_mt_tsan_test.sh`.
- Report: profile built, commands run, findings with reproducer input. Restore the default tree when done (`make -C sdk clean && make -C sdk -j$(nproc)`).

## Token Efficiency

- Never re-read files you just wrote or edited. You know the contents.
- Never re-run commands to "verify" unless the outcome was uncertain.
- Don't echo back large blocks of code or file contents unless asked.
- Batch related edits into single operations. Don't make 5 edits when 1 handles it.
- Skip confirmations like "I'll continue..." Just do it.
- If a task needs 1 tool call, don't use 3. Plan before acting.
- Do not summarize what you just did unless the result is ambiguous or you need additional input.
