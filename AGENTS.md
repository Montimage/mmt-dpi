# MMT-DPI Agent & Role Guide

Etiquette and focused role briefs for autonomous work in this repo.
Project context and commands: @CLAUDE.md · Environment: @docs/AGENT_ENVIRONMENT.md

This guide states no build, test or install command of its own — every one of
them lives in the two documents above. Quote them from there, never from here.

## Etiquette for all agents

- Branches `<type>/<issue>-<short-desc>`; commits follow Conventional Commits with a trailing `(#N)`.
- Docs are reconciled to code: cite `file:line` when documenting behavior; record resolved ambiguities append-only in `docs/DECISIONS.md`.
- Never edit generated trees (`src/mmt_mobile/asn1c/`) or commit build outputs (`sdk/lib/`, `sdk/include/`, `build/`, `dist/`).
- Classification changes must keep the phase0 golden-pcap fingerprint unchanged (`tools/phase0/README.md`). The `classification-gate` job ("Golden classification fingerprint unchanged", `.github/workflows/phase0-baseline.yml`) runs on every PR into `main` and — since issue #184 made the phase0 gates required status checks on `main` — a mismatch blocks the merge.

## Roles

These are **role briefs, not loadable agent definitions**. `.gitignore` keeps
`.claude/` untracked — `CLAUDE.md` and `AGENTS.md` are the only agent files this
repo tracks — so there is no `.claude/agents/*.md` to load and none is intended.
Adopt a brief by reading it.

### protocol-classifier — protocol detection and classification

Scope: `src/mmt_tcpip`, `src/mmt_mobile`, `src/mmt_business_app`, `src/mmt_dicom`.

- Model new signatures on existing dissectors; reuse match-condition helpers instead of ad-hoc byte scans.
- After every change run the test command of record ([CLAUDE.md](CLAUDE.md) → *Critical commands*) plus the relevant phase0 checks (`tools/phase0/README.md`).
- Report: files changed, suites run, fingerprint impact. If the golden fingerprint changes, stop — flag it as an intentional behavior change needing baseline regeneration.

### doc-reconciler — documentation verified against code

Scope: `docs/`, root Markdown, `docs/DECISIONS.md`.

- Verify each doc claim against sources (`rules/*.mk`, `sdk/Makefile`, `src/`, `tests/`); fix or flag unverifiable claims.
- Every non-trivial resolution gets one append-only entry in `docs/DECISIONS.md`: question, answer, source.
- Facts that have a single home stay there: link to [docs/AGENT_ENVIRONMENT.md](docs/AGENT_ENVIRONMENT.md) rather than restating it, and keep `scripts/validate-agent-environment.sh` green.
- Report: files fixed, claims verified, entries appended. Do not reformat docs beyond what the fix requires.

### sanitizer-verifier — memory- and thread-safety verification

Scope: the sanitizer build profiles and the phase0 harnesses.

- Follow the profile-switch clean rule and the `MMT_BASE` prefix contract as stated in [docs/AGENT_ENVIRONMENT.md §5](docs/AGENT_ENVIRONMENT.md#5-sanitizer-build-profiles) and [§4](docs/AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior); this guide states neither of its own.
- Use the recipes in that document (§5–§7) and the TSan harness `tools/phase0/tests/run_mt_tsan_test.sh`.
- Report: profile built, commands run, findings with reproducer input. Restore the default tree when done ([CLAUDE.md](CLAUDE.md) → *Critical commands*).

## Token Efficiency

- Never re-read files you just wrote or edited. You know the contents.
- Never re-run commands to "verify" unless the outcome was uncertain.
- Don't echo back large blocks of code or file contents unless asked.
- Batch related edits into single operations. Don't make 5 edits when 1 handles it.
- Skip confirmations like "I'll continue..." Just do it.
- If a task needs 1 tool call, don't use 3. Plan before acting.
- Do not summarize what you just did unless the result is ambiguous or you need additional input.
