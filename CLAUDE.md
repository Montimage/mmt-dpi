# MMT-DPI Agent Context

C deep-packet-inspection SDK (plain Make, no autotools/cmake). Linux only;
GCC is the supported toolchain. Environment details: @docs/AGENT_ENVIRONMENT.md

## Critical commands

- Build (there is no top-level Makefile): `make -C sdk -j$(nproc)` — exit 0 = green; warnings are informational (never `-Werror`)
- Test: `bash tests/run_all_tests.sh` — suites compile standalone against `src/`, no prior build or install needed; expected result (suite count, runtime band, exit codes): [docs/AGENT_ENVIRONMENT.md §3](docs/AGENT_ENVIRONMENT.md#3-testing)
- Run a subset: `bash tests/run_all_tests.sh hashmap memory`
- Sanitized suites: `SANITIZE=asan|tsan bash tests/run_all_tests.sh` (mirrors `BUILD=asan`/`BUILD=tsan`; tsan re-execs under `setarch -R`)
- Coverage: `bash tests/run_all_tests.sh --coverage` — writes `tests/coverage/coverage.info` (lcov tracefile) and prints the overall line percentage
- Clean: `make -C sdk clean`
- Optional security engines: `make -C sdk ENABLESEC=1 -j$(nproc)` (requires libxml2-dev)

## Architecture map

| Path | Contents |
|------|----------|
| `sdk/Makefile` | Build entry point; `install` and `test` targets |
| `src/mmt_core`, `src/mmt_tcpip` | Core engine and TCP/IP protocol detection |
| `src/mmt_mobile` | Mobile protocol dissectors; `asn1c/` subtree is generated code |
| `src/mmt_business_app`, `src/mmt_dicom` | Business-app and DICOM dissectors |
| `src/mmt_security`, `src/mmt_fuzz_engine` | Compiled only with `ENABLESEC=1` |
| `rules/*.mk` | Every build flag: `MMT_BASE`, `BUILD=asan\|tsan`, `ENABLESEC`, `DEBUG`, `SHOWLOG` |
| `tests/` | Standalone unit suites (suite list in `DEFAULT_SUITES` of `run_all_tests.sh`) |
| `tools/phase0/` | CI baseline gates: golden-pcap classification fingerprint, precision/recall, ASan/TSan harnesses |
| `docs/` | Per-topic design docs; `docs/AGENT_ENVIRONMENT.md` = authoritative env/build/test notes |

## Hard rules

- IMPORTANT: never hand-edit asn1c-generated sources under `src/mmt_mobile/asn1c/` — they are regenerated from ASN.1 specs, so manual edits are silently lost.
- YOU MUST follow the profile-switch clean rule stated in [docs/AGENT_ENVIRONMENT.md §5](docs/AGENT_ENVIRONMENT.md#5-sanitizer-build-profiles) before building `BUILD=asan` / `BUILD=tsan`.
- NEVER use `make -C sdk test` as a smoke test: it compiles examples from the installed prefix and fails without a prior `sudo make install`. Use `bash tests/run_all_tests.sh`.
- Classification logic changes must keep the phase0 golden-pcap fingerprint unchanged — CI blocks the PR otherwise (`.github/workflows/phase0-baseline.yml`). An intentional behavior change requires regenerating baselines per `tools/phase0/README.md`.
- YOU MUST follow the `MMT_BASE` prefix contract stated in [docs/AGENT_ENVIRONMENT.md §4](docs/AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior) when building and installing.
- Never commit generated artifacts: `sdk/lib/`, `sdk/include/`, `sdk/examples/`, `sdk/bin/`, `build/`, `dist/`.

## Workflow preferences

- Minimal diffs: change only what the task requires; never reformat or mass-rename unrelated code.
- After any source change run `bash tests/run_all_tests.sh`; after touching `rules/*.mk` or core sources, also rebuild the default profile before pushing.

## Token Efficiency

- Never re-read files you just wrote or edited. You know the contents.
- Never re-run commands to "verify" unless the outcome was uncertain.
- Don't echo back large blocks of code or file contents unless asked.
- Batch related edits into single operations. Don't make 5 edits when 1 handles it.
- Skip confirmations like "I'll continue..." Just do it.
- If a task needs 1 tool call, don't use 3. Plan before acting.
- Do not summarize what you just did unless the result is ambiguous or you need additional input.
