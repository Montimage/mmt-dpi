# Decision Log

Append-only log of ambiguities resolved during doc-manager runs.

## 2026-07-21

- Q: README.md lists `simple_packet_handler` and `mmt_online` as examples, but neither exists in `src/examples/`. Which should be documented?
  A (doc-manager): Replace with actual examples: `packet_handler` and `mmt_export_info`.
  Source: confirmed absence via `grep` across `src/examples/`.

- Q: DEVELOPMENT.md lists `cmake` as a prerequisite and `TCP_SEGMENT=1`/`STATIC_LINK=1` as build options, but neither exists in the codebase.
  A (doc-manager): Remove `cmake` from prerequisites; remove `TCP_SEGMENT=1` and `STATIC_LINK=1` from build options table; flag them.
  Source: no CMake in `rules/` or `sdk/Makefile`; no `TCP_SEGMENT`/`STATIC_LINK` in `rules/common.mk`.

- Q: DEVELOPMENT.md says `NDEBUG=1` shows debug messages, but the code defines `-DNDEBUG` by default (which disables debug).
  A (doc-manager): Fix description to: "Define `-DNDEBUG` (default build; disables debug() output)".
  Source: `rules/common.mk:38-42`.

- Q: DEPLOYMENT.md references `MMT_SEC_DTLS_CIPHER_ALLOWLIST` env var, but no code reference was found.
  A (doc-manager): Flag as unverified; remove from env var table.
  Source: grep across `sdk/` and `src/` returned no matches.

- Q: DEPLOYMENT.md says ldconfig file is `mmt.conf`, but code uses `mmt-dpi.conf`.
  A (doc-manager): Fix to `mmt-dpi.conf`.
  Source: `sdk/Makefile:70,117`.

- Q: USER_GUIDE.md says plugins and examples are under `MMT_BASE/dpi/`, but code installs plugins to `$(MMT_BASE)/plugins/` and examples to `$(MMT_BASE)/examples/`.
  A (doc-manager): Fix install layout to show correct paths.
  Source: `rules/common.mk:4-7`.

- Q: USER_GUIDE.md says install script installs `cmake`, but the script does not.
  A (doc-manager): Remove `cmake` from dependency list.
  Source: `install.sh` — no cmake reference.

- Q: Compilation-and-Installation-Instructions.md has wrong git URL (`montimage/mmt-dpi` instead of `montimage-projects/mmt-dpi`), wrong example path (`./examples` instead of `src/examples`), and invalid Homebrew packages (`libpth-dev`, `ldconfig`).
  A (doc-manager): Fix all three issues.

- Q: Add-New-Protocol.md references old paths (`lib/protocols/`, `lib/mmt_common_internal_include.h`, `lib/configured_protocols.c`).
  A (doc-manager): Update to current paths under `src/mmt_tcpip/lib/`.
  Source: confirmed paths via `ls` and `grep`.

- Q: Examples.md references `mmt-sdk/sdk/examples/` as example source location and outdated plugin path (`libmmt_tcpip.so.0.100`).
  A (doc-manager): Update to `src/examples/` and remove hardcoded version from plugin path.

- Q: Data-Types.md has wrong path (`../src/mmt_core/public_include/types_defs.h`), wrong type name (`MMT_STRING_LONG_DATA_POINTER` vs `MMT_STRING_LONG_DATA`), and incorrect descriptions for binary/string types.
  A (doc-manager): Fix path, type name, and descriptions.
  Source: `sdk/include/types_defs.h:169-200, 50-72, 89, 101, 106`.

- Q: MMT-Handler.md says `get_active_session_count` returns `mmt_handler_t*`, but it returns `uint64_t`.
  A (doc-manager): Fix return type description.
  Source: `sdk/include/mmt_core.h:209`.

- Q: MMT-Handler.md has wrong evasion_handler callback signature (missing `void * args` parameter) and wrong constant names (`EVA_IP_FRAG_PACKET` vs `EVA_IP_FRAGMENT_PACKET`).
  A (doc-manager): Fix signature and constant names.
  Source: `sdk/include/mmt_core.h:86-90, 105`.

- Q: MMT-Packet.md shows outdated `pkthdr_t` and `ipacket_struct` (missing many fields).
  A (doc-manager): Update to match current struct definitions.
  Source: `sdk/include/data_defs.h:114-163`.

- Q: Prepare-for-a-new-released-version.md references non-existent `mmt-test/` directories and `wall_e` tool.
  A (doc-manager): Replace with Valgrind-based memory leak check using existing `src/examples/`.

- Q: DNS-protocol.md, HTTP2-protocol.md have outdated development task lists and branch info.
  A (doc-manager): Replace with current protocol description.

- Q: Protocol-Modeling.md contains TBD/???/blablabla placeholder text.
  A (doc-manager): Mark as incomplete and redirect to actual code definitions.

- Q: NDN-protocol.md and NDN-packet-format.md reference non-existent `mmt-test/scripts/ndn.lua`.
  A (doc-manager): Flag as unverified/historical.

- Q: Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md references `ARCH=green-arm` which no longer exists.
  A (doc-manager): Document available targets and suggest cross-compiler approach.

- Q: FTP-design.md has placeholder attribute names `MMT_FTP_XXXX_CMD` and `MMT_FTP_XXX_CODE`.
  A (doc-manager): Flag as placeholder names.

- Q: `docs/Install-mmt-sdk-on-CubieBoard-X.md` is an orphaned doc (not linked from any other doc) referencing mmt-sdk 0.1 for a CubieBoard X. It is not linked from `docs/README.md` or `Developer.md`.
  A (doc-manager): Left in place for historical reference but flagged as orphaned. Not linked from any navigation doc.

- Q: Issue #123 asks for c-cpp.yml jobs that "build with BUILD=asan and BUILD=tsan and run bash tests/run_all_tests.sh", but BUILD= is a rules/*.mk variable that only affects SDK library builds — the standalone suites compile directly with gcc and never read it.
  A (issue-resolver): The runner gained a SANITIZE=asan|tsan mode that applies the exact flag sets of the SDK profiles to every suite compile+link line, and suites that build the SDK internally (citrix_ica_detection, http_header_case) forward BUILD=${SDK_BUILD_PROFILE} to their internal make. The workflow matrix carries the literal BUILD=asan / BUILD=tsan tokens mapping them to SANITIZE values.
  Source: `tests/run_all_tests.sh:58-84`, `tests/citrix_ica_detection/run_tests.sh:26-31`, `.github/workflows/c-cpp.yml` (sanitizer-tests job).
- Q: TSan-instrumented suite binaries abort at startup with "ThreadSanitizer: unexpected memory mapping" on modern kernels (vm.mmap_rnd_bits default raised to 32; TSan's fixed shadow layout needs ~28-30 bits).
  A (issue-resolver): tests/run_all_tests.sh re-execs itself once under `setarch $(uname -m) -R` (ASLR disabled) when SANITIZE=tsan, guarded by MMT_TSAN_REEXEC so it happens exactly once. No user/CI action needed.
  Source: `tests/run_all_tests.sh:75-78`.
- Q: Issue #124 suggests gcov+lcov (or gcovr), but neither lcov nor gcovr is installed in the dev environment and the acceptance criteria only require a machine-readable report plus a printed line percentage.
  A (issue-resolver): Implemented with gcov alone (`gcov --json-format` + jq, both shipped with gcc/standard images); the runner emits a genuine lcov-format tracefile at tests/coverage/coverage.info, so lcov tooling can still consume it. System headers outside the repo are excluded from the report.
  Source: `tests/run_all_tests.sh:166-249`.
- Q: docs/AGENT_ENVIRONMENT.md, DEVELOPMENT.md and CONTRIBUTING.md claim 8 suites / `make test` as the test command, but code now has 12 suites and `make test` is an install-dependent trap.
  A (doc-manager): Update suite count to 12 (`tests/run_all_tests.sh:141-154`) and replace `make test` docs with `bash tests/run_all_tests.sh`; add trap note citing `sdk/Makefile:239-242`, `rules/common.mk:4-8`. Fix `NDEBUG=1` description — it suppresses `-DNDEBUG` (keeps debug active) per `rules/common.mk:38-43`.
  Source: `tests/run_all_tests.sh:141-154`, `sdk/Makefile:8-13,239-242`, `rules/common.mk:38-43`.
- Q: CONTRIBUTING.md and Compilation-and-Installation-Instructions.md list `cmake` as a prerequisite and unconditional `libxml2-dev`, and use stale git URL `montimage/mmt-dpi`.
  A (doc-manager): Remove `cmake`; make `libxml2-dev` conditional on `ENABLESEC=1` (`rules/common.mk:76-84`); note `libnghttp2-dev` optional (`rules/common.mk:56-74`); fix URL to `montimage-projects/mmt-dpi.git`.
  Source: `rules/common.mk:56-84`, `install.sh:122-130`.
- Q: docs/DEPLOYMENT.md shows installed plugins under `/opt/mmt/dpi/plugins/` and omits examples path.
  A (doc-manager): Fix to `/opt/mmt/plugins/` and add `/opt/mmt/examples/` per `rules/common.mk:7-8`; plugin load path at `rules/common.mk:30`.
  Source: `rules/common.mk:4-8,30`.
- Q: docs/README.md navigation omits `troubleshooting.md`, `ChronoChat.md`, `External-Attribution.md` and several protocol docs.
  A (doc-manager): Add Troubleshooting, ChronoChat, External-Attribution links; per-protocol docs remain reachable via `Developer.md`.
  Source: `docs/` directory listing.

- Q: Issue #142 (spike) — should the vendored `http_parser` (Joyent/nodejs http-parser 2.5.0 at `src/mmt_tcpip/lib/http_parser.{c,h}`) be updated or replaced? Is there a CVE/deprecation driver, and what is used for HTTP/2?
  A (spike): Keep the vendored parser but bump it to the final upstream release 2.9.4 (Mar 2020). Findings: (1) Current 2.5.0 is 9 years behind HEAD; upstream is now archived and explicitly recommends llhttp for new projects, but llhttp is TS-generated and not a drop-in (different API, rewrite of `http_parser_integration.c` + `proto_http.c` required — high risk, fingerprint impact). (2) 2.5.0→2.9.4 fixes that matter to DPI: OOB read via `strtoul` in `http_parser_parse_url()` (9ce7316, not on the hot path — `proto_http.c:383` only calls `http_parser_execute()` and `request_url_cb` is a no-op — but still reachable), strict `Content-Length` blank/empty rejection (01da95f/3502589, prevents request-smuggling-tolerant parsing), nread accounting and pointer-arithmetic fixes. No CVEs were issued but the fixes are security-hardening. (3) HTTP/2 is NOT parsed by `http_parser`; `src/mmt_tcpip/lib/protocols/http2.c:18` uses a bespoke frame parser (`http2_can_read()` bounds checks added in #146) so no dependency. (4) Bump is trivial and ABI-compatible: only `src/mmt_tcpip/lib/http_parser.h:8-10` version macros and the vendored `.c` change; `http_parser_init`/`http_parser_execute`/`HTTP_PARSER_ERRNO`/`parser->upgrade` contract is unchanged and SDK builds clean (`make -C sdk -j`). Decision: bump to 2.9.4 now, defer llhttp migration unless a future CVE or fingerprint requirement forces it.
  Source: `src/mmt_tcpip/lib/http_parser.h:8-10`, `src/mmt_tcpip/lib/http_parser.c` (vendored 2.5.0 vs nodejs/http-parser@2.9.4), `src/mmt_tcpip/lib/protocols/proto_http.c:372-390`, `src/mmt_tcpip/lib/http_parser_integration.{h,c}`, `src/mmt_tcpip/lib/protocols/http2.c:12-18`, nodejs/http-parser README deprecation notice + tags `v2.5.0`→`v2.9.4` (76 commits).
