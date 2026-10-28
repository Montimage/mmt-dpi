---
layout: default
title: "Agent Environment Notes"
---

# Agent Environment Notes

This document describes the build/test environment an automated agent (or a
fresh contributor) needs to install, configure, build, and test this
repository without unwritten context. Everything here is derived from the
repository itself; the authoritative sources are:

| Source of truth | What it defines |
|-----------------|-----------------|
| `rules/common.mk` | Compiler flags, `MMT_BASE`, `BUILD=asan`/`tsan`/`coverage`, `ENABLESEC`, debug/valgrind toggles |
| `rules/common-linux.mk` | Linux link rules, release hardening, `ENABLESEC` engines |
| `sdk/Makefile` | Build entry point, `install`/`test` targets, default `MMT_BASE` |
| `tests/run_all_tests.sh` | Master test runner and the 30 standalone suites |

## 1. Toolchain Requirements

Only **Linux** is supported (macOS/Windows are not). The default architecture
is Linux (`sdk/Makefile:1`), with GCC/G++ selected by
`rules/arch-linux.mk:2-3`.

This is the **single source** for the toolchain install line: other documents
link here instead of repeating it. Two kinds of apt line elsewhere in the
repository are deliberately not copies of it — executable package lists, which
have to be runnable (`install.sh`, `tools/ci/build-package.sh`, the CI
workflows), and package sets for a different job (the CubieBoard/ARM notes,
the QoE demo, the prebuilt ZIP, the Debian packaging checklist).

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc g++ make git libxml2-dev libpcap-dev bash pkg-config jq
```

| Package | Why it is needed |
|---------|------------------|
| `gcc`, `make` | The whole build (`rules/common-linux.mk:62` enables LTO for GCC only) |
| `libpcap-dev` | Examples that read pcap files (`src/examples/`); no SDK library links it |
| `libxml2-dev` | Only needed with `ENABLESEC=1` (`rules/common.mk:76-84`) |
| `bash` | Test scripts are bash (`tests/run_all_tests.sh`) |
| `jq` | JSON checks in the `release_gates`, `sdk_coverage` and `resource_bounds` suites and in `--coverage` mode |

The build links no other third-party library (issue #495). This line and the
executable lists — `install.sh`, `tools/ci/install-build-deps.sh`, the rpm
`BuildRequires:` in `sdk/Makefile` and `.github/actions/bootstrap-deps` — are
each checked against `tools/ci/build-deps.txt`, which records what every list
must hold, by `tools/ci/check-dependency-lists.sh`: change a package there
first.

CI builds and tests on `ubuntu-24.04` (GCC 13) — see
`.github/workflows/c-cpp.yml`. That is the reference toolchain. The full
suite also runs on the native `ubuntu-24.04-arm` runner (`unit-tests-arm`)
and with `-funsigned-char` on x86 (`unit-tests-unsigned-char`, through
`EXTRA_CFLAGS` and `MMT_EXTRA_CFLAGS`), so ARM's unsigned plain `char` is
exercised (issue #528). The x86 mirror, like the `-fsigned-char` leg of
`unit-tests`, runs in the merge queue (and on push and the schedule), not on
pull requests (issue #658): both contexts are required, so the queue waits
for them.

**Supported floor (issue #218, F-DEP-207):** GCC ≥ 11 with glibc ≥ 2.34 and
libstdc++6 ≥ 11 — the oldest toolchain the release matrix
(`.github/workflows/release-packages.yml`) still builds on, carried by
Rocky 9 / CentOS Stream 9 and Ubuntu 22.04. The constants live in
`rules/common.mk` (`MMT_GCC_MIN`, `MMT_GLIBC_MIN`, `MMT_LIBSTDCXX_MIN`):
`rules/arch-linux.mk` fails the build below GCC 11 with a message naming
the detected compiler, the generated `.deb` declares the same glibc floor
in its `Depends:` line (`sdk/Makefile` `deb` target) — and the libstdc++
one only for a shipped library that NEEDs libstdc++, which none does since
issue #539 ported the SDK's last C++ source to C — and
the `toolchain-floor` job in `c-cpp.yml` builds the SDK and runs the full
suite, unprivileged, in a digest-pinned `ubuntu:22.04` container (GCC 11.4)
on an `ubuntu-24.04` runner, so the floor is exercised, not just asserted.
The CentOS Stream 9 and Ubuntu 22.04 images retire on 2027-04-30, before
their end of life (issue #516): the `# retire-by:` date on their
`tools/ci/base-images.txt` lines makes `tools/ci/check-image-digests.sh`
warn 60 days ahead and fail from that date. The floor does not move with
them — Rocky 9 (GCC 11, glibc 2.34) stays in the matrix; the schedule and
the floor job's next image are in
[DECISIONS.md](https://github.com/montimage-projects/mmt-dpi/blob/main/docs/DECISIONS.md).

**C dialect and toolchain ceiling (issue #514, F-DEP-301/F-DEP-307):** the
default GCC toolchain (`ARCH=linux`) compiles C as gnu17
(`rules/arch-linux.mk:20-21`) — GCC 11–14 default to it, GCC 15 to gnu23.
`MMT_EXTRA_CFLAGS` is appended after the pin, so its last `-std` wins:
`make -C sdk ENABLESEC=1 MMT_EXTRA_CFLAGS=-std=gnu2x` builds the SDK as C23.
Both apply to C only (C++ keeps `CXX`/`CXXFLAGS`) and to the GCC toolchain
only (`ARCH=linux-clang`/`linux-icc` are unchanged). The `toolchain-ceiling`
job in `c-cpp.yml` runs on `ubuntu-26.04` (GCC ≥ 15, a GitHub preview runner
label) with `MMT_EXTRA_CFLAGS=-std=gnu23`: it builds the SDK with
`ENABLESEC=1` and runs the full suite, whose SDK builds (the runner's shared
ones and the suites' own) inherit the variable and build the SDK as C23; the suites' own test programs keep the
`-std` their `run_tests.sh` pins (GCC 15's C23 default where none is
pinned). The floor job above is unchanged.

**Package dependency declarations (issue #219):** the `.deb` `Depends:` and
the `.rpm` `Requires:` are not hand-maintained lists (the `.rpm`
`BuildRequires:` is a literal list, checked against `tools/ci/build-deps.txt`
by `tools/ci/check-dependency-lists.sh` — issue #495) —
`tools/ci/shlib-deps.sh` derives them at package-build time from the NEEDED
entries `objdump -p` reports for the shipped `.so` files (the glibc floor
above survives as the `libc6`/`glibc` entry; a `libstdc++6`/`libstdc++`
entry would carry the libstdc++ floor, but no shipped library NEEDs
libstdc++ since issue #539).
`tools/ci/build-package.sh` builds with `ENABLESEC=1` and verifies each
artifact with `tools/ci/check-package-deps.sh --verify-package`, which
compares `dpkg-deb -f` / `rpm -qp` output against the derived set and fails
on divergence. One entry is not derived: `mmt-dpi-security` (issue #497)
requires exactly its own `mmt-dpi` version. `libmmt_security` resolves
`libmmt_core` symbols at load time, which NEEDED does not show, and the
check requires that sibling entry.

**Reproducible packages (issue #220, F-CI-011):** `make -C sdk deb` /
`make -C sdk rpm` are byte-deterministic for a given commit — the staging
dir name, the `Built time:`/`Build date:` metadata fields and every staged
file mtime are pinned to `SOURCE_DATE_EPOCH` (honoured when exported;
otherwise derived from the commit's own timestamp in `rules/common.mk`),
never the wall clock. `tools/ci/check-reproducible-build.sh` is the CI gate:
it builds the package twice in the release container and diffs the sha256
sums. A missing git history is a hard error under `CI=true` — it used to
silently downgrade the package revision to a date stamp; local tarball
builds get the deterministic `nogit` revision and a warning instead. Release
tags are gated by `tools/ci/check-release-tag.sh`, which requires the pushed
tag to equal `v$(VERSION)` and, given the tag as an argument as the
`verify-tag` job does, its commit to be an ancestor of `origin/main`
(issue #489 — fail-closed on a missing tag or base ref or a shallow clone)
before the publish job runs. That job alone creates the GitHub Release
(`tools/ci/publish-release.sh`: draft with every asset, then published;
refused when a Release for the tag already exists), and the
`release-alert` job opens an issue when a tag run fails
(`tools/ci/release-alert.sh`). Run without a tag
it checks that `install.sh`'s `RELEASE_TAG_SHA` is the peeled commit of its
`RELEASE_TAG` (issue #484 — skipped when the tag is not fetched, fatal under
`REQUIRE_RELEASE_TAG=1`, as the `version-agreement` job runs it).

Notes:

- Clang is available via `make ARCH=linux-clang`; icc via `ARCH=linux-icc`
  (rule files in `rules/arch-*.mk`). GCC is the default and best-tested path.
- The SDK is plain C: the shared libraries are linked with `$(CC)`
  (`rules/common-linux.mk:271`), so no library NEEDs libstdc++ (issue #539).
  `g++` (pulled in by `build-essential`) stays in the toolchain line for
  the tooling that still compiles C++ — the pinned cppcheck build and the
  hardening self-test's `CXX` case.
- `cppcheck` is not in the toolchain line: only the `lint` job needs it.
  `tools/ci/run-cppcheck.sh` pins the release its findings ratchet
  (`tools/ci/cppcheck-ratchet.txt`) was measured with —
  `CPPCHECK_PINNED_VERSION` (2.22) — because other releases report a
  different total on unchanged code (issue #345). No distribution package
  carries it: the `lint` job runs in the digest-pinned `ubuntu:24.04`
  container and builds it from its sha256-pinned source tarball with
  `tools/ci/install-cppcheck.sh` (issue #518). Under `CI=true` a different
  version fails the script (exit 2); locally it warns and treats the
  ratchet as advisory while the error-severity gate stays enforced. For a
  CI-equivalent local verdict, build it the same way — in an `ubuntu:24.04`
  container with `g++ make python3 curl ca-certificates`, run
  `bash tools/ci/install-cppcheck.sh` — then run the gate there. The
  script has two scan modes (`CPPCHECK_MODE`, issue #653), each with its
  own line in the ratchet: `full`, the default, checks every `#ifdef`
  configuration; `pr` checks only the one the SDK build compiles
  (`--max-configs=1 -DNDEBUG -D_MMT_BUILD_SDK`). The `lint` job runs `pr`
  on pull requests and `full` on pushes, tags, the merge queue and the
  weekly schedule.

### Documentation-site toolchain

The C SDK does not require Ruby. For the documentation site, use Ruby **3.4**
as in CI (`.github/workflows/c-cpp.yml:507-512`), with Bundler to install
the gems and run Jekyll; every workflow's `ruby-version:` is that same
release (issue #517). CI enables `bundler-cache` through `ruby/setup-ruby`
and verifies the committed `docs/Gemfile.lock` under `BUNDLE_FROZEN=true`
(issue #372) — after changing `docs/Gemfile`, regenerate the lock
(`bundle lock`) and commit it or the frozen install fails. The Bundler
release is the lock's `BUNDLED WITH` (4.0.x, issue #520): `ruby/setup-ruby`
installs exactly that one, and an older local Bundler installs it and
restarts with it. With Ruby 3.4 available:

```bash
gem install bundler
(cd docs && bundle install && bundle exec jekyll build)
```

`docs/Gemfile:12-17` defines Jekyll and its plugins. CI builds the site with
`tools/ci/build-docs-site.sh` (`.github/workflows/c-cpp.yml:525`): source and
built-site link checks around a frozen Jekyll 4 build, the lock-unchanged
check, and a `docs/_site/build-manifest.json` recording the renderer versions,
the lock digest and a site digest. GitHub Pages publishes the artifact that
same script builds (`.github/workflows/pages.yml`, issue #386) — there is no
separate deployment-time renderer; `docs/_config.yml` declares the Pages
`url`/`baseurl`, so local builds use the published `/mmt-dpi` prefix too.

No application `.env` file is required: this is a Make-built SDK, configured
through make variables (`sdk/Makefile:8-12`, `rules/common.mk:3-8`), and the
test runner takes shell variables such as `SANITIZE`
(`tests/run_all_tests.sh:8-118`). No application service setup is needed for
the build/test commands below.

## 2. Building

There is no top-level Makefile. The build entry point is `sdk/Makefile`:

```bash
make -C sdk -j$(nproc)
```

Exit code `0` = green build. Warnings in the output (e.g. from vendored asn1c
code) are informational; extra diagnostic warnings are deliberately not
`-Werror` (`rules/common.mk:251-265`), so they never fail the build.

The build produces versioned shared libraries and static archives under
`sdk/lib/` (`libmmt_core.so.$(VERSION)`, `libmmt_tcpip.so.$(VERSION)`,
`libmmt_tmobile.so.$(VERSION)`, `libmmt_business_app.so.$(VERSION)`,
`libmmt_tdicom.so.$(VERSION)`, plus matching `.a` files; the unversioned
`.so` symlinks are created by `make install`, `sdk/Makefile:88-94`), copies
public headers under `sdk/include/` and example sources under
`sdk/examples/` (`sdk/bin/` stays empty in a plain build). It does **not**
require root and does **not** install anything.

Clean rebuild if needed:

```bash
make -C sdk clean && make -C sdk -j$(nproc)
```

### Useful build flags

All flags are passed as make variables, e.g. `make -C sdk DEBUG=1`.

| Flag | Effect | Source |
|------|--------|--------|
| `DEBUG=1` | `-g` instead of `-O3`; asserts/debug() stay active | `rules/common.mk:87-93` |
| `NDEBUG=1` | Keep debug/assert active (suppress `-DNDEBUG`; default build defines `-DNDEBUG`) | `rules/common.mk:38-43` |
| `SHOWLOG=1` | Show `MMT_LOG()` output (`-DDEBUG`). ⚠ Prints decoded, subscriber-identifying fields (IMSI, M-TMSI, UE/eNB IPs, URLs) — build only for captures you may expose, never ship where output is collected (F-SEC-016, #214) | `rules/common.mk:159-171` |
| `VALGRIND=1` | Valgrind-friendly instrumentation | `rules/common.mk:94-98` |
| `TUNE=native` | Opt-in `-march=native` (unsafe for redistributed binaries — off by default) | `rules/common-linux.mk:177-185` |
| `VERBOSE=1` | Print full compile commands | `rules/common.mk:21-24` |
| `MMT_EXTRA_CFLAGS=...` | Extra C flags appended after the gnu17 dialect pin (the last `-std` wins, e.g. `-std=gnu2x`); default GCC toolchain only | `rules/arch-linux.mk:20-21` |
| `MMT_CCACHE=ccache` | Opt-in compiler cache (issue #553): the launcher goes in front of `$(CC)`/`$(CXX)`; unset changes nothing. Make reads it from the environment, so `MMT_CCACHE=ccache bash tests/run_all_tests.sh` caches every SDK the suites build. `CCACHE_BASEDIR` defaults to the checkout; `BUILD=coverage` stays uncached; a missing launcher stops the build. Default GCC toolchain only | `rules/arch-linux.mk:73-85` |

## 3. Testing

This section is the **single source** for the test-runner contract — the command,
the suite count and the runtime band. Other documents name the command and link
here for the expected result.

```bash
bash tests/run_all_tests.sh
```

Expected result: **30/30 suites pass**, total runtime roughly **60–240 s** on
a typical development machine (measured: 103 s for the full run, against
201 s on the same machine before the shared builds of issue #654) — the wall
clock is dominated by SDK builds (the shared ones below, plus the own builds
of `installer` and `sdk_coverage`), not by the assertions. Exit code `0` on
success, `1` on any failure. The runner has no `-j` option: the 30 suites run
sequentially. The suite list lives in `DEFAULT_SUITES`
(`tests/run_all_tests.sh:245-276`)
(`tests/run_all_tests.sh`):
`hashmap`, `memory`, `fault_injection`, `core_engine`, `hexdump`, `mmt_utils`,
`mmt_inet_ntop`,
`avltree`, `citrix_ica_detection`, `http_header_case`, `s1ap_ngap_decode`,
`rule_engine`, `radius_hardening`, `nas_ies_tail`, `installer`,
`dicom_dissector`, `ndn_dissector`, `business_app`, `proto_classifiers`,
`dpi_profiles`, `fuzz_verdicts`, `precision_metrics`, `installed_consumer`,
`release_gates`, `parser_boundaries`, `resource_bounds`,
`tcp_pending_order`, `sdk_coverage`, `docs_lifecycle`, `docs_onboarding`.
`fuzz_verdicts`, `precision_metrics`, `release_gates` and `sdk_coverage` are
delegate suites for CI self-tests living under `tools/ci/tests/` — the fuzz
gate's verdict handling, regression replay and libFuzzer mode
(`test-fuzz-verdicts.sh`, issues #370/#486/#530) and its scheduled-failure
alert (`test-fuzz-alert.sh`), the
precision-gate metric accounting (`test-precision-metrics.py`, issue #373,
plus the accuracy-corpus oracle self-test `test-accuracy-corpus.py`, issues #389/#390),
the exact-release-SHA publish gate (`test-release-gates.py`, issue
#371, plus the cppcheck version-pin self-test `test-cppcheck-version.sh`,
issue #345, and the version-agreement self-test `test-version-agreement.sh`,
issue #483, the release-tag pin self-test `test-release-tag-pin.sh`, issue
#484, the single-publisher self-test `test-release-publish.sh`, issue
#489, the vendored-inventory self-test `test-vendored-components.py`,
issue #496, the release-hardening self-test
`test-hardening-identity.sh`, issue #508, which evaluates the makefiles
without compiling, and the path-to-test selection self-test
`test-classify-changes.sh`, issues #528/#552/#656, which also runs the
test-map checker `tools/ci/check-test-map.sh`, the public-API contract
checker self-test `test-api-contracts.sh` and the ABI-diff self-test
`test-abi-diff.sh`, issue #525, and the plugin export-gate self-test
`test-exported-symbols.sh`, issue #534, the phase0 harness-shard self-test
`test-harness-shards.sh`, issue #655, the shared-build self-test
`test-shared-sdk-build.sh`, issue #654, which drives a copy of the runner
over fake suites with a stub `make`, and the weak-type ratchet self-test
`test-weak-types.sh`, issue #539, which proves the `opaque` metric of
`tools/ci/count-weak-types.sh` fails on fixture headers) and the SDK integration coverage path (`test-sdk-coverage.sh`, issue
#387); the first three build nothing, `sdk_coverage` builds its own
`BUILD=coverage` SDK whatever the mode and cleans `sdk/` afterwards. `installed_consumer` (issue #374) drives the
other
`tools/ci/tests/` payload — `run-installed-consumer.sh` +
`installed_consumer.c` — against a throwaway ENABLESEC=1 install prefix.
`docs_lifecycle` (issue #392) checks the `path:line` citations of the
embedding lifecycle in `docs/USER_GUIDE.md` §3 (and of the handler and
fragment-limit API in `docs/MMT-Handler.md`, issue #396) and compiles and runs the
installed `packet_handler.c` example against a throwaway install prefix.
`docs_onboarding` (issue #393) runs the first-run steps shown in
`docs/_includes/first-example.md` verbatim from an empty directory — fetch
the published `docs/first-run/hello_packet.c` and `traffic.pcap`, compile
against a throwaway install prefix, compare the output with the displayed
one — and checks that the capture is regenerated byte-for-byte by
`tests/docs_onboarding/make_traffic_pcap.py`. It fetches from the `docs/`
source tree by default; `DOCS_SITE_DIR=docs/_site` (relative to the repository
root) points it at a built site, whose rendered landing page it then checks —
the `verify-helpers` CI job (issues #396, #659) runs it that way after
`tools/ci/build-docs-site.sh`.

Key property for agents: these suites are **standalone** — no prior build, no
install, no `sudo` needed. Most suites' `run_tests.sh` compiles the test
directly against sources under `src/` with plain `gcc`; suites that need the
built SDK (`hashmap`, `citrix_ica_detection`, `http_header_case`,
`s1ap_ngap_decode`, `rule_engine`, `radius_hardening`, `nas_ies_tail`, `installer`,
`installed_consumer`, `parser_boundaries`, `sdk_coverage`, `docs_lifecycle`, `docs_onboarding`, and the engine
leg of `fault_injection`, `tests/fault_injection/run_tests.sh:115-117`) run `make -C sdk clean` and build
it themselves into a throwaway prefix when run on their own
(`bash tests/<suite>/run_tests.sh`), so running them discards an existing
`sdk/` build.

**Shared SDK builds (issue #654).** Under the runner, the suites that only
consume an installed SDK do not build it. Before the first suite, the runner
builds each group the selected suites need once, into its own throwaway
prefix (`tests/run_all_tests.sh:285-335`): `default` for `hashmap`,
`fault_injection` (not under `SANITIZE`, which skips its engine leg),
`citrix_ica_detection`, `http_header_case`, `s1ap_ngap_decode`,
`radius_hardening`, `nas_ies_tail`, `parser_boundaries`, `docs_lifecycle` and
`docs_onboarding`; `enablesec` (`ENABLESEC=1`) for `rule_engine` and
`installed_consumer` — incremental on top of `default` when both are needed,
since `ENABLESEC=1` only adds the engine objects (`tests/run_all_tests.sh:174-186`).
Each build is logged as `sdk_build <n>: group=<g> profile=<p>`, followed by
`sdk_builds=<n>` and a `Shared SDK builds:` line in the result table; a full
run makes 2. A failed shared build fails the run before any suite. Each
consumer runs with `MMT_SDK_PREBUILT=1` and `MMT_PREFIX` (`MMT_FI_PREFIX` for
`fault_injection`) naming its group's prefix, and refuses to run when that
prefix holds no installed SDK. `installer` and `sdk_coverage` test the build
and install themselves and keep their own builds, so a run still discards an
existing `sdk/` build. You
can run one suite by passing its directory name:

```bash
bash tests/run_all_tests.sh hashmap memory   # subset
```

A listed suite whose `run_tests.sh` is absent counts as **failed**, not
skipped — the runner exits non-zero (issue #186).

**Public-API contracts and the ABI diff (issue #525).** `core_engine` also
builds `test_api_contracts`, one compiled `CONTRACT()` entry per `MMTAPI`
function (`tests/core_engine/test_api_contracts.c`), then runs
`tools/ci/check-api-contracts.sh`, which fails when a name printed by
`tools/ci/check-public-decls.sh --list` (which itself exits 2 on an `MMTAPI`
declaration without the `MMTCALL` marker) has no entry, an entry names no
`MMTAPI` function, or the error-path waivers differ from
`tests/core_engine/api-contract-waivers.txt`: a new export fails the suite
until it has a contract. `tools/ci/abi-diff.sh` builds the v1.9.1 tag and
`HEAD` in temporary git worktrees (release profile plus `-g`; the checkout's
`sdk/` is untouched) and runs libabigail's `abidiff` per library; the
`abi-diff` job in `c-cpp.yml` runs it, plus a symbol-level leg against the
shipped v1.9.1 `.deb`, both with `--fail-on incompatible`, as a required
context (issue #536): an incompatible change fails unless the library's
SONAME moved — every library is linked as `lib<name>.so.$(SOVERSION)`
(`SOVERSION` at the end of `rules/common.mk`), and `make install` and the
packages add the `lib<name>.so.$(SOVERSION)` runtime link. Locally it needs
`abigail-tools` (or `ABIDIFF=/path/to/abidiff`) and a fetched `v1.9.1` tag:
`bash tools/ci/abi-diff.sh --fail-on incompatible --report abi.txt`.

### Suite modes: sanitizers and coverage

`tests/run_all_tests.sh` has two opt-in modes (`tests/run_all_tests.sh:8-118`):

- `SANITIZE=asan bash tests/run_all_tests.sh` — compiles every suite with
  ASan + UBSan (same flag set as the SDK's `BUILD=asan`,
  `rules/common.mk:120-127`) and sets `ASAN_OPTIONS=detect_leaks=0`
  (leak detection stays with Valgrind). The shared builds and the SDK-building suites inherit `BUILD=asan` for their
  SDK build, except `fault_injection`: its engine leg is skipped under sanitizers
  while its unit leg still runs (`tests/fault_injection/run_tests.sh:97-102`).
- `SANITIZE=tsan bash tests/run_all_tests.sh` — same with TSan
  (`rules/common.mk:150-157`). On kernels with high-entropy ASLR the runner
  re-execs itself once under `setarch -R`
  (`tests/run_all_tests.sh:106-109`).
- `bash tests/run_all_tests.sh --coverage` — instruments the suites with gcov,
  aggregates all `.gcda`, and writes an lcov-format tracefile of **library
  (`src/`) sources only** to `tests/coverage/coverage.info` plus the library
  line percentage, instrumented-file count/list and
  `tests/coverage/summary.json` in stdout
  (`tests/run_all_tests.sh:373-499`). Requires `gcov` (shipped with
  gcc) and `jq`; no lcov install needed. The coverage CI job enforces the
  committed floor `tests/coverage/floor.json` — both counters plus the
  required sources it names — via `tools/ci/check-coverage-floor.sh`.
  The mode also exports `SDK_BUILD_PROFILE=coverage`
  (`tests/run_all_tests.sh:120-129`), so the shared builds and every
  SDK-building suite build the `BUILD=coverage` profile (§5). Their consumers
  write counters next to the in-tree objects under `src/`, which survive the
  throwaway prefix's deletion; the runner harvests them with
  `tools/ci/sdk-coverage.sh` after each suite, before the next suite's SDK
  rebuild would delete them (`tests/run_all_tests.sh:213-232`). Right after
  each shared build the runner copies the `.gcno` notes it left under `src/`,
  then deletes them from `src/`; a consumer's counters are harvested against a
  fresh copy of its group's notes, so its per-suite record is the one its own
  build gave before issue #654. `summary.json` then gains a `cohorts`
  object and `tests/coverage/coverage-combined.info` is written; the
  top-level keys and `coverage.info` stay unit-only. The harvest also reads
  the `.gcno` of every object that wrote no `.gcda` (compiled, never loaded)
  at count 0, so zero-hit sources stay in the denominator (issue #388), and a
  run that built a `BUILD=coverage` SDK ends with `make -C sdk clean` so no
  coverage objects are left for a later plain build. A full `--coverage`
  run (no suite named) then replays the phase0 harnesses against one
  `BUILD=coverage` SDK — `tools/phase0/run_all_harnesses.sh --profile
  coverage`, which skips the four harnesses of its `COVERAGE_SKIP` list
  (reasons in `tools/phase0/README.md`) — and harvests that build once into
  the `harness` cohort (`tests/run_all_tests.sh:341-371`, issue #524). The
  arm counts as one extra entry in the result table (31 under `--coverage`)
  and its failure fails the run. `--coverage` cannot be
  combined with `SANITIZE` (exit 2): both select the SDK profile.
- `bash tests/run_all_tests.sh --with-harnesses` — after the suites, runs
  every phase0 harness (`tools/phase0/tests/run_*.sh`) via the aggregate
  runner `tools/phase0/run_all_harnesses.sh`, which builds the SDK once per
  required profile (asan / tsan / default) into a shared prefix and replays
  all harnesses against it (`tests/run_all_tests.sh:501-517`). The arm counts
  as one extra entry in the result table; any harness failure fails the
  invocation. Runtime is minutes, not seconds — the suites build nothing for
  it, the runner's shared builds dominate.

The modernization task's **30-file coverage scope** refers to an audit-time
instrumented subset, not all library sources and not a fixed runner limit.
The 2026-09-22 audit at commit `2ab7b73516113009622cb3d32194d20121457010`
reported 82.9% (5,660/6,831 lines) over those 30 files; this is historical
evidence, not a new measurement (provenance recorded in [DECISIONS.md](https://github.com/montimage-projects/mmt-dpi/blob/main/docs/DECISIONS.md)).
Coverage includes only the `src/` files represented in emitted gcov data
(`tests/run_all_tests.sh:397-401`); its percentage uses the lines in that
subset, so it must not be reported as whole-library coverage. The current
run's exact scope is `instrumented_sources` and `instrumented_files` in
`summary.json` (`tests/run_all_tests.sh:458-472`). The committed minimum is
**42 instrumented files**, alongside a **73.7%** line floor and required
source names (`tests/coverage/floor.json:2-10`); the 30-file audit cohort
does not change that floor. Consult a fresh summary for the current count.

The `cohorts` object (issue #387) names five denominators, each stated in
its `denominator` field (`harness` only in a full run, issue #524);
whole-SDK coverage is reported separately below:

| Cohort | Denominator |
|--------|-------------|
| `unit` | `src/` lines recorded by the unit-suite binaries — the records the top-level keys and the floor measure |
| `sdk_integration` | `src/` lines of the `BUILD=coverage` SDK builds the SDK-building suites used (shared or their own) — lines their consumers ran plus zero-hit objects at count 0 — with a per-suite breakdown in `suites` |
| `harness` | `src/` lines of the one `BUILD=coverage` SDK build the phase0 harnesses ran against (`run_all_harnesses.sh --profile coverage`), harvested once after the arm — lines they ran plus zero-hit objects at count 0 |
| `combined` | the union of the three above, one record per repo-relative path and line (logical and physical checkout paths are merged), counts summed |
| `generated_asn1c` | lines under `src/mmt_mobile/asn1c/` from any cohort, excluded from the four above |

**Whole-SDK accounting (issue #388).** `bash tools/ci/check-sdk-coverage.sh`
(after a full `--coverage` run) reconciles `coverage-combined.info` with the
handwritten sources the SDK object lists build (`make ENABLESEC=1`), writes
`tests/coverage/sdk-coverage.json` and prints line coverage per family —
`core`, `tcpip`, handwritten `mobile`, `business_app`, `dicom` and the
optional ENABLESEC=1 cohort `security_fuzz` — plus `whole_sdk` (the five
default families, its own denominator), the fixed 30-file `original_cohort`
of the audit, and the recorded exclusions: generated asn1c, vendored llhttp
(`tools/ci/vendor-paths.txt`) and the handwritten sources justified in
`tests/coverage/floor.json` (`sdk.excluded_sources`). Branch coverage is Not
Assessed. The coverage CI job fails when a built handwritten source is
missing from the records, a tracked one is neither built nor justified, a
family measures nothing or drops below its `sdk.family_floors` entry
(issue #524: core 85.3, tcpip 60.3, mobile 74.3 since issue #532,
business_app 88.8, dicom 88.1, security_fuzz 70.4), the original cohort drops below 82.9% or the
whole SDK drops below `sdk.whole_sdk_line_pct` (measured 65.53% at issue
#524 with the harness cohort, floor 64.5%). The same job runs
`tools/ci/report-uncovered-runs.sh` as a gate: a contiguous run of more than
10 uncovered lines in `coverage.info` fails it (issue #524).

CI runs both modes on every push/PR to main (`.github/workflows/c-cpp.yml`,
jobs `sanitizer-tests` and `coverage`); the coverage job uploads
`tests/coverage/` as a workflow artifact.

## 4. `MMT_BASE` Install-Prefix Behavior

This section is the **single source** for the `MMT_BASE` prefix contract; other
documents link here.

`MMT_BASE` is the install prefix. Defaults:

- `rules/common.mk:3` — `MMT_BASE ?=/opt/mmt` (used by compile-time paths)
- `sdk/Makefile:8-12` — when `MMT_BASE` is unset, `make install` targets
  `/opt/mmt`

### Install, loader registration and uninstall (issue #485)

- **`make install` never compiles.** It consumes the artifacts of a prior
  `make -C sdk` and refuses (`--check-built`, `sdk/Makefile:70-80`) when
  there is no build, or when the build's baked-in plugin directory is not
  this install's `$(MMT_PLUGINS)` — build and install with the same
  `MMT_BASE`. So `sudo make install` runs no compiler as root.
- **The loader is registered by privilege, not by prefix**
  (`sdk/Makefile:58-68`). `LDCONF=auto` (default): an install run as root
  writes `/etc/ld.so.conf.d/mmt-dpi.conf` naming `$(MMT_LIB)` and runs
  `ldconfig`, whatever `MMT_BASE` is; an unprivileged install touches no
  system path and prints the `LD_LIBRARY_PATH` to use. `LDCONF=0` opts a
  root install out; `LDCONF=1` forces registration; `LDCONF_DIR` and
  `LDCONFIG` relocate the drop-in and the command (the installer suite uses
  a staged directory and a fake `ldconfig`).
- **`make -C sdk MMT_BASE=<prefix> uninstall`** (`sdk/Makefile:183-224`)
  removes exactly the entries `install` recorded in
  `<prefix>/.mmt-dpi-manifest` (one path per line, relative to the prefix,
  merged across reinstalls), then the SDK directories left empty (`rmdir`,
  deepest first — never `rm -rf` on a tree and never a directory above the
  prefix), and the drop-in when it names that prefix's `dpi/lib`; files
  another product put under the prefix — even inside `examples/` or
  `dpi/include/` — survive. A symlinked manifest is refused, the manifest
  is written via `mktemp` + rename (never through a planted symlink), and an
  entry is removed only when its directory resolves (`cd -P`) inside the
  real prefix, so a directory symlink under the prefix cannot redirect a
  root uninstall; keep the prefix writable only by the installing user.
  An install that predates the manifest is
  reconstructed from the checkout's `sdk/include` and `sdk/examples` when
  they exist; otherwise only the `libmmt_*` libraries and plugins go and the
  include/examples trees are kept with a warning. `dist-clean` is kept as an
  alias. From the one-command installer:
  `bash install.sh --uninstall [--prefix <dir>]`, which applies the same
  manifest rules (and writes the manifest itself after installing from the
  pinned tag, whose Makefile predates it).
- **Prefix guard.** `install` and `uninstall` refuse an unsafe layout before
  touching anything: `MMT_BASE` and each of `MMT_DPI`, `MMT_LIB`, `MMT_INC`,
  `MMT_PLUGINS`, `MMT_EXAMS` must be absolute, at most 256 characters of
  `[A-Za-z0-9._/-]` (no whitespace or glob character), without an empty,
  `.` or `..` component or a trailing slash (so `/`, `//`, `/.` and
  `/opt/*` are refused), and each SDK directory must lie strictly under
  `MMT_BASE`. `install.sh`'s `validate_mmt_base` applies the same rules.
- The root leg (install as root → drop-in + `ldconfig -p`, the installed
  consumer with `LD_LIBRARY_PATH` unset, uninstall → nothing left) writes
  `/etc`, so it runs only in a disposable container:
  `tools/ci/tests/run-root-install.sh`, the `root-install` job of
  `.github/workflows/c-cpp.yml`. Never run it on a development host.

### The `make test` trap

`sdk/Makefile`'s `test` target (`sdk/Makefile:621-626`) compiles the
`proto_attributes_iterator` example **from the installed prefix**:

```
$(MMT_EXAMS)/proto_attributes_iterator.c  # = $(MMT_BASE)/examples/...
-I $(MMT_INC) -L $(MMT_LIB)               # = $(MMT_BASE)/dpi/{include,lib}
```

So a bare `make -C sdk test` silently depends on a previous
`sudo make install` into `/opt/mmt` — without it, the target fails to find
the example source or links against stale libraries. This is why the agent
test command of record is `bash tests/run_all_tests.sh`, which has no such
hidden dependency.

### Isolating with `MMT_BASE`

To exercise the real install flow without root, use a unique writable prefix.
`MMT_BASE` redirects installation only: build artifacts still live in the
checkout's `sdk/` and source object directories (`rules/common.mk:187-206`,
`rules/common.mk:467-469`). This subshell removes its temporary installation
and restores a clean default build on exit:

```bash
(
  set -e
  mmt_prefix=$(mktemp -d /tmp/mmt-sandbox.XXXXXX)
  trap 'rm -rf -- "$mmt_prefix"; make -C sdk clean && make -C sdk -j$(nproc)' EXIT
  make -C sdk clean
  make -C sdk MMT_BASE="$mmt_prefix" -j$(nproc)
  make -C sdk MMT_BASE="$mmt_prefix" install
  # Libraries: "$mmt_prefix/dpi/lib"; headers: "$mmt_prefix/dpi/include"
  # Plugins: "$mmt_prefix/plugins"; example sources: "$mmt_prefix/examples"
  # Run your compiled consumer with LD_LIBRARY_PATH="$mmt_prefix/dpi/lib".
)
```

The plugin repository path is baked into `plugins_engine.o` as
`PLUGINS_REPOSITORY_OPT` (`-DPLUGINS_REPOSITORY_OPT=\"$(MMT_PLUGINS)\"`,
`rules/common.mk:630`; only that object carries it, issue #553). `plugins_engine.o` depends on a stamp file holding
the plugin directory it was compiled with (`sdk/Makefile:25-29`): a build
with a different `MMT_BASE` recompiles exactly that object, a rebuild with
the same one compiles nothing, and `make install` — which never builds —
refuses a mismatch. Keep `MMT_BASE` identical across build/install
invocations so compilation and installation use one path.

## 5. Sanitizer Build Profiles

Two sanitizer profiles exist in `rules/common.mk`, plus the `BUILD=coverage`
profile below (all add flags to `CFLAGS` and `CXXFLAGS` so they reach the
shared-library link lines):

> **⚠ Always `make -C sdk clean` before switching build profiles.**
> *(This warning is the single source for the rule; other documents link here.)*
> Object rules depend on source timestamps only (`rules/common.mk:467-469`) —
> changing `BUILD=` does *not* invalidate existing `.o` files, so building
> `BUILD=asan` on top of a plain tree relinks sanitized `.so` files from
> non-instrumented objects and reports success. Clean first, then build the
> new profile.

### `BUILD=asan` — AddressSanitizer + UBSan

Defined at `rules/common.mk:100-127`. Verification vehicle for memory-safety
hardening: catches OOB reads/writes, use-after-free, and UB on untrusted
packet input.

```bash
(
  set -e
  mmt_prefix=$(mktemp -d /tmp/mmt-asan.XXXXXX)
  trap 'rm -rf -- "$mmt_prefix"; make -C sdk clean && make -C sdk -j$(nproc)' EXIT
  make -C sdk clean
  make -C sdk BUILD=asan MMT_BASE="$mmt_prefix" -j$(nproc)
  make -C sdk BUILD=asan MMT_BASE="$mmt_prefix" install
  # Compile any consumer with ASan/UBSan before running it against this prefix.
)
```

Install copies example sources; it does not compile `extract_all`. For an
executable sanitizer test, use `SANITIZE=asan bash tests/run_all_tests.sh`
from §3. Leak detection is left to Valgrind; ASan here targets memory safety/UB.

### `BUILD=tsan` — ThreadSanitizer

Defined at `rules/common.mk:129-157`. Verification vehicle for thread-safety
work (registry mutexes, per-session state). TSan only sees races in code
compiled with `-fsanitize=thread`, so both the SDK and the multi-threaded
harness must be built with this profile — see
`tools/phase0/tests/run_mt_tsan_test.sh` for the full pipeline and
[THREADING.md](./THREADING.md) for what it verifies.

```bash
(
  set -e
  mmt_prefix=$(mktemp -d /tmp/mmt-tsan.XXXXXX)
  trap 'rm -rf -- "$mmt_prefix"; make -C sdk clean && make -C sdk -j$(nproc)' EXIT
  make -C sdk clean
  make -C sdk BUILD=tsan MMT_BASE="$mmt_prefix" -j$(nproc)
  make -C sdk BUILD=tsan MMT_BASE="$mmt_prefix" install
)
```

In both profiles the release-hardening block (LTO, FORTIFY, stack protector,
RELRO — `rules/common-linux.mk:85-193`) is automatically disabled, and the
`-Wl,-z,defs` self-containedness guard is skipped because sanitizer runtime
symbols are intentionally left undefined (`rules/common-linux.mk:236-248`).
In a release build the block is keyed on the compiler's identity, read from
its preprocessor macros, so `CC=/usr/bin/gcc` or `CC=gcc-13` is hardened like
`CC=gcc`; a `$(CC)` identified as neither GCC nor Clang skips it with a build
`$(warning)`, and LTO needs only `$(CC)` to be GCC: the libraries are
compiled and linked by `$(CC)` since issue #539 (issue #508 had required
`$(CC)` and `$(CXX)` to be the same GCC release while the link ran through
`$(CXX)`). `bash tools/ci/check-hardening-flags.sh --built [DIR...]`
checks built libraries (default `sdk/lib/`); the release workflow runs it
on the installed packages.

### `BUILD=coverage` — gcov instrumentation

Defined at `rules/common.mk:548-566` (issue #387): `-g -O0 --coverage`, with
the release-hardening block disabled as for the sanitizers; the
`-Wl,-z,defs` guard stays on, because `--coverage` links libgcov into each
library. `bash tests/run_all_tests.sh --coverage` selects it for every
SDK-building suite (§3). Counters are written next to the in-tree objects
under `src/` (redirect them with `GCOV_PREFIX`/`GCOV_PREFIX_STRIP`), and the
next build of any profile deletes them, so harvest them first with
`tools/ci/sdk-coverage.sh harvest`. The clean-before-switching rule applies.

## 6. `ENABLESEC=1` Security Engines Flag

`ENABLESEC` gates two optional libraries — `libmmt_security` and
`libmmt_fuzz` — which are otherwise not built at all:

- Object/header selection: `rules/common.mk:201-203, 225-228, 310-313`
- Link rules and libxml2 wiring: `rules/common-linux.mk:6-12, 249-252, 260-264, 297-313`
- Install symlinks for both engines: `sdk/Makefile:89-90, 341-342`

Usage (requires `libxml2-dev`):

```bash
make -C sdk ENABLESEC=1 -j$(nproc)
```

Without the flag those sources are skipped entirely, so a missing libxml2 is
only fatal when `ENABLESEC=1`.

With the engines built, `make -C sdk deb`/`rpm` stages them into a second
package, `mmt-dpi-security` (issue #497): `libmmt_security` is
GPL-3.0-or-later, unlike the rest of the SDK. That package requires the same
`mmt-dpi` version. Each package's SPDX licence expression is `PKG_LICENSE`
or `SEC_PKG_LICENSE` in `sdk/Makefile`, and
`python3 tools/ci/vendored-components.py notices --check` verifies both.

## 7. Quick Verification Checklist

Run this after setting up a fresh environment; all four commands must succeed:

```bash
make -C sdk -j$(nproc)          # exit 0, green build (seconds to ~2 min depending on machine)
bash tests/run_all_tests.sh     # 30/30 suites PASSED, exit 0 (60–240 s)
make -C sdk ENABLESEC=1 -j$(nproc)   # exit 0 (optional engines build)
make -C sdk clean && make -C sdk BUILD=asan -j$(nproc)   # exit 0 (sanitizer profile)
```

If any of these fails, fix the environment before attempting code changes —
upstream tasks assume this baseline is green. After sanitizer/`ENABLESEC`
experiments, restore the default tree with `make -C sdk clean &&
make -C sdk -j$(nproc)`.

## 8. Working-Tree, Gate and Access Notes

Facts a later agent cannot infer from the build system alone (issue #480).

- **The maintainer's #475 Debian work is not on `main`.** It lives on the
  open PR #476 (branch `feat/475-publish-mmt-dpi-through-official-ubuntu`)
  and, while it is in progress, in the maintainer's local checkout as
  uncommitted changes: about a dozen modified tracked files plus the untracked
  `debian/`, `tools/ci/build-debian-package.sh` and
  `tools/ci/build-source-tarball.sh`. Run `git status --short` before
  starting any modernization task; if that work is in the tree, land it on its
  own branch (`git switch -c <branch> && git add -A && git commit`) or stash
  it (`git stash push -u -m "#475 Debian work"`) before P0 starts. Never
  overwrite, reset, `git clean`, pop or drop it — and never pop, apply or drop
  a stash entry you did not create.
- **Phase0 gate commands.** Both gates build and install the SDK themselves;
  give each a scratch prefix (`MMT_PREFIX`; unset, each gate installs into a
  fresh `mktemp -d /tmp/mmt-phase0.XXXXXX` it removes on exit — issue #508):

  ```bash
  MMT_PREFIX=$(mktemp -d) bash tools/phase0/ci/check_classification.sh   # golden fingerprint
  MMT_PREFIX=$(mktemp -d) bash tools/phase0/ci/check_precision.sh        # precision/recall
  ```

  **Baseline-regeneration rule** (`tools/phase0/README.md`, *What each gate
  asserts*): a fingerprint mismatch is a stop — flag it. Only for an
  intentional classification change, copy
  `tools/phase0/ci/baseline/classification.actual.txt` over
  `tools/phase0/ci/baseline/classification.txt` (likewise
  `precision.actual.txt` over `precision.txt`) in the same PR, with the reason
  in the PR body. The two baselines are reviewed separately: one changing
  never requires regenerating the other.
- **Pre-push tier.** `bash tests/run_all_tests.sh --with-harnesses` — the 30
  suites plus every phase0 harness (§3). Run it before pushing a change to
  core sources, `rules/*.mk` or anything a harness exercises; it takes
  minutes.
- **Local gate runner (issue #553).** `bash tools/ci/local-gates.sh --fast`
  runs the `run:` steps of the required `lint`, `verify-helpers` and
  `doc-validators` jobs, read from `.github/workflows/c-cpp.yml` itself, so
  it cannot drift from them; `--full` adds `bash tests/run_all_tests.sh` and
  the two phase0 gates. By default it runs them in a container built once
  from the `lint` job's digest-pinned `ubuntu:24.04` with the pinned cppcheck
  (needs docker or podman, else exit 2); `--host` runs them on this machine,
  `--list` prints them. The image's Ruby is Ubuntu 24.04's 3.2, not CI's 3.4.
- **Pull-request test selection (issue #656).** On a pull request CI runs
  only the tests the changed paths select: `tools/ci/classify-changes.sh`
  reads `tools/ci/test-map.txt` (the five tiers are in `CONTRIBUTING.md`,
  *Required checks and review*); pushes and the merge queue run everything.
  A new suite in `DEFAULT_SUITES` or a new `tools/phase0/tests/run_<stem>.sh`
  needs a map entry — `bash tools/ci/check-test-map.sh` exits 1 naming what
  is missing or mis-tagged — and
  `bash tools/phase0/run_all_harnesses.sh --only <stem>[,<stem>...]` runs
  chosen harnesses locally.
- **`gh` CLI with admin access.** The release and branch-protection tasks
  (plan phases 0.x/1.x) call `gh release …` and
  `gh api repos/montimage-projects/mmt-dpi/branches/main/protection`, which
  need a `gh` login with admin permission on the repository and a token with
  the `repo` and `workflow` scopes. Check before starting:
  `gh auth status` (scopes) and
  `gh api repos/montimage-projects/mmt-dpi --jq .permissions.admin` (prints
  `true`). Without it, stop and hand those tasks back.
- **No `.env`.** No `.env` file exists in the repository
  (`git ls-files '.env*'` prints nothing) and none is needed — the build is
  configured through make variables (§1).
