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
| `rules/common.mk` | Compiler flags, `MMT_BASE`, `BUILD=asan`/`tsan`, `ENABLESEC`, debug/valgrind toggles |
| `rules/common-linux.mk` | Linux link rules, release hardening, `ENABLESEC` engines |
| `sdk/Makefile` | Build entry point, `install`/`test` targets, default `MMT_BASE` |
| `tests/run_all_tests.sh` | Master test runner and the 23 standalone suites |

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
sudo apt-get install -y build-essential gcc make libxml2-dev libpcap-dev libnghttp2-dev bash git pkg-config
```

| Package | Why it is needed |
|---------|------------------|
| `gcc`, `make` | The whole build (`rules/common-linux.mk:62` enables LTO for GCC only) |
| `libpcap-dev` | Examples that read pcap files (`src/examples/`) |
| `libxml2-dev` | Only needed with `ENABLESEC=1` (`rules/common.mk:76-84`) |
| `libnghttp2-dev` | Optional at build time — the Makefile auto-detects its absence and keeps building (`rules/common.mk:56-74`) |
| `bash` | Test scripts are bash (`tests/run_all_tests.sh`) |

CI builds and tests on `ubuntu-24.04` (GCC 13) — see
`.github/workflows/c-cpp.yml`. That is the reference toolchain.

**Supported floor (issue #218, F-DEP-207):** GCC ≥ 11 with glibc ≥ 2.34 and
libstdc++6 ≥ 11 — the oldest toolchain the release matrix
(`.github/workflows/release-packages.yml`) still builds on, carried by
Rocky 9 / CentOS Stream 9 and Ubuntu 22.04. The constants live in
`rules/common.mk` (`MMT_GCC_MIN`, `MMT_GLIBC_MIN`, `MMT_LIBSTDCXX_MIN`):
`rules/arch-linux.mk` fails the build below GCC 11 with a message naming
the detected compiler, the generated `.deb` declares the same glibc and
libstdc++ floors in its `Depends:` line (`sdk/Makefile` `deb` target), and
the `toolchain-floor` job in `c-cpp.yml` builds the SDK and runs the full
suite on `ubuntu-22.04` (GCC 11.4) so the floor is exercised, not just
asserted.

**Package dependency declarations (issue #219):** the `.deb` `Depends:` and
the `.rpm` `Requires:`/`BuildRequires:` are not hand-maintained lists —
`tools/ci/shlib-deps.sh` derives them at package-build time from the NEEDED
entries `objdump -p` reports for the shipped `.so` files (the floors above
survive as the `libc6`/`glibc` and `libstdc++6`/`libstdc++` entries).
`tools/ci/build-package.sh` builds with `ENABLESEC=1` and verifies each
artifact with `tools/ci/check-package-deps.sh --verify-package`, which
compares `dpkg-deb -f` / `rpm -qp` output against the derived set and fails
on divergence.

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
tag to equal `v$(VERSION)` before the publish job runs.

Notes:

- Clang is available via `make ARCH=linux-clang`; icc via `ARCH=linux-icc`
  (rule files in `rules/arch-*.mk`). GCC is the default and best-tested path.
- A C++ compiler (`g++`, pulled in by `build-essential`) is required because
  shared libraries are linked with `$(CXX)` (`rules/common-linux.mk:237`).

### Documentation-site toolchain

The C SDK does not require Ruby. For the documentation site, use Ruby **3.3**
as in CI (`.github/workflows/c-cpp.yml:213-218`), with Bundler to install
the gems and run Jekyll. CI enables `bundler-cache` through `ruby/setup-ruby`
and verifies the committed `docs/Gemfile.lock` under `BUNDLE_FROZEN=true`
(issue #372) — after changing `docs/Gemfile`, regenerate the lock
(`bundle lock`) and commit it or the frozen install fails. With Ruby 3.3
available:

```bash
gem install bundler
(cd docs && bundle install && bundle exec jekyll build)
```

`docs/Gemfile:11-16` defines Jekyll and its plugins; CI's corresponding build
is at `.github/workflows/c-cpp.yml:231`.

No application `.env` file is required: this is a Make-built SDK, configured
through make variables (`sdk/Makefile:8-13`, `rules/common.mk:3-8`), and the
test runner takes shell variables such as `SANITIZE`
(`tests/run_all_tests.sh:8-98`). No application service setup is needed for
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
`.so` symlinks are created by `make install`, `sdk/Makefile:53-59`), copies
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
| `TUNE=native` | Opt-in `-march=native` (unsafe for redistributed binaries — off by default) | `rules/common-linux.mk:149-157` |
| `VERBOSE=1` | Print full compile commands | `rules/common.mk:21-24` |

## 3. Testing

This section is the **single source** for the test-runner contract — the command,
the suite count and the runtime band. Other documents name the command and link
here for the expected result.

```bash
bash tests/run_all_tests.sh
```

Expected result: **23/23 suites pass**, total runtime roughly **90–360 s** on
a typical development machine (measured: 113 s for the full run) — the wall
clock is dominated by the suites
that build+install the SDK internally (`rule_engine`, `installer`,
`installed_consumer`, …), not by the assertions. Exit code `0` on
success, `1` on any failure. The runner has no `-j` option: the 23 suites run
sequentially. The suite list lives in `DEFAULT_SUITES`
(`tests/run_all_tests.sh:155-179`)
(`tests/run_all_tests.sh`):
`hashmap`, `memory`, `fault_injection`, `core_engine`, `hexdump`, `mmt_utils`,
`mmt_inet_ntop`,
`avltree`, `citrix_ica_detection`, `http_header_case`, `s1ap_ngap_decode`,
`rule_engine`, `radius_hardening`, `nas_ies_tail`, `installer`,
`dicom_dissector`, `ndn_dissector`, `business_app`, `proto_classifiers`,
`dpi_profiles`, `fuzz_verdicts`, `precision_metrics`, `installed_consumer`.
`fuzz_verdicts` and `precision_metrics` are
delegate suites for CI self-tests living under `tools/ci/tests/` — the fuzz
gate's verdict handling (`test-fuzz-verdicts.sh`, issue #370) and the
precision-gate metric accounting (`test-precision-metrics.py`, issue #373);
both build nothing. `installed_consumer` (issue #374) drives the other
`tools/ci/tests/` payload — `run-installed-consumer.sh` +
`installed_consumer.c` — against a throwaway ENABLESEC=1 install prefix.

Key property for agents: these suites are **standalone** — no prior build, no
install, no `sudo` needed. Most suites' `run_tests.sh` compiles the test
directly against sources under `src/` with plain `gcc`; suites that need the
built SDK (`citrix_ica_detection`, `http_header_case`, `s1ap_ngap_decode`,
`rule_engine`, `nas_ies_tail`, `installer`, `installed_consumer`, and the default-profile engine
leg of `fault_injection`, `tests/fault_injection/run_tests.sh:90-92`) run `make -C sdk clean` and build
it themselves into a throwaway prefix, so running them discards an existing
`sdk/` build. You
can run one suite by passing its directory name:

```bash
bash tests/run_all_tests.sh hashmap memory   # subset
```

A listed suite whose `run_tests.sh` is absent counts as **failed**, not
skipped — the runner exits non-zero (issue #186).

### Suite modes: sanitizers and coverage

`tests/run_all_tests.sh` has two opt-in modes (`tests/run_all_tests.sh:8-98`):

- `SANITIZE=asan bash tests/run_all_tests.sh` — compiles every suite with
  ASan + UBSan (same flag set as the SDK's `BUILD=asan`,
  `rules/common.mk:120-127`) and sets `ASAN_OPTIONS=detect_leaks=0`
  (leak detection stays with Valgrind). The SDK-building suites inherit `BUILD=asan` for their internal SDK
  build, except `fault_injection`: its engine leg is skipped under sanitizers
  while its unit leg still runs (`tests/fault_injection/run_tests.sh:77-82`).
- `SANITIZE=tsan bash tests/run_all_tests.sh` — same with TSan
  (`rules/common.mk:150-157`). On kernels with high-entropy ASLR the runner
  re-execs itself once under `setarch -R`
  (`tests/run_all_tests.sh:86-89`).
- `bash tests/run_all_tests.sh --coverage` — instruments the suites with gcov,
  aggregates all `.gcda`, and writes an lcov-format tracefile of **library
  (`src/`) sources only** to `tests/coverage/coverage.info` plus the library
  line percentage, instrumented-file count/list and
  `tests/coverage/summary.json` in stdout
  (`tests/run_all_tests.sh:192-301`). Requires `gcov` (shipped with
  gcc) and `jq`; no lcov install needed. The coverage CI job enforces the
  committed floor `tests/coverage/floor.json` — both counters plus the
  required sources it names — via `tools/ci/check-coverage-floor.sh`.
- `bash tests/run_all_tests.sh --with-harnesses` — after the suites, runs
  every phase0 harness (`tools/phase0/tests/run_*.sh`) via the aggregate
  runner `tools/phase0/run_all_harnesses.sh`, which builds the SDK once per
  required profile (asan / tsan / default) into a shared prefix and replays
  all harnesses against it (`tests/run_all_tests.sh:303-319`). The arm counts
  as one extra entry in the result table; any harness failure fails the
  invocation. Runtime is minutes, not seconds — the suites build nothing for
  it, the runner's shared builds dominate.

The modernization task's **30-file coverage scope** refers to an audit-time
instrumented subset, not all library sources and not a fixed runner limit.
The 2026-09-22 audit at commit `2ab7b73516113009622cb3d32194d20121457010`
reported 82.9% (5,660/6,831 lines) over those 30 files; this is historical
evidence, not a new measurement (provenance recorded in [DECISIONS.md](https://github.com/montimage-projects/mmt-dpi/blob/main/docs/DECISIONS.md)).
Coverage includes only the `src/` files represented in emitted gcov data
(`tests/run_all_tests.sh:216-220`); its percentage uses the lines in that
subset, so it must not be reported as whole-library coverage. The current
run's exact scope is `instrumented_sources` and `instrumented_files` in
`summary.json` (`tests/run_all_tests.sh:276-290`). The committed minimum is
**29 instrumented files**, alongside an **80.0%** line floor and required
source names (`tests/coverage/floor.json:2-10`); a 30-file measurement does
not change that floor. Consult a fresh summary for the current count.

CI runs both modes on every push/PR to main (`.github/workflows/c-cpp.yml`,
jobs `sanitizer-tests` and `coverage`); the coverage job uploads
`tests/coverage/` as a workflow artifact.

## 4. `MMT_BASE` Install-Prefix Behavior

This section is the **single source** for the `MMT_BASE` prefix contract; other
documents link here.

`MMT_BASE` is the install prefix. Defaults:

- `rules/common.mk:3` — `MMT_BASE ?=/opt/mmt` (used by compile-time paths)
- `sdk/Makefile:8-13` — when `MMT_BASE` is unset, `make install` targets
  `/opt/mmt` and sets `NEED_ROOT_PERMISSION := 1` (writes
  `/etc/ld.so.conf.d/mmt-dpi.conf` and runs `ldconfig`)

### The `make test` trap

`sdk/Makefile`'s `test` target (`sdk/Makefile:316-321`) compiles the
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

The plugin repository path is baked into compiled code as
`PLUGINS_REPOSITORY_OPT` (`-DPLUGINS_REPOSITORY_OPT=\"$(MMT_PLUGINS)\"`,
`rules/common.mk:30`). Every SDK target invocation
refreshes `plugins_engine.o` (`sdk/Makefile:28-35`), including during install;
this is not conditional on a detected prefix change. Keep `MMT_BASE` identical across
build/install invocations so compilation and installation use one path.

## 5. Sanitizer Build Profiles

Two verification profiles exist in `rules/common.mk` (both add flags to
`CFLAGS` and `CXXFLAGS` so they reach the shared-library link lines):

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
RELRO — `rules/common-linux.mk:66-163`) is automatically disabled, and the
`-Wl,-z,defs` self-containedness guard is skipped because sanitizer runtime
symbols are intentionally left undefined (`rules/common-linux.mk:202-214`).

## 6. `ENABLESEC=1` Security Engines Flag

`ENABLESEC` gates two optional libraries — `libmmt_security` and
`libmmt_fuzz` — which are otherwise not built at all:

- Object/header selection: `rules/common.mk:201-203, 225-228, 310-313`
- Link rules and libxml2 wiring: `rules/common-linux.mk:6-12, 215-218, 226-230, 263-279`
- Install symlinks for both engines: `sdk/Makefile:54-55, 140-141`

Usage (requires `libxml2-dev`):

```bash
make -C sdk ENABLESEC=1 -j$(nproc)
```

Without the flag those sources are skipped entirely, so a missing libxml2 is
only fatal when `ENABLESEC=1`.

## 7. Quick Verification Checklist

Run this after setting up a fresh environment; all four commands must succeed:

```bash
make -C sdk -j$(nproc)          # exit 0, green build (seconds to ~2 min depending on machine)
bash tests/run_all_tests.sh     # 23/23 suites PASSED, exit 0 (90–360 s)
make -C sdk ENABLESEC=1 -j$(nproc)   # exit 0 (optional engines build)
make -C sdk clean && make -C sdk BUILD=asan -j$(nproc)   # exit 0 (sanitizer profile)
```

If any of these fails, fix the environment before attempting code changes —
upstream tasks assume this baseline is green. After sanitizer/`ENABLESEC`
experiments, restore the default tree with `make -C sdk clean &&
make -C sdk -j$(nproc)`.
