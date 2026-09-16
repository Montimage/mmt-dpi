---
layout: default
title: "Troubleshooting Log"
---

# Troubleshooting Log

Append-only log of real fixes applied during doc-manager validation runs.

## 2026-07-21

- **Fix**: `DEPLOYMENT.md` referenced wrong ldconfig file name (`mmt.conf` → `mmt-dpi.conf`).
  Source: `sdk/Makefile:89,145`.
  Impact: Users following the doc would look for a non-existent config file.

- **Fix**: `DEVELOPMENT.md` listed `cmake` as a build prerequisite that doesn't exist in the build system.
  Source: no CMake files found in `rules/` or `sdk/Makefile`.
  Impact: Users would install unnecessary dependencies.

- **Fix**: `DEVELOPMENT.md` had inverted description for `NDEBUG=1` build option.
  Source: `rules/common.mk:38-42` — `NDEBUG=1` defines `-DNDEBUG` which *disables* debug output.
  Impact: Users would be confused about the option's effect.

- **Fix**: `USER_GUIDE.md` showed incorrect install layout (plugins/examples under `dpi/` instead of `$(MMT_BASE)/`).
  Source: `rules/common.mk:4-7`.
  Impact: Users would look for plugins and examples in the wrong directory.

- **Fix**: `Compilation-and-Installation-Instructions.md` had wrong git clone URL.
  Source: remote is `git@gh-work:montimage-projects/mmt-dpi.git`.
  Impact: Clone would fail with 404.

- **Fix**: `Compilation-and-Installation-Instructions.md` had wrong example directory path (`./examples` → `src/examples`).
  Source: `src/examples/` contains all example source files.
  Impact: Build commands would fail with "file not found".

- **Fix**: `Add-New-Protocol.md` referenced outdated source paths (`lib/protocols/` → `src/mmt_tcpip/lib/protocols/`).
  Source: confirmed via `ls src/mmt_tcpip/`.
  Impact: Developers following the guide would not find the referenced files.

- **Fix**: `README.md` listed non-existent examples (`simple_packet_handler`, `mmt_online`).
  Source: confirmed absence via `ls src/examples/`.
  Impact: Users would try to run non-existent examples.

- **Fix**: `Data-Types.md` referenced wrong header path and had incorrect type name (`MMT_STRING_LONG_DATA_POINTER` → `MMT_STRING_LONG_DATA`).
  Source: `sdk/include/types_defs.h:197`.
  Impact: Developers looking up types would find the wrong definition.

- **Fix**: `MMT-Handler.md` had wrong return type for `get_active_session_count()` and wrong evasion constant names.
  Source: `sdk/include/mmt_core.h:209, 86-90`.
  Impact: Code written from the doc would not compile.
