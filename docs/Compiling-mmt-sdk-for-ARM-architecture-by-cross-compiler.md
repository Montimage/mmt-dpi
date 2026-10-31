---
layout: default
title: "Building mmt-sdk for ARM (arm64)"
---

# Building mmt-sdk for ARM (arm64)

**Status: native arm64 builds are supported; cross-compilation is not.**

## Native arm64 (aarch64)

On a Linux arm64 host the SDK builds and installs exactly as on x86-64 — the
same toolchain line, `make -C sdk -j$(nproc)` and `make -C sdk install`
([Compilation and Installation Instructions](./Compilation-and-Installation-Instructions.md)).
CI tests it on a native arm64 runner: the `unit-tests-arm` job of
`.github/workflows/c-cpp.yml` runs the full suite on `ubuntu-24.04-arm`, and
the release workflow builds and checks the arm64 packages on the same runner
label. The toolchain and CI facts are stated once, in
[Agent Environment Notes §1](./AGENT_ENVIRONMENT.md#1-toolchain-requirements).

## Cross-compilation

Building on one architecture for another is not supported and no CI job
tests it. The default toolchain file sets the compiler and archiver itself
(`CC := gcc`, `AR := ar rcsD` at `rules/arch-linux.mk:3-4`), so an exported
`CC` is ignored, and the build wires no sysroot or target triplet. The older
recipe that lived here (a buildroot toolchain and a `green-arm` build target)
no longer applies: that target was removed. Build on an arm64 host instead.

## Build targets

`ARCH` selects one of the `rules/arch-<name>.mk` files (`sdk/Makefile:1,17`),
and these are the only targets:

| `ARCH=` | Toolchain |
|---------|-----------|
| `linux` (default) | GCC |
| `linux-gcc` | GCC |
| `linux-clang` | Clang |
| `linux-icc` | Intel icc |
