---
layout: default
title: "Compiling mmt-sdk for ARM architecture by cross-compiler"
---

# Compiling mmt-sdk for ARM architecture by cross-compiler

> ⚠️ This document references the `ARCH=green-arm` build target which no longer
> exists in the current codebase. The current available build targets are:
> `linux`, `linux-gcc`, `linux-clang`, `linux-icc`, `osx`, `win32`, `win64`
> (`rules/arch-*.mk`).
>
> For ARM cross-compilation, use `ARCH=linux` with a cross-compiler toolchain
> and set `CC=arm-linux-gnueabihf-gcc` (or your target's compiler).

**Note:** To compile the buildroot, it needs ~2GB RAM memory.

Download the cross-compiler for arm: `greencom-buildroot.tgz` (can be found on `mmt-probe` project, on branch `SAN-QOLSR` at location `mmt-probe/qolsr/docs`). Then build the compiler

```sh
sudo apt-get install unzip # if it is not installed yet
tar xzf greencom-buildroot.tgz
cd greencom-buildroot
make greencom-rpi_defconfig
make toolchain
```

Add the compiler path:

```sh
export PATH="/home/USER/greencom-buildroot/output/host/usr/bin:$PATH"
```

Then build the SDK:

```sh
make -j4 ARCH=linux CC=arm-linux-gnueabihf-gcc
```