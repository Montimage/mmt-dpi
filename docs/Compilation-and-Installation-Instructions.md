---
layout: default
title: "Before compiling"
---

**Compilation and Installation instructions**

------------------

# Before compiling
A modern C/C++ toolchain is required. MMT-DPI is continuously built and tested
on Ubuntu 22.04 / 24.04, Debian 12, Rocky Linux 9 and CentOS Stream 9 using the
GCC and Clang versions shipped by those distributions (GCC 11–13, Clang 14+).
GCC 11 is the enforced floor — `rules/arch-linux.mk` fails the build on an
older GCC; the contract and the matching glibc/libstdc++ floors are stated in
[Agent Environment Notes §1](./AGENT_ENVIRONMENT.md#1-toolchain-requirements).

# Pre-requisites

Required packages: `libxml2-dev` (only for `ENABLESEC=1` — `rules/common.mk:76-84`),
`libpcap-dev` (for examples), `libnghttp2-dev` (optional, auto-detected — `rules/common.mk:56-74`).

### Get source code
```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi
```
 
# Linux 

## Install required tools and packages

The toolchain and package list are maintained in one place — install them with
the `apt-get` line in
[Agent Environment Notes §1 Toolchain Requirements](./AGENT_ENVIRONMENT.md#1-toolchain-requirements),
which also records why each package is needed.

## Compile and install/uninstall

Assume that we are in mmt-dpi directory:
```sh
cd sdk
make
sudo make install
```

To uninstall run `sudo make dist-clean`

# [Compile MMT-DPI for ARM architecture by cross-compiler](./Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md)

# Examples

In this example, we are going to use `libpcap` to capture packets from a given NIC. So we need to install `libpcap-dev` library:

```bash
sudo apt-get install libpcap-dev
```

You can test `mmt-dpi` library with some examples in [`src/examples`](https://github.com/montimage-projects/mmt-dpi/tree/main/src/examples) to see how it works.

```sh
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./extract_all -i eth0
```

---------------------------------

> **Note:** macOS and Windows are **not supported** — only Linux is
> ([Agent Environment Notes](./AGENT_ENVIRONMENT.md)). The make rules the old
> macOS/Windows builds relied on (`rules/arch-osx.mk`, `rules/arch-win32.mk`,
> `rules/arch-win64.mk`, `rules/common-windows.mk`) were removed in #228, so
> `ARCH=osx|win32|win64` fails at the `include arch-$(ARCH).mk` line; the
> unsupported-platform instruction blocks that once stood here were deleted in
> #249.
