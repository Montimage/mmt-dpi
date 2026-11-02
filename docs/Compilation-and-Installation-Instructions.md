---
layout: default
title: "Compilation and Installation Instructions"
---

**Compilation and Installation instructions**

------------------

# Prerequisites

MMT-DPI builds on Linux only, with GCC 11 or newer and GNU Make. It is
continuously built and tested on Ubuntu 22.04 / 24.04 / 26.04, Debian 12 / 13,
Rocky Linux 9 / 10 and CentOS Stream 9 / 10 with the GCC and Clang versions
those distributions ship (GCC 11–15, Clang 14+); an older GCC stops the build
with a message naming the compiler it found (`rules/arch-linux.mk`).

To build the SDK you need a C compiler, `make` and `git`; to compile the
example programs, which read packet captures, you also need the libpcap
headers. One command installs all of them:

Debian, Ubuntu:

```bash
sudo apt-get install -y build-essential gcc g++ make git libpcap-dev
```

Fedora, Rocky Linux, AlmaLinux, CentOS Stream (on Rocky Linux, AlmaLinux and
CentOS Stream `libpcap-devel` is in the CRB repository: add
`--enablerepo=crb` after `dnf`):

```bash
sudo dnf install -y gcc gcc-c++ make git libpcap-devel
```

openSUSE:

```bash
sudo zypper install -y gcc gcc-c++ make git libpcap-devel
```

Arch Linux (best-effort):

```bash
sudo pacman -S --needed base-devel git libpcap
```

Two optional extras:

- the security engines (`make -C sdk ENABLESEC=1`) also need the libxml2
  headers, `libxml2-dev` or `libxml2-devel` (`rules/common.mk:76-84`); no
  other third-party library is linked;
- contributors who run the test suite also need `pkg-config` and `jq`.

The one-command source installer of the
[Quick Start](./index.html#quick-start) installs the build packages itself;
this list is for building from a checkout. If a step below fails, the
[Troubleshooting](./troubleshooting.md) page has the fix for each first-run
error.

### Get source code
```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi
```
 
# Linux 

## Compile and install/uninstall

Assume that we are in mmt-dpi directory:
```sh
cd sdk
make
sudo make install
```

To uninstall run `sudo make uninstall` (pass the same `MMT_BASE` as the install). A root install registers the libraries with the dynamic loader; `make install` never compiles, so run `make` first.

# [Building MMT-DPI for ARM (arm64)](./Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md)

# Examples

In this example, we are going to use `libpcap` to capture packets from a given NIC, so the libpcap headers of the [prerequisites](#prerequisites) must be installed.

You can test `mmt-dpi` library with some examples in [`src/examples`](https://github.com/montimage-projects/mmt-dpi/tree/main/src/examples) to see how it works.

```sh
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./extract_all -i eth0
```

---------------------------------

> **Note:** macOS and Windows are **not supported** — only Linux is
> (see [Prerequisites](#prerequisites)). The make rules the old
> macOS/Windows builds relied on (`rules/arch-osx.mk`, `rules/arch-win32.mk`,
> `rules/arch-win64.mk`, `rules/common-windows.mk`) were removed in #228, so
> `ARCH=osx|win32|win64` fails at the `include arch-$(ARCH).mk` line; the
> unsupported-platform instruction blocks that once stood here were deleted in
> #249.
