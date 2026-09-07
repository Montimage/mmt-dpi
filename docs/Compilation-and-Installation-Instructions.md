**Compilation and Installation instructions**

------------------

# Before compiling
A modern C/C++ toolchain is required. MMT-DPI is continuously built and tested
on Ubuntu 22.04 / 24.04, Debian 12, Rocky Linux 9 and CentOS Stream 9 using the
GCC and Clang versions shipped by those distributions (GCC 11–13, Clang 14+).
Any reasonably recent GCC or Clang should work.

# Pre-requisites

Required packages: `libxml2-dev` (only for `ENABLESEC=1` — `rules/common.mk:76-84`),
`libpcap-dev` (for examples), `libnghttp2-dev` (optional, auto-detected — `rules/common.mk:56-74`).

### Get source code
```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi
```
 
# Linux 

## Install required tools

```bash
sudo apt-get install gcc make build-essential git
```

## Install required packages

This chain of tools depends on the following packages:
```bash
sudo apt-get update
sudo apt-get install libxml2-dev libpcap-dev libnghttp2-dev
# libxml2-dev is only needed for ENABLESEC=1 (rules/common.mk:76-84);
# libnghttp2-dev is optional — the build auto-detects its absence (rules/common.mk:56-74).
```

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

You can test `mmt-dpi` library with some examples in [`src/examples`](../src/examples) to see how it works.

```sh
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./extract_all -i eth0
```

---------------------------------

> **Note:** macOS and Windows are **not currently supported**. The instructions below are retained for historical reference only and may not work with the current codebase.

<details>
<summary>Mac OSX (unsupported)</summary>

## Install required tools

* XCode
* Install Hombrew
```bash
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew install/master/install)"
```
* Git: See [Install Git for Mac OSX](http://git-scm.com/download/mac)

## Install some required packages
```bash
brew install gcc48
brew install cmake libpth-dev ldconfig
brew install libxml2 hiredis confuse libpcap
```

## Compile and install

Assume that we are in mmt-dpi directory:
```sh
cd sdk/
make -j4 ARCH=osx
sudo make ARCH=osx install
```

</details>

<details>
<summary>Windows cross-compilation (unsupported)</summary>

## Install some required tools
* Git: See [Install Git for Window](http://git-scm.com/download/win)

## Compile
Cross-compiling for Windows requires `mingw-w64` (NOT `mingw32`, as this version is deprecated)
and some Windows libraries (`libxml`, etc...).

All the required Windows libraries can be found in `/windows` on the public share.
Make expects the files to be available locally in `/opt/windows/`.

Example setup looks like this:
```sh
oprs@oxps% ls -l /opt/windows/
total 12
drwxr-xr-x 7 oprs oprs 4096 May 28 16:38 32
drwxr-xr-x 7 oprs oprs 4096 May 28 16:17 64
```
So assuming the public share directory was mounted on `/mnt/share`, perform:
```sh
sudo mkdir -p /opt
sudo cp -R /mnt/share/windows /opt/
```
(you can discard the 'packages' directory, it just contains the original archives)

Then build either a 32-bit version of the MMT-DPI:
```sh
make -j4 ARCH=win32
make install
```
... or a 64-bit version:
```sh
make -j4 ARCH=win64
make install
```

</details>
