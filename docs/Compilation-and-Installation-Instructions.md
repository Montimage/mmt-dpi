**Compilation and Installation instructions**

------------------

# Before compiling
Please use the gxx version from `4.9` upto `9.x`. Some users have experienced some problems during the installation with the compiler `gxx >= 10`

# Pre-requisites

Required packages: `libxml2-dev`

### Get source code
```bash
git clone https://github.com/montimage/mmt-dpi
cd mmt-dpi
```
 
# Linux 

## Install required tools

```bash
sudo apt-get install gcc make build-essential git cmake 
```

## Install required packages

This chain of tools depends on the following packages:
```bash
sudo apt-get update
sudo apt-get install libxml2-dev
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
cd ./examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
sudo ./extract_all -i eth0
```

---------------------------------

# Mac OSX **(Need update)**

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

---------------------------------
# Build on Linux for Windows (cross-compilation)**(Need update)**

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
