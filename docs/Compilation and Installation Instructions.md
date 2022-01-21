**Compilation and Installation instructions**

[TOC]

------------------

# Pre-requisites

Required packages: `libxml2-dev`

### Get source code of MMT-SDK
```sh
git clone https://YOUR_USERNAME@bitbucket.org/montimage/mmt-sdk.git
cd mmt-sdk
```
 
# Linux 

## Install some required tools

```bash
apt-get install gcc make build-essential git cmake 
```

## Install some required packages

This chain of tools depends on the following packages:
```bash
apt-get update
apt-get install libxml2-dev
```

## Compile and install/uninstall `mmt-sdk`

Assume that we are in mmt-sdk directory:
```sh
cd sdk
make
make install
```

To uninstall mmt-sdk, go to `mmt-sdk/sdk` and run `sudo make clean`

## [Compiling mmt-sdk for ARM architecture by cross-compiler](https://bitbucket.org/montimage/mmt-sdk/wiki/Compiling%20mmt-sdk%20for%20ARM%20architecture%20by%20cross-compiler)

## Examples

In this example, we are going to use `libpcap` as the tool to capture the packet. So we need to install `libpcap-dev` library:

```
apt-get install libpcap-dev
```

You can test `mmt-sdk` library with some examples in `mmt-sdk/sdk/examples` to see how it works. See [more examples](https://bitbucket.org/montimage/mmt-sdk/wiki/Examples)
```sh
cd sdk/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
sudo ./extract_all -i eth0
```

---------------------------------

# Mac OSX **(Need update)**

## Install some required tools

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

## Compile and install/uninstall `mmt-sdk`

Assume that we are in mmt-sdk directory:
```sh
cd sdk/
make -j4 ARCH=osx
sudo make ARCH=osx install
```

To uninstall mmt-sdk, go to `mmt-sdk/sdk` and run `sudo make dist-clean`

## Examples

You can test `mmt-sdk` library with some examples in `mmt-sdk/sdk/examples` to see how it works. See [more examples](https://bitbucket.org/montimage/mmt-sdk/wiki/Examples)
```sh
cd sdk/examples
gcc48 -o extract_all extract_all.c -lmmt_core -ldl -lpcap -lpthread
#enter root mode
sudo ./extract_all -i eth0
```

---------------------------------
# Build on Linux for Windows (cross-compilation)**(Need update)**

## Install some required tools
* Git: See [Install Git for Window](http://git-scm.com/download/win)

## Compile `mmt-sdk`
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

Then build either a 32-bit version of the SDK:
```sh
make -j4 ARCH=win32
make install  
```
... or a 64-bit version:
```sh
make -j4 ARCH=win64
make install  
```