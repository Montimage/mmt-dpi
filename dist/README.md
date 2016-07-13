
# **How to make .deb and .zip file**

[TOC]

## Make .deb file

### Update DEBIAN/

#### DEBIAN/control file

Location: DEBIAN/control

Contains the metadata for the package. Put/update something like this:

```sh
Package: mmt-sdk
Version: 0.1-0
Section: base
Priority: standard
Architecture: all
Maintainer: Montimage <contact@montimage.com>
Description: MMT-SDK
 A software C library desinged to extract data attributes 
 from network packets, server logs, and from structured events in general, 
 in odrder to make them available for analysis
```

The space before each line in the description is important

#### DEBIAN/conffile file

Location: DEBIAN/conffile

Needs to contain a list of configuration files (usually placed in /etc) that the package management system will not overwrite when the package is upgraded.
To determine exactly which files are preserved during an upgrade:
```sh
dpkg --status package
```

#### DEBIAN/preinst script

Location: DEBIAN/preinst

When: This script executes before that package will be unpacked from its Debian archive (".deb") file.
Why: stop services for packages which are being upgraded until their installation or upgrade is completed

#### DEBIAN/postinst

Location: DEBIAN/postinst

When: typically completes any required configuration of the package `foo` once `foo` has been unpacked from its Debian archive (".deb"). Often it asks the user for input, and/or warn the user that if he accepts default values.
Why: execute any commands necessary to start or restart a service once a new package has been installed or upgraded

#### DEBIAN/prerm

Location: DEBIAN/prerm

Why: stops any deamons which a associated with a package.
When: Before the removal of files associated with the package

#### DEBIAN/postrm

Location: DEBIAN/postrm

Why: modifies links or other files associated with `foo` and/or removes files created by the package

### Build .deb file

Before building the .deb file, we need to compile mmt-sdk to get the source code.

```sh
cd mmt-sdk/sdk
make -j4
```

When finished compiling, just run script to build
```
cd mmt-sdk/dist
./build-deb.sh

```

### Name for package:

The name of package conform to the following convention: `<foo>_<VersionNumer>-<DebianRevisionNumber>_<DebianArchitecture>.deb`

Example: `mmt_sdk_0.1-0_i386.deb`, `mmt_sdk_0.4-0_amd64.deb`, `mmt_sdk_1.2-1_all.deb`

```sh
mv mm_sdk.deb mmt_sdk_0.1-0_all.deb

```
### Install .deb file

To install .deb file into your system
```sh
dpkg -i mmt_sdk_0.1-0_all.deb
```

## Make .zip file

### Make .zip file

To make .zip file, you also need to compile the mm-sdk first.

After compiling mmt-sdk, you can build a .zip file by this command:

```sh
./build-zip.sh
```

After finished building, you need to rename the mmt\_sdk.zip with the same convention for .deb file.

### Install mmt-sdk from .zip file

Install mmt-sdk from .zip file required install `make`.

Unzip the downloaded file and install mmt-sdk by following command:

```sh
cd mmt-sdk
sudo ./install.sh
```

To uninstall mmt-sdk:

```sh
sudo ./uninstall.sh
```

## Test mmt-sdk

To know how mmt-sdk work and to test installation of mmt-sdk, we can go to /opt/mmt/examples to see the examples

To run the examples, we need to install `libpcap` which is the packet capturing tool we use in the examples.


## References

[1 - Basic of the Debian package management system](https://www.debian.org/doc/manuals/debian-faq/ch-pkg_basics.en.html)


