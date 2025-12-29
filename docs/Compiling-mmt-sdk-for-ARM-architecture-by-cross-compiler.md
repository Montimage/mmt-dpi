# Compiling mmt-sdk for ARM architecture by cross-compiler

**Note:** To compile the buildroot, it needs ~2GB RAM memory

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

Then build the sdk:

```sh
make -j4 ARCH=green-arm
```
