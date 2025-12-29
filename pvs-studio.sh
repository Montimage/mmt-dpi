#!/bin/bash
# Reset mmt-sdk
BUILD_PATH=/home/montimage/build/
PUBLIC_PATH=/home/montimage/workspace/express-server/public/sdk
SRC=/home/montimage/workspace/montimage/mmt-sdk
cd "$BUILD_PATH/mmt-sdk/sdk" || exit 1
make clean
# sudo make dist-clean
cd ~ || exit 1
rm -rf "$BUILD_PATH/mmt-sdk"
cp -r "$SRC" "$BUILD_PATH"
cd "$BUILD_PATH/mmt-sdk/sdk" || exit 1
pvs-studio-analyzer trace -- make
# Hack the license
pvs-studio-analyzer analyze -l ~/.config/PVS-Studio/PVS-Studio.lic
plog-converter -a GA:1,2 -t html -o "pvs_$1/" PVS-Studio.log
cp -Ru "pvs_$1/" "$PUBLIC_PATH"
cd ~ || exit 1
