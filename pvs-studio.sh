#!/bin/bash
# Reset mmt-sdk
BUILD_PATH=/home/montimage/build/
PUBLIC_PATH=/home/montimage/workspace/express-server/public/sdk
SRC=/home/montimage/workspace/montimage/mmt-sdk
cd $BUILD_PATH/mmt-sdk/sdk
make clean
# sudo make dist-clean
cd ~
rm -rf $BUILD_PATH/mmt-sdk
cp -r $SRC $BUILD_PATH
cd $BUILD_PATH/mmt-sdk/sdk
pvs-studio-analyzer trace -- make
# Hack the license
pvs-studio-analyzer analyze -l ~/.config/PVS-Studio/PVS-Studio.lic
plog-converter -a GA:1,2 -t html -o sdk_$1/ PVS-Studio.log
cp -Ru sdk_$1/ $PUBLIC_PATH
cd ~