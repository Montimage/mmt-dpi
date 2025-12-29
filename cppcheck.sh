#!/bin/bash
# Reset mmt-probe
WORKSPACE=/home/montimage/workspace
PUBLIC_PATH=$WORKSPACE/express-server/public/sdk
SRC=$WORKSPACE/montimage/mmt-sdk
TOHTML=$WORKSPACE/montimage/mmt-test/pythons/cppcheck2html.py
cd "$SRC/" || exit 1
cppcheck --xml src/* 2> cppcheck_output.xml
mkdir -p "cppcheck_$1"
python "$TOHTML" --file=cppcheck_output.xml --report-dir="cppcheck_$1" --title=MMT-SDK
mv "cppcheck_$1" "$PUBLIC_PATH"
rm cppcheck_output.xml
