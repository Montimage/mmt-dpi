#!/bin/bash
if [[ $(id -u) -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user"
    exit 1
else
	echo "Start installing mmt-sdk .... "
	VERSION=1.6.3.0
	MMT_BASE=/opt/mmt
	MMT_LIB=$MMT_BASE/lib
	MMT_INC=$MMT_BASE/include
	OPT_MMT_PLUGINS=$MMT_BASE/plugins
	OPT_MMT_EXAMS=$MMT_BASE/examples

	SDKINC=`pwd`/include
	SDKLIB=`pwd`/lib
	SDKXAM=`pwd`/examples

	#  - - - - - - -
	#  I N S T A L L
	#  - - - - - - -

	echo "Preparing location ... "
	echo "VERSION: "$VERSION
	echo "MMT_BASE: "$MMT_BASE
	echo "MMT_LIB: "$MMT_LIB
	echo "MMT_INC: "$MMT_INC
	echo "OPT_MMT_PLUGINS: "$OPT_MMT_PLUGINS
	echo "SDKINC: "$SDKINC
	echo "SDKLIB: "$SDKLIB
	echo "SDKXAM: "$SDKXAM
	mkdir -p $MMT_BASE
	mkdir -p $MMT_LIB
	mkdir -p $MMT_INC
	mkdir -p $OPT_MMT_PLUGINS
	mkdir -p $OPT_MMT_EXAMS
	echo "Copying resource ... "
	cp $SDKLIB/* $MMT_LIB
	echo "[MMT-]> Installed  "$SDKLIB" at "$MMT_LIB
	cp -R $SDKINC/* $MMT_INC
	echo "[MMT-]> Installed  "$SDKINC" at "$MMT_INC
	cp -R $SDKXAM/* $OPT_MMT_EXAMS
	echo "[MMT-]> Installed  "$SDKXAM" at "$OPT_MMT_EXAMS
	cp $SDKLIB/libmmt_tcpip.so.$VERSION $OPT_MMT_PLUGINS/libmmt_tcpip.so
	echo "[MMT-]> Installed "$OPT_MMT_PLUGINS/libmmt_tcpip.so
	echo "/opt/mmt/lib" >> /etc/ld.so.conf.d/mmt.conf
	ldconfig
	echo "[MMT-]> Done! "
	echo "Thanks you for installing mmt-sdk, you can learn more about mmt-sdk at: http://www.montimage.com"
fi

