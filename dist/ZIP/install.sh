#!/bin/bash
if [[ $(id -u) -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user"
    exit 1
else
	echo "Start installing mmt-sdk .... "
	VERSION=1.6.13.1
	MMT_BASE=/opt/mmt
	MMT_DPI=$MMT_BASE/dpi
	MMT_LIB=$MMT_DPI/lib
	MMT_INC=$MMT_DPI/include
	MMT_PLUGINS=$MMT_BASE/plugins
	MMT_EXAMS=$MMT_BASE/examples

	SDKINC=`pwd`/include
	SDKLIB=`pwd`/lib
	SDKXAM=`pwd`/examples

	#  - - - - - - -
	#  I N S T A L L
	#  - - - - - - -

	echo "Preparing location ... "
	echo "VERSION: "$VERSION
	echo "MMT_DPI: "$MMT_DPI
	echo "MMT_LIB: "$MMT_LIB
	echo "MMT_INC: "$MMT_INC
	echo "MMT_PLUGINS: "$MMT_PLUGINS
	echo "SDKINC: "$SDKINC
	echo "SDKLIB: "$SDKLIB
	echo "SDKXAM: "$SDKXAM
	mkdir -p $MMT_DPI
	mkdir -p $MMT_LIB
	mkdir -p $MMT_INC
	mkdir -p $MMT_PLUGINS
	mkdir -p $MMT_EXAMS
	echo "Copying resource ... "
	cp $SDKLIB/* $MMT_LIB
	ln -s $MMT_LIB/libmmt_core.so.* $MMT_LIB/libmmt_core.so
	ln -s $MMT_LIB/libmmt_fuzz.so.* $MMT_LIB/libmmt_fuzz.so
	ln -s $MMT_LIB/libmmt_security.so.* $MMT_LIB/libmmt_security.so
	ln -s $MMT_LIB/libmmt_tcpip.so.* $MMT_LIB/libmmt_tcpip.so
	echo "[MMT-]> Installed  "$SDKLIB" at "$MMT_LIB
	cp -R $SDKINC/* $MMT_INC
	echo "[MMT-]> Installed  "$SDKINC" at "$MMT_INC
	cp -R $SDKXAM/* $MMT_EXAMS
	echo "[MMT-]> Installed  "$SDKXAM" at "$MMT_EXAMS
	cp $SDKLIB/libmmt_tcpip.so.* $MMT_PLUGINS/libmmt_tcpip.so
	echo "[MMT-]> Installed "$MMT_PLUGINS/libmmt_tcpip.so
	echo $MMT_DPI"/lib" >> /etc/ld.so.conf.d/mmt.conf
	ldconfig
	echo "[MMT-]> Done! "
	echo "Thanks you for installing mmt-sdk, you can learn more about mmt-sdk at: http://www.montimage.com"
fi

