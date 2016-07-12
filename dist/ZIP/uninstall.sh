#!/bin/bash
if [[ $(id -u) -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user"
    exit 1
else
	echo "Start uninstalling mmt-sdk .... "
	VERSION=1.6.3.0
	MMT_BASE=/opt/mmt
	MMT_LIB=$MMT_BASE/lib
	MMT_INC=$MMT_BASE/include
	OPT_MMT_PLUGINS=$MMT_BASE/plugins
	OPT_MMT_EXAMS=$MMT_BASE/examples

	#  - - - - - - -
	#  I N S T A L L
	#  - - - - - - -

	echo "Checking location ... "
	echo "MMT_BASE: "$MMT_BASE
	echo "Removing mmt-sdk ... "
	rm -rf $MMT_BASE
	echo "Cleaning environment ... "
	rm /etc/ld.so.conf.d/mmt.conf
	ldconfig
	echo "[MMT-]> mmt-sdk has been removed from the system! "
	echo "You can learn more about mmt-sdk at: http://www.montimage.com"
fi
