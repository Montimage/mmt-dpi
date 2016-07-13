#!/bin/bash
if [[ $(id -u) -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user"
    exit 1
else
	echo "Start uninstalling mmt-sdk .... "
	MMT_BASE=/opt/mmt
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
