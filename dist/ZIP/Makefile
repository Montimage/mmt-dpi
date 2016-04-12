#  - - - - - - -
#  I N S T A L L
#  - - - - - - -
install:
	@ cp lib/libmmt_core.* lib/libmmt_fuzz.* /usr/lib
	@ echo "Installing lib/libmmt_core.* and lib/libmmt_fuzz.* to /usr/lib"
	@ mkdir -p /usr/local/include/mmt
	@ echo "# include \"mmt/mmt_core.h\"">>/usr/local/include/mmt_core.h
	@ echo "Installing mmt_core.h at /usr/local/include"
	@ cp -R include/* /usr/local/include/mmt
	@ echo "Installing include/* at /usr/local/include/mmt"
	@ cp -R examples /opt/mmt
	@ echo "Copied examples/ to /opt/mmt/examples"
	@ mkdir -p "/opt/mmt/plugins"
	@ cp lib/libmmt_tcpip.so.* /opt/mmt/plugins/libmmt_tcpip.so
	@ echo "Installing lib/libmmt_tcpip.so at /opt/mmt/plugins/libmmt_tcpip.so"
	@ echo "Thanks you for installing mmt-sdk, you can learn more about mmt-sdk at: http://www.montimage.com"
# - - - - - - - - -  
# U N I N S T A L L 
# - - - - - - - - -  

uninstall:
	@ rm -rf /opt/mmt
	@ echo "Removed /opt/mmt"
	@ rm -rf /usr/lib/libmmt_*
	@ echo "Removed /usr/lib/libmmt_*"
	@ rm -rf /usr/local/include/mmt
	@ echo "Removed /usr/local/include/mmt"
	@ rm -f /usr/local/include/mmt_core.h
	@ echo "Removed /usr/local/include/mmt_core.h"

