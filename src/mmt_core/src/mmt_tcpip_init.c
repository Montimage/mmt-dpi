
#include <stdio.h>
#include <stdlib.h>
#include "packet_processing.h"
#include "mmt_tcpip_plugin.h"

MMTAPI int MMTCALL package_dependent_init()
{
	return init_tcpip_plugin();
}
