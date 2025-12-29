/* Generated with MMT Plugin Generator */

#ifndef ARP_H
#define ARP_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

	struct ethernet_arp_data {
		mac_addr_t ar_sha ;
		uint32_t ar_sip ;
		mac_addr_t ar_tha ;
		uint32_t ar_tip ;
	};
	struct arphdr {
		uint16_t ar_hrd, ar_pro ;
		uint8_t ar_hln, ar_pln ;
		uint16_t ar_op ;
	};

	int init_arp_proto_struct();




#ifdef	__cplusplus
}
#endif
#endif	/* ARP_H */
