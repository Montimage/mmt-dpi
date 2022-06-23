/* Generated with MMT Plugin Generator */

#ifndef BNPB_H
#define BNPB_H
#ifdef __cplusplus
extern "C"
{
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

	struct btpb
	{
		uint16_t destination_port;
		uint16_t destination_port_info;
	};

	enum btpb_networking_attributes
	{
		BTPB_DESTINATION_PORT = 1,
		BTPB_DESTINATION_PORT_INFO,
		BTPB_ATTRIBUTES_NB = BTPB_DESTINATION_PORT_INFO,
	};

#define BTPB_DESTINATION_PORT_ALIAS "btpb_destination_port"
#define BTPB_DESTINATION_PORT_INFO_ALIAS "btpb_destination_port_info"
#ifdef __cplusplus
}
#endif
#endif /* ARP_H */
