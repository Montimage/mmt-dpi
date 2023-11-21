/*
 * proto_vxlan.c
 *
 *  Created on: Nov 20, 2023
 *      Author: nhnghia
 *
 *  This implements protocol VxLAN-GBP
 *  https://www.ietf.org/archive/id/draft-smith-vxlan-group-policy-05.txt
 */


#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"



#define NOT_FOUND 0
#define FOUND     1

/**
 https://www.ietf.org/archive/id/draft-smith-vxlan-group-policy-05.txt
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |G|R|R|R|I|R|R|R|R|D|R|R|A|R|R|R|        Group Policy ID        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          VXLAN Network Identifier (VNI)       |   Reserved    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                       Figure 1: VXLAN-GBP Extension
 */

typedef struct vxlan_struct {
	uint16_t flag;
	uint16_t group_policy;
	uint8_t network_id[3];
	uint8_t reserved;
} vxlan_t;

static int _classify_vxlan_from_udp(ipacket_t * ipacket, unsigned index) {

	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	struct mmt_internal_tcpip_session_struct *flow = packet->flow;

	MMT_LOG(PROTO_VXLAN_GBP, MMT_LOG_DEBUG, "search VxLAN-GBP.\n");

	// const u_int8_t *packet_payload = packet->payload;
	u_int32_t payload_len = packet->payload_packet_len;

	// UDP packet and have enough room for VxLAN
	if ((packet->udp != NULL) && (payload_len >= sizeof( vxlan_t ))) {

		u_int16_t vxlan_port = ntohs(4789); //destination port reserved for VxLAN
		//1. reserved destination port
		if( packet->udp->dest == vxlan_port ){
			vxlan_t *header = ( vxlan_t *)packet->payload;

			//2. the reserved fields must be set to zero
			if( header->reserved == 0 ){
				// no more signature to check ==> conclude VxLAN
				MMT_LOG(PROTO_VXLAN_GBP, MMT_LOG_DEBUG, "found VxLAN-GBP.\n");
				mmt_internal_add_connection(ipacket, PROTO_VXLAN_GBP, MMT_REAL_PROTOCOL);
				return FOUND;
			}
		}
	}

	MMT_LOG(PROTO_VXLAN_GBP, MMT_LOG_DEBUG, "exclude VxLAN-GBP.\n");
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_VXLAN_GBP);
	return NOT_FOUND;
}

static int _vxlan_classify_next_proto(ipacket_t * ipacket, unsigned index) {
	classified_proto_t retval;
	retval.offset = 8;
	retval.proto_id = PROTO_ETHERNET;
	retval.status = Classified;
	set_classified_proto(ipacket, index+1, retval);
	return FOUND;
}

int _extract_vxlan_network_id(const ipacket_t * packet, unsigned proto_index,
                                      attribute_t * extracted_data) {
	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	vxlan_t *header = (vxlan_t *) & packet->data[proto_offset];
	uint32_t vni = *(uint32_t *) header->network_id;
	*((uint32_t *) extracted_data->data) = (ntohl( vni ) >> 8);
	return 1;
}

static attribute_metadata_t vxlan_attributes_metadata[] = {
	{VXLAN_GBP_FLAG,         VXLAN_GBP_FLAG_ALIAS,       MMT_U16_DATA, sizeof (uint16_t), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
	{VXLAN_GBP_GROUP_POLICY, VXLAN_GBP_GROUP_POLI_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
	{VXLAN_GBP_NETWORK_ID,   VXLAN_GBP_NETWORK_ID_ALIAS, MMT_U32_DATA, sizeof (uint32_t), 4, SCOPE_PACKET, _extract_vxlan_network_id},
};

int init_proto_vxlan_struct() {
	const int length = (sizeof(vxlan_attributes_metadata) / sizeof(vxlan_attributes_metadata[0]) );
	protocol_t *protocol_struct = init_protocol_struct_for_registration(
			PROTO_VXLAN_GBP, PROTO_VXLAN_GBP_ALIAS);

	if (protocol_struct != NULL) {
		int i = 0;
		for (; i < length; i++) {
			if( !register_attribute_with_protocol(protocol_struct, &vxlan_attributes_metadata[i]) )
				log_err("Cannot register attribute %s.%s", PROTO_VXLAN_GBP_ALIAS, vxlan_attributes_metadata[i].alias);;
		}
		int ret = register_classification_function_with_parent_protocol( PROTO_UDP, _classify_vxlan_from_udp, 100 );
		if( ret == 0 ){
			log_err("Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
			return PROTO_NOT_REGISTERED;
		}
		register_classification_function(protocol_struct, _vxlan_classify_next_proto);
		return register_protocol(protocol_struct, PROTO_VXLAN_GBP);
	} else {
		log_err("Cannot register protocol %s (id=%d)", PROTO_VXLAN_GBP_ALIAS, PROTO_VXLAN_GBP);
		return 0;
	}
}
