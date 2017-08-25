#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_dofus_add_connection(ipacket_t * ipacket)
{
	mmt_internal_add_connection(ipacket, PROTO_DOFUS, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_dofus(ipacket_t * ipacket, unsigned index) {
    

  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;


	/* Dofus v 1.x.x */
	if (packet->payload_packet_len == 13 && get_u16(packet->payload, 1) == ntohs(0x0508)
		&& get_u16(packet->payload, 5) == ntohs(0x04a0)
		&& get_u16(packet->payload, packet->payload_packet_len - 2) == ntohs(0x0194)) {
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "found dofus.\n");
		mmt_dofus_add_connection(ipacket);
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len == 3 && mmt_memcmp(packet->payload, "HG", 2) == 0
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len == 35 && mmt_memcmp(packet->payload, "HC", 2) == 0
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len > 2 && packet->payload[0] == 'A'
		&& (packet->payload[1] == 'x' || packet->payload[1] == 'X')
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len == 12 && mmt_memcmp(packet->payload, "Af", 2) == 0
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (flow->l4.tcp.dofus_stage == 0 && packet->payload_packet_len > 2 && mmt_memcmp(packet->payload, "Ad", 2)
		&& packet->payload[packet->payload_packet_len - 1] == 0) {
		flow->l4.tcp.dofus_stage = 1;
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "maybe dofus.\n");
		return;
	}
	if (packet->payload_packet_len == 11 && mmt_memcmp(packet->payload, "AT", 2) == 0 && packet->payload[10] == 0x00) {
		if (flow->l4.tcp.dofus_stage == 1) {
			MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "found dofus.\n");
			mmt_dofus_add_connection(ipacket);
			return;
		}
	}
	if (flow->l4.tcp.dofus_stage == 1 && packet->payload_packet_len == 5
		&& packet->payload[0] == 'A' && packet->payload[4] == 0x00 && (packet->payload[1] == 'T'
																	   || packet->payload[1] == 'k')) {
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "found dofus asym.\n");
		mmt_dofus_add_connection(ipacket);
		return;
	}
	/* end Dofus 1.x.x */


	/* Dofus 2.0 */
	if ((packet->payload_packet_len == 11 || packet->payload_packet_len == 13 || packet->payload_packet_len == 49)
		&& get_u32(packet->payload, 0) == ntohl(0x00050800)
		&& get_u16(packet->payload, 4) == ntohs(0x0005)
		&& get_u16(packet->payload, 8) == ntohs(0x0005)
		&& packet->payload[10] == 0x18) {
		if (packet->payload_packet_len == 13
			&& get_u16(packet->payload, packet->payload_packet_len - 2) != ntohs(0x0194)) {
			goto exclude;
		}
		if (packet->payload_packet_len == 49 && ntohs(get_u16(packet->payload, 15)) + 17 != packet->payload_packet_len) {
			goto exclude;
		}
		MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "found dofus.\n");
		mmt_dofus_add_connection(ipacket);
		return;
	}
	if (packet->payload_packet_len >= 41 && get_u16(packet->payload, 0) == ntohs(0x01b9) && packet->payload[2] == 0x26) {
		uint16_t len, len2;
		len = ntohs(get_u16(packet->payload, 3));
		if ((len + 5 + 2) > packet->payload_packet_len)
			goto exclude;
		len2 = ntohs(get_u16(packet->payload, 5 + len));
		if (5 + len + 2 + len2 == packet->payload_packet_len) {
			MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "found dofus.\n");
			mmt_dofus_add_connection(ipacket);
			return;
		}
	}
	if (packet->payload_packet_len == 56
		&& mmt_memcmp(packet->payload, "\x00\x11\x35\x02\x03\x00\x93\x96\x01\x00", 10) == 0) {
		uint16_t len, len2;
		len = ntohs(get_u16(packet->payload, 10));
		if ((len + 12 + 2) > packet->payload_packet_len)
			goto exclude;
		len2 = ntohs(get_u16(packet->payload, 12 + len));
		if ((12 + len + 2 + len2 + 1) > packet->payload_packet_len)
			goto exclude;
		if (12 + len + 2 + len2 + 1 == packet->payload_packet_len && packet->payload[12 + len + 2 + len2] == 0x01) {
			MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "found dofus.\n");
			mmt_dofus_add_connection(ipacket);
			return;
		}
	}
  exclude:
	MMT_LOG(PROTO_DOFUS, MMT_LOG_DEBUG, "exclude dofus.\n");
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DOFUS);
}

int mmt_check_dofus(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_dofus(ipacket, index);
    }
    return 4;
}

void mmt_init_classify_me_dofus() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_DOFUS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dofus_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DOFUS, PROTO_DOFUS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_dofus();

        return register_protocol(protocol_struct, PROTO_DOFUS);
    } else {
        return 0;
    }
}


