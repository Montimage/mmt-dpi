#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_sopcast_add_connection(ipacket_t * ipacket)
{
	mmt_internal_add_connection(ipacket, PROTO_SOPCAST, MMT_REAL_PROTOCOL);
}

/**
 * this function checks for sopcast tcp pattern
 *
 * NOTE: if you add more patterns please keep the number of if levels
 * low, it is already complex enough
 */
static uint8_t mmt_int_is_sopcast_tcp(const uint8_t * payload, const uint16_t payload_len)
{
	if (payload_len != 54)
		return 0;

	if (payload[2] != payload[3] - 4 && payload[2] != payload[3] + 4)
		return 0;

	if (payload[2] != payload[4] - 1 && payload[2] != payload[4] + 1)
		return 0;

	if (payload[25] != payload[25 + 16 - 1] + 1 && payload[25] != payload[25 + 16 - 1] - 1) {

		if (payload[3] != payload[25] &&
			payload[3] != payload[25] - 4 && payload[3] != payload[25] + 4 && payload[3] != payload[25] - 21) {
			return 0;
		}
	}

	if (payload[4] != payload[28] ||
		payload[28] != payload[30] ||
		payload[30] != payload[31] ||
		get_u16(payload, 30) != get_u16(payload, 32) || get_u16(payload, 32) != get_u16(payload, 34)) {

		if ((payload[2] != payload[5] - 1 && payload[2] != payload[5] + 1) ||
			payload[2] != payload[25] ||
			payload[4] != payload[28] ||
			payload[4] != payload[31] ||
			payload[4] != payload[32] ||
			payload[4] != payload[33] ||
			payload[4] != payload[34] ||
			payload[4] != payload[35] || payload[4] != payload[30] || payload[2] != payload[36]) {
			return 0;
		}
	}

	if (payload[42] != payload[53])
		return 0;

	if (payload[45] != payload[46] + 1 && payload[45] != payload[46] - 1)
		return 0;

	if (payload[45] != payload[49] || payload[46] != payload[50] || payload[47] != payload[51])
		return 0;

	return 1;
}

static void mmt_search_sopcast_tcp(ipacket_t * ipacket) {



  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;
	if (ipacket->session->data_packet_count == 1 && packet->payload_packet_len == 54 && get_u16(packet->payload, 0) == ntohs(0x0036)) {
		if (mmt_int_is_sopcast_tcp(packet->payload, packet->payload_packet_len)) {
			MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast TCP \n");
			mmt_int_sopcast_add_connection(ipacket);
			return;
		}
	}

	MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "exclude sopcast TCP.  \n");
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SOPCAST);


}

static void mmt_search_sopcast_udp(ipacket_t * ipacket) {


  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;

//      struct mmt_id_struct         *src=mmt_struct->src;
//      struct mmt_id_struct         *dst=mmt_struct->dst;

	MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "search sopcast.  \n");


	if (packet->payload_packet_len == 52 && packet->payload[0] == 0xff
		&& packet->payload[1] == 0xff && packet->payload[2] == 0x01
		&& packet->payload[8] == 0x02 && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x2c
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00 && packet->payload[14] == 0x00) {
		MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast with if I.  \n");
		mmt_int_sopcast_add_connection(ipacket);
		return;
	}
	if ((packet->payload_packet_len == 80 || packet->payload_packet_len == 28 || packet->payload_packet_len == 94)
		&& packet->payload[0] == 0x00 && (packet->payload[2] == 0x02 || packet->payload[2] == 0x01)
		&& packet->payload[8] == 0x01 && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x14
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast with if II.  \n");
		mmt_int_sopcast_add_connection(ipacket);
		return;
	}
	/* this case has been seen once. Please revome this comment, if you see it another time */
	if (packet->payload_packet_len == 60 && packet->payload[0] == 0x00
		&& packet->payload[2] == 0x01
		&& packet->payload[8] == 0x03 && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x34
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00 && packet->payload[14] == 0x00) {
		MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast with if III.  \n");
		mmt_int_sopcast_add_connection(ipacket);
		return;
	}
	if (packet->payload_packet_len == 42 && packet->payload[0] == 0x00
		&& packet->payload[1] == 0x02 && packet->payload[2] == 0x01
		&& packet->payload[3] == 0x07 && packet->payload[4] == 0x03
		&& packet->payload[8] == 0x06
		&& packet->payload[9] == 0x01 && packet->payload[10] == 0x00
		&& packet->payload[11] == 0x22 && packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast with if IV.  \n");
		mmt_int_sopcast_add_connection(ipacket);
		return;
	}
	if (packet->payload_packet_len == 28 && packet->payload[0] == 0x00
		&& packet->payload[1] == 0x0c && packet->payload[2] == 0x01
		&& packet->payload[3] == 0x07 && packet->payload[4] == 0x00
		&& packet->payload[8] == 0x01
		&& packet->payload[9] == 0x01 && packet->payload[10] == 0x00
		&& packet->payload[11] == 0x14 && packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast with if V.  \n");
		mmt_int_sopcast_add_connection(ipacket);
		return;
	}
	/* this case has been seen once. Please revome this comment, if you see it another time */
	if (packet->payload_packet_len == 286 && packet->payload[0] == 0x00
		&& packet->payload[1] == 0x02 && packet->payload[2] == 0x01
		&& packet->payload[3] == 0x07 && packet->payload[4] == 0x03
		&& packet->payload[8] == 0x06
		&& packet->payload[9] == 0x01 && packet->payload[10] == 0x01
		&& packet->payload[11] == 0x16 && packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast with if VI.  \n");
		mmt_int_sopcast_add_connection(ipacket);
		return;
	}
	if (packet->payload_packet_len == 76 && packet->payload[0] == 0xff
		&& packet->payload[1] == 0xff && packet->payload[2] == 0x01
		&& packet->payload[8] == 0x0c && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x44
		&& packet->payload[16] == 0x01 && packet->payload[15] == 0x01
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00 && packet->payload[14] == 0x00) {
		MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "found sopcast with if VII.  \n");
		mmt_int_sopcast_add_connection(ipacket);
		return;
	}

	/* Attention please: no asymmetric detection necessary. This detection works asymmetrically as well. */

	MMT_LOG(PROTO_SOPCAST, MMT_LOG_DEBUG, "exclude sopcast.  \n");
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SOPCAST);



}

void mmt_classify_me_sopcast(ipacket_t * ipacket, unsigned index) {
  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

	if (packet->udp != NULL)
		mmt_search_sopcast_udp(ipacket);
	if (packet->tcp != NULL)
		mmt_search_sopcast_tcp(ipacket);

}

int mmt_check_sopcast_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_search_sopcast_tcp(ipacket);
    }
    return 4;
}

int mmt_check_sopcast_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_search_sopcast_udp(ipacket);
    }
    return 4;
}

void mmt_init_classify_me_sopcast() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SOPCAST);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_sopcast_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SOPCAST, PROTO_SOPCAST_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_sopcast();

        return register_protocol(protocol_struct, PROTO_SOPCAST);
    } else {
        return 0;
    }
}


