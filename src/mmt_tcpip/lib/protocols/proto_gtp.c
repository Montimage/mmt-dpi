#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

struct gtp_header_generic {
	u_int8_t flags, message_type;
	u_int16_t message_len;
	u_int32_t teid;
};

// end of TDS header
static void mmt_int_gtp_add_connection(ipacket_t * ipacket) {
	mmt_internal_add_connection(ipacket, PROTO_GTP, MMT_REAL_PROTOCOL);
}

int mmt_check_gtp(ipacket_t * ipacket, unsigned index) {


	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	struct mmt_internal_tcpip_session_struct *flow = packet->flow;

	MMT_LOG(PROTO_GTP, MMT_LOG_DEBUG, "search gtp.\n");

	// const u_int8_t *packet_payload = packet->payload;
	u_int32_t payload_len = packet->payload_packet_len;

	if ((packet->udp != NULL) && (payload_len > sizeof(struct gtp_header_generic))) {
		u_int32_t gtp_u  = ntohs(2152);
		u_int32_t gtp_c  = ntohs(2123);
		u_int32_t gtp_v0 = ntohs(3386);

		if ((packet->udp->source == gtp_u) || (packet->udp->dest == gtp_u)
		        || (packet->udp->source == gtp_c) || (packet->udp->dest == gtp_c)
		        || (packet->udp->source == gtp_v0) || (packet->udp->dest == gtp_v0)
		   ) {
			struct gtp_header_generic *gtp = (struct gtp_header_generic*)packet->payload;
			u_int8_t gtp_version = (gtp->flags & 0xE0) >> 5;

			if ((gtp_version == 0) || (gtp_version == 1) || (gtp_version == 2)) {
				u_int16_t message_len = ntohs(gtp->message_len);

				if (message_len <= (payload_len - sizeof(struct gtp_header_generic))) {
					MMT_LOG(PROTO_GTP, MMT_LOG_DEBUG, "found gtp.\n");
					mmt_int_gtp_add_connection(ipacket);
					return 1;
				}
			}
		}
	}
	MMT_LOG(PROTO_GTP, MMT_LOG_DEBUG, "exclude gtp.\n");
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_GTP);
	return 0;
}

void mmt_init_classify_me_gtp() {
	selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
	MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
	MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_GTP);
}

int init_proto_gtp_struct() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GTP, PROTO_GTP_ALIAS);
	if (protocol_struct != NULL) {
		mmt_init_classify_me_gtp();
		return register_protocol(protocol_struct, PROTO_GTP);
	} else {
		return 0;
	}
}


