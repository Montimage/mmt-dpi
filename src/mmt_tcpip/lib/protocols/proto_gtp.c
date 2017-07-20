#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

/**
 * http://www.qtc.jp/3GPP/Specs/29060-790.pdf
 * http://etutorials.org/Mobile+devices/gprs+mobile+internet/Chapter+8+User+Plane/GTP+Layer+for+the+User+Plane/
 *
 */

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

struct gtp_header_generic {
	uint8_t ndpu_number : 1, sequence_number : 1, extension_header : 1, reserved : 1, proto_type : 1 , version : 3;
	u_int8_t message_type;
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

	if ((packet->udp != NULL) && (payload_len >= sizeof(struct gtp_header_generic))) {
		u_int32_t gtp_u  = ntohs(2152);
		u_int32_t gtp_c  = ntohs(2123);
		u_int32_t gtp_v0 = ntohs(3386);

		if ((packet->udp->source == gtp_u) || (packet->udp->dest == gtp_u)
		        || (packet->udp->source == gtp_c) || (packet->udp->dest == gtp_c)
		        || (packet->udp->source == gtp_v0) || (packet->udp->dest == gtp_v0)
		   ) {
			struct gtp_header_generic *gtp = (struct gtp_header_generic*)packet->payload;
			// u_int8_t gtp_version = (gtp->flags & 0xE0) >> 5;

			if ((gtp->version == 0) || (gtp->version == 1) || (gtp->version == 2)) {
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

int gtp_classify_next_proto(ipacket_t * ipacket, unsigned index) {

	int offset = get_packet_offset_at_index(ipacket, index);
	struct gtp_header_generic *gtp = (struct gtp_header_generic*)& ipacket->data[offset];
	int gtp_offset = sizeof (struct gtp_header_generic);
	if(gtp->sequence_number == 1){
		gtp_offset += 4;
	}
	if(gtp->ndpu_number == 1){
		gtp_offset += 2;
	}
	if(gtp->extension_header == 1){
		gtp_offset += 2;	
	}
	if (gtp->message_type == 0xff) {
		classified_proto_t retval;
		retval.proto_id = PROTO_IP;
		retval.offset = gtp_offset;
		retval.status = Classified;
		return set_classified_proto(ipacket, index + 1, retval);
	}
	return 0;
}


void mmt_init_classify_me_gtp() {
	selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
	MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
	MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_GTP);
}

int gtp_version_flag_extraction(const ipacket_t * packet, unsigned proto_index,
                                attribute_t * extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	struct gtp_header_generic * gtp = (struct gtp_header_generic *) & packet->data[proto_offset];
	*((unsigned char *) extracted_data->data) = gtp->version;
	return 1;
}


int gtp_protocol_type_flag_extraction(const ipacket_t * packet, unsigned proto_index,
                                      attribute_t * extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	struct gtp_header_generic * gtp = (struct gtp_header_generic *) & packet->data[proto_offset];
	*((unsigned char *) extracted_data->data) = gtp->proto_type;
	return 1;
}

int gtp_reserved_flag_extraction(const ipacket_t * packet, unsigned proto_index,
                                 attribute_t * extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	struct gtp_header_generic * gtp = (struct gtp_header_generic *) & packet->data[proto_offset];
	*((unsigned char *) extracted_data->data) = gtp->reserved;
	return 1;
}

int gtp_extension_header_flag_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	struct gtp_header_generic * gtp = (struct gtp_header_generic *) & packet->data[proto_offset];
	*((unsigned char *) extracted_data->data) = gtp->extension_header;
	return 1;
}

int gtp_sequence_number_flag_extraction(const ipacket_t * packet, unsigned proto_index,
                                        attribute_t * extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	struct gtp_header_generic * gtp = (struct gtp_header_generic *) & packet->data[proto_offset];
	*((unsigned char *) extracted_data->data) = gtp->sequence_number;
	return 1;
}

int gtp_npdu_number_flag_extraction(const ipacket_t * packet, unsigned proto_index,
                                    attribute_t * extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	struct gtp_header_generic * gtp = (struct gtp_header_generic *) & packet->data[proto_offset];
	*((unsigned char *) extracted_data->data) = gtp->ndpu_number;
	return 1;
}


static attribute_metadata_t gtp_attributes_metadata[GTP_ATTRIBUTES_NB] = {
	{GTP_VERSION, GTP_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, gtp_version_flag_extraction},
	{GTP_PROTOCOL_TYPE, GTP_PROTOCOL_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, gtp_protocol_type_flag_extraction},
	{GTP_RESERVED, GTP_RESERVED_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, gtp_reserved_flag_extraction},
	{GTP_EXTENSION_HEADER, GTP_EXTENSION_HEADER_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, gtp_extension_header_flag_extraction},
	{GTP_SEQUENCE_NUMBER, GTP_SEQUENCE_NUMBER_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, gtp_sequence_number_flag_extraction},
	{GTP_NPDU_NUMBER, GTP_NPDU_NUMBER_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, gtp_npdu_number_flag_extraction},
	{GTP_MESSAGE_TYPE, GTP_MESSAGE_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_byte_to_byte_extraction},
	{GTP_LENGTH, GTP_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
	{GTP_TEID, GTP_TEID_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
};

int init_proto_gtp_struct() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GTP, PROTO_GTP_ALIAS);
	if (protocol_struct != NULL) {
		int i = 0;
		for (; i < GTP_ATTRIBUTES_NB; i++) {
			register_attribute_with_protocol(protocol_struct, &gtp_attributes_metadata[i]);
		}
		mmt_init_classify_me_gtp();
		register_classification_function(protocol_struct, gtp_classify_next_proto);
		return register_protocol(protocol_struct, PROTO_GTP);
	} else {
		return 0;
	}
}


