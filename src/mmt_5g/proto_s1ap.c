/*
 * proto_s1ap.c
 *
 *  Created on: Nov 2, 2018
 *          by: nhnghia
 */

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"

#include "proto_s1ap.h"
#include "mmt_tcpip.h"
#include "s1ap_common.h"

#define __PACKED __attribute__((packed))

struct sctp_datahdr {
	uint8_t type;
	uint8_t flags;
	uint16_t length;
	uint32_t tsn;
	uint16_t stream;
	uint16_t ssn;
	uint32_t ppid;
} __PACKED;


static int _parse_s1ap_packet( s1ap_message_t *msg, const ipacket_t * packet, unsigned proto_index ){

	int offset = get_packet_offset_at_index(packet, proto_index);
	if( unlikely( packet->p_hdr->caplen < offset ))
		return 0;

	const uint16_t data_len = packet->p_hdr->caplen - offset;

	return s1ap_decode( msg, & packet->data[offset], data_len );
}


static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	if (packet->session == NULL)
		return 0;

	s1ap_message_t msg;
	_parse_s1ap_packet( &msg, packet, proto_index );

	mmt_header_line_t *h;
	mmt_binary_data_t *b;
	switch( extracted_data->field_id ){
	case S1AP_UE_IP:
		*((uint32_t *) extracted_data->data) = msg.ue_ipv4;
		break;
	case S1AP_ENB_IP:
		*((uint32_t *) extracted_data->data) = msg.enb_ipv4;
		break;
	case S1AP_MME_IP:
		*((uint32_t *) extracted_data->data) = msg.mme_ipv4;
		break;
	case S1AP_TEID:
		*((uint32_t *) extracted_data->data) = ntohl( msg.gtp_teid );
		break;
	case S1AP_ENB_NAME:
		h = (mmt_header_line_t *)extracted_data->data;
		h->len = msg.enb_name.len;
		h->ptr = msg.enb_name.ptr;
		break;
	case S1AP_MME_NAME:
		h = (mmt_header_line_t *)extracted_data->data;
		h->len = msg.mme_name.len;
		h->ptr = msg.mme_name.ptr;
		break;
	case S1AP_IMSI:
		b = (mmt_binary_data_t *) extracted_data->data;
		b->len = sizeof( msg.imsi );
		memcpy( b->data, msg.imsi, b->len);
		b->data[ b->len + 1 ] = '\0';
		break;
	}

	return 1;
}


static attribute_metadata_t s1ap_attributes_metadata[] = {
		{S1AP_IMSI,     S1AP_IMSI_ALIAS,     MMT_STRING_DATA,  sizeof( mmt_binary_data_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_TEID,     S1AP_TEID_ALIAS,     MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_UE_IP,    S1AP_UE_IP_ALIAS,    MMT_DATA_IP_ADDR, sizeof( MMT_DATA_IP_ADDR),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ENB_NAME, S1AP_ENB_NAME_ALIAS, MMT_HEADER_LINE,  sizeof (MMT_HEADER_LINE),   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ENB_IP,   S1AP_ENB_IP_ALIAS,   MMT_DATA_IP_ADDR, sizeof (MMT_DATA_IP_ADDR),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_MME_NAME, S1AP_MME_NAME_ALIAS, MMT_HEADER_LINE,  sizeof (MMT_HEADER_LINE),   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_MME_IP,   S1AP_MME_IP_ALIAS,   MMT_DATA_IP_ADDR, sizeof (MMT_DATA_IP_ADDR),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att}
};
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

static int _classify_s1ap_from_sctp_data( ipacket_t * ipacket, unsigned index ){
	int offset = get_packet_offset_at_index(ipacket, index);
	//not enough room
	if( offset > ipacket->p_hdr->caplen + sizeof(struct sctp_datahdr) )
		return 0;

	classified_proto_t retval;

	struct sctp_datahdr *hdr = (struct sctp_datahdr *) &ipacket->data[ offset ];
	switch( ntohl( hdr->ppid )){
	case 18: //S1AP
		retval.proto_id = PROTO_S1AP;
		retval.offset = sizeof( struct sctp_datahdr );
		retval.status = Classified;

		//fix length
		ipacket->proto_hierarchy->len =      (index + 1) + 1;
		return set_classified_proto(ipacket, (index + 1), retval);
	default:
		return 0;
	}

	return 0;
}


/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_s1ap() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_S1AP, PROTO_S1AP_ALIAS);

	if( protocol_struct == NULL ){
		fprintf(stderr, "Cannot initialize S1AP protocol");
		return 0;
	}

	int i = 0;
	int len = sizeof( s1ap_attributes_metadata ) / sizeof( attribute_metadata_t );
	for (; i < len; i++)
		register_attribute_with_protocol(protocol_struct, &s1ap_attributes_metadata[i]);

	register_classification_function_with_parent_protocol( PROTO_SCTP_DATA, _classify_s1ap_from_sctp_data, 100 );

	//register_classification_function(protocol_struct, sctp_classify_next_chunk);

	if (protocol_struct != NULL) {
		return register_protocol(protocol_struct, PROTO_S1AP);
	} else {
		return 0;
	}
}


int init_proto() {
	return init_proto_s1ap();
}
int cleanup_proto(){
	//printf("close s1ap protocol");
	return 0;
}
