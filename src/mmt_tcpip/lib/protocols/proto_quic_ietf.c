/*
 * proto_quic_ietf.c
 *
 *  Created on: Feb 16, 2023
 *      Author: nhnghia
 */

#include "proto_quic_ietf.h"
#include "mmt_tcpip_protocols.h"
#include "../mmt_common_internal_include.h"
#include <arpa/inet.h>

#define NOT_FOUND 0
#define FOUND     1

#define QUIC_IETF_VERSION_1 0x00000001

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static int _extraction_quic_ietf_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	size_t offset = get_packet_offset_at_index(ipacket, index);
	// get the first bit in the UDP payload
	uint8_t first_bit = ipacket->data[ offset ] & 0b10000000;
	const uint8_t *p;
	const uint32_t *u32;
	mmt_string_data_t *string;

	if( first_bit != 0 ){
		//Long header
		quic_ietf_long_header_t *hdr = (quic_ietf_long_header_t*) &ipacket->data[offset];
		p = &hdr->destination_connection_id_length;
		p += 1; //start of DESTINATION_CONNECTION_ID
		hdr->destination_connection_id = p;
		//jump over DESTINATION_CONNECTION_ID
		p += hdr->destination_connection_id_length;

		hdr->source_connection_id_length = *p;
		p += 1;
		hdr->source_connection_id = p;
		p += hdr->source_connection_id_length;

		//payload
		hdr->types_pecific_payload = p;

		switch( extracted_data->field_id ){
		case QUIC_IETF_HEADER_FORM:
			(*(uint8_t *) extracted_data->data) = hdr->header_form;
			return ATTRIBUTE_SET;
		case QUIC_IETF_LONG_PACKET_TYPE:
			(*(uint8_t *) extracted_data->data) = hdr->long_packet_type;
			return ATTRIBUTE_SET;
		case QUIC_IETF_VERSION:
			(*(uint32_t *) extracted_data->data) = ntohl( hdr->version );
			return ATTRIBUTE_SET;
		case QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH:
			(*(uint16_t *) extracted_data->data) = hdr->destination_connection_id_length;
			return ATTRIBUTE_SET;
		case QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH:
			(*(uint16_t *) extracted_data->data) = hdr->source_connection_id_length;
			return ATTRIBUTE_SET;
		}

		//for each type of packet
		switch( hdr->long_packet_type ){
		//Initial: https://datatracker.ietf.org/doc/html/rfc9000#packet-initial
		case 0: {
			quic_ietf_initial_packet_t *ext = (quic_ietf_initial_packet_t* ) hdr->types_pecific_payload;
			switch( extracted_data->field_id ){
			case QUIC_IETF_TOKEN_LENGTH:
				(*(uint16_t *) extracted_data->data) = ext->token_length;
				return ATTRIBUTE_SET;
			}
		}
			break;
		//0-RTT: https://datatracker.ietf.org/doc/html/rfc9000#packet-0rtt
		case 1:
			break;

		//Handshake: https://datatracker.ietf.org/doc/html/rfc9000#packet-handshake
		case 2:
			break;
		//Retry: https://datatracker.ietf.org/doc/html/rfc9000#packet-retry
		case 3:
			break;
		}
	} else {
		//Short header
		quic_ietf_short_packet_t *hdr = (quic_ietf_short_packet_t *) &ipacket->data[offset];
		switch( extracted_data->field_id ){
		case QUIC_IETF_HEADER_FORM:
			(*(uint8_t *) extracted_data->data) = hdr->header_form;
			return ATTRIBUTE_SET;
		case QUIC_IETF_SPIN_BIT:
			(*(uint8_t *) extracted_data->data) = hdr->spin_bit;
			return ATTRIBUTE_SET;
		case QUIC_IETF_PACKET_NUMBER_LENGTH:
			(*(uint8_t *) extracted_data->data) = hdr->packet_number_length;
			return ATTRIBUTE_SET;
		case QUIC_IETF_DESTINATION_CONNECTION_ID:
			string = (mmt_string_data_t *) extracted_data;
			string->len = 8;
			snprintf( (char*)string->data, 8, "%s", hdr->destination_connection_id );
			return ATTRIBUTE_SET;
		case QUIC_IETF_PACKET_NUMBER:
			u32 = (uint32_t*)&hdr->packet_number;
			(*(uint32_t *) extracted_data->data) = 0;//ntohl( *u32 );
			return ATTRIBUTE_SET;
		}
	}
	return ATTRIBUTE_UNSET;
}

static int _classify_quic_ietf_from_udp(ipacket_t *ipacket, unsigned index) {
	size_t offset = get_packet_offset_at_index(ipacket, index);
	//const struct udphdr *udp = (struct udphdr *) &ipacket->data[ offset ];
	offset += 8; //8 bytes of UDP header
	size_t payload_len = ipacket->p_hdr->len - offset;

	// get the first bit in the UDP payload
	uint8_t first_bit = ipacket->data[ offset ] & 0b10000000;


	if( first_bit != 0 ){
		// Long Header
		const quic_ietf_long_header_t *hdr = (quic_ietf_long_header_t*) &ipacket->data[offset];
		// must have enough room
		if( payload_len < sizeof( *hdr))
			goto _not_found_quic_ietf;

		//is set to 1.
		// Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded
		// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
		if( hdr->fixed_bit != 1 )
			goto _not_found_quic_ietf;
		//TODO: support only version 1 for now
		if( ntohl(hdr->version) != QUIC_IETF_VERSION_1 )
			goto _not_found_quic_ietf;

	} else {
		//Short Header
		const quic_ietf_short_packet_t *hdr = (quic_ietf_short_packet_t *) &ipacket->data[offset];
		// must have enough room
		if( payload_len < sizeof( *hdr))
			goto _not_found_quic_ietf;

		if( hdr->fixed_bit != 1 ) //
			goto _not_found_quic_ietf;

		//The value included prior to protection MUST be set to 0.
		if( hdr->reserved_bits != 0 ) //
			goto _not_found_quic_ietf;

		//check correct packet length

	}

	//if we can reach here => all signatures are valid => got QUIC
	mmt_internal_add_connection(ipacket, PROTO_QUIC_IETF, MMT_REAL_PROTOCOL);
	return FOUND;

	_not_found_quic_ietf:
	//checked but not found
	//=> exclude from the next check
	MMT_ADD_PROTOCOL_TO_BITMASK(ipacket->internal_packet->flow->excluded_protocol_bitmask, PROTO_QUIC_IETF);
	return NOT_FOUND;
}

static void _session_data_init(ipacket_t * ipacket, unsigned index) {
	quic_ietf_session_t * session_data = (quic_ietf_session_t *) mmt_malloc(sizeof (*session_data));

	memset(session_data, 0, sizeof(*session_data));
	ipacket->session->session_data[index] = session_data;
}


static void _session_data_cleanup(mmt_session_t * session, unsigned index) {
	if (session->session_data[index] != NULL) {
		mmt_free(session->session_data[index]);
	}
}

static int _session_data_analysis(ipacket_t * ipacket, unsigned index) {
	//Dummy function! just calls the function registered with the session context
	//struct quic_ietf_session_t * session_data = ipacket->session->session_data[index];
	return MMT_CONTINUE;
}


void _init_bitmask() {
	selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
	MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
	MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_UDP);
	MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_QUIC_IETF);
}

#define def_att(id, data_type, data_len ) { id, id##_ALIAS, data_type, data_len, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_quic_ietf_att}
static attribute_metadata_t _attributes_metadata[] = {
	def_att( QUIC_IETF_HEADER_FORM,      MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_LONG_PACKET_TYPE, MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_SPIN_BIT,         MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_VERSION,          MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH, MMT_U16_DATA,            sizeof(uint16_t) ),
	def_att( QUIC_IETF_DESTINATION_CONNECTION_ID,        MMT_STRING_DATA_POINTER, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH,      MMT_U16_DATA,            sizeof(uint16_t) ),
	def_att( QUIC_IETF_SOURCE_CONNECTION_ID,             MMT_STRING_DATA_POINTER, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_LENGTH,               MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_PACKET_NUMBER_LENGTH, MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_PACKET_NUMBER,        MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_TOKEN_LENGTH,         MMT_U16_DATA, sizeof(uint16_t) ),
	def_att( QUIC_IETF_TOKEN,                MMT_STRING_DATA_POINTER, sizeof(mmt_string_data_t) )
};


int init_proto_quic_ietf_struct() {

	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_QUIC_IETF, PROTO_QUIC_IETF_ALIAS);
	if( protocol_struct == NULL ){
		log_err("Cannot initialize PROTO_QUIC_IETF having id=%d", PROTO_QUIC_IETF);
		return PROTO_NOT_REGISTERED;
	}

	int i, len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ ){
		if( ! register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i]) ){
			log_err("Cannot register attribute %s.%s", PROTO_QUIC_IETF_ALIAS,  _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	}

	//QUIC is after UDP, so we classify it once we got UDP
	//TODO: need to classify QUIC after QUIC
	if( !register_classification_function_with_parent_protocol( PROTO_UDP, _classify_quic_ietf_from_udp, 100 ) ){
		log_err("Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}

	_init_bitmask();

	//TODO: need to get QUIC session
	register_session_data_initialization_function(protocol_struct, _session_data_init);
	register_session_data_cleanup_function(protocol_struct, _session_data_cleanup);
	register_session_data_analysis_function(protocol_struct, _session_data_analysis);

	return register_protocol(protocol_struct, PROTO_QUIC_IETF);
}
