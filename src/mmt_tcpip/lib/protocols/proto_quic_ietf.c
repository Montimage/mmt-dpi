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

/* Parse the long header at data[0..len) into the LOCAL descriptor `hdr`.
 * Returns !=0 only when the whole variable-length section (dcid_len, dcid,
 * scid_len, scid) fits inside `len`: each cursor step is validated against
 * the captured length before it is taken (issue #203, F-BUG-063). A header
 * whose declared spans overrun the capture is malformed — nothing is
 * extracted from it. */
static int _quic_ietf_parse_long_header(const uint8_t *data, size_t len,
		quic_ietf_long_header_t *hdr) {
	//flags octet + version + dcid_len must all be present
	if( len < 6 )
		return 0;
	hdr->flags = data[0];
	{
		uint32_t v;
		memcpy(&v, data + 1, sizeof(v));
		hdr->version = ntohl(v);
	}
	hdr->destination_connection_id_length = data[5];
	size_t cursor = 6;
	if( cursor + hdr->destination_connection_id_length > len )
		return 0;
	hdr->destination_connection_id_offset = cursor;
	cursor += hdr->destination_connection_id_length;
	if( cursor + 1 > len )
		return 0;
	hdr->source_connection_id_length = data[cursor];
	cursor += 1;
	if( cursor + hdr->source_connection_id_length > len )
		return 0;
	hdr->source_connection_id_offset = cursor;
	cursor += hdr->source_connection_id_length;
	hdr->types_pecific_payload_offset = cursor;
	return 1;
}

/* non-static: driven directly by tools/phase0/tests/quic_dtls_extractor_test.c
   (declared in internal_decls.h — internal seam, not a public API) */
int _extraction_quic_ietf_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	int ioff = get_packet_offset_at_index(ipacket, index);
	if( ioff < 0 || (size_t)ioff >= ipacket->p_hdr->caplen )
		return ATTRIBUTE_UNSET;
	size_t offset = (size_t)ioff;
	size_t avail  = ipacket->p_hdr->caplen - offset;
	const uint8_t *data = ipacket->data;
	// first octet: header_form bit7
	uint8_t flags = data[ offset ];
	uint32_t u32;
	quic_ietf_session_t * session_data = ipacket->session->session_data[index];
	//extract session's attributes
	if( session_data != NULL ){
		int dir = (ipacket->internal_packet->src == session_data->quic_client ? CLIENT_TO_SERVER : SERVER_TO_CLIENT );
		spinbit_edge_t *edge = &session_data->spinbit_edge[dir];
		switch( extracted_data->field_id ){
		case QUIC_IETF_RTT:
			//return RTT only when we got 2 halfs of RTT
			if( edge->rtt_us ){
				(*(uint64_t *) extracted_data->data) = edge->rtt_us;
				return ATTRIBUTE_SET;
			} else
				return ATTRIBUTE_UNSET;
		}
	}

	if( flags & 0x80 ){
		//Long header — parse into a local descriptor, never onto the packet
		quic_ietf_long_header_t hdr;
		if( ! _quic_ietf_parse_long_header(data + offset, avail, &hdr) )
			return ATTRIBUTE_UNSET;

		switch( extracted_data->field_id ){
		case QUIC_IETF_HEADER_FORM:
			(*(uint8_t *) extracted_data->data) = (hdr.flags >> 7) & 1;
			return ATTRIBUTE_SET;
		case QUIC_IETF_LONG_PACKET_TYPE:
			(*(uint8_t *) extracted_data->data) = (hdr.flags >> 4) & 3;
			return ATTRIBUTE_SET;
		case QUIC_IETF_VERSION:
			(*(uint32_t *) extracted_data->data) = hdr.version;
			return ATTRIBUTE_SET;
		case QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH:
			(*(uint16_t *) extracted_data->data) = hdr.destination_connection_id_length;
			return ATTRIBUTE_SET;
		case QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH:
			(*(uint16_t *) extracted_data->data) = hdr.source_connection_id_length;
			return ATTRIBUTE_SET;
		}

		//for each type of packet
		switch( (hdr.flags >> 4) & 3 ){
		//Initial: https://datatracker.ietf.org/doc/html/rfc9000#packet-initial
		case QUIC_IETF_INITIAL_PACKET_TYPE:
			switch( extracted_data->field_id ){
			case QUIC_IETF_TOKEN_LENGTH:
				//token_length is the first byte of the type-specific payload
				if( hdr.types_pecific_payload_offset >= avail )
					return ATTRIBUTE_UNSET;
				(*(uint16_t *) extracted_data->data) = data[ offset + hdr.types_pecific_payload_offset ];
				return ATTRIBUTE_SET;
			}
			break;
		//0-RTT: https://datatracker.ietf.org/doc/html/rfc9000#packet-0rtt
		case QUIC_IETF_0RTT_PACKET_TYPE:
			break;

		//Handshake: https://datatracker.ietf.org/doc/html/rfc9000#packet-handshake
		case QUIC_IETF_HANDSHAKE_PACKET_TYPE:
			break;
		//Retry: https://datatracker.ietf.org/doc/html/rfc9000#packet-retry
		case QUIC_IETF_RETRY_PACKET_TYPE:
			break;
		}
	} else {
		//Short header — flag bits are in data[offset]; the fixed 8-byte
		//destination connection id is at offset+1, the packet number at
		//offset+9 (see quic_ietf_1_rtt_packet_t: "TODO: fixed 8 bytes").
		switch( extracted_data->field_id ){
		case QUIC_IETF_HEADER_FORM:
			(*(uint8_t *) extracted_data->data) = (flags >> 7) & 1;
			return ATTRIBUTE_SET;
		case QUIC_IETF_SPIN_BIT:
			(*(uint8_t *) extracted_data->data) = (flags >> 5) & 1;
			return ATTRIBUTE_SET;
		case QUIC_IETF_PACKET_NUMBER_LENGTH:
			(*(uint8_t *) extracted_data->data) = flags & 3;
			return ATTRIBUTE_SET;
		case QUIC_IETF_DESTINATION_CONNECTION_ID:
			if( avail < 1 + 8 )
				return ATTRIBUTE_UNSET;
			{
				mmt_string_data_t *string = (mmt_string_data_t *) extracted_data->data;
				string->len = 8;
				memcpy( string->data, &data[ offset + 1 ], 8 );
				string->data[8] = '\0';
			}
			return ATTRIBUTE_SET;
		case QUIC_IETF_PACKET_NUMBER:
			if( avail < 1 + 8 + 4 )
				return ATTRIBUTE_UNSET;
			//the length of the Packet Number field is the value of QUIC_IETF_PACKET_NUMBER_LENGTH plus one
			memcpy((char*)&u32, &data[ offset + 1 + 8 ], 4);

			switch( (flags & 3) + 1 ){
			case 1:
				((char*)&u32)[1] = 0; //no break here as we need to clear 2nd and 3rd elements
			case 2:
				((char*)&u32)[2] = 0; //no break here as we need to clear 3rd element
			case 3:
				((char*)&u32)[3] = 0;
				break;
			}

			(*(uint32_t *) extracted_data->data) = ntohl(u32);
			return ATTRIBUTE_SET;
		}
	}
	return ATTRIBUTE_UNSET;
}

/* Wire minimums preserved from the old packed-overlay size gates so the
 * classification boundary is byte-identical: the old code required
 * sizeof(quic_ietf_long_header_t)=31 payload bytes for a long header and
 * sizeof(quic_ietf_1_rtt_packet_t)=21 for a short header. */
#define QUIC_IETF_LONG_HEADER_WIRE_MIN  31
#define QUIC_IETF_SHORT_HEADER_WIRE_MIN 21

static int _classify_quic_ietf_from_data_offset(ipacket_t *ipacket, unsigned parent_proto_index, size_t offset) {
	if( offset >= ipacket->p_hdr->caplen )
		return NOT_FOUND;
	size_t payload_len = ipacket->p_hdr->caplen - offset;
	// get the first octet of the UDP payload: header_form bit7, fixed_bit bit6
	uint8_t flags = ipacket->data[ offset ];
	if( flags & 0x80 ){
		// Long Header — must have enough room
		if( payload_len < QUIC_IETF_LONG_HEADER_WIRE_MIN )
			goto _not_found_quic_ietf;

		//fixed_bit (bit6) is set to 1.
		// Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded
		// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
		if( !(flags & 0x40) )
			goto _not_found_quic_ietf;
		//TODO: support only version 1 for now
		{
			uint32_t version;
			memcpy(&version, &ipacket->data[offset + 1], sizeof(version));
			if( ntohl(version) != QUIC_IETF_VERSION_1 )
				goto _not_found_quic_ietf;
		}

	} else {
		//Short Header

		unsigned quick_proto_index = parent_proto_index+1; //index of QUIC protocol if it is available

		//must have enough room to contain QUIC
		if( quick_proto_index >= PROTO_PATH_SIZE )
			goto _not_found_quic_ietf;

		//QUIC session must be initialized (must be seen long header first)
		if( ipacket->session->session_data[quick_proto_index] == NULL )
			goto _not_found_quic_ietf;

		// must have enough room
		if( payload_len < QUIC_IETF_SHORT_HEADER_WIRE_MIN )
			goto _not_found_quic_ietf;

		if( !(flags & 0x40) ) //fixed_bit is set to 1
			goto _not_found_quic_ietf;

		//FIXME: not sure why this value can be non-zero
		//The value included prior to protection MUST be set to 0.
		//if( (flags & 0x18) != 0 ) //reserved_bits
		//	goto _not_found_quic_ietf;

		//check correct packet length
	}

	//if we can reach here => all signatures are valid => got QUIC
	//mmt_internal_add_connection(ipacket, PROTO_QUIC_IETF, MMT_REAL_PROTOCOL);
	//debug("classified QUIC");
	return FOUND;

	_not_found_quic_ietf:
	//checked but not found
	//=> exclude from the next check
	//MMT_ADD_PROTOCOL_TO_BITMASK(ipacket->internal_packet->flow->excluded_protocol_bitmask, PROTO_QUIC_IETF);
	return NOT_FOUND;
}

static void _quic_ietf_session_data_init(ipacket_t * ipacket, unsigned index);
static int _quic_ietf_session_data_analysis(ipacket_t * ipacket, unsigned index);

static int _classified_quic_ietf(ipacket_t *ipacket, unsigned index, size_t offset){
	classified_proto_t retval;
	retval.offset = offset;
	retval.proto_id = PROTO_QUIC_IETF;
	retval.status = Classified;

	//TODO: need to find a suitable place to put these 2 functions
	_quic_ietf_session_data_init( ipacket, index+1 );
	_quic_ietf_session_data_analysis( ipacket, index+1 );
	return set_classified_proto(ipacket, index+1, retval);
}
static int _classify_quic_ietf_from_udp(ipacket_t *ipacket, unsigned index) {
	int base = get_packet_offset_at_index(ipacket, index);
	if( base < 0 || (size_t)base + 8 > ipacket->p_hdr->caplen )
		return NOT_FOUND;
	size_t offset = (size_t)base + 8; //8 bytes of UDP header
	if( _classify_quic_ietf_from_data_offset( ipacket, index, offset ) == FOUND )
		return _classified_quic_ietf( ipacket, index, 8 );
	return NOT_FOUND;
}

static int _classify_quic_ietf_from_int(ipacket_t *ipacket, unsigned index) {
	//it is evident
	if( ipacket->proto_hierarchy->proto_path[index] != PROTO_INT )
		return NOT_FOUND;
	//classify only if we got UDP
	if( index >=1 && ipacket->proto_hierarchy->proto_path[index-1] != PROTO_UDP )
		return NOT_FOUND;

	int base = get_packet_offset_at_index(ipacket, index);
	if( base < 0 || (size_t)base + 56 > ipacket->p_hdr->caplen )
		return NOT_FOUND;
	size_t offset = (size_t)base + 56; //56 bytes of INT
	if( offset >= ipacket->p_hdr->caplen )
		return NOT_FOUND;

	if( _classify_quic_ietf_from_data_offset( ipacket, index, offset ) == FOUND )
		return _classified_quic_ietf( ipacket, index, 56 );
	return NOT_FOUND;
}

static void _quic_ietf_session_data_init(ipacket_t * ipacket, unsigned index) {
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

	quic_ietf_session_t * session_data = ipacket->session->session_data[index];
	if( session_data == NULL ){
		session_data = (quic_ietf_session_t *) mmt_malloc(sizeof (*session_data));
		debug("QUIC session init");
		memset(session_data, 0, sizeof(*session_data));
		ipacket->session->session_data[index] = session_data;

		session_data->quic_client = packet->src;
	}
}


static void _quic_ietf_session_data_cleanup(mmt_session_t * session, unsigned index) {
	debug("QUIC session clean");
	if (session->session_data[index] != NULL) {
		mmt_free(session->session_data[index]);
	}
}



static void _quic_ietf_calculate_rtts(ipacket_t * ipacket, unsigned index, quic_ietf_session_t * session){
	attribute_t extracted_data;
	uint8_t spinbit = 0;
	//prepare to extract spinbit
	extracted_data.proto_id = PROTO_QUIC_IETF;
	extracted_data.field_id = QUIC_IETF_SPIN_BIT;
	extracted_data.data     = &spinbit;
	//get spinbit
	if( _extraction_quic_ietf_att( ipacket, index, &extracted_data ) == ATTRIBUTE_UNSET ){
		//no spinbit => long header
		//=> reset rtt
		memset(& session->spinbit_edge[0], 0, sizeof(spinbit_edge_t));
		memset(& session->spinbit_edge[1], 0, sizeof(spinbit_edge_t));
		debug("QUIC reset spinbit edge");

		//extract long packet type
		uint8_t long_packet_type = 0;
		extracted_data.field_id = QUIC_IETF_LONG_PACKET_TYPE;
		extracted_data.data     = &long_packet_type;

		//update quic client depending on the type of packet
		if( _extraction_quic_ietf_att( ipacket, index, &extracted_data ) == ATTRIBUTE_SET ){
			if( long_packet_type == QUIC_IETF_INITIAL_PACKET_TYPE )
				session->quic_client = ipacket->internal_packet->src;
			else if( long_packet_type == QUIC_IETF_HANDSHAKE_PACKET_TYPE )
				session->quic_client = ipacket->internal_packet->dst;
		}
		return;
	}

	int dir = (ipacket->internal_packet->src == session->quic_client ? CLIENT_TO_SERVER : SERVER_TO_CLIENT );
	spinbit_edge_t *edge = &session->spinbit_edge[dir];
	//we do not see see any modification of spinbit
	if( spinbit == edge->last_pkt_spinbit )
		return;
	edge->last_pkt_spinbit = spinbit;

	// avoid 2 consecutive edge in the same direction
	//if( session->spinbit_edge.pkt_src == ipacket->internal_packet->src )
	//	return;

	//timestamp of the current packet in microsecond
	size_t us = ipacket->p_hdr->ts.tv_sec * 1000000 + ipacket->p_hdr->ts.tv_usec;
	//avoid unordered packets
	if( us <= edge->pkt_us)
		return;

	//we got the spinbit edge here
	debug("QUIC spinbit edge %s at packet_id=%zu", dir == CLIENT_TO_SERVER? "c->s":"s->c", ipacket->packet_id);

	//get RTT ( pkt_us==0 for the first time )
	if( edge->pkt_us > 0 )
		edge->rtt_us = us - edge->pkt_us;

	//remember the last values
	edge->pkt_us  = us;
}

static int _quic_ietf_session_data_analysis(ipacket_t * ipacket, unsigned index) {
	//debug("QUIC session analysis");
	quic_ietf_session_t * session_data = ipacket->session->session_data[index];
	if( session_data == NULL )
		return MMT_CONTINUE;

	_quic_ietf_calculate_rtts( ipacket, index, session_data );
	return MMT_CONTINUE;
}


void _init_bitmask() {
	selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
	MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
	MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_INT);
	MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_QUIC_IETF);
}

#define def_att(id, data_type, data_len ) { id, id##_ALIAS, data_type, data_len, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_quic_ietf_att}
static attribute_metadata_t _attributes_metadata[] = {
	def_att( QUIC_IETF_HEADER_FORM,      MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_LONG_PACKET_TYPE, MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_SPIN_BIT,         MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_VERSION,          MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH, MMT_U16_DATA,            sizeof(uint16_t) ),
	def_att( QUIC_IETF_DESTINATION_CONNECTION_ID,        MMT_STRING_LONG_DATA, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH,      MMT_U16_DATA,            sizeof(uint16_t) ),
	def_att( QUIC_IETF_SOURCE_CONNECTION_ID,             MMT_STRING_LONG_DATA, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_LENGTH,               MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_PACKET_NUMBER_LENGTH, MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_PACKET_NUMBER,        MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_TOKEN_LENGTH,         MMT_U16_DATA, sizeof(uint16_t) ),
	def_att( QUIC_IETF_TOKEN,                MMT_STRING_LONG_DATA, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_RTT,                  MMT_U64_DATA, sizeof(uint64_t) )
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

	if( !register_classification_function_with_parent_protocol( PROTO_INT, _classify_quic_ietf_from_int, 100 ) ){
		log_err("Need mmt_tcpip library containing PROTO_INT having id = %d", PROTO_INT);
		return PROTO_NOT_REGISTERED;
	}

	_init_bitmask();

	//TODO: need to get QUIC session
	register_session_data_initialization_function(protocol_struct, _quic_ietf_session_data_init);
	register_session_data_cleanup_function(protocol_struct, _quic_ietf_session_data_cleanup);
	register_session_data_analysis_function(protocol_struct, _quic_ietf_session_data_analysis);

	return register_protocol(protocol_struct, PROTO_QUIC_IETF);
}
