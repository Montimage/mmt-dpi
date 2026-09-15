/*
 * proto_diameter.c
 *
 *  Created on: Dec 7, 2020
 *      Author: nhnghia
 */

#include "mmt_mobile_internal.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/**
 * Extract attribute
 */
static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
	int offset = get_packet_offset_at_index(ipacket, proto_index);
	//the cast below needs the whole 20-byte header to be captured
	if( offset < 0 || (size_t)offset + sizeof(struct diameter_header) > ipacket->p_hdr->caplen )
		return 0;
	const struct diameter_header *hdr = (struct diameter_header *) &ipacket->data[offset];

	//depending on id of attribute to be extracted
	switch( extracted_data->field_id ){
	case DIAMETER_VERSION:
		*((uint8_t *) extracted_data->data) = hdr->version;
		break;
	case DIAMETER_MESSAGE_LENGTH:
		//https://www.ietf.org/proceedings/52/I-D/draft-ietf-aaa-diameter-08.txt:
		*((uint32_t *) extracted_data->data) = copy_4bytes_order(hdr->length, 3);
		break;
	case DIAMETER_FLAG_R:
		*((uint8_t *) extracted_data->data) = hdr->flag_r;
		break;
	case DIAMETER_FLAG_P:
		*((uint8_t *) extracted_data->data) = hdr->flag_p;
		break;
	case DIAMETER_FLAG_E:
		*((uint8_t *) extracted_data->data) = hdr->flag_e;
		break;
	case DIAMETER_FLAG_T:
		*((uint8_t *) extracted_data->data) = hdr->flag_t;
		break;
	case DIAMETER_COMMAND_CODE:
		*((uint32_t *) extracted_data->data) = copy_4bytes_order( hdr->command_code, 3);
		break;
	case DIAMETER_APPLICATION_ID:
		*((uint32_t *) extracted_data->data) = copy_4bytes_order( hdr->application_id, 4 );
		break;
	case DIAMETER_HOP_TO_HOP_ID:
		*((uint32_t *) extracted_data->data) = copy_4bytes_order( hdr->hop_to_hop_id, 4 );
		break;
	case DIAMETER_END_TO_END_ID:
		*((uint32_t *) extracted_data->data) = copy_4bytes_order( hdr->end_to_end_id, 4 );
		break;
	default:
		log_warn("Unknown attribute %d.%d", mmt_attr_get_proto_id_typed(extracted_data), extracted_data->field_id );
	}
	return 1;
}

static uint32_t _classify_by_sctp_ports( ipacket_t *ipacket, unsigned index, unsigned offset ){
	//first SCTP from the lattest proto in protocol hierarchy
	int sctp_index = get_protocol_index_by_id( ipacket, PROTO_SCTP );
	//not found SCTP
	if( sctp_index == -1 )
		return PROTO_UNKNOWN;
	//offset of sctp in packet
	int sctp_offset = get_packet_offset_at_index(ipacket, sctp_index);
	if( sctp_offset < 0 || (size_t)sctp_offset + sizeof(mmt_una_sctphdr_t) > ipacket->p_hdr->caplen )
		return PROTO_UNKNOWN;
	const mmt_una_sctphdr_t *sctp_hdr = (const mmt_una_sctphdr_t *) &ipacket->data[ sctp_offset ];

	/*
	 * Issue #59: sctp_hdr points into the byte-aligned capture buffer, so read
	 * the 16-bit ports with memcpy rather than dereferencing the struct directly
	 * (a misaligned load is UB and aborts under -fsanitize=alignment). memcpy of
	 * a fixed small size lowers to a single load on targets with native
	 * unaligned access — no hot-path cost. Mirrors ip_fragment_key() in PR #58.
	 */
	uint16_t sctp_src, sctp_dst;
	memcpy(&sctp_src, &sctp_hdr->source, sizeof(sctp_src));
	memcpy(&sctp_dst, &sctp_hdr->dest,   sizeof(sctp_dst));
	if( ntohs( sctp_src ) == 3868 && ntohs( sctp_dst ) == 3868 ){
		//F-BUG-080: prove the full Diameter header is captured before touching it
		if( (size_t)offset + sizeof(struct diameter_header) > ipacket->p_hdr->caplen )
			return PROTO_UNKNOWN;
		//need to confirm more by other signatures of diameter: version
		const struct diameter_header *hdr = (struct diameter_header *) &ipacket->data[offset];
		uint32_t length = copy_4bytes_order( hdr->length, 3 );
		//length = ntohl( length );
		//currently only version = 1
		//printf("offset: %d, version: %d, length: %d", offset, hdr->version, length);
		if( hdr->version != 1 )
			return PROTO_UNKNOWN;
		//length is incorrect
		if( length + offset > ipacket->p_hdr->caplen )
			return PROTO_UNKNOWN;
		//always a multiple of 4 bytes

		//need to check other features???
		return PROTO_DIAMETER;
	}
	return PROTO_UNKNOWN;
}

static int _classify_from_sctp_data( ipacket_t * ipacket, unsigned index ){
	//index: index of the parent protocol (SCTP_DATA)
	int sctp_data_index  = index; //get_protocol_index_by_id( ipacket, PROTO_SCTP_DATA );
	int sctp_data_offset = get_packet_offset_at_index(ipacket, sctp_data_index);
	//the datahdr cast below needs the whole 16-byte chunk header to be captured
	if( sctp_data_offset < 0 || (size_t)sctp_data_offset + sizeof(struct sctp_datahdr) > ipacket->p_hdr->caplen )
		return 0;

	//next porotocol is encapsulated inside payload of SCTP_DATA
	size_t next_offset = (size_t)sctp_data_offset + sizeof(struct sctp_datahdr);
	//F-BUG-080: a Diameter classification needs the whole 20-byte header to be
	//captured — extraction casts next_offset to struct diameter_header. This
	//applies to the PPID-46 path as much as to the port-based fallback.
	if( next_offset + sizeof(struct diameter_header) > ipacket->p_hdr->caplen )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_UNKNOWN;

	const mmt_una_sctp_datahdr_t *hdr = (const mmt_una_sctp_datahdr_t *) &ipacket->data[ sctp_data_offset ];
	//sctp data Packet payload ID
	switch( ntohl( hdr->ppid )){
	case 46: //DIAMETER
		retval.proto_id = PROTO_DIAMETER;
		break;
	default:
		//try to gues DIAMETER using sctp ports, then verified by other signatures (version, length, etc)
		retval.proto_id = _classify_by_sctp_ports( ipacket, index, (unsigned)next_offset );
		break;
	}
	//we found something
	if( retval.proto_id != PROTO_UNKNOWN ){
		retval.offset = sizeof(struct sctp_datahdr); //offset from its precedent protocol, not from root
		retval.status = Classified;
		//fix length
		//ipacket->proto_hierarchy->len =      (index + 1) + 1;
		return set_classified_proto(ipacket, (index + 1), retval);
	}

	return 0;
}

static attribute_metadata_t diameter_attributes_metadata[] = {
		{DIAMETER_VERSION,        DIAMETER_VERSION_ALIAS,        MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_MESSAGE_LENGTH, DIAMETER_MESSAGE_LENGTH_ALIAS, MMT_U32_DATA, sizeof( uint32_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_FLAG_R,         DIAMETER_FLAG_R_ALIAS,         MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_FLAG_P,         DIAMETER_FLAG_P_ALIAS,         MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_FLAG_E,         DIAMETER_FLAG_E_ALIAS,         MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_FLAG_T,         DIAMETER_FLAG_T_ALIAS,         MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_COMMAND_CODE,   DIAMETER_COMMAND_CODE_ALIAS,   MMT_U32_DATA, sizeof( uint32_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_APPLICATION_ID, DIAMETER_APPLICATION_ID_ALIAS, MMT_U32_DATA, sizeof( uint32_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_HOP_TO_HOP_ID,  DIAMETER_HOP_TO_HOP_ID_ALIAS,  MMT_U32_DATA, sizeof( uint32_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{DIAMETER_END_TO_END_ID,  DIAMETER_END_TO_END_ID_ALIAS,  MMT_U32_DATA, sizeof( uint32_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
};
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_diameter_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_DIAMETER, PROTO_DIAMETER_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( diameter_attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &diameter_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_DIAMETER_ALIAS, diameter_attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	int ret = register_classification_function_with_parent_protocol( PROTO_SCTP_DATA, _classify_from_sctp_data, 100 );
	if( ret == 0 ){
		//no SCTP (need to do if diameter can work with TCP)
		fprintf(stderr, "Need mmt_tcpip library containing PROTO_SCTP_DATA having id = %d", PROTO_SCTP_DATA);
		return PROTO_NOT_REGISTERED;
	}
	return register_protocol(protocol_struct, PROTO_DIAMETER);

}

