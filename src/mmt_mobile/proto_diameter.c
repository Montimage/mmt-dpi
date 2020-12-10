/*
 * proto_diameter.c
 *
 *  Created on: Dec 7, 2020
 *      Author: nhnghia
 */

#include "mmt_mobile_internal.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define __PACKED __attribute__((packed))

struct diameter_header {
	uint8_t version        :  8; //0-7
	uint32_t length        : 24; //9-31 ;//length of the Diameter message in bytes, including the header, always a multiple of 4
	uint8_t flag_r         :  1; //32
	uint8_t flag_p         :  1; //33
	uint8_t flag_e         :  1; //34
	uint8_t flag_t         :  1; //35
	uint8_t padding        :  4; //  4 bit padding
	uint32_t command_code  : 24;
	uint32_t application_id: 32;
	uint32_t hop_to_hop_id : 32;
	uint32_t end_to_end_id : 32;
} __PACKED;

/**
 * Extract attribute
 */
static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index,
		attribute_t * extracted_data) {
	int offset = get_packet_offset_at_index(ipacket, proto_index);
	const struct diameter_header *hdr = (struct diameter_header *) &ipacket->data[offset];

	//depending on id of attribute to be extracted
	switch( extracted_data->field_id ){

	}
	return 1;
}

static int _classify_by_sctp_ports( ipacket_t *ipacket, unsigned index, uint16_t offset ){
	//first SCTP from the lattest proto in protocol hierarchy
	int sctp_index = get_protocol_index_by_id( ipacket, PROTO_SCTP );
	//not found SCTP
	if( sctp_index == -1 )
		return PROTO_UNKNOWN;
	//offset of sctp in packet
	int sctp_offset = get_packet_offset_at_index(ipacket, sctp_index);
	const struct sctphdr *sctp_hdr = (struct sctphdr *) &ipacket->data[ sctp_offset ];

	if( ntohs( sctp_hdr->source ) == 3868 && ntohs( sctp_hdr->dest) == 3868 ){
		//need to confirm more by other signatures of diameter: version
		const struct diameter_header *hdr = (struct diameter_header *) &ipacket->data[offset];
		uint32_t length = hdr->length;
		//length = ntohl( length );
		//currently only version = 1
		printf("offset: %d, version: %d, length: %d", offset, hdr->version, length);
		if( hdr->version != 1 )
			return PROTO_UNKNOWN;
		//length is incorrect
		//TODO: check hdr->length
		if( length + offset > ipacket->p_hdr->caplen )
			return PROTO_UNKNOWN;
		//need to check other features???
		return PROTO_DIAMETER;
	}
	return PROTO_UNKNOWN;
}

static int _classify_from_sctp_data( ipacket_t * ipacket, unsigned index ){
	//index: index of the current proto to be classified (DIAMETER?), not the one of parent (SCTP_DATA)

	int offset = get_packet_offset_at_index(ipacket, index);
	uint16_t next_offset = offset + sizeof(struct sctp_datahdr);
	//not enough room for other data
	if( next_offset  >= ipacket->p_hdr->caplen )
		return 0;

	classified_proto_t retval;

	const struct sctp_datahdr *hdr = (struct sctp_datahdr *) &ipacket->data[ offset ];
	//sctp data Packet payload ID
	switch( ntohl( hdr->ppid )){
	case 46: //DIAMETER
		retval.proto_id = PROTO_DIAMETER;
		break;
	default:
		//try to gues DIAMETER using sctp ports, then verified by other signatures (version, length, etc)
		//printf("offset: %d, next: %d", offset, next_offset );
		//the rest is not enough for diameter header
		if( next_offset +  sizeof(struct diameter_header) > ipacket->p_hdr->caplen )
			return 0;
		retval.proto_id = _classify_by_sctp_ports( ipacket, index, next_offset );
		break;
	}
	//we found something
	if( retval.proto_id != PROTO_UNKNOWN ){
		retval.offset = next_offset;
		retval.status = Classified;
		//fix length
		ipacket->proto_hierarchy->len =      (index + 1) + 1;
		return set_classified_proto(ipacket, (index + 1), retval);
	}

	return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_diameter_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_DIAMETER, PROTO_DIAMETER_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	int ret = register_classification_function_with_parent_protocol( PROTO_SCTP_DATA, _classify_from_sctp_data, 100 );
	if( ret == 0 ){
		//no SCTP (need to do if diameter can work with TCP)
		fprintf(stderr, "Need mmt_tcpip library containing PROTO_SCTP_DATA having id = %d", PROTO_SCTP_DATA);
		return 0;
	}
	return register_protocol(protocol_struct, PROTO_DIAMETER);

}

