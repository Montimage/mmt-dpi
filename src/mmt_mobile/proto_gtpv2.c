/*
 * proto_gtpv2.c
 *
 *  Created on: Dec 11, 2020
 *      Author: nhnghia
 */
#include "mmt_mobile_internal.h"

static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
	uint16_t seq_num;
	uint32_t teid;
	int offset = get_packet_offset_at_index(ipacket, proto_index);
	const struct gtpv2_header *hdr = (struct gtpv2_header *) &ipacket->data[offset];
	switch( extracted_data->field_id ){
	case GTPV2_VERSION:
		*((uint8_t *) extracted_data->data) = hdr->version;
		break;
	case GTPV2_FLAG_P:
		*((uint8_t *) extracted_data->data) = hdr->flag_p;
		break;
	case GTPV2_FLAG_T:
		*((uint8_t *) extracted_data->data) = hdr->flag_t;
		break;
	case GTPV2_MESSAGE_TYPE:
		*((uint8_t *) extracted_data->data) = hdr->type;
		break;
	case GTPV2_MESSAGE_LENGTH:
		*((uint16_t *) extracted_data->data) = ntohs(hdr->length);
		break;
	case GTPV2_TEID:

		// If T flag is set to 1, then TEID shall be placed into octets 5-8.
		// Otherwise, TEID field is not present at all.
		if( hdr->flag_t == 1 )
			teid = copy_4bytes_order(hdr->teid, 4);
		else
			teid = 0;
		*((uint32_t *) extracted_data->data) = teid;
		break;
	case GTPV2_SEQUENCE_NUMBER:

		//no TEID presents
		if( hdr->flag_t == 0 )
			seq_num = copy_4bytes_order(hdr->teid, 3);
		else
			seq_num = copy_4bytes_order(hdr->sequence_number, 3);
		*((uint16_t *) extracted_data->data) = seq_num;
		break;
	}
	return 1;
}

static int _classify_gtpv2( ipacket_t * ipacket, unsigned index ){

	//check udp ports
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	const struct udphdr *udp = packet->udp;
	//should not happen since we enter here from UDP, but check anyway
	if (udp == NULL)
		return 0;
	u_int32_t gtp_u  = htons(2152);
	u_int32_t gtp_c  = htons(2123);
	//we expect UDP ports should be one of 2152 or 2153
	if (!((udp->source == gtp_u) || (udp->dest == gtp_u)
	   || (udp->source == gtp_c) || (udp->dest == gtp_c)))
		return 0;

	int offset = get_packet_offset_at_index(ipacket, index);
	int udp_header_size = sizeof( struct udphdr );
	int next_offset = offset + udp_header_size;

	//not enough room for other data ?
	//3bytes of TEID that could be not present
	if( next_offset + sizeof(struct gtpv2_header) - 3 > ipacket->p_hdr->caplen )
		return 0;


	const struct gtpv2_header *hdr = (struct gtpv2_header *) &ipacket->data[ next_offset ];
	//start checking gtpv2's signature
	//version is incorect
	if( hdr->version != 2 )
		return 0;
	//length is incorrect
	if( next_offset + ntohs( hdr->length) > ipacket->p_hdr->caplen )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_GTPV2;
	retval.offset   = udp_header_size; //GTP is inside UDP payload
	retval.status   = Classified;
	return set_classified_proto(ipacket, index + 1, retval);
}
static attribute_metadata_t gtpv2_attributes_metadata[] = {
		{GTPV2_VERSION,        GTPV2_VERSION_ALIAS,        MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{GTPV2_FLAG_T,         GTPV2_FLAG_T_ALIAS,         MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{GTPV2_FLAG_P,         GTPV2_FLAG_P_ALIAS,         MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{GTPV2_MESSAGE_TYPE,   GTPV2_MESSAGE_TYPE_ALIAS,   MMT_U8_DATA,  sizeof( uint8_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{GTPV2_MESSAGE_LENGTH, GTPV2_MESSAGE_LENGTH_ALIAS, MMT_U16_DATA, sizeof( uint16_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{GTPV2_TEID,           GTPV2_TEID_ALIAS,           MMT_U32_DATA, sizeof( uint32_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{GTPV2_SEQUENCE_NUMBER,GTPV2_SEQUENCE_NUMBER_ALIAS,MMT_U32_DATA, sizeof( uint32_t ), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
};

int init_proto_gtpv2_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_GTPV2, PROTO_GTPV2_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( gtpv2_attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &gtpv2_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_GTPV2_ALIAS, gtpv2_attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	int ret = register_classification_function_with_parent_protocol( PROTO_UDP, _classify_gtpv2, 100 );
	if( ret == 0 ){
		//no SCTP (need to do if diameter can work with TCP)
		fprintf(stderr, "Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}
	return register_protocol(protocol_struct, PROTO_GTPV2);

}

