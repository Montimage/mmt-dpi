/*
 * proto_ngap.c
 *
 *  Created on: Dec 11, 2020
 *      Author: nhnghia
 */


#include "mmt_mobile_internal.h"
#include "ngap/ngap.h"

static bool _is_valid_by_sctp_ports( const ipacket_t *ipacket ){
	int sctp_index = get_protocol_index_by_id( ipacket, PROTO_SCTP );
	//not found SCTP
	if( sctp_index == -1 )
		return false;
	//offset of sctp in packet
	int sctp_offset = get_packet_offset_at_index(ipacket, sctp_index);
	const struct sctphdr *sctp_hdr = (struct sctphdr *) &ipacket->data[ sctp_offset ];

	//https://www.etsi.org/deliver/etsi_ts/138400_138499/138412/15.00.00_60/ts_138412v150000p.pdf
	//The SCTP Destination Port number value assigned by IANA to be used for NGAP is 38412.
	const uint16_t sctp_port_for_ngap = htons( 38412 );
	if( sctp_hdr->dest != sctp_port_for_ngap )
		return false;
	return true;
}

static bool _get_ngap_offset_and_length( const ipacket_t *ipacket, unsigned *offset, unsigned *length ){
	if( length == NULL || offset == NULL )
		return false;

	int sctp_data_index  = get_protocol_index_by_id( ipacket, PROTO_SCTP_DATA );
	int sctp_data_offset = get_packet_offset_at_index(ipacket, sctp_data_index);

	const int SCTP_DATA_HEADER_SIZE = sizeof(struct sctp_datahdr);
	const struct sctp_datahdr *hdr = (struct sctp_datahdr *) &ipacket->data[ sctp_data_offset ];
	int ngap_offset = sctp_data_offset + SCTP_DATA_HEADER_SIZE;
	//not enought room for NGAP
	if( ngap_offset >= ipacket->p_hdr->len )
		return false;
	//sctp data Packet payload ID
	switch( ntohl( hdr->ppid )){
	case 60: //
		break;
	case 0: //not specified
		//try to classify NGAP
		//is it used valid SCTP ports?
		if( ! _is_valid_by_sctp_ports(ipacket ))
			return false;
		break;
	default:
		return false;
	}
	//SCTP data chunk length: A 16-bit unsigned value specifying the total length of the chunk in bytes (excludes any padding)
	// that includes chunk type, flags, length, and value fields.
	uint16_t ngap_length = ntohs(hdr->length) - SCTP_DATA_HEADER_SIZE;
	*offset = ngap_offset;
	*length = ngap_length;
	return true;
}

static int _classify_ngap_from_sctp_data( ipacket_t * ipacket, unsigned index ){
	//index: index of the parent protocol (SCTP_DATA)
	if( index == 0 )
		return 0;
	int sctp_data_index  = index; //get_protocol_index_by_id( ipacket, PROTO_SCTP_DATA );
	int sctp_data_offset = get_packet_offset_at_index(ipacket, sctp_data_index);

	classified_proto_t retval;
	retval.proto_id = PROTO_UNKNOWN;
	const int SCTP_DATA_HEADER_SIZE = sizeof(struct sctp_datahdr);
	const struct sctp_datahdr *hdr = (struct sctp_datahdr *) &ipacket->data[ sctp_data_offset ];
	int ngap_offset = sctp_data_offset + SCTP_DATA_HEADER_SIZE;
	//not enought room for NGAP
	if( ngap_offset >= ipacket->p_hdr->len )
		return 0;
	//sctp data Packet payload ID
	switch( ntohl( hdr->ppid )){
	case 60: //
		retval.proto_id = PROTO_NGAP;
		break;
	case 0: //not specified
		//try to classify NGAP
		//is it used valid SCTP ports?
		if( ! _is_valid_by_sctp_ports(ipacket ))
			return 0;
		//SCTP data chunk length: A 16-bit unsigned value specifying the total length of the chunk in bytes (excludes any padding)
		// that includes chunk type, flags, length, and value fields.
		uint16_t ngap_length = ntohs(hdr->length) - SCTP_DATA_HEADER_SIZE;
		//can we parse NGAP packet?
		if( !try_decode_ngap(&ipacket->data[ ngap_offset ], ngap_length))
			return 0;
		//now we can confirm NGAP
		retval.proto_id = PROTO_NGAP;
		break;
	default:
		break;
	}

	//we found something
	if( retval.proto_id != PROTO_UNKNOWN ){
		retval.offset = SCTP_DATA_HEADER_SIZE; //offset from its precedent protocol, not from root
		retval.status = Classified;
		return set_classified_proto(ipacket, (index + 1), retval);
	}

	return 0;
}

static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	ngap_message_t msg;
	unsigned offset   = 0;
	unsigned data_len = 0;
	if( ! _get_ngap_offset_and_length(packet, &offset, &data_len ))
		return 0;
	if( ! decode_ngap(&msg, & packet->data[offset], data_len ) )
		return 0;

	switch( extracted_data->field_id ){
	case NGAP_ATT_PROCEDURE_CODE:
		*((uint16_t *) extracted_data->data) = msg.procedure_code;
		break;
	case NGAP_ATT_PDU_PRESENT:
		*((uint8_t *) extracted_data->data) = msg.pdu_present;
		break;
	case NGAP_ATT_AMF_UE_ID:
		*((uint64_t *) extracted_data->data) = msg.amf_ue_id;
		break;
	case NGAP_ATT_RAN_UE_ID:
		*((uint16_t *) extracted_data->data) = msg.ran_ue_id;
		break;
	}
	return 1;
}

int ngap_classify_next_proto(ipacket_t *packet, unsigned index) {
	ngap_message_t msg;
	int offset = get_packet_offset_at_index(packet, index);
	const int data_len = packet->p_hdr->caplen - offset;
	if( data_len <= 0 )
		return 0;
	if( ! decode_ngap(&msg, & packet->data[offset], data_len ) )
		return 0;
	if( msg.nas_pdu.size == 0 )
		return 0;
	//offset from root
	int nas_offset = 0; /*msg.nas_pdu.data - packet->data;
	if( nas_offset <= 0 || nas_offset >= packet->p_hdr->caplen )
		return 0;
	//offset from ngap
	nas_offset -= offset;
	*/

	classified_proto_t retval;
	retval.proto_id = PROTO_NAS5G;
	retval.offset = nas_offset;
	retval.status = Classified;
	return set_classified_proto(packet, index + 1, retval);
	return 0;
}

static attribute_metadata_t _attributes_metadata[] = {
		{NGAP_ATT_PROCEDURE_CODE, NGAP_PROCEDURE_CODE_ALIAS, MMT_U16_DATA,     sizeof( uint16_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{NGAP_ATT_PDU_PRESENT,    NGAP_PDU_PRESENT_ALIAS,    MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{NGAP_ATT_AMF_UE_ID,      NGAP_AMF_UE_ID_ALIAS,      MMT_U64_DATA,     sizeof( uint64_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{NGAP_ATT_RAN_UE_ID,      NGAP_RAN_UE_ID_ALIAS,      MMT_U16_DATA,     sizeof( uint16_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att}
};

int init_proto_ngap_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_NGAP, PROTO_NGAP_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_NGAP_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	int ret = register_classification_function_with_parent_protocol( PROTO_SCTP_DATA, _classify_ngap_from_sctp_data, 100 );
	if( ret == 0 ){
		fprintf(stderr, "Need mmt_tcpip library containing PROTO_SCTP_DATA having id = %d", PROTO_SCTP_DATA);
		return PROTO_NOT_REGISTERED;
	}
	register_classification_function(protocol_struct, ngap_classify_next_proto);
	return register_protocol(protocol_struct, PROTO_NGAP);

}



uint32_t update_ngap_data( u_char *data, uint32_t data_size, const ipacket_t *ipacket, uint32_t proto_id, uint32_t att_id, uint64_t new_val ){
	uint32_t ret = 0;
	if( proto_id != PROTO_NGAP )
		return ret;
	int index = get_protocol_index_by_id( ipacket, PROTO_NGAP );
	if( index == -1 )
		return ret;

	unsigned ngap_offset = 0;
	unsigned ngap_length = 0;
	if( !_get_ngap_offset_and_length(ipacket, &ngap_offset, &ngap_length))
		return 0;

	ngap_message_t msg;
	//can we parse NGAP packet?
	if( !decode_ngap(&msg, &ipacket->data[ ngap_offset ], ngap_length)){
		return ret;
	}

	switch( att_id ){
	case NGAP_ATT_PROCEDURE_CODE:
		msg.procedure_code = new_val;
		break;
	case NGAP_ATT_PDU_PRESENT:
		msg.pdu_present = new_val;
		break;
	case NGAP_ATT_AMF_UE_ID:
		msg.amf_ue_id = new_val;
		break;
	case NGAP_ATT_RAN_UE_ID:
		msg.ran_ue_id = new_val;
		break;
	}

	void *buffer = &data[ ngap_offset ];
	return encode_ngap( buffer, data_size - ngap_offset, &msg, &ipacket->data[ ngap_offset ], ngap_length );
}
