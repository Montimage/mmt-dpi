/*
 * proto_ngap.c
 *
 *  Created on: Dec 11, 2020
 *      Author: nhnghia
 */


#include "mmt_mobile_internal.h"
#include "ngap/ngap.h"

static bool _is_valid_by_sctp_ports( ipacket_t *ipacket ){
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

static int _classify_ngap_from_sctp_data( ipacket_t * ipacket, unsigned index ){
	//index: index of the parent protocol (SCTP_DATA)
	if( index == 0 )
		return 0;
	int sctp_data_index  = index; //get_protocol_index_by_id( ipacket, PROTO_SCTP_DATA );
	int sctp_data_offset = get_packet_offset_at_index(ipacket, sctp_data_index);

	classified_proto_t retval;
	retval.proto_id = PROTO_UNKNOWN;

	const struct sctp_datahdr *hdr = (struct sctp_datahdr *) &ipacket->data[ sctp_data_offset ];
	int ngap_offset = sctp_data_offset + sizeof(struct sctp_datahdr);
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
		//can we parse NGAP packet?
		if( !try_decode_ngap(&ipacket->data[ sctp_data_offset ], hdr->length))
			return 0;
		break;
	default:
		break;
	}

	//we found something
	if( retval.proto_id != PROTO_UNKNOWN ){
		retval.offset = sizeof(struct sctp_datahdr); //offset from its precedent protocol, not from root
		retval.status = Classified;
		return set_classified_proto(ipacket, (index + 1), retval);
	}

	return 0;
}

static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	ngap_message_t msg;
	const int offset = get_packet_offset_at_index(packet, proto_index);
	const int data_len = packet->p_hdr->caplen - offset;
	if( data_len <= 0 )
		return 0;
	if( ! decode_ngap(&msg, & packet->data[offset], data_len ) )
		return 0;

	switch( extracted_data->field_id ){
	case S1AP_ATT_PROCEDURE_CODE:
		*((uint16_t *) extracted_data->data) = msg.procedure_code;
		break;
	case S1AP_ATT_PDU_PRESENT:
		*((uint8_t *) extracted_data->data) = msg.pdu_present;
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
		{S1AP_ATT_PROCEDURE_CODE, S1AP_PROCEDURE_CODE_ALIAS, MMT_U16_DATA,     sizeof( uint16_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_PDU_PRESENT,    S1AP_PDU_PRESENT_ALIAS,    MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_UE_ID,          S1AP_UE_ID_ALIAS,          MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_IMSI,           S1AP_IMSI_ALIAS,           MMT_STRING_DATA,  BINARY_64DATA_LEN,          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_M_TMSI,         S1AP_M_TMSI_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_TEID,           S1AP_TEID_ALIAS,           MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_QCI,            S1AP_QCI_ALIAS,            MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_PRIORITY_LEVEL, S1AP_PRIORITY_LEVEL_ALIAS, MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_UE_IP,          S1AP_UE_IP_ALIAS,          MMT_DATA_IP_ADDR, sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_UE_STATUS,      S1AP_UE_STATUS_ALIAS,      MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},


		{S1AP_ATT_MME_ID,         S1AP_MME_ID_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_NAME,       S1AP_MME_NAME_ALIAS,       MMT_STRING_DATA,  BINARY_64DATA_LEN,          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_IP,         S1AP_MME_IP_ALIAS,         MMT_DATA_IP_ADDR, sizeof( uint32_t ),         POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_UE_ID,      S1AP_MME_UE_ID_ALIAS,      MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_STATUS,     S1AP_MME_STATUS_ALIAS,     MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_ENB_ID,         S1AP_ENB_ID_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_NAME,       S1AP_ENB_NAME_ALIAS,       MMT_STRING_DATA,  BINARY_64DATA_LEN,          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_IP,         S1AP_ENB_IP_ALIAS,         MMT_DATA_IP_ADDR, sizeof( uint32_t ),         POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_UE_ID,      S1AP_ENB_UE_ID_ALIAS,      MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_STATUS,     S1AP_ENB_STATUS_ALIAS,     MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},


		{S1AP_ATT_ENTITY_UE,      S1AP_ENTITY_UE_ALIAS,      MMT_BINARY_VAR_DATA, BINARY_1024DATA_TYPE_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENTITY_MME,     S1AP_ENTITY_MME_ALIAS,     MMT_BINARY_VAR_DATA, BINARY_1024DATA_TYPE_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENTITY_ENODEB,  S1AP_ENTITY_ENODEB_ALIAS,  MMT_BINARY_VAR_DATA, BINARY_1024DATA_TYPE_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

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

