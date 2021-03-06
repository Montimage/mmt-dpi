/*
 * proto_nas_5g.c
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#include "mmt_mobile_internal.h"
#include "nas_5g/nas_5g.h"
#include "ngap/ngap.h"

//whether a message is MOBILE MANAGEMENT MESSAGE and the message is encrpyted
static inline bool _is_encrypt_mmm( const nas_5g_msg_t *nas_msg ){
	return (
			( nas_msg->protocol_discriminator == NAS5G_MOBILITY_MANAGEMENT_MESSAGE )
			&& (nas_msg->mmm.security_header_type != 0 )
	);
}

static int _extraction_att_nas_5g(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	nas_5g_msg_t nas_msg, nas_msg_2;
	ngap_message_t ngap_msg;
	uint32_t val;
	//Ensure NGAP is existing (before NAS-5G)
	const int ngap_index = get_protocol_index_by_id(packet, PROTO_NGAP);
	if( ngap_index < 0 )
		return 0;
	const int offset = get_packet_offset_at_index(packet, ngap_index);
	const int data_len = packet->p_hdr->caplen - offset;
	if( data_len <= 0 )
		return 0;
	//get length of NGAP payload
	int sctp_data_index  = get_protocol_index_by_id( packet, PROTO_SCTP_DATA );
	if( sctp_data_index < 0 )
		return 0;
	int sctp_data_offset = get_packet_offset_at_index(packet, sctp_data_index);
	const int SCTP_DATA_HEADER_SIZE = sizeof(struct sctp_datahdr);
	const struct sctp_datahdr *hdr = (struct sctp_datahdr *) &packet->data[ sctp_data_offset ];
	int ngap_offset = sctp_data_offset + SCTP_DATA_HEADER_SIZE;
	uint16_t ngap_length = ntohs(hdr->length) - SCTP_DATA_HEADER_SIZE;

	const uint32_t MAX_NAS_PDU_SIZE = 0xFFFF;
	uint8_t nas_pdu[MAX_NAS_PDU_SIZE];
	uint32_t nas_length = get_nas_pdu(nas_pdu, MAX_NAS_PDU_SIZE, & packet->data[offset], ngap_length);

	if( nas_length == 0 )
		return 0;

	if( !nas_5g_decode( &nas_msg, nas_pdu, nas_length ))
		return 0;
	switch( extracted_data->field_id ){
	case NAS5G_ATT_PROTOCOL_DISCRIMINATOR:
		*((uint8_t *) extracted_data->data) = nas_msg.protocol_discriminator;
		break;
	case NAS5G_ATT_MESSAGE_TYPE:
		if( nas_msg.protocol_discriminator == NAS5G_SESSION_MANAGEMENT_MESSAGE )
			*((uint8_t *) extracted_data->data) = nas_msg.smm.message_type;
		else {
			//when no security (plain text) => having message type
			switch( nas_msg.mmm.security_header_type ){
			case 0:
				*((uint8_t *) extracted_data->data) = nas_msg.mmm.message_type;
				break;
				//a special case where the content is in plain text
			case 3:
				if( !nas_5g_decode( &nas_msg_2, nas_pdu+7, nas_length - 7))
					return 0;
				*((uint8_t *) extracted_data->data) =  nas_msg_2.mmm.message_type;
				break;
			default:
				//otherwise the message is encrypted
				*((uint8_t *) extracted_data->data) = 0;
			}
		}
		break;
	case NAS5G_ATT_PROCEDURE_TRANSACTION_ID:
		if( nas_msg.protocol_discriminator == NAS5G_SESSION_MANAGEMENT_MESSAGE )
			*((uint8_t *) extracted_data->data) = nas_msg.smm.procedure_transaction_identity;
		else
			*((uint8_t *) extracted_data->data) = 0;
		break;
	case NAS5G_ATT_SECURITY_TYPE:
		if( nas_msg.protocol_discriminator == NAS5G_SESSION_MANAGEMENT_MESSAGE )
			*((uint8_t *) extracted_data->data) = 0;
		else
			*((uint8_t *) extracted_data->data) = nas_msg.mmm.security_header_type;
		break;
	case NAS5G_ATT_MESSAGE_AUTHENTICAION_CODE:
		//only available when the message is encrypted
		if( _is_encrypt_mmm( &nas_msg )){
			val = *((uint32_t*) (nas_pdu + 2));
			*((uint32_t *) extracted_data->data) = ntohl(val); //after 2 bytes headers
		} else
			*((uint32_t *) extracted_data->data) = 0;
		break;
	case NAS5G_ATT_SEQUENCE_NUMBER:
		if( _is_encrypt_mmm( &nas_msg )){
			*((uint8_t *) extracted_data->data) = nas_pdu[2 + 4]; //after 2 bytes headers, 4 bytes authentication code
		} else
			*((uint8_t *) extracted_data->data) = 0;
		break;
	}

	return 1;
}

static attribute_metadata_t _attributes_metadata[] = {
		{NAS5G_ATT_PROTOCOL_DISCRIMINATOR,   NAS5G_PROTOCOL_DISCRIMINATOR_ALIAS,   MMT_U8_DATA, sizeof( uint8_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att_nas_5g},
		{NAS5G_ATT_MESSAGE_TYPE,             NAS5G_MESSAGE_TYPE_ALIAS,             MMT_U8_DATA, sizeof( uint8_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att_nas_5g},
		{NAS5G_ATT_SECURITY_TYPE,            NAS5G_SECURITY_TYPE_ALIAS,            MMT_U8_DATA, sizeof( uint8_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att_nas_5g},
		{NAS5G_ATT_PROCEDURE_TRANSACTION_ID, NAS5G_PROCEDURE_TRANSACTION_ID_ALIAS, MMT_U8_DATA, sizeof( uint8_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att_nas_5g},
		{NAS5G_ATT_MESSAGE_AUTHENTICAION_CODE, NAS5G_ATT_MESSAGE_AUTHENTICAION_CODE_ALIAS, MMT_U32_DATA, sizeof( uint32_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att_nas_5g},
		{NAS5G_ATT_SEQUENCE_NUMBER, NAS5G_ATT_SEQUENCE_NUMBER_ALIAS,   MMT_U8_DATA, sizeof( uint8_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att_nas_5g},
};

int init_proto_nas_5g_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_NAS5G, PROTO_NAS5G_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_NAS5G_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	return register_protocol(protocol_struct, PROTO_NAS5G);

}
