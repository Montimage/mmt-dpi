/*
 * proto_dtls.c
 *
 *  Created on: Apr 21, 2022
 *      Author: nhnghia
 */

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/*
 * Search info about DTLS header structure on April 21, 2022
 * version 1.0: https://datatracker.ietf.org/doc/html/rfc4347#section-4.1
 *  there is no DTLS 1.1 because this version-number was skipped to harmonize version numbers with TLS
 * version 1.2: https://datatracker.ietf.org/doc/html/rfc6347#section-4.1
 * version 1.3: https://tools.ietf.org/id/draft-ietf-tls-dtls13-34.html#rfc.section.4
 */
typedef struct {
	uint8_t content_type;
	uint16_t version;
	uint16_t epoch;
	uint8_t sequence_number[6];
	uint16_t length;
} __attribute__((packed))
dtls_header_t;

static bool _is_dtls_content_type( uint8_t content_type ){
	switch( content_type){
	case DTLS_CONTENT_TYPE_CHANGE_CIPER_SPECT:
	case DTLS_CONTENT_TYPE_ALERT:
	case DTLS_CONTENT_TYPE_HANDSHAKE:
	case DTLS_CONTENT_TYPE_APPLICATION:
	case DTLS_CONTENT_TYPE_HEARTBEAT:
		return true;
	default:
		return false;
	}
}

static bool _is_dtls_version( uint16_t version ){
	switch( version ){
	case DTLS_VERSION_1_0:
	case DTLS_VERSION_1_2:
	case DTLS_VERSION_1_3:
	case 0x0100: //1.0??? HN does not found doc about this number
		// but it is in a pcap file:
		// https://wiki.wireshark.org/SampleCaptures#dtls-with-decryption-keys
		return true;
	default:
		return false;
	}
}

static int classify_dtls_from_udp(ipacket_t * ipacket, unsigned index) {
	int offset = get_packet_offset_at_index(ipacket, index);
	dtls_header_t *dtls;
	offset += 8; //8 bytes of UDP header
	//not enough room for the DTLS header and its payload
	if( ipacket->p_hdr->len - offset <= sizeof( dtls_header_t))
		goto _not_found_dtls;

	dtls = (dtls_header_t *) &ipacket->data[ offset ];

		//check content type
	if( ! _is_dtls_content_type( dtls->content_type ))
		goto _not_found_dtls;

	if( !_is_dtls_version( ntohs(dtls->version )))
		goto _not_found_dtls;

		//until here, we conclude that we found DTLS
	mmt_internal_add_connection(ipacket, PROTO_DTLS, MMT_REAL_PROTOCOL);
	return 1;

	_not_found_dtls:
	MMT_ADD_PROTOCOL_TO_BITMASK(ipacket->internal_packet->flow->excluded_protocol_bitmask, PROTO_DTLS)
	return 0;
}


static int _dtls_extract_attribute(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data){
	size_t offset = get_packet_offset_at_index(ipacket, proto_index);
	dtls_header_t *dtls = (dtls_header_t *) &ipacket->data[ offset ];
	uint64_t u64;
	uint8_t *p;
	switch( extracted_data->field_id ){
	case DTLS_CONTENT_TYPE:
		*((uint8_t *) extracted_data->data) = dtls->content_type;
		return 1;
	case DTLS_VERSION:
		*((uint16_t *) extracted_data->data) = ntohs(dtls->version);
		return 1;
	case DTLS_EPOCH:
		*((uint16_t *) extracted_data->data) = ntohs(dtls->epoch);
		return 1;
	case DTLS_SEQUENCE_NUMBER:
		u64 = 0;
		p = (uint8_t *) &u64;
		p += 2;
		memcpy( p, dtls->sequence_number, 6 );
		*((uint64_t *) extracted_data->data) = ntohll(u64);
		return 1;
	case DTLS_LENGTH:
		*((uint16_t *) extracted_data->data) = ntohs(dtls->length);
		return 1;
	}
	return 0;
}

////////////////  attributes
static attribute_metadata_t dtls_attributes_metadata[] = {
	{DTLS_CONTENT_TYPE,    DTLS_CONTENT_TYPE_ALIAS,    MMT_U8_DATA,  sizeof (uint8_t),  0, SCOPE_PACKET, _dtls_extract_attribute},
	{DTLS_VERSION,         DTLS_VERSION_ALIS,          MMT_U16_DATA, sizeof (uint16_t), 0, SCOPE_PACKET, _dtls_extract_attribute},
	{DTLS_EPOCH,           DTLS_EPOCH_ALIAS,           MMT_U16_DATA, sizeof (uint16_t), 0, SCOPE_PACKET, _dtls_extract_attribute},
	{DTLS_SEQUENCE_NUMBER, DTLS_SEQUENCE_NUMBER_ALIAS, MMT_U64_DATA, sizeof (uint64_t), 0, SCOPE_PACKET, _dtls_extract_attribute},
	{DTLS_LENGTH,          DTLS_LENGTH_ALIAS,          MMT_U16_DATA, sizeof (uint16_t), 0, SCOPE_PACKET, _dtls_extract_attribute},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dtls_struct() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DTLS, PROTO_DTLS_ALIAS);
	const size_t nb_attributes = sizeof(dtls_attributes_metadata)/sizeof(dtls_attributes_metadata[0]);
	if (protocol_struct != NULL) {
		int i = 0;
		for (; i < nb_attributes; i++) {
			register_attribute_with_protocol(protocol_struct, &dtls_attributes_metadata[i]);
		}

		register_classification_function_with_parent_protocol(PROTO_UDP, classify_dtls_from_udp, 20);
		return register_protocol(protocol_struct, PROTO_DTLS);
	} else {
		return 0;
	}
}
