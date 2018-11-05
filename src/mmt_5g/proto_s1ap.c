/*
 * proto_s1ap.c
 *
 *  Created on: Oct 29, 2018
 *      by: nhnghia
 */


#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"

#include "proto_s1ap.h"
#include "mmt_tcpip.h"

#define __PACKED __attribute__((packed))

struct sctp_datahdr {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t tsn;
        uint16_t stream;
        uint16_t ssn;
        uint32_t ppid;
        //uint8_t payload[0];
    };

//
struct s1ap_pdu{
	uint8_t present;
	uint8_t procedureCode;
	uint8_t criticality;
	uint8_t value[];
}__PACKED;

//
struct s1ap_protocol_IE_field{
	uint16_t id;
	uint8_t criticality;
	uint8_t len;
	uint8_t value[];
}__PACKED;

static int _extraction_teid(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    if (packet->session == NULL)
    	return 0;

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    struct s1ap_pdu *pdu = (struct s1ap_pdu *) & packet->data[proto_offset];

    printf(" procedureCode: %d\n", pdu->procedureCode );


    *((uint32_t *) extracted_data->data) = 1;
    //printf("proto index: %d\n", proto_index);
    return 1;
}
static int _extraction_ipv4(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {
    if (packet->session != NULL) {
        *((uint32_t *) extracted_data->data) = 1;
        return 1;
    }
    return 0;
}

static int _extraction_imsi(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {
    if (packet->session != NULL) {
    	mmt_binary_data_t *data = (mmt_binary_data_t *) extracted_data->data;
    	data->len = 0;
        return 1;
    }
    return 0;
}

static attribute_metadata_t s1ap_attributes_metadata[] = {
	{S1AP_IMSI, S1AP_IMSI_ALIAS, MMT_BINARY_DATA,  sizeof (MMT_BINARY_DATA), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_imsi},
	{S1AP_TEID, S1AP_TEID_ALIAS, MMT_U32_DATA,     sizeof( uint32_t),        POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_teid},
	{S1AP_IP,   S1AP_IP_ALIAS,   MMT_DATA_IP_ADDR, sizeof( uint32_t),        POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_ipv4},
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
	case 18:
		retval.proto_id = PROTO_S1AP;
		retval.offset = sizeof( struct sctp_datahdr );
		retval.status = Classified;
		return set_classified_proto(ipacket, index + 1, retval);
	default:
		return 0;
	}

	return 0;
}


/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_S1AP, PROTO_S1AP_ALIAS);

    if( protocol_struct == NULL ){
    	fprintf(stderr, "Cannot initialize S1AP protocol");
    	return 0;
    }

    int i = 0;
    int len = sizeof( s1ap_attributes_metadata ) / sizeof( attribute_metadata_t );
    for (; i < len; i++)
    	register_attribute_with_protocol(protocol_struct, &s1ap_attributes_metadata[i]);

    register_classification_function_with_parent_protocol( PROTO_SCTP_DATA, _classify_s1ap_from_sctp_data, 50 );

    if (protocol_struct != NULL) {
        return register_protocol(protocol_struct, PROTO_S1AP);
    } else {
        return 0;
    }
}

int cleanup_proto(){
	//printf("close s1ap protocol");
	return 0;
}
