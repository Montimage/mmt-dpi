/*
 * proto_ngap.c
 *
 *  Created on: Dec 11, 2020
 *      Author: nhnghia
 */


#include "mmt_mobile_internal.h"

static uint32_t  _classify_by_sctp_ports( ipacket_t *ipacket, unsigned index, uint16_t offset ){
	int sctp_index = get_protocol_index_by_id( ipacket, PROTO_SCTP );
	//not found SCTP
	if( sctp_index == -1 )
		return PROTO_UNKNOWN;
	//offset of sctp in packet
	int sctp_offset = get_packet_offset_at_index(ipacket, sctp_index);
	const struct sctphdr *sctp_hdr = (struct sctphdr *) &ipacket->data[ sctp_offset ];

	//https://www.etsi.org/deliver/etsi_ts/138400_138499/138412/15.00.00_60/ts_138412v150000p.pdf
	//The SCTP Destination Port number value assigned by IANA to be used for NGAP is 38412.
	const uint16_t sctp_port_for_ngap = htons( 38412 );
	if( sctp_hdr->dest != sctp_port_for_ngap )
		return PROTO_UNKNOWN;
	//need to check other signatures of NGAP
	return PROTO_NGAP;
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
	int s1ap_offset = sctp_data_offset + sizeof(struct sctp_datahdr);
	//sctp data Packet payload ID
	switch( ntohl( hdr->ppid )){
	case 60: //
		retval.proto_id = PROTO_NGAP;
		break;
	case 0: //not specified
		//try to classify NGAP
		retval.proto_id = _classify_by_sctp_ports(ipacket, index, s1ap_offset);
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

static attribute_metadata_t _attributes_metadata[] = {
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
	return register_protocol(protocol_struct, PROTO_NGAP);

}

