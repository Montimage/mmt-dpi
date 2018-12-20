#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "sctp.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static attribute_metadata_t sctp_attributes_metadata[SCTP_ATTRIBUTES_NB] = {
    {SCTP_SCR_PORT, SCTP_SCR_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_DEST_PORT, SCTP_DEST_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_VERIF_TAG, SCTP_VERIF_TAG_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {SCTP_CHECKSUM, SCTP_CHECKSUM_ALIAS, MMT_U32_DATA, sizeof (int), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {SCTP_CH_TYPE, SCTP_CH_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 12, SCOPE_PACKET, general_char_extraction},
    {SCTP_CH_FLAGS, SCTP_CH_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 13, SCOPE_PACKET, general_char_extraction},
    {SCTP_CH_LENGTH, SCTP_CH_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 14, SCOPE_PACKET, general_short_extraction_with_ordering_change},

};

static attribute_metadata_t sctp_data_attributes_metadata[SCTP_DATA_ATTRIBUTES_NB] = {
    {SCTP_DATA_CH_TYPE, SCTP_DATA_CH_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, general_char_extraction},
    {SCTP_DATA_CH_FLAGS, SCTP_DATA_CH_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {SCTP_DATA_CH_LENGTH, SCTP_DATA_CH_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_DATA_TSN, SCTP_DATA_TSN_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {SCTP_DATA_STREAM, SCTP_DATA_STREAM_ALIAS, MMT_U16_DATA, sizeof (short), 8, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_DATA_SSN, SCTP_DATA_SSN_ALIAS, MMT_U16_DATA, sizeof (short), 10, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_DATA_PPID, SCTP_DATA_PPID_ALIAS, MMT_U32_DATA, sizeof (int), 12, SCOPE_PACKET, general_int_extraction_with_ordering_change},

};

static attribute_metadata_t sctp_sack_attributes_metadata[SCTP_SACK_ATTRIBUTES_NB] = {
    {SCTP_SACK_CH_TYPE, SCTP_SACK_CH_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, general_char_extraction},
    {SCTP_SACK_CH_FLAGS, SCTP_SACK_CH_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {SCTP_SACK_CH_LENGTH, SCTP_SACK_CH_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_SACK_CUM_TSN_ACK, SCTP_SACK_CUM_TSN_ACK_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {SCTP_SACK_A_RWND, SCTP_SACK_A_RWND_ALIAS, MMT_U32_DATA, sizeof (int), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {SCTP_SACK_NUM_GAP_BLOCKS, SCTP_SACK_NUM_GAP_BLOCKS_ALIAS , MMT_U16_DATA, sizeof (short), 12, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_SACK_NUM_DUP_TSN, SCTP_SACK_NUM_DUP_TSN_ALIAS, MMT_U32_DATA, sizeof (int), 14, SCOPE_PACKET, general_int_extraction_with_ordering_change},

};

static attribute_metadata_t sctp_init_attributes_metadata[SCTP_INIT_ATTRIBUTES_NB] = {
    {SCTP_INIT_CH_TYPE, SCTP_INIT_CH_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, general_char_extraction},
    {SCTP_INIT_CH_FLAGS, SCTP_INIT_CH_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {SCTP_INIT_CH_LENGTH, SCTP_INIT_CH_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_INIT_INI_TAG, SCTP_INIT_INI_TAG_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {SCTP_INIT_A_RWND, SCTP_INIT_A_RWND_ALIAS, MMT_U32_DATA, sizeof (int), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {SCTP_INIT_NUM_OUT_STREAMS, SCTP_INIT_NUM_OUT_STREAMS_ALIAS , MMT_U16_DATA, sizeof (short), 12, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_INIT_NUM_IN_STREAMS, SCTP_INIT_NUM_IN_STREAMS_ALIAS, MMT_U16_DATA, sizeof (short), 14, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SCTP_INIT_INI_TSN, SCTP_INIT_INI_TSN_ALIAS, MMT_U32_DATA, sizeof (int), 16, SCOPE_PACKET, general_int_extraction_with_ordering_change},
};


static inline uint32_t _get_next_proto_id( uint8_t type ) {
	uint32_t proto_id = PROTO_UNKNOWN;
    switch( type ){
        case SCTP_DATA:
            proto_id = PROTO_SCTP_DATA;
            break;
        case SCTP_SACK:
            proto_id = PROTO_SCTP_SACK;
            break;

        case 1: //init
        case 2: //init ack
            proto_id = PROTO_SCTP_INIT;
            break;
        case 4: //heartbeat
        case 5: //heartbeat ack
        	proto_id = PROTO_SCTP_HEARTBEAT;
        	break;
        case 6:
        	proto_id = PROTO_SCTP_ABORT;
        	break;
        case 7: //shutdown
        case 8: //shutdown ack
        	proto_id = PROTO_SCTP_SHUTDOWN;
        	break;
        case 9:
        	proto_id = PROTO_SCTP_ERROR;
        	break;
        case 10: //cookie echo
        case 11: //cookie ack
        	proto_id = PROTO_SCTP_COOKIE_ECHO;
        	break;
        case 12:
        	proto_id = PROTO_SCTP_ECNE;
        	break;
        case 13:
        	proto_id = PROTO_SCTP_CWR;
        	break;
        case 14:
        	proto_id = PROTO_SCTP_SHUTDOWN_COMPLETE;
        	break;
        case 15:
        	proto_id = PROTO_SCTP_AUTH;
        	break;
        case 128: //asconf ack
        case 193: //asconf
        	proto_id = PROTO_SCTP_ASCONF;
        	break;
        case 130:
        	proto_id = PROTO_SCTP_RE_CONFIG;
        	break;
         default:
             proto_id = PROTO_UNKNOWN;
             break;
    }
    return proto_id;
}

static int sctp_classify_next_proto(ipacket_t * ipacket, unsigned index) {
	int offset = get_packet_offset_at_index(ipacket, index);

	const struct sctphdr *hdr = (struct sctphdr *) & ipacket->data[offset];

	classified_proto_t retval;
	retval.proto_id = _get_next_proto_id( hdr->type );
	retval.status   = Classified;
	retval.offset   = 12; //the next protocol is started after 12 bytes of SCTP header

	 //HN: do not copy session proto path into ipacket's proto path.
	//As we know explicitly the protocol at index-th position in the hierarchy,
	// so we limit the length of hierarchy for now.
	//This length will be increased by another classification function
	//  if further protocols will classified latter.
	ipacket->proto_hierarchy->len = index + 1 + 1;

	return set_classified_proto(ipacket, index + 1, retval);
}

static int sctp_classify_next_chunk(ipacket_t * ipacket, unsigned index) {
	int current_chunk_offset = get_packet_offset_at_index(ipacket, index);

	const struct sctp_chunkhdr *current_chunk_hdr = (struct sctp_chunkhdr *) & ipacket->data[current_chunk_offset];
	const uint16_t current_chunk_len = ntohs(current_chunk_hdr->length);

	//ensure that we still have room for the next chunk
	if( current_chunk_offset + current_chunk_len + sizeof( struct sctp_chunkhdr ) <= ipacket->p_hdr->caplen ){
		//the next chunk is started after this chunk
		const struct sctp_chunkhdr *next_chunk_hdr = (struct sctp_chunkhdr *) & ipacket->data[current_chunk_offset + current_chunk_len];

		classified_proto_t retval;
		retval.proto_id = _get_next_proto_id( next_chunk_hdr->type );
		retval.status   = Classified;
		retval.offset   = current_chunk_len; //the next chunk is just after this one

		ipacket->proto_hierarchy->len = index + 1 + 1;

		return set_classified_proto(ipacket, index + 1, retval);
	}
	return 0;
}


int init_sctp_proto_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SCTP, PROTO_SCTP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < SCTP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &sctp_attributes_metadata[i]);
        }
        register_classification_function(protocol_struct, sctp_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_SCTP);
    } else {
        return 0;
    }
}

int init_sctp_data_proto_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SCTP_DATA, PROTO_SCTP_DATA_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < SCTP_DATA_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &sctp_data_attributes_metadata[i]);
        }
        //register_classification_function(protocol_struct, sctp_classify_next_chunk);
        return register_protocol(protocol_struct, PROTO_SCTP_DATA);
    } else {
        return 0;
    }
}

int init_sctp_sack_proto_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SCTP_SACK, PROTO_SCTP_SACK_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < SCTP_SACK_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &sctp_sack_attributes_metadata[i]);
        }
        register_classification_function(protocol_struct, sctp_classify_next_chunk);
        return register_protocol(protocol_struct, PROTO_SCTP_SACK);
    } else {
        return 0;
    }
}

int init_sctp_init_proto_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SCTP_INIT, PROTO_SCTP_INIT_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < SCTP_INIT_ATTRIBUTES_NB ; i++) {
            register_attribute_with_protocol(protocol_struct, &sctp_init_attributes_metadata[i]);
        }
        register_classification_function(protocol_struct, sctp_classify_next_chunk);
        return register_protocol(protocol_struct, PROTO_SCTP_INIT);
    } else {
        return 0;
    }
}

static inline int _registe_protocol( uint16_t proto_id, const char *proto_name ){
	protocol_t * protocol_struct = init_protocol_struct_for_registration(proto_id, proto_name);

	if (protocol_struct != NULL){
		register_classification_function(protocol_struct, sctp_classify_next_chunk);
		return register_protocol(protocol_struct, proto_id);
	}
	return 0;
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_sctp_struct()
{
	//int init_sctp_data_proto_struct();
	init_sctp_proto_struct();

	init_sctp_data_proto_struct();
	init_sctp_sack_proto_struct();
	init_sctp_init_proto_struct();

	//register other sub-protocols of SCTP
	const uint32_t protos_id[] = {
			PROTO_SCTP_HEARTBEAT          ,
			PROTO_SCTP_SHUTDOWN           ,
			PROTO_SCTP_SHUTDOWN_COMPLETE  ,
			PROTO_SCTP_ABORT              ,
			PROTO_SCTP_ERROR              ,
			PROTO_SCTP_COOKIE_ECHO        ,
			PROTO_SCTP_ECNE               ,
			PROTO_SCTP_CWR                ,
			PROTO_SCTP_AUTH               ,
			PROTO_SCTP_ASCONF             ,
			PROTO_SCTP_RE_CONFIG
	};
	const char * protos_name[] = {
			PROTO_SCTP_HEARTBEAT_ALIAS         ,
			PROTO_SCTP_SHUTDOWN_ALIAS          ,
			PROTO_SCTP_SHUTDOWN_COMPLETE_ALIAS ,
			PROTO_SCTP_ABORT_ALIAS             ,
			PROTO_SCTP_ERROR_ALIAS             ,
			PROTO_SCTP_COOKIE_ECHO_ALIAS       ,
			PROTO_SCTP_ECNE_ALIAS              ,
			PROTO_SCTP_CWR_ALIAS               ,
			PROTO_SCTP_AUTH_ALIAS              ,
			PROTO_SCTP_ASCONF_ALIAS            ,
			PROTO_SCTP_RE_CONFIG_ALIAS
	};

	const int n = sizeof (protos_id) / sizeof( protos_id[0] );
	int i = 0;
    for( i=0; i<n; i++ )
		_registe_protocol( protos_id[i], protos_name[i] );

	return 1;
}



