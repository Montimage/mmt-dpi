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


int sctp_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    const struct sctphdr *sctp = (struct sctphdr *) & ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;
    switch (sctp->type) // check type of packet
    {
            /* SCTP_DATA */
        case SCTP_DATA:
            retval.proto_id = PROTO_SCTP_DATA;
            retval.offset = 12; //TODO replace with defination
            retval.status = Classified;
            break;
        case SCTP_SACK:
            retval.proto_id = PROTO_SCTP_SACK;
            retval.offset = 12; //TODO replace with defination
            retval.status = Classified;
            break;

        case SCTP_INIT:
            retval.proto_id = PROTO_SCTP_INIT;
            retval.offset = 12; //TODO replace with defination
            retval.status = Classified;
            break;

        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = 12; //TODO replace with defination
            retval.status = Classified;
            break;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

classified_proto_t sctp_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = PROTO_SCTP;
    retval.status = Classified;
    return retval;
}


int init_sctp_proto_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SCTP, PROTO_SCTP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < SCTP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &sctp_attributes_metadata[i]);
        }
        register_classification_function(protocol_struct, sctp_classify_next_proto); //BW TODO: check this out
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
        return register_protocol(protocol_struct, PROTO_SCTP_INIT);
    } else {
        return 0;
    }
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_sctp_struct()
{
//int init_sctp_data_proto_struct();
 init_sctp_proto_struct();

 init_sctp_data_proto_struct();
 init_sctp_sack_proto_struct();
 init_sctp_init_proto_struct();

return 1;
}



