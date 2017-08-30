#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

classified_proto_t s7comm_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = PROTO_S7COMM;
    retval.status = Classified;
    return retval;
}

//////////////////////////// EXTRACTION ///////////////////////////////////////

static attribute_metadata_t s7comm_attributes_metadata[S7COMM_ATTRIBUTES_NB] = {

    {S7COMM_PROTO_ID, S7COMM_PROTO_ID_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, general_char_extraction},

    {S7COMM_ROSCTR, S7COMM_ROSCTR_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 1, SCOPE_PACKET, general_char_extraction},

    {S7COMM_RESERVED, S7COMM_RESERVED_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},

    {S7COMM_PDUR, S7COMM_PDUR_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},

    {S7COMM_PARAM_LENGTH, S7COMM_PARAM_LENGTH_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 6, SCOPE_PACKET, general_short_extraction_with_ordering_change},

    {S7COMM_DATA_LENGTH, S7COMM_DATA_LENGTH_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 8, SCOPE_PACKET, general_short_extraction_with_ordering_change},

};
//////////////////////////// END OF EXTRACTION /////////////////////////////////

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

int mmt_check_s7comm(ipacket_t * ipacket, unsigned index) {
    int l5_offset = get_packet_offset_at_index(ipacket, index);
    classified_proto_t s7comm_proto = s7comm_stack_classification(ipacket);
    struct cotphdr * cotp_header = (struct cotphdr *)&ipacket->data[l5_offset];
    if(cotp_header->length == 2 || cotp_header->length == 17){
        s7comm_proto.offset = cotp_header->length + 1;
        int s7comm_offset = l5_offset + cotp_header->length + 1; // 1 - for length  
        char payload_len = ipacket->p_hdr->caplen - s7comm_offset;
        if(payload_len == 0){
            return 0;
        }
        struct s7commphdr * s7comm_header = (struct s7commphdr *)&ipacket->data[s7comm_offset];
        if(s7comm_header->proto_id == 50){
            // printf("S7COMM: found S7COMM packet %lu\n",ipacket->packet_id);
            return set_classified_proto(ipacket, index + 1, s7comm_proto);
        }
    }
    return 0;
}


/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_s7comm_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_S7COMM, PROTO_S7COMM_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for(; i < S7COMM_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &s7comm_attributes_metadata[i]);
        }

        if (!register_classification_function_with_parent_protocol(PROTO_COTP, mmt_check_s7comm, 50)) {
            fprintf(stderr, "[err] init_cotp_proto_struct - cannot register_classification_function_with_parent_protocol\n");
        };
        // register_protocol_stack(PROTO_S7COMM, PROTO_S7COMM_ALIAS, s7comm_stack_classification);
        return register_protocol(protocol_struct, PROTO_S7COMM);
    } else {
        return -1;
    }
}

