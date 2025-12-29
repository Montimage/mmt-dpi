#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "icmp.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
int icmp_identifier_and_seq_nb_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    char type = *(char *) & packet->data[proto_offset];
    switch (type) {
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
            return general_short_extraction_with_ordering_change(packet, proto_index, extracted_data);
        default:
            return 0;
    }
}

int icmp_gateway_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    char type = *(char *) & packet->data[proto_offset];
    switch (type) {
        case ICMP_REDIRECT:
            return general_int_extraction(packet, proto_index, extracted_data);
        default:
            return 0;
    }
}

int icmp_data_extraction(const ipacket_t * packet, unsigned proto_index,
            attribute_t * extracted_data) {

    //protocol_t * protocol_struct = get_protocol_struct_by_id(extracted_data->proto_id);
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    int data_len = packet->p_hdr->len - (proto_offset + attribute_offset);
    if( data_len < 0 ) {
        MMT_LOG( PROTO_ICMP, MMT_LOG_DEBUG, "*** Warning: malformed packet (icmp length mismatch)\n" );
        return 0;
    }
    char type = *(char *) & packet->data[proto_offset];
    switch (type) {
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
            if (data_len > BINARY_1024DATA_LEN) data_len = BINARY_1024DATA_LEN;
            *((unsigned int *) extracted_data->data) = data_len;
            memcpy(& ((u_char *) extracted_data->data)[sizeof (int)], (char *) & packet->data[proto_offset + attribute_offset], data_len);
            return 1;
        default:
            return 0;
    }
}

classified_proto_t icmp_classify_next_proto(ipacket_t * ipacket, unsigned index, void * args) {
    int offset = get_packet_offset_at_index(ipacket, index);
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    char type = *(char *) & ipacket->data[offset];

    switch (type) {
        case ICMP_DEST_UNREACH:
        case ICMP_SOURCE_QUENCH:
        case ICMP_REDIRECT:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
            retval.proto_id = PROTO_IP;
            retval.offset = 8;
            retval.status = Classified;
            break;
        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = 8;
            retval.status = Classified;
            break;
    }

    return retval;
}

static attribute_metadata_t icmp_attributes_metadata[ICMP_ATTRIBUTES_NB] = {
    {ICMP_TYPE, ICMP_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, general_byte_to_byte_extraction},
    {ICMP_CODE, ICMP_CODE_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_byte_to_byte_extraction},
    {ICMP_CHECKSUM, ICMP_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {ICMP_IDENTIFIER, ICMP_IDENTIFIER_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, icmp_identifier_and_seq_nb_extraction},
    {ICMP_SEQUENCE_NB, ICMP_SEQUENCE_NB_ALIAS, MMT_U16_DATA, sizeof (short), 6, SCOPE_PACKET, icmp_identifier_and_seq_nb_extraction},
    {ICMP_GATEWAY, ICMP_GATEWAY_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, icmp_gateway_extraction},
    {ICMP_DATA, ICMP_DATA_ALIAS, MMT_BINARY_VAR_DATA, BINARY_1024DATA_TYPE_LEN, 8, SCOPE_PACKET, icmp_data_extraction},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_icmp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ICMP, PROTO_ICMP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for(; i < ICMP_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &icmp_attributes_metadata[i]);
        }

        register_classification_function(protocol_struct, NULL); //TODO: do not classify what comes next! Check this out

        return register_protocol(protocol_struct, PROTO_ICMP);
    } else {
        return 0;
    }
}
