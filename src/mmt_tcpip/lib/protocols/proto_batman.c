#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "batman.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
int batman_packet_type_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    struct batman_packet * b_packet = (struct batman_packet *) &packet->data[proto_offset];

    *((unsigned char *) extracted_data->data) = b_packet->packet_type;

    return 1;
}

int batman_packet_format_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    /* unused
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    struct batman_packet * b_packet = (struct batman_packet *) &packet->data[proto_offset];
    */

    //TODO: teste si le packet est bien formatte

    *((unsigned int *) extracted_data->data) = 1;

    return 1;
}


int batman_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    const struct batman_packet *batman = (struct batman_packet *) & ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    //Classification goes here
    switch (batman->packet_type) // Batman protocol encapsulation
    {
        case BAT_PACKET:
            retval.proto_id = BATMAN_PACKET;
            retval.offset = 0;
            retval.status = Classified;
            break;
            /* Batman ICMP */
        case BAT_ICMP:
            retval.proto_id = BATMAN_ICMP;
            retval.offset = 0;
            retval.status = Classified;
            break;
            /* Batman Unicast */
        case BAT_UNICAST:
            retval.proto_id = BATMAN_UNICAST;
            retval.offset = 0;
            retval.status = Classified;
            break;
        case BAT_BCAST:
            retval.proto_id = BATMAN_BCAST;
            retval.offset = 0;
            retval.status = Classified;
            break;
        case BAT_VIS:
            retval.proto_id = BATMAN_VIS;
            retval.offset = 0;
            retval.status = Classified;
            break;
        case BAT_UNICAST_FRAG:
            retval.proto_id = BATMAN_UNICAST_FRAG;
            retval.offset = 0;
            retval.status = Classified;
            break;
        default:
            break;
    }

    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

static attribute_metadata_t batman_attributes_metadata[BATMAN_PACKET_ATTRIBUTES_NB] = {
    {BATMAN_PACKET_TYPE, BATMAN_PACKET_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, batman_packet_type_extraction},
    {BATMAN_VERSION, BATMAN_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {BATMAN_FLAGS, BATMAN_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 2, SCOPE_PACKET, general_char_extraction},
    {BATMAN_TQ, BATMAN_TQ_ALIAS, MMT_U8_DATA, sizeof (char), 3, SCOPE_PACKET, general_char_extraction},
    {BATMAN_SEQNO, BATMAN_SEQNO_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {BATMAN_ORIG, BATMAN_ORIG_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 8, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_PREV_SENDER, BATMAN_PREV_SENDER_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 14, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_TTL, BATMAN_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 20, SCOPE_PACKET, general_char_extraction},
    {BATMAN_NUM_TT, BATMAN_NUM_TT_ALIAS, MMT_U8_DATA, sizeof (char), 21, SCOPE_PACKET, general_char_extraction},
    {BATMAN_GW_FLAGS, BATMAN_GW_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 22, SCOPE_PACKET, general_char_extraction},
    {BATMAN_ALIGN, BATMAN_ALIGN_ALIAS, MMT_U8_DATA, sizeof (char), 23, SCOPE_PACKET, general_char_extraction},
    {BATMAN_PACKET_FORMATTING, BATMAN_PACKET_FORMATTING_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, batman_packet_format_extraction},
};

static attribute_metadata_t batman_attributes_metadata1[BATMAN_ICMP_ATTRIBUTES_NB] = {
    {BATMAN_PACKET_TYPE, BATMAN_PACKET_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, batman_packet_type_extraction},
    {BATMAN_VERSION, BATMAN_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {BATMAN_MSG_TYPE, BATMAN_MSG_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 2, SCOPE_PACKET, general_char_extraction},
    {BATMAN_TTL, BATMAN_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 3, SCOPE_PACKET, general_char_extraction},
    {BATMAN_DST, BATMAN_DST_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 4, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_ORIG, BATMAN_ORIG_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 10, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_SEQNO, BATMAN_SEQNO_ALIAS, MMT_U16_DATA, sizeof (short), 16, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {BATMAN_UID, BATMAN_UID_ALIAS, MMT_U8_DATA, sizeof (char), 18, SCOPE_PACKET, general_char_extraction},
};

static attribute_metadata_t batman_attributes_metadata2[BATMAN_UNICAST_ATTRIBUTES_NB] = {
    {BATMAN_PACKET_TYPE, BATMAN_PACKET_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, batman_packet_type_extraction},
    {BATMAN_VERSION, BATMAN_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {BATMAN_DST, BATMAN_DST_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 2, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_TTL, BATMAN_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 8, SCOPE_PACKET, general_char_extraction},
};


static attribute_metadata_t batman_attributes_metadata3[BATMAN_BCAST_ATTRIBUTES_NB] = {
    {BATMAN_PACKET_TYPE, BATMAN_PACKET_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, batman_packet_type_extraction},
    {BATMAN_VERSION, BATMAN_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {BATMAN_ORIG, BATMAN_ORIG_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 2, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_TTL, BATMAN_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 8, SCOPE_PACKET, general_char_extraction},
    {BATMAN_SEQNO, BATMAN_SEQNO_ALIAS, MMT_U32_DATA, sizeof (int), 9, SCOPE_PACKET, general_int_extraction_with_ordering_change},
};

static attribute_metadata_t batman_attributes_metadata4[BATMAN_VIS_ATTRIBUTES_NB] = {
    {BATMAN_PACKET_TYPE, BATMAN_PACKET_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, batman_packet_type_extraction},
    {BATMAN_VERSION, BATMAN_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {BATMAN_VIS_TYPE, BATMAN_VIS_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 2, SCOPE_PACKET, general_char_extraction},
    {BATMAN_ENTRIES, BATMAN_ENTRIES_ALIAS, MMT_U8_DATA, sizeof (char), 3, SCOPE_PACKET, general_char_extraction},
    {BATMAN_SEQNO, BATMAN_SEQNO_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {BATMAN_TTL, BATMAN_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 8, SCOPE_PACKET, general_char_extraction},
    {BATMAN_VIS_ORIG, BATMAN_VIS_ORIG_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 9, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_TARGET_ORIG, BATMAN_TARGET_ORIG_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 15, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_SENDER_ORIG, BATMAN_SENDER_ORIG_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 21, SCOPE_PACKET, general_byte_to_byte_extraction},
};

static attribute_metadata_t batman_attributes_metadata5[BATMAN_UNICAST_FRAG_ATTRIBUTES_NB] = {
    {BATMAN_PACKET_TYPE, BATMAN_PACKET_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, batman_packet_type_extraction},
    {BATMAN_VERSION, BATMAN_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {BATMAN_DST, BATMAN_DST_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 2, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_TTL, BATMAN_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 8, SCOPE_PACKET, general_char_extraction},
    {BATMAN_FLAGS, BATMAN_FLAGS_ALIAS, MMT_U8_DATA, sizeof (char), 9, SCOPE_PACKET, general_char_extraction},
    {BATMAN_ORIG, BATMAN_ORIG_ALIAS, MMT_DATA_MAC_ADDR, ETH_ALEN, 10, SCOPE_PACKET, general_byte_to_byte_extraction},
    {BATMAN_SEQNO, BATMAN_SEQNO_ALIAS, MMT_U16_DATA, sizeof (short), 16, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};

int init_batman_packet() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(BATMAN_PACKET, BATMAN_PACKET_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < BATMAN_ICMP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &batman_attributes_metadata[i]);
        }

        return register_protocol(protocol_struct, BATMAN_PACKET);
    } else {
        return -1;
    }
}

int init_proto_batman() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_BATMAN, PROTO_BATMAN_ALIAS);

    if (protocol_struct != NULL) {

        //register_classification_function(protocol_struct, batman_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_BATMAN);
    } else {
        return -1;
    }
}

int init_batman_icmp() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(BATMAN_ICMP, BATMAN_ICMP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < BATMAN_ICMP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &batman_attributes_metadata1[i]);
        }

        return register_protocol(protocol_struct, BATMAN_ICMP);
    } else {
        return -1;
    }
}

int init_batman_unicast() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(BATMAN_UNICAST, BATMAN_UNICAST_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < BATMAN_UNICAST_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &batman_attributes_metadata2[i]);
        }

        return register_protocol(protocol_struct, BATMAN_UNICAST);
    } else {
        return -1;
    }
}

int init_batman_bcast() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(BATMAN_BCAST, BATMAN_BCAST_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < BATMAN_BCAST_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &batman_attributes_metadata3[i]);
        }

        return register_protocol(protocol_struct, BATMAN_BCAST);
    } else {
        return -1;
    }
}

int init_batman_vis() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(BATMAN_VIS, BATMAN_VIS_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < BATMAN_VIS_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &batman_attributes_metadata4[i]);
        }

        return register_protocol(protocol_struct, BATMAN_VIS);
    } else {
        return -1;
    }
}

int init_batman_uni_frag() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(BATMAN_UNICAST_FRAG, BATMAN_UNICAST_FRAG_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < BATMAN_UNICAST_FRAG_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &batman_attributes_metadata5[i]);
        }

        return register_protocol(protocol_struct, BATMAN_UNICAST_FRAG);
    } else {
        return -1;
    }
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_batman_struct() {
    init_proto_batman();
/*
    init_batman_packet();
    init_batman_icmp();
    init_batman_unicast();
    init_batman_bcast();
    init_batman_vis();
    init_batman_uni_frag();
*/
    return 1;
}

