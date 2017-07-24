/* Generated with MMT Plugin Generator */

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "proto_sll.h"
#include "ip_session_id_management.h"

uint16_t sll_protocol_get_value(const ipacket_t * ipacket, int proto_index);


/*
 * SLL data extraction routines
 */
classified_proto_t sll_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = PROTO_SLL;
    retval.status = Classified;
    return retval;
}

static attribute_metadata_t sll_attributes_metadata[SLL_ATTRIBUTES_NB] = {
    {SLL_PKTTYPE, SLL_PKTTYPE_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SLL_HATYPE, SLL_HATYPE_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SLL_HALEN, SLL_HALEN_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {SLL_ADDR, SLL_ADDR_ALIAS, MMT_U64_DATA, sizeof(uint64_t), 6, SCOPE_PACKET, general_byte_to_byte_extraction},
    {SLL_PROTOCOL, SLL_PROTOCOL_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 14, SCOPE_PACKET, general_short_extraction_with_ordering_change},

};


uint16_t sll_protocol_get_value(const ipacket_t * ipacket, int proto_index) {
    uint16_t retval;
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    retval = ntohs(*(uint16_t *) & ipacket->data[proto_offset + sll_attributes_metadata[4].position_in_packet]);
    return retval;
}


int sll_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;


    switch(sll_protocol_get_value(ipacket, index)) {
            /* IPv4 */
        case ETH_P_IP:
            retval.proto_id = PROTO_IP;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
            /* IPv6 */
        case ETH_P_IPV6:
            retval.proto_id = PROTO_IPV6;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
            /* ARP */
            /* RARP: will be processed as ARP */
        case ETH_P_RARP:
        case ETH_P_ARP:
            retval.proto_id = PROTO_ARP;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
            /* 802.1Q */
        case ETH_P_8021Q:
            retval.proto_id = PROTO_8021Q;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
        case 0x9100:
        case 0x9200:
        case 0x9300:
            retval.proto_id = PROTO_8021Q;
            retval.offset = sizeof (struct sll_header) + 4;
            retval.status = Classified;
            break;
             /* PPPoE Discovery */
        case ETH_P_PPPoED:
            retval.proto_id = PROTO_PPPOE;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
            /* PPPoE Session */
        case ETH_P_PPPoES:
            retval.proto_id = PROTO_PPPOE;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
            /* Batman */
        case ETH_P_BATMAN:
            retval.proto_id = PROTO_BATMAN;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = sizeof (struct sll_header);
            retval.status = Classified;
            break;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

int init_proto_sll_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SLL, PROTO_SLL_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for(; i < SLL_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &sll_attributes_metadata[i]);
        }


        /* Classify encapsulated protocol */
        register_classification_function(protocol_struct, sll_classify_next_proto);


        register_protocol_stack(PROTO_SLL, PROTO_SLL_ALIAS, sll_stack_classification);
        return register_protocol(protocol_struct, PROTO_SLL);
    } else {
        return 0;
    }
}

