#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

classified_proto_t tpkt_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = PROTO_TPKT;
    retval.status = Classified;
    return retval;
}

//////////////////////////// EXTRACTION ///////////////////////////////////////


static attribute_metadata_t tpkt_attributes_metadata[TPKT_ATTRIBUTES_NB] = {

    {TPKT_VERSION, TPKT_VERSION_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, general_char_extraction},

    {TPKT_RESERVED, TPKT_RESERVED_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 1, SCOPE_PACKET, general_char_extraction},

    {TPKT_LENGTH, TPKT_LENGTH_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},

};
//////////////////////////// END OF EXTRACTION /////////////////////////////////

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

int mmt_check_tpkt(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
        uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

        if (payload_len == 0) {
            return 0;
        }

        if (packet->tcp != NULL) {
            if (ntohs(packet->tcp->dest) == 102 || ntohs(packet->tcp->source) == 102) {
                int tpkt_offset = get_packet_offset_at_index(ipacket, index + 1);
                struct tpkthdr * tpkt_header = (struct tpkthdr *)&ipacket->data[tpkt_offset];
                if (tpkt_header != NULL && ntohs(tpkt_header->length) == payload_len) {
                    int l3_offset = get_packet_offset_at_index(ipacket, index);
                    classified_proto_t tpkt_proto = tpkt_stack_classification(ipacket);
                    tpkt_proto.offset = tpkt_offset - l3_offset;
                    set_classified_proto(ipacket, index + 1, tpkt_proto);
                    return 1;
                }
            }
        }
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(packet->flow->excluded_protocol_bitmask, PROTO_TPKT);
    return 0;
}

void mmt_init_classify_me_tpkt() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TPKT);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_TPKT);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_tpkt_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_TPKT, PROTO_TPKT_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < TPKT_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &tpkt_attributes_metadata[i]);
        }
        mmt_init_classify_me_tpkt();
        return register_protocol(protocol_struct, PROTO_TPKT);
    } else {
        return -1;
    }
}


