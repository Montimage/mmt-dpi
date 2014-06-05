#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_maplestory_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_MAPLESTORY, protocol_type);
}

void mmt_classify_me_maplestory(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;



    if (packet->payload_packet_len == 16
            && (ntohl(get_u32(packet->payload, 0)) == 0x0e003a00 || ntohl(get_u32(packet->payload, 0)) == 0x0e003b00
            || ntohl(get_u32(packet->payload, 0)) == 0x0e004200)
            && ntohs(get_u16(packet->payload, 4)) == 0x0100 && (packet->payload[6] == 0x32 || packet->payload[6] == 0x33)) {
        MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "found maplestory.\n");
        mmt_int_maplestory_add_connection(ipacket, MMT_REAL_PROTOCOL);
        return;
    }

    if (packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /maple")
            && memcmp(packet->payload, "GET /maple", MMT_STATICSTRING_LEN("GET /maple")) == 0) {
        mmt_parse_packet_line_info(ipacket);
        /* Maplestory update */
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /maple/patch")
                && packet->payload[MMT_STATICSTRING_LEN("GET /maple")] == '/') {
            if (packet->user_agent_line.ptr != NULL && packet->host_line.ptr != NULL
                    && packet->user_agent_line.len == MMT_STATICSTRING_LEN("Patcher")
                    && packet->host_line.len > MMT_STATICSTRING_LEN("patch.")
                    && memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /maple/")], "patch",
                    MMT_STATICSTRING_LEN("patch")) == 0
                    && memcmp(packet->user_agent_line.ptr, "Patcher", MMT_STATICSTRING_LEN("Patcher")) == 0
                    && memcmp(packet->host_line.ptr, "patch.", MMT_STATICSTRING_LEN("patch.")) == 0) {
                MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "found maplestory update.\n");
                mmt_int_maplestory_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        } else if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len == MMT_STATICSTRING_LEN("AspINet")
                && memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /maple")], "story/",
                MMT_STATICSTRING_LEN("story/")) == 0
                && memcmp(packet->user_agent_line.ptr, "AspINet", MMT_STATICSTRING_LEN("AspINet")) == 0) {
            MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "found maplestory update.\n");
            mmt_int_maplestory_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
    }

    MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "exclude maplestory.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MAPLESTORY);

}

int mmt_check_maplestory(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (packet->payload_packet_len == 16
                && (ntohl(get_u32(packet->payload, 0)) == 0x0e003a00 || ntohl(get_u32(packet->payload, 0)) == 0x0e003b00
                || ntohl(get_u32(packet->payload, 0)) == 0x0e004200)
                && ntohs(get_u16(packet->payload, 4)) == 0x0100 && (packet->payload[6] == 0x32 || packet->payload[6] == 0x33)) {
            MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "found maplestory.\n");
            mmt_int_maplestory_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /maple")
                && memcmp(packet->payload, "GET /maple", MMT_STATICSTRING_LEN("GET /maple")) == 0) {
            mmt_parse_packet_line_info(ipacket);
            /* Maplestory update */
            if (packet->payload_packet_len > MMT_STATICSTRING_LEN("GET /maple/patch")
                    && packet->payload[MMT_STATICSTRING_LEN("GET /maple")] == '/') {
                if (packet->user_agent_line.ptr != NULL && packet->host_line.ptr != NULL
                        && packet->user_agent_line.len == MMT_STATICSTRING_LEN("Patcher")
                        && packet->host_line.len > MMT_STATICSTRING_LEN("patch.")
                        && memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /maple/")], "patch",
                        MMT_STATICSTRING_LEN("patch")) == 0
                        && memcmp(packet->user_agent_line.ptr, "Patcher", MMT_STATICSTRING_LEN("Patcher")) == 0
                        && memcmp(packet->host_line.ptr, "patch.", MMT_STATICSTRING_LEN("patch.")) == 0) {
                    MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "found maplestory update.\n");
                    mmt_int_maplestory_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                    return 1;
                }
            } else if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len == MMT_STATICSTRING_LEN("AspINet")
                    && memcmp(&packet->payload[MMT_STATICSTRING_LEN("GET /maple")], "story/",
                    MMT_STATICSTRING_LEN("story/")) == 0
                    && memcmp(packet->user_agent_line.ptr, "AspINet", MMT_STATICSTRING_LEN("AspINet")) == 0) {
                MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "found maplestory update.\n");
                mmt_int_maplestory_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }

        MMT_LOG(PROTO_MAPLESTORY, MMT_LOG_DEBUG, "exclude maplestory.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MAPLESTORY);
    }
    return 1;
}

void mmt_init_classify_me_maplestory() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MAPLESTORY);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_maplestory_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MAPLESTORY, PROTO_MAPLESTORY_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_maplestory();

        return register_protocol(protocol_struct, PROTO_MAPLESTORY);
    } else {
        return 0;
    }
}


