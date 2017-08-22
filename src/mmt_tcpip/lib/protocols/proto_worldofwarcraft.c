#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_worldofwarcraft_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_WORLDOFWARCRAFT, protocol_type);
}


static uint8_t mmt_int_is_wow_port(const uint16_t port) {
    if (port == htons(3724) || port == htons(6112) || port == htons(6113) ||
            port == htons(6114) || port == htons(4000) || port == htons(1119)) {
        return 1;
    }
    return 0;
}

void mmt_classify_me_worldofwarcraft(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    MMT_LOG(PROTO_WORLDOFWARCRAFT, MMT_LOG_DEBUG, "Search World of Warcraft.\n");

    if (packet->tcp != NULL) {
        if ((packet->payload_packet_len > 6 &&
                memcmp(packet->payload, "POST /", 6) == 0) ||
                (packet->payload_packet_len > 5 &&
                memcmp(packet->payload, "GET /", 5) == 0)) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->user_agent_line.ptr != NULL &&
                    packet->user_agent_line.len == 19 &&
                    memcmp(packet->user_agent_line.ptr, "Blizzard Web Client",
                    19) == 0) {
                mmt_int_worldofwarcraft_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                MMT_LOG(PROTO_WORLDOFWARCRAFT, MMT_LOG_DEBUG,
                        "World of Warcraft: Web Client found\n");
                return;
            }
        }
        if (packet->payload_packet_len > 5
                && memcmp(packet->payload, "GET /", 5) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->user_agent_line.ptr != NULL && packet->host_line.ptr != NULL
                    && packet->user_agent_line.len > 19
                    && packet->host_line.len > 19
                    && memcmp(packet->user_agent_line.ptr, "Blizzard Downloader",
                    19) == 0
                    && memcmp(&packet->host_line.ptr[packet->host_line.len - 19],
                    "worldofwarcraft.com", 19) == 0) {
                mmt_int_worldofwarcraft_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                MMT_LOG(PROTO_WORLDOFWARCRAFT, MMT_LOG_DEBUG,
                        "World of Warcraft: Web Client found\n");
                return;
            }
        }
        if (packet->payload_packet_len == 50 && memcmp(&packet->payload[2], "WORLD OF WARCRAFT CONNECTION",
                28) == 0) {
            mmt_int_worldofwarcraft_add_connection(ipacket, MMT_REAL_PROTOCOL);
            MMT_LOG(PROTO_WORLDOFWARCRAFT, MMT_LOG_DEBUG, "World of Warcraft: Login found\n");
            return;
        }
        if (packet->tcp->dest == htons(3724) && packet->payload_packet_len < 70
                && packet->payload_packet_len > 40 && (memcmp(&packet->payload[4], "WoW", 3) == 0
                || memcmp(&packet->payload[5], "WoW", 3) == 0)) {
            mmt_int_worldofwarcraft_add_connection(ipacket, MMT_REAL_PROTOCOL);
            MMT_LOG(PROTO_WORLDOFWARCRAFT, MMT_LOG_DEBUG, "World of Warcraft: Login found\n");
            return;
        }

        if (MMT_SRC_OR_DST_HAS_PROTOCOL(src, dst, PROTO_WORLDOFWARCRAFT) != 0) {
            if (packet->tcp->source == htons(3724)
                    && packet->payload_packet_len == 8 && get_u32(packet->payload, 0) == htonl(0x0006ec01)) {
                mmt_int_worldofwarcraft_add_connection(ipacket, MMT_REAL_PROTOCOL);
                MMT_LOG(PROTO_WORLDOFWARCRAFT,
                        MMT_LOG_DEBUG, "World of Warcraft: connection detected\n");
                return;
            }

        }

        /* for some well known WoW ports
           check another pattern */
        if (flow->l4.tcp.wow_stage == 0) {
            if (mmt_int_is_wow_port(packet->tcp->source) &&
                    packet->payload_packet_len >= 14 &&
                    ntohs(get_u16(packet->payload, 0)) == (packet->payload_packet_len - 2)) {
                if (get_u32(packet->payload, 2) == htonl(0xec010100)) {

                    MMT_LOG(PROTO_WORLDOFWARCRAFT,
                            MMT_LOG_DEBUG, "probably World of Warcraft, waiting for final packet\n");
                    flow->l4.tcp.wow_stage = 2;
                    return;
                } else if (packet->payload_packet_len == 41 &&
                        (get_u16(packet->payload, 2) == htons(0x0085) ||
                        get_u16(packet->payload, 2) == htons(0x0034) ||
                        get_u16(packet->payload, 2) == htons(0x1960))) {
                    MMT_LOG(PROTO_WORLDOFWARCRAFT,
                            MMT_LOG_DEBUG, "maybe World of Warcraft, need next\n");
                    flow->l4.tcp.wow_stage = 1;
                    return;
                }
            }
        }

        if (flow->l4.tcp.wow_stage == 1) {
            if (packet->payload_packet_len == 325 &&
                    ntohs(get_u16(packet->payload, 0)) == (packet->payload_packet_len - 2) &&
                    get_u16(packet->payload, 4) == 0 &&
                    (get_u16(packet->payload, packet->payload_packet_len - 3) == htons(0x2331) ||
                    get_u16(packet->payload, 67) == htons(0x2331)) &&
                    (memcmp
                    (&packet->payload[packet->payload_packet_len - 18],
                    "\x94\xec\xff\xfd\x67\x62\xd4\x67\xfb\xf9\xdd\xbd\xfd\x01\xc0\x8f\xf9\x81", 18) == 0
                    || memcmp(&packet->payload[packet->payload_packet_len - 30],
                    "\x94\xec\xff\xfd\x67\x62\xd4\x67\xfb\xf9\xdd\xbd\xfd\x01\xc0\x8f\xf9\x81", 18) == 0)) {
                mmt_int_worldofwarcraft_add_connection(ipacket, MMT_REAL_PROTOCOL);
                MMT_LOG(PROTO_WORLDOFWARCRAFT,
                        MMT_LOG_DEBUG, "World of Warcraft: connection detected\n");
                return;
            }
            if (packet->payload_packet_len > 32 &&
                    ntohs(get_u16(packet->payload, 0)) == (packet->payload_packet_len - 2)) {
                if (get_u16(packet->payload, 4) == 0) {

                    MMT_LOG(PROTO_WORLDOFWARCRAFT,
                            MMT_LOG_DEBUG, "probably World of Warcraft, waiting for final packet\n");
                    flow->l4.tcp.wow_stage = 2;
                    return;
                } else if (get_u32(packet->payload, 2) == htonl(0x12050000)) {
                    MMT_LOG(PROTO_WORLDOFWARCRAFT,
                            MMT_LOG_DEBUG, "probably World of Warcraft, waiting for final packet\n");
                    flow->l4.tcp.wow_stage = 2;
                    return;
                }
            }
        }

        if (flow->l4.tcp.wow_stage == 2) {
            if (packet->payload_packet_len == 4) {
                mmt_int_worldofwarcraft_add_connection(ipacket, MMT_REAL_PROTOCOL);
                MMT_LOG(PROTO_WORLDOFWARCRAFT,
                        MMT_LOG_DEBUG, "World of Warcraft: connection detected\n");
                return;
            } else if (packet->payload_packet_len > 4 && packet->payload_packet_len <= 16 && packet->payload[4] == 0x0c) {
                mmt_int_worldofwarcraft_add_connection(ipacket, MMT_REAL_PROTOCOL);
                MMT_LOG(PROTO_WORLDOFWARCRAFT,
                        MMT_LOG_DEBUG, "World of Warcraft: connection detected\n");
                return;
            } else if (ipacket->session->data_packet_count < 3) {
                MMT_LOG(PROTO_WORLDOFWARCRAFT, MMT_LOG_DEBUG, "waiting for final packet\n");
                return;
            }
        }
        if (flow->l4.tcp.wow_stage == 0 && packet->tcp->dest == htons(1119)) {
            /* special log in port for battle.net/world of warcraft */

            if (packet->payload_packet_len >= 77 &&
                    get_u32(packet->payload, 0) == htonl(0x40000aed) && get_u32(packet->payload, 4) == htonl(0xea070aed)) {

                mmt_int_worldofwarcraft_add_connection(ipacket, MMT_REAL_PROTOCOL);
                MMT_LOG(PROTO_WORLDOFWARCRAFT,
                        MMT_LOG_DEBUG, "World of Warcraft: connection detected\n");
                return;
            }
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WORLDOFWARCRAFT);
}

int mmt_check_worldofwarcraft(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_worldofwarcraft(ipacket, index);
    }
    return 4;
}

void mmt_init_classify_me_worldofwarcraft() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_WORLDOFWARCRAFT);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_worldofwarcraft_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WORLDOFWARCRAFT, PROTO_WORLDOFWARCRAFT_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_worldofwarcraft();

        return register_protocol(protocol_struct, PROTO_WORLDOFWARCRAFT);
    } else {
        return 0;
    }
}


