#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_qq_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_QQ, protocol_type);
}


/*
 * a qq client packet looks like this:
 *
 * TCP packets starts with 16 bit length, then the normal packets follows
 *
 * 0 1 byte packet tag (usually 0x02)
 * 1 2 byte client tag (client version)
 * 3 2 byte command
 * 5 2 byte sequence number
 * 7 4 byte userid
 * 11 x bytes data
 * LAST 1 byte packet tail (usually 0x03)
 *
 * a qq server packet looks like this:
 *
 * TCP packets starts with 16 bit length, then the normal packets follows
 *
 * 0 1 byte packet tag (usually 0x02)
 * 1 2 byte source tag (client version, might also be a server id)
 * 3 2 byte command (usually reply to client request, so same command id)
 * 5 2 byte sequence number
 * LAST 1 byte packet tail (usually 0x03)
 *
 * NOTE: there are other qq versions which uses different packet types!
 */

/*
 * these are some currently known client ids (or server ids)
 * new ids might be added here if the traffic is really QQ
 */
static const uint16_t mmt_valid_qq_versions[] = {
    0x0100, 0x05a5, 0x062e, 0x06d5, 0x072e, 0x0801, 0x087d, 0x08d2, 0x0961,
    0x0a1d, 0x0b07, 0x0b2f, 0x0b35, 0x0b37, 0x0c0b, 0x0c0d, 0x0c21, 0x0c49,
    0x0d05, 0x0d51, 0x0d55, 0x0d61, 0x0e1b, 0x0e35, 0x0f15, 0x0f4b, 0x0f5f,
    0x1105, 0x111b, 0x111d, 0x1131, 0x113f, 0x115b, 0x1203, 0x1205, 0x120b,
    0x1251, 0x1412, 0x1441, 0x1501, 0x1549, 0x163a, 0x1801, 0x180d, 0x1c27,
    0x1e0d
};

/**
 * this functions checks whether the packet is a valid qq packet
 * it can handle tcp and udp packets
 */

static uint8_t mmt_is_valid_qq_packet(const struct mmt_tcpip_internal_packet_struct *packet) {
    uint8_t real_start = 0;
    uint16_t command;
    uint8_t ids, found = 0;
    uint16_t version_id;

    if (packet->payload_packet_len < 9)
        return 0;

    /* for tcp the length is prefixed */
    if (packet->tcp) {
        if (ntohs(get_u16(packet->payload, 0)) != packet->payload_packet_len) {
            return 0;
        }
        real_start = 2;
    }

    /* packet usually starts with 0x02 */
    if (packet->payload[real_start] != 0x02) {
        return 0;
    }

    /* packet usually ends with 0x03 */
    if (packet->payload[packet->payload_packet_len - 1] != 0x03) {
        return 0;
    }

    version_id = ntohs(get_u16(packet->payload, real_start + 1));

    if (version_id == 0) {
        return 0;
    }

    /* check for known version id */
    for (ids = 0; ids < sizeof (mmt_valid_qq_versions) / sizeof (mmt_valid_qq_versions[0]); ids++) {
        if (version_id == mmt_valid_qq_versions[ids]) {
            found = 1;
            break;
        }
    }

    if (!found)
        return 0;

    command = ntohs(get_u16(packet->payload, real_start + 3));

    /* these are some known commands, not all need to be checked
       since many are used with already established connections */

    switch (command) {
        case 0x0091: /* get server */
        case 0x00ba: /* login token */
        case 0x00dd: /* password verify */
        case 0x00e5:
        case 0x00a4:
        case 0x0030:
        case 0x001d:
        case 0x0001:
        case 0x0062:
        case 0x0002:
        case 0x0022:
        case 0x0029:
            break;
        default:
            return 0;
            break;
    }

    return 1;
}

/*
 * some file transfer packets look like this
 *
 * 0 1 byte packet tag (usually 0x04)
 * 1 2 byte client tag (client version)
 * 3 2 byte length (this is speculative)
 * LAST 1 byte packet tail (usually 0x03)
 *
 */
/**
 * this functions checks whether the packet is a valid qq file transfer packet
 * it can handle tcp and udp packets
 */

static uint8_t mmt_is_valid_qq_ft_packet(const struct mmt_tcpip_internal_packet_struct *packet)
{
    uint8_t ids, found = 0;
    uint16_t version_id;

    if (packet->payload_packet_len < 9)
        return 0;

    /* file transfer packets may start with 0x00 (control), 0x03 (data), 0x04 (agent) */

    if (packet->payload[0] != 0x04 && packet->payload[0] != 0x03 && packet->payload[0] != 0x00) {
        return 0;
    }

    version_id = ntohs(get_u16(packet->payload, 1));

    if (version_id == 0) {
        return 0;
    }

    /* check for known version id */
    for (ids = 0; ids < sizeof (mmt_valid_qq_versions) / sizeof (mmt_valid_qq_versions[0]); ids++) {
        if (version_id == mmt_valid_qq_versions[ids]) {
            found = 1;
            break;
        }
    }

    if (!found)
        return 0;

    if (packet->payload[0] == 0x04) {

        if (ntohs(get_u16(packet->payload, 3)) != packet->payload_packet_len) {
            return 0;
        }

        /* packet usually ends with 0x03 */
        if (packet->payload[packet->payload_packet_len - 1] != 0x03) {
            return 0;
        }
    } else if (packet->payload[0] == 0x03) {
        /* TODO currently not detected */
        return 0;
    } else if (packet->payload[0] == 0x00) {

        /* packet length check, there might be other lengths */
        if (packet->payload_packet_len != 84) {
            return 0;
        }

        /* packet usually ends with 0x0c ? */
        if (packet->payload[packet->payload_packet_len - 1] != 0x0c) {
            return 0;
        }
    }
    return 1;
}

static void mmt_search_qq_udp(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    static const uint16_t p8000_patt_02[12] = // maybe version numbers
    {0x1549, 0x1801, 0x180d, 0x0961, 0x01501, 0x0e35, 0x113f, 0x0b37, 0x1131, 0x163a, 0x1e0d};
    uint16_t no_of_patterns = 11, index = 0;


    MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "search qq udp.\n");


    if (flow->qq_stage <= 3) {
        if ((packet->payload_packet_len == 27 && ntohs(get_u16(packet->payload, 0)) == 0x0300
                && packet->payload[2] == 0x01)
                || (packet->payload_packet_len == 84 && ((ntohs(get_u16(packet->payload, 0)) == 0x000e
                && packet->payload[2] == 0x35)
                || (ntohs(get_u16(packet->payload, 0)) == 0x0015
                && packet->payload[2] == 0x01)
                || (ntohs(get_u16(packet->payload, 0)) == 0x000b
                && packet->payload[2] == 0x37)
                || (ntohs(get_u16(packet->payload, 0)) == 0x0015
                && packet->payload[2] == 0x49)))
                || (packet->payload_packet_len > 10
                && ((get_u16(packet->payload, 0) == htons(0x000b) && packet->payload[2] == 0x37)
                || (get_u32(packet->payload, 0) == htonl(0x04163a00)
                && packet->payload[packet->payload_packet_len - 1] == 0x03
                && packet->payload[4] == packet->payload_packet_len)))) {
            /*
               if (flow->qq_stage == 3 && flow->detected_protocol == IPOQUE_PROTOCOL_QQ) {
               if (flow->packet_direction_counter[0] > 0 && flow->packet_direction_counter[1] > 0) {
               flow->protocol_subtype = IPOQUE_PROTOCOL_QQ_SUBTYPE_AUDIO;
               return;
               } else if (flow->packet_counter < 10) {
               return;
               }
               } */
            flow->qq_stage++;
            if (flow->qq_stage == 3) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                        "found qq udp pattern 030001 or 000e35 four times.\n");
                mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            return;
        }
        if (packet->payload_packet_len > 2 && (packet->payload[0] == 0x02 || packet->payload[0] == 0x04)) {
            uint16_t pat = ntohs(get_u16(packet->payload, 1));
            for (index = 0; index < no_of_patterns; index++) {
                if (pat == p8000_patt_02[index] && packet->payload[packet->payload_packet_len - 1] == 0x03) {
                    flow->qq_stage++;
                    // maybe we can test here packet->payload[4] == packet->payload_packet_len
                    if (flow->qq_stage == 3) {
                        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                                "found qq udp pattern 02 ... 03 four times.\n");
                        /*
                           if (packet->payload[0] == 0x04) {
                           mmt_int_qq_add_connection( IPOQUE_REAL_PROTOCOL);
                           return;
                           } */
                        mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                    return;
                }
            }
        }
        if (packet->payload_packet_len == 84 && (packet->payload[0] == 0 || packet->payload[0] == 0x03)) {
            uint16_t pat = ntohs(get_u16(packet->payload, 1));
            for (index = 0; index < no_of_patterns; index++) {
                if (pat == p8000_patt_02[index]) {
                    flow->qq_stage++;
                    /*
                       if (flow->qq_stage == 3 && flow->packet_direction_counter[0] > 0 &&
                       flow->packet_direction_counter[1] > 0) {
                       IPQ_LOG(IPOQUE_PROTOCOL_QQ, IPQ_LOG_DEBUG, "found qq udp pattern four times.\n");
                       mmt_int_qq_add_connection( IPOQUE_REAL_PROTOCOL);
                       return;
                       } else */ if (flow->qq_stage == 3) {
                        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq udp pattern four times.\n");
                        mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                        return;
                    }
                    return;
                }
            }
        }
        if (packet->payload_packet_len > 2 && packet->payload[0] == 0x04
                && ((ntohs(get_u16(packet->payload, 1)) == 0x1549
                || ntohs(get_u16(packet->payload, 1)) == 0x1801 || ntohs(get_u16(packet->payload, 1)) == 0x0961)
                ||
                (packet->payload_packet_len > 16
                && (ntohs(get_u16(packet->payload, 1)) == 0x180d || ntohs(get_u16(packet->payload, 1)) == 0x096d)
                && ntohl(get_u32(packet->payload, 12)) == 0x28000000
                && ntohs(get_u16(packet->payload, 3)) == packet->payload_packet_len))
                && packet->payload[packet->payload_packet_len - 1] == 0x03) {
            flow->qq_stage++;
            if (flow->qq_stage == 3) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                        "found qq udp pattern 04 1159 ... 03 four times.\n");
                mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            return;
        }
        if (packet->payload_packet_len > 2 && (packet->payload[0] == 0x06 || packet->payload[0] == 0x02)
                && ntohs(get_u16(packet->payload, 1)) == 0x0100
                && (packet->payload[packet->payload_packet_len - 1] == 0x00
                || packet->payload[packet->payload_packet_len - 1] == 0x03)) {
            flow->qq_stage++;
            if (flow->qq_stage == 3) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                        "found qq udp pattern 02/06 0100 ... 03/00 four times.\n");
                mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            return;
        }

        if (packet->payload_packet_len > 2 && (packet->payload[0] == 0x02)
                && ntohs(get_u16(packet->payload, 1)) == 0x1131 && packet->payload[packet->payload_packet_len - 1] == 0x03) {
            flow->qq_stage++;
            if (flow->qq_stage == 3) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                        "found qq udp pattern 02 1131 ... 03 four times.\n");
                mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            return;
        }

        if (packet->payload_packet_len > 5 && get_u16(packet->payload, 0) == htons(0x0203) &&
                ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len &&
                get_u16(packet->payload, 4) == htons(0x0b0b)) {
            flow->qq_stage++;
            if (flow->qq_stage == 3) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                        "found qq udp pattern 0203[packet_length_0b0b] three times.\n");
                mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            return;
        }

        if (packet->udp->dest == htons(9000) || packet->udp->source == htons(9000)) {
            if (packet->payload_packet_len > 3
                    && ntohs(get_u16(packet->payload, 0)) == 0x0202
                    && ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len) {
                flow->qq_stage++;
                if (flow->qq_stage == 3) {
                    MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                            "found qq udp pattern 02 02 <length> four times.\n");
                    mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                    return;
                }
                return;
            }

        }
    }

    if (mmt_is_valid_qq_packet(packet)) {
        flow->qq_stage++;
        if (flow->qq_stage == 3) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over udp.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq packet stage %d\n", flow->qq_stage);
        return;
    }

    if (mmt_is_valid_qq_ft_packet(packet)) {
        flow->qq_stage++;
        if (flow->qq_stage == 3) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq ft over udp.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        return;
    }

    if (flow->qq_stage && ipacket->session->data_packet_count <= 5) {
        return;
    }

    MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "QQ excluded\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QQ);
}

static void mmt_search_qq_tcp(ipacket_t * ipacket)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint16_t i = 0;
    //  u16 a = 0;

    MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "search qq tcp.\n");

    if (packet->payload_packet_len == 39 && get_u32(packet->payload, 0) == htonl(0x27000000) &&
            get_u16(packet->payload, 4) == htons(0x0014) && get_u32(packet->payload, 11) != 0 &&
            get_u16(packet->payload, packet->payload_packet_len - 2) == htons(0x0000)) {
        if (flow->qq_stage == 4) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over tcp - maybe ft/audio/video.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        flow->qq_stage = 4;
        return;
    }

    if ((packet->payload_packet_len > 4 && ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len
            && get_u16(packet->payload, 2) == htons(0x0212) && packet->payload[4] == 0x0b)
            || (packet->payload_packet_len > 6 && packet->payload[0] == 0x02
            && packet->payload[packet->payload_packet_len - 1] == 0x03
            && ntohs(get_u16(packet->payload, 1)) == packet->payload_packet_len
            && (get_u16(packet->payload, 3) == htons(0x0605) || get_u16(packet->payload, 3) == htons(0x0608))
            && packet->payload[5] == 0x00)
            || (packet->payload_packet_len > 9 && get_u32(packet->payload, 0) == htonl(0x04154900)
            && get_l16(packet->payload, 4) == packet->payload_packet_len
            && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 9 && get_u32(packet->payload, 0) == htonl(0x040e3500)
            && get_l16(packet->payload, 4) == packet->payload_packet_len
            && packet->payload[9] == 0x33 && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 9 && get_u32(packet->payload, 0) == htonl(0x040e0215)
            && get_l16(packet->payload, 4) == packet->payload_packet_len
            && packet->payload[9] == 0x33 && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 6 && get_u32(packet->payload, 2) == htonl(0x020d5500)
            && ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len
            && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 6 && get_u16(packet->payload, 0) == htons(0x0418)
            && packet->payload[2] == 0x01
            && ntohs(get_u16(packet->payload, 3)) == packet->payload_packet_len
            && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 6 && get_u16(packet->payload, 0) == htons(0x0411)
            && packet->payload[2] == 0x31
            && ntohs(get_u16(packet->payload, 3)) == packet->payload_packet_len
            && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 6 && ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len
            && get_u16(packet->payload, 2) == htons(0x0211) && packet->payload[4] == 0x31
            && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 6 && ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len
            && get_u16(packet->payload, 2) == htons(0x0218) && packet->payload[4] == 0x01
            && packet->payload[packet->payload_packet_len - 1] == 0x03)
            || (packet->payload_packet_len > 10 && get_u32(packet->payload, 0) == htonl(0x04163a00)
            && packet->payload[packet->payload_packet_len - 1] == 0x03
            && packet->payload[4] == packet->payload_packet_len)
            ) {
        flow->qq_stage++;
        if (flow->qq_stage == 3) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over tcp.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        return;
    }

    if (mmt_is_valid_qq_packet(packet)) {
        flow->qq_stage++;
        if (flow->qq_stage == 3) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over tcp.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        return;
    }

    if (mmt_is_valid_qq_ft_packet(packet)) {
        flow->qq_stage++;
        if (flow->qq_stage == 3) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq ft over tcp.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        return;
    }

    if (packet->payload_packet_len == 2) {
        flow->l4.tcp.qq_nxt_len = ntohs(get_u16(packet->payload, 0));
        return;
    }
    if (packet->payload_packet_len > 5 && (((flow->l4.tcp.qq_nxt_len == packet->payload_packet_len + 2)
            && packet->payload[0] == 0x02
            && packet->payload[packet->payload_packet_len - 1] == 0x03
            && get_u16(packet->payload, 1) == htons(0x0f5f))
            || (ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len
            && packet->payload[2] == 0x02
            && packet->payload[packet->payload_packet_len - 1] == 0x03
            && get_u16(packet->payload, 3) == htons(0x0f5f)))) {
        flow->qq_stage++;
        if (flow->qq_stage == 3) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq udp pattern 02 ... 03 four times.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        return;

    }
    if (packet->payload_packet_len > 2 && packet->payload[0] == 0x04 && ((get_u16(packet->payload, 1) == htons(0x1549)
            || get_u16(packet->payload,
            1) == htons(0x1801)
            || get_u16(packet->payload,
            1) == htons(0x0961))
            || (packet->payload_packet_len > 16
            && (get_u16(packet->payload, 1) ==
            htons(0x180d)
            || get_u16(packet->payload,
            1) == htons(0x096d))
            && get_u32(packet->payload,
            12) == htonl(0x28000000)
            && ntohs(get_u16(packet->payload, 3)) ==
            packet->payload_packet_len))
            && packet->payload[packet->payload_packet_len - 1] == 0x03) {
        flow->qq_stage++;
        if (flow->qq_stage == 3) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG,
                    "found qq udp pattern 04 1159 ... 03 four times.\n");
            mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        return;
    }



    if (packet->payload_packet_len > 100
            && ((mmt_mem_cmp(packet->payload, "GET", 3) == 0) || (mmt_mem_cmp(packet->payload, "POST", 4) == 0))) {
        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found GET or POST.\n");
        if (memcmp(packet->payload, "GET /qqfile/qq", 14) == 0) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over tcp GET /qqfile/qq.\n");
            mmt_int_qq_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
        mmt_parse_packet_line_info(ipacket);

        if (packet->user_agent_line.ptr != NULL
                && (packet->user_agent_line.len > 7 && memcmp(packet->user_agent_line.ptr, "QQClient", 8) == 0)) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over tcp GET...QQClient\n");
            mmt_int_qq_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
            return;
        }
        for (i = 0; i < packet->parsed_lines; i++) {
            if (packet->line[i].len > 3 && memcmp(packet->line[i].ptr, "QQ: ", 4) == 0) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over tcp GET...QQ: \n");
                mmt_int_qq_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
        if (packet->host_line.ptr != NULL) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "host line ptr\n");
            if (packet->host_line.len > 11 && memcmp(&packet->host_line.ptr[0], "www.qq.co.za", 12) == 0) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq over tcp Host: www.qq.co.za\n");
                mmt_int_qq_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
    }
    if (flow->qq_stage == 0 && packet->payload_packet_len == 82
            && get_u32(packet->payload, 0) == htonl(0x0000004e) && get_u32(packet->payload, 4) == htonl(0x01010000)) {
        for (i = 8; i < 82; i++) {
            if (packet->payload[i] != 0x00) {
                break;
            }
            if (i == 81) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq Mail.\n");
                mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
    }
    if (flow->qq_stage == 0 && packet->payload_packet_len == 182 && get_u32(packet->payload, 0) == htonl(0x000000b2)
            && get_u32(packet->payload, 4) == htonl(0x01020000)
            && get_u32(packet->payload, 8) == htonl(0x04015151) && get_u32(packet->payload, 12) == htonl(0x4d61696c)) {
        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq Mail.\n");
        mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
        return;
    }
    if (packet->payload_packet_len == 204 && flow->qq_stage == 0 && get_u32(packet->payload, 200) == htonl(0xfbffffff)) {
        for (i = 0; i < 200; i++) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "i = %u\n", i);
            if (packet->payload[i] != 0) {
                break;
            }
            if (i == 199) {
                MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found qq chat or file transfer\n");
                mmt_int_qq_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
    }
#ifdef PROTO_HTTP
    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP) != 0) {
#endif							/* IPOQUE_PROTOCOL_HTTP */

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QQ);
        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "QQ tcp excluded; len %u\n",
                packet->payload_packet_len);

#ifdef PROTO_HTTP
    }
#endif							/* IPOQUE_PROTOCOL_HTTP */

}

void mmt_classify_me_qq(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    if (packet->udp != NULL && flow->detected_protocol_stack[0] != PROTO_QQ)
        mmt_search_qq_udp(ipacket);

    if (packet->tcp != NULL && flow->detected_protocol_stack[0] != PROTO_QQ)
        mmt_search_qq_tcp(ipacket);
}

int mmt_check_qq_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->detected_protocol_stack[0] != PROTO_QQ) {
            mmt_search_qq_tcp(ipacket);
        }

    }
    return 4;
}

int mmt_check_qq_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if (flow->detected_protocol_stack[0] != PROTO_QQ) {
            mmt_search_qq_udp(ipacket);
        }

    }
    return 4;
}

void mmt_init_classify_me_qq() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_QQ);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_QQ);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_qq_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_QQ, PROTO_QQ_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_qq();

        return register_protocol(protocol_struct, PROTO_QQ);
    } else {
        return 0;
    }
}


