#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_imesh_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_IMESH, protocol_type);
}

void mmt_classify_me_imesh(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->udp != NULL) {

        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "UDP FOUND\n");

        // this is the login packet
        if (packet->payload_packet_len == 28 && (get_u32(packet->payload, 0)) == htonl(0x02000000) &&
                get_u32(packet->payload, 24) == 0 &&
                (packet->udp->dest == htons(1864) || packet->udp->source == htons(1864))) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh Login detected\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 36) {
            if (get_u32(packet->payload, 0) == htonl(0x02000000) && packet->payload[4] != 0 &&
                    packet->payload[5] == 0 && get_u16(packet->payload, 6) == htons(0x0083) &&
                    get_u32(packet->payload, 24) == htonl(0x40000000) &&
                    (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
                    packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5]
                    || packet->payload[packet->payload_packet_len - 1] ==
                    packet->payload[packet->payload_packet_len - 5] - 1)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            if (get_u16(packet->payload, 0) == htons(0x0200) && get_u16(packet->payload, 2) != 0 &&
                    get_u32(packet->payload, 4) == htonl(0x02000083) && get_u32(packet->payload, 24) == htonl(0x40000000) &&
                    (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
                    packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5]
                    || packet->payload[packet->payload_packet_len - 1] ==
                    packet->payload[packet->payload_packet_len - 5] - 1)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
        if (packet->payload_packet_len == 24 && get_u16(packet->payload, 0) == htons(0x0200)
                && get_u16(packet->payload, 2) != 0 && get_u32(packet->payload, 4) == htonl(0x03000084) &&
                (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
                packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5] ||
                packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] - 1)) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 32 && get_u32(packet->payload, 0) == htonl(0x02000000) &&
                get_u16(packet->payload, 21) == 0 && get_u16(packet->payload, 26) == htons(0x0100)) {
            if (get_u32(packet->payload, 4) == htonl(0x00000081) && packet->payload[11] == packet->payload[15] &&
                    get_l16(packet->payload, 24) == htons(packet->udp->source)) {
                /* packet->payload[28] = source address */
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
            if (get_u32(packet->payload, 4) == htonl(0x01000082)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return;
            }
        }
        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh UDP packetlen: %d\n",
                packet->payload_packet_len);

    }

    if (packet->tcp != NULL) {

        if (packet->payload_packet_len == 64 && get_u32(packet->payload, 0) == htonl(0x40000000) &&
                get_u32(packet->payload, 4) == 0 && get_u32(packet->payload, 8) == htonl(0x0000fcff) &&
                get_u32(packet->payload, 12) == htonl(0x04800100) && get_u32(packet->payload, 45) == htonl(0xff020000) &&
                get_u16(packet->payload, 49) == htons(0x001a)) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 95 && get_u32(packet->payload, 0) == htonl(0x5f000000) &&
                get_u16(packet->payload, 4) == 0 && get_u16(packet->payload, 7) == htons(0x0004) &&
                get_u32(packet->payload, 20) == 0 && get_u32(packet->payload, 28) == htonl(0xc8000400) &&
                packet->payload[9] == 0x80 && get_u32(packet->payload, 10) == get_u32(packet->payload, 24)) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
        if (packet->payload_packet_len == 28 && get_u32(packet->payload, 0) == htonl(0x1c000000) &&
                get_u16(packet->payload, 10) == htons(0xfcff) && get_u32(packet->payload, 12) == htonl(0x07801800) &&
                (get_u16(packet->payload, packet->payload_packet_len - 2) == htons(0x1900) ||
                get_u16(packet->payload, packet->payload_packet_len - 2) == htons(0x1a00))) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }

        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "TCP FOUND :: Payload %u\n",
                packet->payload_packet_len);

        if (packet->actual_payload_len == 0) {
            return;
        }
        if ((packet->actual_payload_len == 8 || packet->payload_packet_len == 10) /* PATTERN:: 04 00 00 00 00 00 00 00 [00 00] */
                && get_u32(packet->payload, 0) == htonl(0x04000000)
                && get_u32(packet->payload, 4) == 0) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: ?? ?? 04|00 00 64|00 00 */
                && (packet->payload[2] == 0x04 || packet->payload[2] == 0x00)
                && packet->payload[3] == 0x00 && (packet->payload[4] == 0x00 || packet->payload[4] == 0x64)
                && packet->payload[5] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 2 && packet->payload[0] == 0x06 && packet->payload[1] == 0x00) {
            flow->l4.tcp.imesh_stage++;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: 06 00 04|00 00 01|00 00 01|00 00 ?? 00 */
                && packet->payload[0] == 0x06
                && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x00)
                && packet->payload[3] == 0x00 && (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)
                && packet->payload[5] == 0x00 && (packet->payload[6] == 0x01 || packet->payload[6] == 0x00)
                && packet->payload[7] == 0x00 && packet->payload[9] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 24 && packet->payload[0] == 0x06 // PATTERN :: 06 00 12 00 00 00 34 00 00
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x12
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00
                && packet->payload[6] == 0x34 && packet->payload[7] == 0x00 && packet->payload[8] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 8 /* PATTERN:: 06|00 00 02 00 00 00 33 00 */
                && (packet->payload[0] == 0x06 || packet->payload[0] == 0x00)
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x02
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && packet->payload[6] == 0x33 && packet->payload[7] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->payload_packet_len == 6 /* PATTERN:: 02 00 00 00 33 00 */
                && packet->payload[0] == 0x02
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x00
                && packet->payload[3] == 0x00 && packet->payload[4] == 0x33 && packet->payload[5] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 12 && packet->payload[0] == 0x06 // PATTERN : 06 00 06 00 00 00 64 00
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x06
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && packet->payload[6] == 0x64 && packet->payload[7] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: 06 00 04|01 00 00 00 01|00 00 ?? 00 */
                && packet->payload[0] == 0x06
                && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x01)
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && (packet->payload[6] == 0x01 || packet->payload[6] == 0x00)
                && packet->payload[7] == 0x00
                /* && packet->payload[8]==0x00 */
                && packet->payload[9] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if ((packet->actual_payload_len == 64 || packet->actual_payload_len == 52 /* PATTERN:: [len] 00 00 00 00 */
                || packet->actual_payload_len == 95)
                && get_u16(packet->payload, 0) == (packet->actual_payload_len)
                && packet->payload[1] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[3] == 0x00 && packet->payload[4] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 6 && packet->payload[0] == 0x06 // PATTERN : 06 00 04|6c 00|01 00 00
                && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x6c)
                && (packet->payload[3] == 0x00 || packet->payload[3] == 0x01)
                && packet->payload[4] == 0x00 && packet->payload[5] == 0x00) {

            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 6 /* PATTERN:: [len] ?? ee 00 00 00 */
                && get_u16(packet->payload, 0) == (packet->actual_payload_len)
                && packet->payload[2] == 0xee
                && packet->payload[3] == 0x00 && packet->payload[4] == 0x00 && packet->payload[5] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: 06 00 00 00 00 00 00 00 */
                && packet->payload[0] == 0x06
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x00
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && packet->payload[6] == 0x00 && packet->payload[7] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        }


        /* http login */
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("POST /registration") &&
                memcmp(packet->payload, "POST /registration", MMT_STATICSTRING_LEN("POST /registration")) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->parsed_lines > 6 &&
                    packet->host_line.ptr != NULL &&
                    packet->host_line.len == MMT_STATICSTRING_LEN("login.bearshare.com") &&
                    packet->line[1].ptr != NULL &&
                    packet->line[1].len == MMT_STATICSTRING_LEN("Authorization: Basic Og==") &&
                    packet->line[4].ptr != NULL &&
                    packet->line[4].len == MMT_STATICSTRING_LEN("Accept-Encoding: identity") &&
                    memcmp(packet->line[1].ptr, "Authorization: Basic Og==",
                    MMT_STATICSTRING_LEN("Authorization: Basic Og==")) == 0 &&
                    memcmp(packet->host_line.ptr, "login.bearshare.com",
                    MMT_STATICSTRING_LEN("login.bearshare.com")) == 0 &&
                    memcmp(packet->line[4].ptr, "Accept-Encoding: identity",
                    MMT_STATICSTRING_LEN("Accept-Encoding: identity") == 0)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh Login detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return;
            }
        }
        /*give one packet tolerance for detection */
        if (flow->l4.tcp.imesh_stage >= 4) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return;
        }
    }

    if ((ipacket->session->data_packet_count < 5) || packet->actual_payload_len == 0) {
        return;
    }
    //imesh_not_found_end:
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IMESH);
    MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh excluded at stage %d\n",
            packet->tcp != NULL ? flow->l4.tcp.imesh_stage : 0);

}

int mmt_check_imesh_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct * flow = packet->flow;

        if (packet->payload_packet_len == 64 && get_u32(packet->payload, 0) == htonl(0x40000000) &&
                get_u32(packet->payload, 4) == 0 && get_u32(packet->payload, 8) == htonl(0x0000fcff) &&
                get_u32(packet->payload, 12) == htonl(0x04800100) && get_u32(packet->payload, 45) == htonl(0xff020000) &&
                get_u16(packet->payload, 49) == htons(0x001a)) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 95 && get_u32(packet->payload, 0) == htonl(0x5f000000) &&
                get_u16(packet->payload, 4) == 0 && get_u16(packet->payload, 7) == htons(0x0004) &&
                get_u32(packet->payload, 20) == 0 && get_u32(packet->payload, 28) == htonl(0xc8000400) &&
                packet->payload[9] == 0x80 && get_u32(packet->payload, 10) == get_u32(packet->payload, 24)) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 28 && get_u32(packet->payload, 0) == htonl(0x1c000000) &&
                get_u16(packet->payload, 10) == htons(0xfcff) && get_u32(packet->payload, 12) == htonl(0x07801800) &&
                (get_u16(packet->payload, packet->payload_packet_len - 2) == htons(0x1900) ||
                get_u16(packet->payload, packet->payload_packet_len - 2) == htons(0x1a00))) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "TCP FOUND :: Payload %u\n",
                packet->payload_packet_len);

        if (packet->actual_payload_len == 0) {
            return 4;
        }
        if ((packet->actual_payload_len == 8 || packet->payload_packet_len == 10) /* PATTERN:: 04 00 00 00 00 00 00 00 [00 00] */
                && get_u32(packet->payload, 0) == htonl(0x04000000)
                && get_u32(packet->payload, 4) == 0) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: ?? ?? 04|00 00 64|00 00 */
                && (packet->payload[2] == 0x04 || packet->payload[2] == 0x00)
                && packet->payload[3] == 0x00 && (packet->payload[4] == 0x00 || packet->payload[4] == 0x64)
                && packet->payload[5] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 2 && packet->payload[0] == 0x06 && packet->payload[1] == 0x00) {
            flow->l4.tcp.imesh_stage++;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: 06 00 04|00 00 01|00 00 01|00 00 ?? 00 */
                && packet->payload[0] == 0x06
                && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x00)
                && packet->payload[3] == 0x00 && (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)
                && packet->payload[5] == 0x00 && (packet->payload[6] == 0x01 || packet->payload[6] == 0x00)
                && packet->payload[7] == 0x00 && packet->payload[9] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 24 && packet->payload[0] == 0x06 // PATTERN :: 06 00 12 00 00 00 34 00 00
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x12
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00
                && packet->payload[6] == 0x34 && packet->payload[7] == 0x00 && packet->payload[8] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 8 /* PATTERN:: 06|00 00 02 00 00 00 33 00 */
                && (packet->payload[0] == 0x06 || packet->payload[0] == 0x00)
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x02
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && packet->payload[6] == 0x33 && packet->payload[7] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->payload_packet_len == 6 /* PATTERN:: 02 00 00 00 33 00 */
                && packet->payload[0] == 0x02
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x00
                && packet->payload[3] == 0x00 && packet->payload[4] == 0x33 && packet->payload[5] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 12 && packet->payload[0] == 0x06 // PATTERN : 06 00 06 00 00 00 64 00
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x06
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && packet->payload[6] == 0x64 && packet->payload[7] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: 06 00 04|01 00 00 00 01|00 00 ?? 00 */
                && packet->payload[0] == 0x06
                && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x01)
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && (packet->payload[6] == 0x01 || packet->payload[6] == 0x00)
                && packet->payload[7] == 0x00
                /* && packet->payload[8]==0x00 */
                && packet->payload[9] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if ((packet->actual_payload_len == 64 || packet->actual_payload_len == 52 /* PATTERN:: [len] 00 00 00 00 */
                || packet->actual_payload_len == 95)
                && get_u16(packet->payload, 0) == (packet->actual_payload_len)
                && packet->payload[1] == 0x00 && packet->payload[2] == 0x00
                && packet->payload[3] == 0x00 && packet->payload[4] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 6 && packet->payload[0] == 0x06 // PATTERN : 06 00 04|6c 00|01 00 00
                && packet->payload[1] == 0x00 && (packet->payload[2] == 0x04 || packet->payload[2] == 0x6c)
                && (packet->payload[3] == 0x00 || packet->payload[3] == 0x01)
                && packet->payload[4] == 0x00 && packet->payload[5] == 0x00) {

            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 6 /* PATTERN:: [len] ?? ee 00 00 00 */
                && get_u16(packet->payload, 0) == (packet->actual_payload_len)
                && packet->payload[2] == 0xee
                && packet->payload[3] == 0x00 && packet->payload[4] == 0x00 && packet->payload[5] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        } else if (packet->actual_payload_len == 10 /* PATTERN:: 06 00 00 00 00 00 00 00 */
                && packet->payload[0] == 0x06
                && packet->payload[1] == 0x00
                && packet->payload[2] == 0x00
                && packet->payload[3] == 0x00
                && packet->payload[4] == 0x00
                && packet->payload[5] == 0x00 && packet->payload[6] == 0x00 && packet->payload[7] == 0x00) {
            flow->l4.tcp.imesh_stage += 2;
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG,
                    "IMESH FOUND :: Payload %u\n", packet->actual_payload_len);
        }


        /* http login */
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("POST /registration") &&
                memcmp(packet->payload, "POST /registration", MMT_STATICSTRING_LEN("POST /registration")) == 0) {
            mmt_parse_packet_line_info(ipacket);
            if (packet->parsed_lines > 6 &&
                    packet->host_line.ptr != NULL &&
                    packet->host_line.len == MMT_STATICSTRING_LEN("login.bearshare.com") &&
                    packet->line[1].ptr != NULL &&
                    packet->line[1].len == MMT_STATICSTRING_LEN("Authorization: Basic Og==") &&
                    packet->line[4].ptr != NULL &&
                    packet->line[4].len == MMT_STATICSTRING_LEN("Accept-Encoding: identity") &&
                    memcmp(packet->line[1].ptr, "Authorization: Basic Og==",
                    MMT_STATICSTRING_LEN("Authorization: Basic Og==")) == 0 &&
                    memcmp(packet->host_line.ptr, "login.bearshare.com",
                    MMT_STATICSTRING_LEN("login.bearshare.com")) == 0 &&
                    memcmp(packet->line[4].ptr, "Accept-Encoding: identity",
                    MMT_STATICSTRING_LEN("Accept-Encoding: identity") == 0)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh Login detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);
                return 1;
            }
        }
        /*give one packet tolerance for detection */
        if (flow->l4.tcp.imesh_stage >= 4) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "found imesh.\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }

        if ((ipacket->session->data_packet_count < 5) || packet->actual_payload_len == 0) {
            return 4;
        }
        //imesh_not_found_end:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IMESH);
        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh excluded at stage %d\n",
                packet->tcp != NULL ? flow->l4.tcp.imesh_stage : 0);
        // XXX return 0 here ?
    }
    return 0;
}

int mmt_check_imesh_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "UDP FOUND\n");

        // this is the login packet
        if (packet->payload_packet_len == 28 && (get_u32(packet->payload, 0)) == htonl(0x02000000) &&
                get_u32(packet->payload, 24) == 0 &&
                (packet->udp->dest == htons(1864) || packet->udp->source == htons(1864))) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh Login detected\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 36) {
            if (get_u32(packet->payload, 0) == htonl(0x02000000) && packet->payload[4] != 0 &&
                    packet->payload[5] == 0 && get_u16(packet->payload, 6) == htons(0x0083) &&
                    get_u32(packet->payload, 24) == htonl(0x40000000) &&
                    (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
                    packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5]
                    || packet->payload[packet->payload_packet_len - 1] ==
                    packet->payload[packet->payload_packet_len - 5] - 1)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (get_u16(packet->payload, 0) == htons(0x0200) && get_u16(packet->payload, 2) != 0 &&
                    get_u32(packet->payload, 4) == htonl(0x02000083) && get_u32(packet->payload, 24) == htonl(0x40000000) &&
                    (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
                    packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5]
                    || packet->payload[packet->payload_packet_len - 1] ==
                    packet->payload[packet->payload_packet_len - 5] - 1)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
        if (packet->payload_packet_len == 24 && get_u16(packet->payload, 0) == htons(0x0200)
                && get_u16(packet->payload, 2) != 0 && get_u32(packet->payload, 4) == htonl(0x03000084) &&
                (packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] ||
                packet->payload[packet->payload_packet_len - 1] - 1 == packet->payload[packet->payload_packet_len - 5] ||
                packet->payload[packet->payload_packet_len - 1] == packet->payload[packet->payload_packet_len - 5] - 1)) {
            MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
            mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (packet->payload_packet_len == 32 && get_u32(packet->payload, 0) == htonl(0x02000000) &&
                get_u16(packet->payload, 21) == 0 && get_u16(packet->payload, 26) == htons(0x0100)) {
            if (get_u32(packet->payload, 4) == htonl(0x00000081) && packet->payload[11] == packet->payload[15] &&
                    get_l16(packet->payload, 24) == htons(packet->udp->source)) {
                /* packet->payload[28] = source address */
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (get_u32(packet->payload, 4) == htonl(0x01000082)) {
                MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh detected\n");
                mmt_int_imesh_add_connection(ipacket, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh UDP packetlen: %d\n",
                packet->payload_packet_len);

        if ((ipacket->session->data_packet_count < 5) || packet->actual_payload_len == 0) {
            //SKIP very short packets
            return 4;
        }
        //imesh_not_found_end:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IMESH);
        MMT_LOG(PROTO_IMESH, MMT_LOG_DEBUG, "iMesh excluded at stage %d\n",
                packet->tcp != NULL ? flow->l4.tcp.imesh_stage : 0);
    }
    return 0;
}

void mmt_init_classify_me_imesh() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SSL);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_IMESH);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_imesh_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IMESH, PROTO_IMESH_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_imesh();
        
        return register_protocol(protocol_struct, PROTO_IMESH);
    } else {
        return 0;
    }
}


