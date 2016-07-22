#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define POP_BIT_AUTH		0x0001
#define POP_BIT_APOP		0x0002
#define POP_BIT_USER		0x0004
#define POP_BIT_PASS		0x0008
#define POP_BIT_CAPA		0x0010
#define POP_BIT_LIST		0x0020
#define POP_BIT_STAT		0x0040
#define POP_BIT_UIDL		0x0080
#define POP_BIT_RETR		0x0100
#define POP_BIT_DELE		0x0200
#define POP_BIT_STLS		0x0400

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mail_pop_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_POP, MMT_REAL_PROTOCOL);
}

static int mmt_int_mail_pop_check_for_client_commands(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    //  struct mmt_id_struct         *src=mmt_struct->src;
    //  struct mmt_id_struct         *dst=mmt_struct->dst;

    if (packet->payload_packet_len > 4) {
        if ((packet->payload[0] == 'A' || packet->payload[0] == 'a')
                && (packet->payload[1] == 'U' || packet->payload[1] == 'u')
                && (packet->payload[2] == 'T' || packet->payload[2] == 't')
                && (packet->payload[3] == 'H' || packet->payload[3] == 'h')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_AUTH;
            return 1;
        } else if ((packet->payload[0] == 'A' || packet->payload[0] == 'a')
                && (packet->payload[1] == 'P' || packet->payload[1] == 'p')
                && (packet->payload[2] == 'O' || packet->payload[2] == 'o')
                && (packet->payload[3] == 'P' || packet->payload[3] == 'p')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_APOP;
            return 1;
        } else if ((packet->payload[0] == 'U' || packet->payload[0] == 'u')
                && (packet->payload[1] == 'S' || packet->payload[1] == 's')
                && (packet->payload[2] == 'E' || packet->payload[2] == 'e')
                && (packet->payload[3] == 'R' || packet->payload[3] == 'r')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_USER;
            return 1;
        } else if ((packet->payload[0] == 'P' || packet->payload[0] == 'p')
                && (packet->payload[1] == 'A' || packet->payload[1] == 'a')
                && (packet->payload[2] == 'S' || packet->payload[2] == 's')
                && (packet->payload[3] == 'S' || packet->payload[3] == 's')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_PASS;
            return 1;
        } else if ((packet->payload[0] == 'C' || packet->payload[0] == 'c')
                && (packet->payload[1] == 'A' || packet->payload[1] == 'a')
                && (packet->payload[2] == 'P' || packet->payload[2] == 'p')
                && (packet->payload[3] == 'A' || packet->payload[3] == 'a')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_CAPA;
            return 1;
        } else if ((packet->payload[0] == 'L' || packet->payload[0] == 'l')
                && (packet->payload[1] == 'I' || packet->payload[1] == 'i')
                && (packet->payload[2] == 'S' || packet->payload[2] == 's')
                && (packet->payload[3] == 'T' || packet->payload[3] == 't')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_LIST;
            return 1;
        } else if ((packet->payload[0] == 'S' || packet->payload[0] == 's')
                && (packet->payload[1] == 'T' || packet->payload[1] == 't')
                && (packet->payload[2] == 'A' || packet->payload[2] == 'a')
                && (packet->payload[3] == 'T' || packet->payload[3] == 't')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_STAT;
            return 1;
        } else if ((packet->payload[0] == 'U' || packet->payload[0] == 'u')
                && (packet->payload[1] == 'I' || packet->payload[1] == 'i')
                && (packet->payload[2] == 'D' || packet->payload[2] == 'd')
                && (packet->payload[3] == 'L' || packet->payload[3] == 'l')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_UIDL;
            return 1;
        } else if ((packet->payload[0] == 'R' || packet->payload[0] == 'r')
                && (packet->payload[1] == 'E' || packet->payload[1] == 'e')
                && (packet->payload[2] == 'T' || packet->payload[2] == 't')
                && (packet->payload[3] == 'R' || packet->payload[3] == 'r')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_RETR;
            return 1;
        } else if ((packet->payload[0] == 'D' || packet->payload[0] == 'd')
                && (packet->payload[1] == 'E' || packet->payload[1] == 'e')
                && (packet->payload[2] == 'L' || packet->payload[2] == 'l')
                && (packet->payload[3] == 'E' || packet->payload[3] == 'e')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_DELE;
            return 1;
        } else if ((packet->payload[0] == 'S' || packet->payload[0] == 's')
                && (packet->payload[1] == 'T' || packet->payload[1] == 't')
                && (packet->payload[2] == 'L' || packet->payload[2] == 'l')
                && (packet->payload[3] == 'S' || packet->payload[3] == 's')) {
            flow->l4.tcp.pop_command_bitmask |= POP_BIT_STLS;
            return 1;
        }
    }
    return 0;
}

void mmt_classify_me_pop(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    //  struct mmt_id_struct         *src=mmt_struct->src;
    //  struct mmt_id_struct         *dst=mmt_struct->dst;

    uint8_t a = 0;
    uint8_t bit_count = 0;

    /* unused
    uint16_t sport = ntohs(packet->tcp->source);
    uint16_t dport = ntohs(packet->tcp->dest);
    */

    MMT_LOG(PROTO_POP, MMT_LOG_DEBUG, "search mail_pop\n");



    if ((packet->payload_packet_len > 3
            && (packet->payload[0] == '+' && (packet->payload[1] == 'O' || packet->payload[1] == 'o')
            && (packet->payload[2] == 'K' || packet->payload[2] == 'k')))
            || (packet->payload_packet_len > 4
            && (packet->payload[0] == '-' && (packet->payload[1] == 'E' || packet->payload[1] == 'e')
            && (packet->payload[2] == 'R' || packet->payload[2] == 'r')
            && (packet->payload[3] == 'R' || packet->payload[3] == 'r')))) {
        // +OK or -ERR seen
        flow->l4.tcp.mail_pop_stage += 1;
    } else if (!mmt_int_mail_pop_check_for_client_commands(ipacket)) {
        goto maybe_split_pop;
    }

    if (packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {

        // count the bits set in the bitmask
        if (flow->l4.tcp.pop_command_bitmask != 0) {
            for (a = 0; a < 16; a++) {
                bit_count += (flow->l4.tcp.pop_command_bitmask >> a) & 0x01;
            }
        }

        MMT_LOG(PROTO_POP, MMT_LOG_DEBUG,
                "mail_pop +OK/-ERR responses: %u, unique commands: %u\n", flow->l4.tcp.mail_pop_stage, bit_count);

        if ((bit_count + flow->l4.tcp.mail_pop_stage) >= 3) {
            if (flow->l4.tcp.mail_pop_stage > 0) {
                MMT_LOG(PROTO_POP, MMT_LOG_DEBUG, "mail_pop identified\n");
                mmt_int_mail_pop_add_connection(ipacket);
                return;
            } else {
                return;
            }
        } else {
            return;
        }

    } else {
        // first part of a split packet
        MMT_LOG(PROTO_POP, MMT_LOG_DEBUG,
                "mail_pop command without line ending -> skip\n");
        return;
    }


maybe_split_pop:

    if (((packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
            || flow->l4.tcp.pop_command_bitmask != 0 || flow->l4.tcp.mail_pop_stage != 0) && ipacket->session->data_packet_count < 12) {
        // maybe part of a split pop packet
        MMT_LOG(PROTO_POP, MMT_LOG_DEBUG,
                "maybe part of split mail_pop packet -> skip\n");
        return 4;
    }

    MMT_LOG(PROTO_POP, MMT_LOG_DEBUG, "exclude mail_pop\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_POP);
}

int mmt_check_pop(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint8_t a = 0;
        uint8_t bit_count = 0;

        /* unused
        uint16_t sport = ntohs(packet->tcp->source);
        uunt16_t dport = ntohs(packet->tcp->dest);
        */

        MMT_LOG(PROTO_POP, MMT_LOG_DEBUG, "search mail_pop\n");

        if ((packet->payload_packet_len > 3
                && (packet->payload[0] == '+' && (packet->payload[1] == 'O' || packet->payload[1] == 'o')
                && (packet->payload[2] == 'K' || packet->payload[2] == 'k')))
                || (packet->payload_packet_len > 4
                && (packet->payload[0] == '-' && (packet->payload[1] == 'E' || packet->payload[1] == 'e')
                && (packet->payload[2] == 'R' || packet->payload[2] == 'r')
                && (packet->payload[3] == 'R' || packet->payload[3] == 'r')))) {
            // +OK or -ERR seen
            flow->l4.tcp.mail_pop_stage += 1;
        } else if (!mmt_int_mail_pop_check_for_client_commands(ipacket)) {
            goto maybe_split_pop;
        }

        if (packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {

            // count the bits set in the bitmask
            if (flow->l4.tcp.pop_command_bitmask != 0) {
                for (a = 0; a < 16; a++) {
                    bit_count += (flow->l4.tcp.pop_command_bitmask >> a) & 0x01;
                }
            }

            MMT_LOG(PROTO_POP, MMT_LOG_DEBUG,
                    "mail_pop +OK/-ERR responses: %u, unique commands: %u\n", flow->l4.tcp.mail_pop_stage, bit_count);

            if ((bit_count + flow->l4.tcp.mail_pop_stage) >= 3) {
                if (flow->l4.tcp.mail_pop_stage > 0) {
                    MMT_LOG(PROTO_POP, MMT_LOG_DEBUG, "mail_pop identified\n");
                    mmt_int_mail_pop_add_connection(ipacket);
                    return 1;
                } else {
                    return 1;
                }
            } else {
                return 1;
            }

        } else {
            // first part of a split packet
            MMT_LOG(PROTO_POP, MMT_LOG_DEBUG,
                    "mail_pop command without line ending -> skip\n");
            return 1;
        }


maybe_split_pop:

        if (((packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
                || flow->l4.tcp.pop_command_bitmask != 0 || flow->l4.tcp.mail_pop_stage != 0) && ipacket->session->data_packet_count < 12) {
            // maybe part of a split pop packet
            MMT_LOG(PROTO_POP, MMT_LOG_DEBUG,
                    "maybe part of split mail_pop packet -> skip\n");
            return 4;
        }

        MMT_LOG(PROTO_POP, MMT_LOG_DEBUG, "exclude mail_pop\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_POP);
    }
    return 0;
}

void mmt_init_classify_me_pop() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_POP);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_pop_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_POP, PROTO_POP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_pop();

        return register_protocol(protocol_struct, PROTO_POP);
    } else {
        return 0;
    }
}


