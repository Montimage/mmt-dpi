#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define SMTP_BIT_220		0x01
#define SMTP_BIT_250		0x02
#define SMTP_BIT_235		0x04
#define SMTP_BIT_334		0x08
#define SMTP_BIT_354		0x10
#define SMTP_BIT_HELO_EHLO	0x20
#define SMTP_BIT_MAIL		0x40
#define SMTP_BIT_RCPT		0x80
#define SMTP_BIT_AUTH		0x100
#define SMTP_BIT_STARTTLS	0x200
#define SMTP_BIT_DATA		0x400
#define SMTP_BIT_NOOP		0x800
#define SMTP_BIT_RSET		0x1000
#define SMTP_BIT_TlRM		0x2000

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mail_smtp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SMTP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_smtp(ipacket_t * ipacket, unsigned index) {
    

  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    MMT_LOG(PROTO_SMTP, MMT_LOG_DEBUG, "search mail_smtp.\n");


    if (packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {

        uint8_t a;
        uint8_t bit_count = 0;

        MMT_PARSE_PACKET_LINE_INFO(ipacket, packet);
        for (a = 0; a < packet->parsed_lines; a++) {

            // expected server responses
            if (packet->line[a].len >= 3) {
                if (mmt_memcmp(packet->line[a].ptr, "220", 3) == 0) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_220;
                } else if (mmt_memcmp(packet->line[a].ptr, "250", 3) == 0) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_250;
                } else if (mmt_memcmp(packet->line[a].ptr, "235", 3) == 0) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_235;
                } else if (mmt_memcmp(packet->line[a].ptr, "334", 3) == 0) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_334;
                } else if (mmt_memcmp(packet->line[a].ptr, "354", 3) == 0) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_354;
                }
            }
            // expected client requests
            if (packet->line[a].len >= 5) {
                if ((((packet->line[a].ptr[0] == 'H' || packet->line[a].ptr[0] == 'h')
                        && (packet->line[a].ptr[1] == 'E' || packet->line[a].ptr[1] == 'e'))
                        || ((packet->line[a].ptr[0] == 'E' || packet->line[a].ptr[0] == 'e')
                        && (packet->line[a].ptr[1] == 'H' || packet->line[a].ptr[1] == 'h')))
                        && (packet->line[a].ptr[2] == 'L' || packet->line[a].ptr[2] == 'l')
                        && (packet->line[a].ptr[3] == 'O' || packet->line[a].ptr[3] == 'o')
                        && packet->line[a].ptr[4] == ' ') {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_HELO_EHLO;
                } else if ((packet->line[a].ptr[0] == 'M' || packet->line[a].ptr[0] == 'm')
                        && (packet->line[a].ptr[1] == 'A' || packet->line[a].ptr[1] == 'a')
                        && (packet->line[a].ptr[2] == 'I' || packet->line[a].ptr[2] == 'i')
                        && (packet->line[a].ptr[3] == 'L' || packet->line[a].ptr[3] == 'l')
                        && packet->line[a].ptr[4] == ' ') {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_MAIL;
                } else if ((packet->line[a].ptr[0] == 'R' || packet->line[a].ptr[0] == 'r')
                        && (packet->line[a].ptr[1] == 'C' || packet->line[a].ptr[1] == 'c')
                        && (packet->line[a].ptr[2] == 'P' || packet->line[a].ptr[2] == 'p')
                        && (packet->line[a].ptr[3] == 'T' || packet->line[a].ptr[3] == 't')
                        && packet->line[a].ptr[4] == ' ') {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_RCPT;
                } else if ((packet->line[a].ptr[0] == 'A' || packet->line[a].ptr[0] == 'a')
                        && (packet->line[a].ptr[1] == 'U' || packet->line[a].ptr[1] == 'u')
                        && (packet->line[a].ptr[2] == 'T' || packet->line[a].ptr[2] == 't')
                        && (packet->line[a].ptr[3] == 'H' || packet->line[a].ptr[3] == 'h')
                        && packet->line[a].ptr[4] == ' ') {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_AUTH;
                }
            }

            if (packet->line[a].len >= 8) {
                if ((packet->line[a].ptr[0] == 'S' || packet->line[a].ptr[0] == 's')
                        && (packet->line[a].ptr[1] == 'T' || packet->line[a].ptr[1] == 't')
                        && (packet->line[a].ptr[2] == 'A' || packet->line[a].ptr[2] == 'a')
                        && (packet->line[a].ptr[3] == 'R' || packet->line[a].ptr[3] == 'r')
                        && (packet->line[a].ptr[4] == 'T' || packet->line[a].ptr[0] == 't')
                        && (packet->line[a].ptr[5] == 'T' || packet->line[a].ptr[1] == 't')
                        && (packet->line[a].ptr[6] == 'L' || packet->line[a].ptr[2] == 'l')
                        && (packet->line[a].ptr[7] == 'S' || packet->line[a].ptr[3] == 's')) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_STARTTLS;
                }
            }

            if (packet->line[a].len >= 4) {
                if ((packet->line[a].ptr[0] == 'D' || packet->line[a].ptr[0] == 'd')
                        && (packet->line[a].ptr[1] == 'A' || packet->line[a].ptr[1] == 'a')
                        && (packet->line[a].ptr[2] == 'T' || packet->line[a].ptr[2] == 't')
                        && (packet->line[a].ptr[3] == 'A' || packet->line[a].ptr[3] == 'a')) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_DATA;
                } else if ((packet->line[a].ptr[0] == 'N' || packet->line[a].ptr[0] == 'n')
                        && (packet->line[a].ptr[1] == 'O' || packet->line[a].ptr[1] == 'o')
                        && (packet->line[a].ptr[2] == 'O' || packet->line[a].ptr[2] == 'o')
                        && (packet->line[a].ptr[3] == 'P' || packet->line[a].ptr[3] == 'p')) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_NOOP;
                } else if ((packet->line[a].ptr[0] == 'R' || packet->line[a].ptr[0] == 'r')
                        && (packet->line[a].ptr[1] == 'S' || packet->line[a].ptr[1] == 's')
                        && (packet->line[a].ptr[2] == 'E' || packet->line[a].ptr[2] == 'e')
                        && (packet->line[a].ptr[3] == 'T' || packet->line[a].ptr[3] == 't')) {
                    flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_RSET;
                }
            }

        }

        // now count the bits set in the bitmask
        if (flow->l4.tcp.smtp_command_bitmask != 0) {
            for (a = 0; a < 16; a++) {
                bit_count += (flow->l4.tcp.smtp_command_bitmask >> a) & 0x01;
            }
        }
        MMT_LOG(PROTO_SMTP, MMT_LOG_DEBUG, "seen smtp commands and responses: %u.\n",
                bit_count);

        if (bit_count >= 3) {
            MMT_LOG(PROTO_SMTP, MMT_LOG_DEBUG, "mail smtp identified\n");
            mmt_int_mail_smtp_add_connection(ipacket);
            return;
        }
        if (bit_count >= 1 && ipacket->session->data_packet_count < 12) {
            return;
        }
    }
    /* when the first or second packets are split into two packets, those packets are ignored. */
    if (ipacket->session->data_packet_count <= 4 &&
            packet->payload_packet_len >= 4 &&
            (ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a
            || mmt_memcmp(packet->payload, "220", 3) == 0 || mmt_memcmp(packet->payload, "EHLO", 4) == 0)) {
        MMT_LOG(PROTO_SMTP, MMT_LOG_DEBUG, "maybe SMTP, need next packet.\n");
        return;
    }

    MMT_LOG(PROTO_SMTP, MMT_LOG_DEBUG, "exclude smtp\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SMTP);

}

int mmt_check_smtp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_smtp(ipacket, index);
    }
    return 4;
}

void mmt_init_classify_me_smtp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SMTP);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_smtp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SMTP, PROTO_SMTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_smtp();
        
        return register_protocol(protocol_struct, PROTO_SMTP);
    } else {
        return 0;
    }
}


