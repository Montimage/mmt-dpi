#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_syslog_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SYSLOG, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_syslog(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint8_t i;

    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "search syslog\n");

    if (packet->payload_packet_len > 20 && packet->payload_packet_len <= 1024 && packet->payload[0] == '<') {
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "checked len>20 and <1024 and first symbol=<.\n");
        i = 1;

        for (;;) {
            if (packet->payload[i] < '0' || packet->payload[i] > '9' || i++ > 3) {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                        "read symbols while the symbol is a number.\n");
                break;
            }
        }

        if (packet->payload[i++] != '>') {
            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "there is no > following the number.\n");
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
            return;
        } else {
            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "a > following the number.\n");
        }

        if (packet->payload[i] == 0x20) {
            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "a blank following the >: increment i.\n");
            i++;
        } else {
            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "no blank following the >: do nothing.\n");
        }

        /* check for "last message repeated" */
        if (i + sizeof ("last message") - 1 <= packet->payload_packet_len &&
                memcmp(packet->payload + i, "last message", sizeof ("last message") - 1) == 0) {

            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by 'last message' string.\n");

            mmt_int_syslog_add_connection(ipacket);

            return;
        } else if (i + sizeof ("snort: ") - 1 <= packet->payload_packet_len &&
                memcmp(packet->payload + i, "snort: ", sizeof ("snort: ") - 1) == 0) {

            /* snort events */

            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by 'snort: ' string.\n");

            mmt_int_syslog_add_connection(ipacket);

            return;
        }

        if (mmt_mem_cmp(&packet->payload[i], "Jan", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Feb", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Mar", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Apr", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "May", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Jun", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Jul", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Aug", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Sep", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Oct", 3) != 0
                && mmt_mem_cmp(&packet->payload[i], "Nov", 3) != 0 && mmt_mem_cmp(&packet->payload[i], "Dec", 3) != 0) {


            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                    "no month-shortname following: syslog excluded.\n");

            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);

            return;

        } else {

            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                    "a month-shortname following: syslog detected.\n");

            mmt_int_syslog_add_connection(ipacket);

            return;
        }
    }
    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "no syslog detected.\n");

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
}

int mmt_check_syslog(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint8_t i;
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "search syslog\n");

        if (packet->payload_packet_len > 20 && packet->payload_packet_len <= 1024 && packet->payload[0] == '<') {
            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "checked len>20 and <1024 and first symbol=<.\n");
            i = 1;
            for (;;) {
                if (packet->payload[i] < '0' || packet->payload[i] > '9' || i++ > 3) {
                    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                            "read symbols while the symbol is a number.\n");
                    break;
                }
            }

            if (packet->payload[i++] != '>') {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "there is no > following the number.\n");
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
                return 4;
            } else {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "a > following the number.\n");
            }

            if (packet->payload[i] == 0x20) {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "a blank following the >: increment i.\n");
                i++;
            } else {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "no blank following the >: do nothing.\n");
            }

            /* check for "last message repeated" */
            if (i + sizeof ("last message") - 1 <= packet->payload_packet_len &&
                    memcmp(packet->payload + i, "last message", sizeof ("last message") - 1) == 0) {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by 'last message' string.\n");
                mmt_int_syslog_add_connection(ipacket);
                return 1;
            } else if (i + sizeof ("snort: ") - 1 <= packet->payload_packet_len &&
                    memcmp(packet->payload + i, "snort: ", sizeof ("snort: ") - 1) == 0) {
                /* snort events */
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by 'snort: ' string.\n");
                mmt_int_syslog_add_connection(ipacket);
                return 1;
            }
            if (mmt_mem_cmp(&packet->payload[i], "Jan", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Feb", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Mar", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Apr", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "May", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Jun", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Jul", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Aug", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Sep", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Oct", 3) != 0
                    && mmt_mem_cmp(&packet->payload[i], "Nov", 3) != 0 && mmt_mem_cmp(&packet->payload[i], "Dec", 3) != 0) {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                        "no month-shortname following: syslog excluded.\n");
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
                return 0;
            } else {
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                        "a month-shortname following: syslog detected.\n");
                mmt_int_syslog_add_connection(ipacket);
                return 1;
            }
        }
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "no syslog detected.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
    }
    return 0;
}

void mmt_init_classify_me_syslog() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SYSLOG);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_syslog_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SYSLOG, PROTO_SYSLOG_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_syslog();

        return register_protocol(protocol_struct, PROTO_SYSLOG);
    } else {
        return 0;
    }
}


