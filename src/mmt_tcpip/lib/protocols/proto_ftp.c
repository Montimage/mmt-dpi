#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_FTP_TIMEOUT                     10

static uint32_t ftp_connection_timeout = MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ftp_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_FTP, MMT_REAL_PROTOCOL);
}

/**
 * checks for possible FTP command
 * not all valid commands are tested, it just need to be 3 or 4 characters followed by a space if the
 * packet is longer
 *
 * this functions is not used to accept, just to not reject
 */
static uint8_t mmt_int_check_possible_ftp_command(const struct mmt_tcpip_internal_packet_struct *packet) {
    if (packet->payload_packet_len < 3)
        return 0;

    if ((packet->payload[0] < 'a' || packet->payload[0] > 'z') &&
            (packet->payload[0] < 'A' || packet->payload[0] > 'Z'))
        return 0;
    if ((packet->payload[1] < 'a' || packet->payload[1] > 'z') &&
            (packet->payload[1] < 'A' || packet->payload[1] > 'Z'))
        return 0;
    if ((packet->payload[2] < 'a' || packet->payload[2] > 'z') &&
            (packet->payload[2] < 'A' || packet->payload[2] > 'Z'))
        return 0;

    if (packet->payload_packet_len > 3) {
        if ((packet->payload[3] < 'a' || packet->payload[3] > 'z') &&
                (packet->payload[3] < 'A' || packet->payload[3] > 'Z') && packet->payload[3] != ' ')
            return 0;

        if (packet->payload_packet_len > 4) {
            if (packet->payload[3] != ' ' && packet->payload[4] != ' ')
                return 0;
        }
    }

    return 1;
}

/**
 * ftp replies are are 3-digit number followed by space or hyphen
 */
static uint8_t mmt_int_check_possible_ftp_reply(const struct mmt_tcpip_internal_packet_struct *packet) {
    if (packet->payload_packet_len < 5)
        return 0;

    if (packet->payload[3] != ' ' && packet->payload[3] != '-')
        return 0;

    if (packet->payload[0] < '0' || packet->payload[0] > '9')
        return 0;
    if (packet->payload[1] < '0' || packet->payload[1] > '9')
        return 0;
    if (packet->payload[2] < '0' || packet->payload[2] > '9')
        return 0;

    return 1;
}

/**
 * check for continuation replies
 * there is no real indication whether it is a continuation message, we just
 * require that there are at least 5 ascii characters
 */
static uint8_t mmt_int_check_possible_ftp_continuation_reply(const struct mmt_tcpip_internal_packet_struct *packet) {
    uint16_t i;

    if (packet->payload_packet_len < 5)
        return 0;

    for (i = 0; i < 5; i++) {
        if (packet->payload[i] < ' ' || packet->payload[i] > 127)
            return 0;
    }

    return 1;
}

/*
 * these are the commands we tracking and expecting to see
 */
enum {
    FTP_USER_CMD = 1 << 0,
    FTP_FEAT_CMD = 1 << 1,
    FTP_COMMANDS = ((1 << 2) - 1),
    FTP_220_CODE = 1 << 2,
    FTP_331_CODE = 1 << 3,
    FTP_211_CODE = 1 << 4,
    FTP_CODES = ((1 << 5) - 1 - FTP_COMMANDS)
};

/*
  return 0 if nothing has been detected
  return 1 if a pop packet
 */

static uint8_t search_ftp(ipacket_t * ipacket) {
    


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint8_t current_ftp_code = 0;

    /* initiate client direction flag */
    if (ipacket->session->data_packet_count == 1) {
        if (flow->l4.tcp.seen_syn) {
            flow->l4.tcp.ftp_client_direction = ipacket->session->setup_packet_direction;
        } else {
            /* no syn flag seen so guess */
            if (packet->payload_packet_len > 0) {
                if (packet->payload[0] >= '0' && packet->payload[0] <= '9') {
                    /* maybe server side */
                    flow->l4.tcp.ftp_client_direction = 1 - ipacket->session->last_packet_direction;
                } else {
                    flow->l4.tcp.ftp_client_direction = ipacket->session->last_packet_direction;
                }
            }
        }
    }

    if (ipacket->session->last_packet_direction == flow->l4.tcp.ftp_client_direction) {
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("USER ") &&
                (memcmp(packet->payload, "USER ", MMT_STATICSTRING_LEN("USER ")) == 0 ||
                memcmp(packet->payload, "user ", MMT_STATICSTRING_LEN("user ")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found USER command\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_USER_CMD;
            current_ftp_code = FTP_USER_CMD;
        } else if (packet->payload_packet_len >= MMT_STATICSTRING_LEN("FEAT") &&
                (memcmp(packet->payload, "FEAT", MMT_STATICSTRING_LEN("FEAT")) == 0 ||
                memcmp(packet->payload, "feat", MMT_STATICSTRING_LEN("feat")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found FEAT command\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_FEAT_CMD;
            current_ftp_code = FTP_FEAT_CMD;
        } else if (!mmt_int_check_possible_ftp_command(packet)) {
            return 0;
        }
    } else {
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("220 ") &&
                (memcmp(packet->payload, "220 ", MMT_STATICSTRING_LEN("220 ")) == 0 ||
                memcmp(packet->payload, "220-", MMT_STATICSTRING_LEN("220-")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found 220 reply code\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("331 ") &&
                (memcmp(packet->payload, "331 ", MMT_STATICSTRING_LEN("331 ")) == 0 ||
                memcmp(packet->payload, "331-", MMT_STATICSTRING_LEN("331-")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found 331 reply code\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_331_CODE;
            current_ftp_code = FTP_331_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("211 ") &&
                (memcmp(packet->payload, "211 ", MMT_STATICSTRING_LEN("211 ")) == 0 ||
                memcmp(packet->payload, "211-", MMT_STATICSTRING_LEN("211-")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found 211reply code\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_211_CODE;
            current_ftp_code = FTP_211_CODE;
        } else if (!mmt_int_check_possible_ftp_reply(packet)) {
            if ((flow->l4.tcp.ftp_codes_seen & FTP_CODES) == 0 ||
                    (!mmt_int_check_possible_ftp_continuation_reply(packet))) {
                return 0;
            }
        }
    }

    if ((flow->l4.tcp.ftp_codes_seen & FTP_COMMANDS) != 0 && (flow->l4.tcp.ftp_codes_seen & FTP_CODES) != 0) {

        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP detected\n");
        mmt_int_ftp_add_connection(ipacket);
        return 1;
    }

    /* if no valid code has been seen for the first packets reject */
    if (flow->l4.tcp.ftp_codes_seen == 0 && ipacket->session->data_packet_count > 3)
        return 0;

    /* otherwise wait more packets, wait more for traffic on known ftp port */
    if ((ipacket->session->last_packet_direction == ipacket->session->setup_packet_direction && packet->tcp && packet->tcp->dest == htons(21)) ||
            (ipacket->session->last_packet_direction != ipacket->session->setup_packet_direction && packet->tcp && packet->tcp->source == htons(21))) {
        /* flow to known ftp port */

        /* wait much longer if this was a 220 code, initial messages might be long */
        if (current_ftp_code == FTP_220_CODE) {
            if (ipacket->session->data_packet_count > 40)
                return 0;
        } else {
            if (ipacket->session->data_packet_count > 20)
                return 0;
        }
    } else {
        /* wait much longer if this was a 220 code, initial messages might be long */
        if (current_ftp_code == FTP_220_CODE) {
            if (ipacket->session->data_packet_count > 20)
                return 0;
        } else {
            if (ipacket->session->data_packet_count > 10)
                return 0;
        }
    }

    return 2;
}

static void search_passive_ftp_mode(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    uint16_t plen;
    uint8_t i;
    uint32_t ftp_ip;


    // TODO check if normal passive mode also needs adaption for ipv6
    if (packet->payload_packet_len > 3 && mmt_mem_cmp(packet->payload, "227 ", 4) == 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP passive mode initial string\n");

        plen = 4; //=4 for "227 "
        while (1) {
            if (plen >= packet->payload_packet_len) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                        "plen >= packet->payload_packet_len, return\n");
                return;
            }
            if (packet->payload[plen] == '(') {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "found (. break.\n");
                break;
            }

            plen++;
        }
        plen++;

        if (plen >= packet->payload_packet_len)
            return;


        ftp_ip = 0;
        for (i = 0; i < 4; i++) {
            uint16_t oldplen = plen;
            ftp_ip =
                    (ftp_ip << 8) +
                    mmt_bytestream_to_number(&packet->payload[plen], packet->payload_packet_len - plen, &plen);
            if (oldplen == plen || plen >= packet->payload_packet_len) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP passive mode %u value parse failed\n",
                        i);
                return;
            }
            if (packet->payload[plen] != ',') {

                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                        "FTP passive mode %u value parse failed, char ',' is missing\n", i);
                return;
            }
            plen++;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                    "FTP passive mode %u value parsed, ip is now: %u\n", i, ftp_ip);

        }
        if (dst != NULL) {
            dst->ftp_ip.ipv4 = htonl(ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
        }
        if (src != NULL) {
            src->ftp_ip.ipv4 = packet->iph->daddr;
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to src");
        }
        return;
    }

    if (packet->payload_packet_len > 34 && mmt_mem_cmp(packet->payload, "229 Entering Extended Passive Mode", 34) == 0) {
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
        }
        if (src != NULL) {
            mmt_get_destination_ip_from_packet(packet, &src->ftp_ip);
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to src");
        }
        return;
    }
}

static void search_active_ftp_mode(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (packet->payload_packet_len > 5
            && (mmt_mem_cmp(packet->payload, "PORT ", 5) == 0 || mmt_mem_cmp(packet->payload, "EPRT ", 5) == 0)) {

        //src->local_ftp_data_port = htons(data_port_number);
        if (src != NULL) {
            mmt_get_destination_ip_from_packet(packet, &src->ftp_ip);
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
                    packet->payload);
        }
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
                    packet->payload);
        }
    }
    return;
}

void mmt_classify_me_ftp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (src != NULL && mmt_compare_packet_destination_ip_to_given_ip(packet, &src->ftp_ip)
            && packet->tcp->syn != 0 && packet->tcp->ack == 0
            && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask,
            PROTO_FTP) != 0 && src->ftp_timer_set != 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data, src!= 0.\n");

        if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - src->ftp_timer)) >= ftp_connection_timeout) {
            src->ftp_timer_set = 0;
        } else if (ntohs(packet->tcp->dest) > 1024
                && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
            mmt_int_ftp_add_connection(ipacket);
            return;
        }
    }

    if (dst != NULL && mmt_compare_packet_source_ip_to_given_ip(packet, &dst->ftp_ip)
            && packet->tcp->syn != 0 && packet->tcp->ack == 0
            && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
            PROTO_FTP) != 0 && dst->ftp_timer_set != 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data; dst!= 0.\n");

        if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - dst->ftp_timer)) >= ftp_connection_timeout) {
            dst->ftp_timer_set = 0;

        } else if (ntohs(packet->tcp->dest) > 1024
                && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
            mmt_int_ftp_add_connection(ipacket);
            return;
        }
    }
    // ftp data asymmetrically


    /* skip packets without payload */
    if (packet->payload_packet_len == 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                "FTP test skip because of data connection or zero byte packet_payload.\n");
        return;
    }
    /* skip excluded connections */

    // we test for FTP connection and search for passive mode
    if (packet->detected_protocol_stack[0] == PROTO_FTP) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                "detected ftp command mode. going to test data mode.\n");
        search_passive_ftp_mode(ipacket);

        search_active_ftp_mode(ipacket);
        return;
    }


    if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "unknown. need next packet.\n");

        return;
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP);
    MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "exclude ftp.\n");

}

int mmt_check_ftp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        if (src != NULL && mmt_compare_packet_destination_ip_to_given_ip(packet, &src->ftp_ip)
                && packet->tcp->syn != 0 && packet->tcp->ack == 0
                && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask,
                PROTO_FTP) != 0 && src->ftp_timer_set != 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data, src!= 0.\n");

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->ftp_timer)) >= ftp_connection_timeout) {
                src->ftp_timer_set = 0;
            } else if (ntohs(packet->tcp->dest) > 1024
                    && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }

        if (dst != NULL && mmt_compare_packet_source_ip_to_given_ip(packet, &dst->ftp_ip)
                && packet->tcp->syn != 0 && packet->tcp->ack == 0
                && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
                PROTO_FTP) != 0 && dst->ftp_timer_set != 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data; dst!= 0.\n");

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->ftp_timer)) >= ftp_connection_timeout) {
                dst->ftp_timer_set = 0;

            } else if (ntohs(packet->tcp->dest) > 1024
                    && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }
        // ftp data asymmetrically


        /* skip packets without payload */
        if (packet->payload_packet_len == 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                    "FTP test skip because of data connection or zero byte packet_payload.\n");
            return 1;
        }
        /* skip excluded connections */

        // we test for FTP connection and search for passive mode
        if (packet->detected_protocol_stack[0] == PROTO_FTP) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                    "detected ftp command mode. going to test data mode.\n");
            search_passive_ftp_mode(ipacket);

            search_active_ftp_mode(ipacket);
            return 1;
        }


        if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "unknown. need next packet.\n");

            return 1;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP);
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "exclude ftp.\n");

    }
    return 1;
}

void mmt_init_classify_me_ftp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FTP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ftp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FTP, PROTO_FTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_ftp();

        return register_protocol(protocol_struct, PROTO_FTP);
    } else {
        return 0;
    }
}


