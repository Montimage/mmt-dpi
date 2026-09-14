#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include <ctype.h>

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_syslog_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SYSLOG, MMT_REAL_PROTOCOL);
}

/*
 * Syslog detection — unified helper for RFC 3164 (BSD) and RFC 5424 (structured) formats.
 *
 * Detection strategy (after PRI parsing):
 *   1. Check for "last message" or "snort: " prefix (legacy/compatibility).
 *   2. Check for RFC 5424 format: version digit '1', space, then ISO-8601 year (4 digits).
 *   3. Check for RFC 3164 format: 3-letter month abbreviation (Jan–Dec).
 *   4. Check for hostname/tag pattern: alphanumeric hostname ending with delimiter.
 *      If stopped on ':', the next char must be a space.
 *
 * When on UDP port 514, detection is lenient — a valid PRI header is sufficient.
 * Off port 514, at least one of the above patterns must match.
 */
static int mmt_int_is_syslog_packet(struct mmt_tcpip_internal_packet_struct *packet,
                                     uint32_t i, int on_port_514, uint32_t payload_len) {

    /* --- "last message repeated" --- */
    if (i + sizeof("last message") - 1 <= payload_len &&
            mmt_memcmp(packet->payload + i, "last message", sizeof("last message") - 1) == 0) {
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by 'last message' string.\n");
        return 1;
    }

    /* --- "snort: " prefix --- */
    if (i + sizeof("snort: ") - 1 <= payload_len &&
            mmt_memcmp(packet->payload + i, "snort: ", sizeof("snort: ") - 1) == 0) {
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by 'snort: ' string.\n");
        return 1;
    }

    /* --- RFC 5424: version '1' followed by space then ISO timestamp --- */
    /* After the optional space following '>', we look for:
       - version digit '1'
       - space
       - ISO-8601 timestamp starting with a 4-digit year (first char is '2' or '1') */
    if (!on_port_514 || i < payload_len) {
        if (packet->payload[i] == '1') {
            i++;
            if (i < payload_len && packet->payload[i] == ' ') {
                i++;
                /* Check for 4-digit year start: '2' or '1' followed by digit */
                if (i + 3 < payload_len &&
                        ((packet->payload[i] == '2' || packet->payload[i] == '1') &&
                         isdigit(packet->payload[i + 1]) &&
                         isdigit(packet->payload[i + 2]) &&
                         isdigit(packet->payload[i + 3]))) {
                    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                            "found syslog by RFC 5424 version+year pattern.\n");
                    return 1;
                }
            }
        }
    }

    /* --- RFC 3164: 3-letter month abbreviation --- */
    if (i + 2 < payload_len &&
            (mmt_mem_cmp(&packet->payload[i], "Jan", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Feb", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Mar", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Apr", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "May", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Jun", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Jul", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Aug", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Sep", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Oct", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Nov", 3) == 0 ||
             mmt_mem_cmp(&packet->payload[i], "Dec", 3) == 0)) {
            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "a month-shortname following: syslog detected.\n");
            return 1;
        }

    /* --- Hostname/tag pattern matching (nDPI-inspired) --- */
    /* Walk alphanumeric chars; stop on recognized delimiters:
       ' ', ':', '=', '[', '-' */
    if (i < payload_len) {
        if (packet->payload[i] == ' ') {
            /* Space after PRI: walk the next token as hostname/tag */
            i++;
            if (i < payload_len && isalnum(packet->payload[i])) {
                while (i < payload_len - 1) {
                    if (isalnum(packet->payload[i])) {
                        i++;
                        continue;
                    }
                    if (packet->payload[i] == ' ' || packet->payload[i] == ':' ||
                        packet->payload[i] == '=' || packet->payload[i] == '[' ||
                        packet->payload[i] == '-')
                        break;
                    /* Unrecognized character — not syslog (off port 514) */
                    if (!on_port_514)
                        return 0;
                    /* On port 514, be lenient: just accept PRI header */
                    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                            "found syslog by lenient PRI header on port 514.\n");
                    return 1;
                }

                /* If we stopped on ':', the next character must be a space */
                if (i < payload_len && packet->payload[i] == ':') {
                    i++;
                    if (i >= payload_len || packet->payload[i] != ' ') {
                        /* If not on port 514, strict: not syslog */
                        if (!on_port_514)
                            return 0;
                    }
                }

                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by hostname/tag pattern.\n");
                return 1;
            }
        } else if (isalnum(packet->payload[i])) {
            /* No space after PRI — hostname starts immediately (non-standard but common) */
            while (i < payload_len - 1) {
                if (isalnum(packet->payload[i])) {
                    i++;
                    continue;
                }
                if (packet->payload[i] == ' ' || packet->payload[i] == ':' ||
                    packet->payload[i] == '=' || packet->payload[i] == '[' ||
                    packet->payload[i] == '-')
                    break;
                if (!on_port_514)
                    return 0;
                MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG,
                        "found syslog by lenient PRI header on port 514.\n");
                return 1;
            }

            if (i < payload_len && packet->payload[i] == ':') {
                i++;
                if (i >= payload_len || packet->payload[i] != ' ') {
                    if (!on_port_514)
                        return 0;
                }
            }

            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by hostname/tag pattern.\n");
            return 1;
        }
    }

    /* --- Port 514 lenient fallback: valid PRI header is enough --- */
    if (on_port_514) {
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "found syslog by lenient PRI header on port 514.\n");
        return 1;
    }

    return 0;
}

/*
 * Parse the PRI header: <PRI> where PRI is 1-3 digits.
 * Returns the index after the '>', or 0 if parsing fails.
 */
static uint8_t mmt_int_parse_syslog_pri(struct mmt_tcpip_internal_packet_struct *packet,
                                        uint32_t payload_len) {
    uint8_t i = 1;

    /* Read 1-3 digit PRI value */
    for (; i <= 3; i++) {
        if (i >= payload_len)
            break;
        if (packet->payload[i] < '0' || packet->payload[i] > '9')
            break;
    }

    /* Must be followed by '>' */
    if (i >= payload_len || packet->payload[i] != '>')
        return 0;

    i++; /* skip '>' */

    /* Optional space after '>' */
    if (i < payload_len && packet->payload[i] == 0x20)
        i++;

    return i;
}

/*
 * Internal classification function used by both mmt_classify_me_syslog and mmt_check_syslog.
 *
 * For UDP: checks port 514 for lenient detection.
 * For TCP: uses strict detection.
 */
static void mmt_int_classify_syslog(ipacket_t * ipacket,
                                     struct mmt_tcpip_internal_packet_struct *packet,
                                     struct mmt_internal_tcpip_session_struct *flow) {
    uint8_t i;

    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "search syslog\n");

    /* Issue #192 (F-BUG-054): bound every payload read by what was actually
     * captured, not by payload_packet_len alone — it derives from the
     * attacker-controlled IPv4 tot_len and may exceed the captured buffer.
     * Same caplen-relative shape as http2_can_read() (F-BUG-059). */
    uint32_t payload_len = packet->payload_packet_len;
    const uint8_t *payload_end = ipacket->data + ipacket->p_hdr->caplen;
    if (packet->payload == NULL || packet->payload >= payload_end)
        payload_len = 0;
    else if (payload_len > (uint32_t)(payload_end - packet->payload))
        payload_len = (uint32_t)(payload_end - packet->payload);

    /* Basic sanity: payload length and must start with '<' */
    if (payload_len <= 20 || payload_len > 1024 ||
            packet->payload[0] != '<') {
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "no syslog detected.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
        return;
    }

    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "checked len>20 and <1024 and first symbol=<.\n");

    /* Parse PRI header: <PRI> */
    i = mmt_int_parse_syslog_pri(packet, payload_len);
    if (i == 0) {
        MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "there is no > following the number.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
        return;
    }

    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "a > following the number.\n");

    /* Determine if we're on UDP port 514 for lenient detection */
    int on_port_514 = 0;
    if (packet->udp != NULL) {
        if (packet->udp->dest == htons(514) || packet->udp->source == htons(514)) {
            on_port_514 = 1;
            MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "detected UDP port 514 — lenient detection.\n");
        }
    }

    if (mmt_int_is_syslog_packet(packet, i, on_port_514, payload_len)) {
        mmt_int_syslog_add_connection(ipacket);
        return;
    }

    MMT_LOG(PROTO_SYSLOG, MMT_LOG_DEBUG, "no syslog detected.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SYSLOG);
}

/*
 * Entry point called from the classify_me registration.
 * No bitmask checks — handles all packets directly.
 */
void mmt_classify_me_syslog(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    mmt_int_classify_syslog(ipacket, packet, flow);
}

/*
 * Entry point called from mmt_check_syslog registration.
 * Performs bitmask selection checks before classification.
 */
int mmt_check_syslog(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        mmt_int_classify_syslog(ipacket, packet, flow);

        if (MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) != 0)
            return 0;

        return 1;
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
