#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_direct_download_link_add_connection(ipacket_t * ipacket) {
    struct mmt_internal_tcpip_session_struct *flow = ipacket->internal_packet->flow;

    mmt_internal_add_connection(ipacket, PROTO_DIRECT_DOWNLOAD_LINK, MMT_CORRELATED_PROTOCOL);

    flow->l4.tcp.ddlink_server_direction = ipacket->session->last_packet_direction;
}

/*
  return 0 if nothing has been detected
  return 1 if it is a megaupload packet
 */
uint8_t search_ddl_domains(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    uint16_t filename_start = 0;
    uint8_t i = 1;
    uint16_t host_line_len_without_port;

    if (packet->payload_packet_len < 100) {
        MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: Packet too small.\n");
        goto end_ddl_nothing_found;
    }



    if (memcmp(packet->payload, "POST ", 5) == 0) {
        filename_start = 5; // POST
        MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: POST FOUND\n");
    } else if (memcmp(packet->payload, "GET ", 4) == 0) {
        filename_start = 4; // GET
        MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: GET FOUND\n");
    } else {
        goto end_ddl_nothing_found;
    }
    // parse packet
    mmt_parse_packet_line_info(ipacket);

    if (packet->host_line.ptr == NULL) {
        MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: NO HOST FOUND\n");
        goto end_ddl_nothing_found;
    }

    MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: Host: found\n");

    if (packet->line[0].len < 9 + filename_start
            || memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) != 0) {
        MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, 
                MMT_LOG_DEBUG, "DDL: PACKET NOT HTTP CONFORM.\nXXX%.*sXXX\n",
                8, &packet->line[0].ptr[packet->line[0].len - 9]);
        goto end_ddl_nothing_found;
    }
    // BEGIN OF AUTOMATED CODE GENERATION
    // first see if we have ':port' at the end of the line
    host_line_len_without_port = packet->host_line.len;
    if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
            && packet->host_line.ptr[packet->host_line.len - i] <= '9') {
        i = 2;
        while (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] >= '0'
                && packet->host_line.ptr[host_line_len_without_port - i] <= '9') {
            MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: number found\n");
            i++;
        }
        if (host_line_len_without_port >= i && packet->host_line.ptr[host_line_len_without_port - i] == ':') {
            MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: ':' found\n");
            host_line_len_without_port = host_line_len_without_port - i;
        }
    }
    // then start automated code generation

    if (host_line_len_without_port >= 0 + 4
            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 4], ".com", 4) == 0) {
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'd') {
            if (host_line_len_without_port >= 5 + 6 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 6], "4share", 6) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 8 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "fileclou", 8) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 5
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "uploa", 5) == 0) {
                if (host_line_len_without_port >= 10 + 6 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 6], "files-", 6) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 10 + 4 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "mega", 4) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 10 + 5 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "rapid", 5) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 10 + 5 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "turbo", 5) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
                    goto end_ddl_found;
                }
                goto end_ddl_nothing_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'o') {
            if (host_line_len_without_port >= 5 + 6 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 6], "badong", 6) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 6 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 5 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "fileh", 5) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'g') {
            if (host_line_len_without_port >= 5 + 2
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 2], "in", 2) == 0) {
                if (host_line_len_without_port >= 7 + 4
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 4], "shar", 4) == 0) {
                    if (host_line_len_without_port >= 11 + 4 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 11 - 4], "best", 4) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 11 - 4 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 11 - 4 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 11 + 5 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 11 - 5], "quick", 5) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 11 - 5 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 11 - 5 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    goto end_ddl_nothing_found;
                }
                if (host_line_len_without_port >= 7 + 6 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 6], "upload", 6) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 7 - 6 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 7 - 6 - 1] == '.')) {
                    goto end_ddl_found;
                }
                goto end_ddl_nothing_found;
            }
            if (host_line_len_without_port >= 5 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "sharebi", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 8 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 8], "bigfilez", 8) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'e') {
            if (host_line_len_without_port >= 5 + 3
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 3], "fil", 3) == 0) {
                if (host_line_len_without_port >= 8 + 2
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 2], "mo", 2) == 0) {
                    if (host_line_len_without_port >= 10 + 5 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "china", 5) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 8 + 2 + 1
                            && (packet->host_line.ptr[host_line_len_without_port - 8 - 2 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 8 - 2 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                }
                if (host_line_len_without_port >= 8 + 3 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 3], "hot", 3) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 8 + 6 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 6], "keepmy", 6) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 8 - 6 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 8 - 6 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 8 + 1
                        && packet->host_line.ptr[host_line_len_without_port - 8 - 1] == 'e') {
                    if (host_line_len_without_port >= 9 + 3 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 3], "sav", 3) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 9 - 3 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 9 - 3 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 9 + 5 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 5], "sendm", 5) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    goto end_ddl_nothing_found;
                }
                if (host_line_len_without_port >= 8 + 8 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 8], "sharebig", 8) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 8 - 8 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 8 - 8 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 8 + 3 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 3], "up-", 3) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 8 - 3 - 1] == '.')) {
                    goto end_ddl_found;
                }
                goto end_ddl_nothing_found;
            }
            if (host_line_len_without_port >= 5 + 1 && packet->host_line.ptr[host_line_len_without_port - 5 - 1] == 'r') {
                if (host_line_len_without_port >= 6 + 3
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 3], "sha", 3) == 0) {
                    if (host_line_len_without_port >= 9 + 1
                            && packet->host_line.ptr[host_line_len_without_port - 9 - 1] == '-') {
                        if (host_line_len_without_port >= 10 + 4 + 1
                                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "easy",
                                4) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
                                || packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] ==
                                '.')) {
                            goto end_ddl_found;
                        }
                        if (host_line_len_without_port >= 10 + 4 + 1
                                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "fast",
                                4) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
                                || packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] ==
                                '.')) {
                            goto end_ddl_found;
                        }
                        if (host_line_len_without_port >= 10 + 4 + 1
                                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 4], "live",
                                4) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] == ' '
                                || packet->host_line.ptr[host_line_len_without_port - 10 - 4 - 1] ==
                                '.')) {
                            goto end_ddl_found;
                        }
                        goto end_ddl_nothing_found;
                    }
                    if (host_line_len_without_port >= 9 + 4 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4], "ftp2", 4) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 9 + 4 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4], "gige", 4) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 9 + 4 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 4], "mega", 4) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 9 - 4 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 9 + 5 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 9 - 5], "rapid", 5) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 9 - 5 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    goto end_ddl_nothing_found;
                }
                if (host_line_len_without_port >= 6 + 7 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 7], "mediafi", 7) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 6 - 7 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 6 - 7 - 1] == '.')) {
                    goto end_ddl_found;
                }
                goto end_ddl_nothing_found;
            }
            if (host_line_len_without_port >= 5 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "gigasiz", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 8 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "sendspac", 8) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "sharebe", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 11 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 11], "sharebigfli", 11) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 8 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "fileserv", 8) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 's') {
            if (host_line_len_without_port >= 5 + 1 && packet->host_line.ptr[host_line_len_without_port - 5 - 1] == 'e') {
                if (host_line_len_without_port >= 6 + 10 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 10], "depositfil",
                        10) == 0 && (packet->host_line.ptr[host_line_len_without_port - 6 - 10 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 6 - 10 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 6 + 8 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 6 - 8], "megashar", 8) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 6 - 8 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 6 - 8 - 1] == '.')) {
                    goto end_ddl_found;
                }
                goto end_ddl_nothing_found;
            }
            if (host_line_len_without_port >= 5 + 10 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10], "fileupyour", 10) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 11 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 11], "filefactory", 11) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 4 - 11 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 4 - 11 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 't') {
            if (host_line_len_without_port >= 5 + 8 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "filefron", 8) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 10 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10], "uploadingi", 10) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 11 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 11], "yourfilehos", 11) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 11 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'r') {
            if (host_line_len_without_port >= 5 + 8 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 8], "mytempdi", 8) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 8 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 10 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 10], "uploadpowe", 10) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 10 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 9 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 9], "mega.1280", 9) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 4 + 9 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 9], "filesonic", 9) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == '.')) {
            goto end_ddl_found;
        }
        goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 0 + 4
            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 4], ".net", 4) == 0) {
        if (host_line_len_without_port >= 4 + 7 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "badongo", 7) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'd') {
            if (host_line_len_without_port >= 5 + 3
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 3], "loa", 3) == 0) {
                if (host_line_len_without_port >= 8 + 5 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "fast-", 5) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 8 + 2
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 2], "up", 2) == 0) {
                    if (host_line_len_without_port >= 10 + 5 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 5], "file-", 5) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 10 - 5 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 10 + 6 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 6], "simple",
                            6) == 0 && (packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 10 - 6 - 1] ==
                            '.')) {
                        goto end_ddl_found;
                    }
                    if (host_line_len_without_port >= 10 + 3 + 1
                            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 10 - 3], "wii", 3) == 0
                            && (packet->host_line.ptr[host_line_len_without_port - 10 - 3 - 1] == ' '
                            || packet->host_line.ptr[host_line_len_without_port - 10 - 3 - 1] == '.')) {
                        goto end_ddl_found;
                    }
                    goto end_ddl_nothing_found;
                }
                goto end_ddl_nothing_found;
            }
            if (host_line_len_without_port >= 5 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 7], "filesen", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 4 + 5 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 5], "filer", 5) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 4 - 5 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 4 - 5 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 4 + 9 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 9], "livedepot", 9) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 4 - 9 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 4 + 1 && packet->host_line.ptr[host_line_len_without_port - 4 - 1] == 'e') {
            if (host_line_len_without_port >= 5 + 5 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "mofil", 5) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 17 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 17], "odsiebie.najlepsz",
                    17) == 0 && (packet->host_line.ptr[host_line_len_without_port - 5 - 17 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 17 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 5 + 5 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 5 - 5], "zshar", 5) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 5 - 5 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 0 + 1 && packet->host_line.ptr[host_line_len_without_port - 0 - 1] == 'u') {
        if (host_line_len_without_port >= 1 + 6 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 6], "data.h", 6) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 1 - 6 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 1 - 6 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 1 + 2
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 2], ".r", 2) == 0) {
            if (host_line_len_without_port >= 3 + 10 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 10], "filearchiv", 10) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 3 - 10 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 3 - 10 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 3 + 8 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 8], "filepost", 8) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 3 - 8 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 3 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 7], "ifolder", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 0 + 11 + 1
            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 11], "filehost.tv", 11) == 0
            && (packet->host_line.ptr[host_line_len_without_port - 0 - 11 - 1] == ' '
            || packet->host_line.ptr[host_line_len_without_port - 0 - 11 - 1] == '.')) {
        goto end_ddl_found;
    }
    if (host_line_len_without_port >= 0 + 3
            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 3], ".to", 3) == 0) {
        if (host_line_len_without_port >= 3 + 1 && packet->host_line.ptr[host_line_len_without_port - 3 - 1] == 'e') {
            if (host_line_len_without_port >= 4 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "filesaf", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 4 + 8 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 8], "sharebas", 8) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 4 - 8 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 3 + 5 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 5], "files", 5) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 3 - 5 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 3 - 5 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 3 + 1 && packet->host_line.ptr[host_line_len_without_port - 3 - 1] == 'd') {
            if (host_line_len_without_port >= 4 + 3
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 3], "loa", 3) == 0) {
                if (host_line_len_without_port >= 7 + 7 + 1
                        && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 7 - 7], "file-up", 7) == 0
                        && (packet->host_line.ptr[host_line_len_without_port - 7 - 7 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 7 - 7 - 1] == '.')) {
                    goto end_ddl_found;
                }
                if (host_line_len_without_port >= 4 + 3 + 1
                        && (packet->host_line.ptr[host_line_len_without_port - 4 - 3 - 1] == ' '
                        || packet->host_line.ptr[host_line_len_without_port - 4 - 3 - 1] == '.')) {
                    goto end_ddl_found;
                }
            }
            if (host_line_len_without_port >= 4 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 4 - 7], "uploade", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 4 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 0 + 1 && packet->host_line.ptr[host_line_len_without_port - 0 - 1] == 'z') {
        if (host_line_len_without_port >= 1 + 14 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 14], "leteckaposta.c", 14) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 1 - 14 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 1 - 14 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 1 + 12 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 12], "yourfiles.bi", 12) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 1 - 12 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 1 - 12 - 1] == '.')) {
            goto end_ddl_found;
        }
        goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 0 + 1 && packet->host_line.ptr[host_line_len_without_port - 0 - 1] == 'n') {
        if (host_line_len_without_port >= 1 + 9 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 9], "netload.i", 9) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 1 - 9 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 1 - 9 - 1] == '.')) {
            goto end_ddl_found;
        }
        if (host_line_len_without_port >= 1 + 2
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 1 - 2], ".v", 2) == 0) {
            if (host_line_len_without_port >= 3 + 7 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 7], "4shared", 7) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 3 - 7 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 3 + 9 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 9], "megashare", 9) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 3 - 9 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 3 - 9 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 0 + 3
            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 3], ".de", 3) == 0) {
        if (host_line_len_without_port >= 3 + 5
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 5], "share", 5) == 0) {
            if (host_line_len_without_port >= 8 + 5 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "rapid", 5) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
                goto end_ddl_found;
            }
            if (host_line_len_without_port >= 8 + 5 + 1
                    && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 8 - 5], "ultra", 5) == 0
                    && (packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == ' '
                    || packet->host_line.ptr[host_line_len_without_port - 8 - 5 - 1] == '.')) {
                goto end_ddl_found;
            }
            goto end_ddl_nothing_found;
        }
        if (host_line_len_without_port >= 3 + 15 + 1
                && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 3 - 15], "uploadyourfiles", 15) == 0
                && (packet->host_line.ptr[host_line_len_without_port - 3 - 15 - 1] == ' '
                || packet->host_line.ptr[host_line_len_without_port - 3 - 15 - 1] == '.')) {
            goto end_ddl_found;
        }
        goto end_ddl_nothing_found;
    }
    if (host_line_len_without_port >= 0 + 14 + 1
            && memcmp((void *) &packet->host_line.ptr[host_line_len_without_port - 0 - 14], "speedshare.org", 14) == 0
            && (packet->host_line.ptr[host_line_len_without_port - 0 - 14 - 1] == ' '
            || packet->host_line.ptr[host_line_len_without_port - 0 - 14 - 1] == '.')) {
        goto end_ddl_found;
    }
    // END OF AUTOMATED CODE GENERATION

    /* This is the hard way. We do this in order to find the download of services when other
       domains are involved. This is not significant if ddl is blocked. --> then the link can not be started because
       the ads are not viewed. But when ddl is only limited then the download is the important part.
     */

end_ddl_nothing_found:
    MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG,
            "Nothing Found\n%.*s\n", packet->payload_packet_len, packet->payload);
    return 0;

end_ddl_found:
    MMT_LOG(PROTO_DIRECT_DOWNLOAD_LINK, MMT_LOG_DEBUG, "DDL: DIRECT DOWNLOAD LINK FOUND\n");
    mmt_int_direct_download_link_add_connection(ipacket);
    return 1;
}

void mmt_classify_me_ddl(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    // do not detect again if it is already ddl
    if (packet->detected_protocol_stack[0] != PROTO_DIRECT_DOWNLOAD_LINK) {
        if (search_ddl_domains(ipacket) != 0) {
            return;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DIRECT_DOWNLOAD_LINK);
    }

}

int mmt_check_direct_download_link(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_ddl(ipacket, index);
    }
    return 1;
}

void mmt_init_classify_me_direct_download_link() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DIRECT_DOWNLOAD_LINK);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_DIRECT_DOWNLOAD_LINK);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_direct_download_link_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DIRECT_DOWNLOAD_LINK, PROTO_DIRECT_DOWNLOAD_LINK_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_direct_download_link();
        
        return register_protocol(protocol_struct, PROTO_DIRECT_DOWNLOAD_LINK);
    } else {
        return 0;
    }
}


