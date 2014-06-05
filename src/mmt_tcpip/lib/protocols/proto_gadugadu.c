#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_GADGADU_TIMEOUT                 120

static uint32_t gadugadu_peer_connection_timeout = MMT_GADGADU_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_gadugadu_add_connection(ipacket_t * ipacket, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, PROTO_GADUGADU, protocol_type);
}

static void parse_gg_foneno(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    uint16_t pos = 18;

    MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: parse_gg_foneno.\n");

    if (packet->payload_packet_len < 19) {
        return;
    }

    while (packet->payload[pos] != '?') {
        pos++;
        if ((pos + 18) > packet->payload_packet_len)
            return;
    }
    pos++;
    if (pos + 16 < packet->payload_packet_len) {
        char fmnumber[8];
        int i = 0;
        if (memcmp(&packet->payload[pos], "fmnumber=", 9) == 0) {
            MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: fmnumber found .\n");
        } else
            return;

        pos += 9;
        while (packet->payload[pos] != '&') {
            fmnumber[i] = packet->payload[pos];
            i++;
            pos++;
            if (pos > packet->payload_packet_len || i > 7)
                break;
        }
        if (i < 8) {
            fmnumber[i] = '\0';
            if (src != NULL) {
                memcpy(src->gg_fmnumber, fmnumber, i);
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                        "Gadu-Gadu: fmnumber %s\n", src->gg_fmnumber);
            }
        }
    }

}

static uint8_t check_for_gadugadu_payload_pattern(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
            "Gadu-Gadu: check for 0xbebadec0 pattern in payload.\n");

    if (packet->payload_packet_len == 12) {
        if ((ipacket->session->data_packet_count == 1) && (ntohl(get_u32(packet->payload, 0)) == 0xbebadec0)) {
            flow->l4.tcp.gadugadu_stage++;
            return 1;
        }
        if ((flow->l4.tcp.gadugadu_stage == 1) && (ipacket->session->data_packet_count == 2)
                && (ntohl(get_u32(packet->payload, 0)) == 0xbebadec0)) {
            MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                    "Gadu-Gadu: gadugadu pattern bebadec0 FOUND \n");

            mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);
            return 1;
        }
    }
    return 0;
}

static uint8_t check_for_http(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: check for http.\n");

    if (packet->payload_packet_len < 50) {
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: Packet too small.\n");
        return 0;
    } else if (memcmp(packet->payload, "GET /appsvc/appmsg", 18) == 0) {
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: GET FOUND\n");
        parse_gg_foneno(ipacket);
        // parse packet
        mmt_parse_packet_line_info(ipacket);
        if (packet->parsed_lines <= 1) {
            return 0;
        }
        if (packet->host_line.ptr == NULL) {
            return 0;
        }
        if (!(packet->host_line.len >= 19 && memcmp(packet->host_line.ptr, "appmsg.gadu-gadu.pl", 19) == 0)) {
            return 0;
        }
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                "Gadu-Gadu: Is gadugadu host FOUND %s\n", packet->host_line.ptr);

        mmt_int_gadugadu_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);

    } else if (memcmp(packet->payload, "POST /send/message/", 15) == 0) {
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: GET FOUND\n");

        // parse packet
        mmt_parse_packet_line_info(ipacket);
        if (packet->parsed_lines <= 1) {
            return 0;
        }
        if (packet->host_line.ptr == NULL) {
            return 0;
        }
        if (!(packet->host_line.len >= 17 && memcmp(packet->host_line.ptr, "life.gadu-gadu.pl", 17) == 0)) {
            return 0;
        }
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                "Gadu-Gadu: Is gadugadu post FOUND %s\n", packet->host_line.ptr);

        mmt_int_gadugadu_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);

    } else if (memcmp(packet->payload, "GET /rotate_token", 17) == 0) {
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: GET FOUND\n");

        // parse packet
        mmt_parse_packet_line_info(ipacket);
        if (packet->parsed_lines <= 1) {
            return 0;
        }
        if (packet->host_line.ptr == NULL) {
            return 0;
        }
        if (!(packet->host_line.len >= 13 && memcmp(packet->host_line.ptr, "sms.orange.pl", 13) == 0)) {
            return 0;
        }
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                "Gadu-Gadu:  gadugadu sms FOUND %s\n", packet->host_line.ptr);

        mmt_int_gadugadu_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);

    } else if ((memcmp(packet->payload, "GET /nowosci.xml", MMT_STATICSTRING_LEN("GET /nowosci.xml")) == 0) ||
            (memcmp(packet->payload, "GET /gadu-gadu.xml", MMT_STATICSTRING_LEN("GET /gadu-gadu.xml")) == 0) ||
            (memcmp(packet->payload, "POST /access_token", MMT_STATICSTRING_LEN("POST /access_token")) == 0)) {
        mmt_parse_packet_line_info(ipacket);
        if (packet->user_agent_line.ptr == NULL) {
            return 0;
        }
        if (!(packet->user_agent_line.len >= MMT_STATICSTRING_LEN("Gadu-Gadu Client") &&
                memcmp(packet->user_agent_line.ptr, "Gadu-Gadu Client", MMT_STATICSTRING_LEN("Gadu-Gadu Client")) == 0)) {
            return 0;
        }
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                "Gadu-Gadu:  gadugadu FOUND %s\n", packet->user_agent_line.ptr);

        mmt_int_gadugadu_add_connection(ipacket, MMT_CORRELATED_PROTOCOL);

    }

    return 1;

}

static void mmt_search_gadugadu_tcp(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (packet->detected_protocol_stack[0] == PROTO_GADUGADU) {
        if (src != NULL)
            src->gg_timeout = packet->tick_timestamp;
        if (dst != NULL)
            dst->gg_timeout = packet->tick_timestamp;

        if (packet->payload_packet_len == 311) {
            if (packet->payload[28] != 0) {
                if (src != NULL) {
                    src->gg_timeout = packet->tick_timestamp;
                    if (ntohs(packet->tcp->dest) == 8074 || ntohs(packet->tcp->dest) == 443)
                        src->gadu_gadu_ft_direction = 0;
                    else
                        src->gadu_gadu_ft_direction = 1;
                    src->gadu_gadu_voice = 0;


                }
                if (dst != NULL) {
                    dst->gg_timeout = packet->tick_timestamp;
                    if (ntohs(packet->tcp->dest) == 8074 || ntohs(packet->tcp->dest) == 443)
                        dst->gadu_gadu_ft_direction = 0;
                    else
                        dst->gadu_gadu_ft_direction = 1;
                    dst->gadu_gadu_voice = 0;


                }

                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "gg filetransfer setup detected\n");

            } else {
                if (src != NULL) {
                    src->gadu_gadu_voice = 1;
                    src->gg_timeout = packet->tick_timestamp;
                }
                if (dst != NULL) {
                    dst->gadu_gadu_voice = 1;
                    dst->gg_timeout = packet->tick_timestamp;
                }
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "gg voice setup detected \n");
            }
        }
        return;
    }
#ifdef PROTO_HTTP
    if (packet->detected_protocol_stack[0] == PROTO_HTTP) {
#endif
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: HTTP CHECK FOUND\n");
        if (packet->tcp != NULL && ntohs(packet->tcp->dest) == 80)
            if (check_for_http(ipacket))
                return;
#ifdef PROTO_HTTP
    }
#endif


    /* the following code is implemented asymmetrically. */
    if (packet->tcp != NULL &&
            (ntohs(packet->tcp->dest) == 443 || ntohs(packet->tcp->dest) == 8074
            || ntohs(packet->tcp->source) == 443 || ntohs(packet->tcp->source) == 8074)) {
        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: found port 8074 or 443.\n");
        if (ipacket->session->data_packet_count <= 6) {


            if ((packet->payload_packet_len == 9
                    || packet->payload_packet_len == 12
                    || packet->payload_packet_len == 100
                    || (packet->payload_packet_len > 190 && packet->payload_packet_len < 210)
                    )
                    && get_l32(packet->payload, 4) == packet->payload_packet_len - 8
                    && (ntohl(get_u32(packet->payload, 0)) == 0x01000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x02000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x03000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x12000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x19000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x31000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x35000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x10000000
                    || ntohl(get_u32(packet->payload, 0)) == 0x15000000)) {
                flow->l4.tcp.gadugadu_stage++;
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                        "Gadu-Gadu: len=9,12,100,190-210, stage++.\n");
            }



            /*detection of mirinda client .this has a different way of communicating ports */
            if (packet->payload_packet_len == 114
                    && ntohl(get_u32(packet->payload, 0)) == 0x19000000
                    && get_l32(packet->payload, 4) == packet->payload_packet_len - 8) {
                flow->l4.tcp.gadugadu_stage++;
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: len=114, stage++.\n");
                /* here the asymmetric implementation ends */


                if (flow->l4.tcp.gadugadu_stage == 2) {
                    if (src != NULL) {

                        memcpy(src->gg_call_id[src->gg_next_id], &packet->payload[8], 4);
                        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "call id parsed %d\n", packet->payload[8]);

                        src->gg_ft_ip_address = get_u32(packet->payload, 86);
                        src->gg_ft_port = htons(get_u16(packet->payload, 90));
                        MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG,
                                "mirinda file transfer port %d \n", ntohs(src->gg_ft_port));
                    }
                    if (dst != NULL) {

                        memcpy(dst->gg_call_id[dst->gg_next_id], &packet->payload[8], 4);
                        MMT_LOG(PROTO_GADUGADU, 
                                MMT_LOG_DEBUG, "call id parsed %d\n", packet->payload[8]);

                        dst->gg_ft_ip_address = get_u32(packet->payload, 86);
                        dst->gg_ft_port = htons(get_u16(packet->payload, 90));

                        MMT_LOG(PROTO_GADUGADU,
                                MMT_LOG_DEBUG,
                                "mirinda file transfer port %d \n", ntohs(dst->gg_ft_port));
                    }
                }
            }

            if (flow->l4.tcp.gadugadu_stage == 2) {
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "Gadu-Gadu: add connection.\n");

                mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);
            }
            return;
        }

    }
    /*mirinda file detection */
    if (packet->tcp != NULL && src != NULL) {
        if (MMT_COMPARE_PROTOCOL_TO_BITMASK
                (src->detected_protocol_bitmask, PROTO_GADUGADU) != 0
                && ((src->gg_ft_ip_address == packet->iph->saddr && src->gg_ft_port == packet->tcp->source)
                || (src->gg_ft_ip_address == packet->iph->daddr && src->gg_ft_port == packet->tcp->dest))) {
            if ((packet->tick_timestamp - src->gg_timeout) < gadugadu_peer_connection_timeout) {

                mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);

                MMT_LOG(PROTO_GADUGADU, 
                        MMT_LOG_DEBUG, "file transfer detected %d\n", ntohs(packet->tcp->dest));
                return;
            } else {
                src->gg_ft_ip_address = 0;
                src->gg_ft_port = 0;
            }
        } else if (MMT_COMPARE_PROTOCOL_TO_BITMASK
                (src->detected_protocol_bitmask, PROTO_GADUGADU) != 0 && (packet->tcp->dest == htons(80)
                || packet->tcp->source ==
                htons(80))
                && packet->payload_packet_len == 12 && (memcmp(src->gg_call_id[0], &packet->payload[5], 4) == 0
                || (src->gg_call_id[1][0]
                && (memcmp(src->gg_call_id[1], &packet->payload[5], 4)
                == 0)))) {
            if ((packet->tick_timestamp - src->gg_timeout) < gadugadu_peer_connection_timeout) {

                mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);

                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "http file transfer detetced \n");
                return;
            } else {
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "http file transfer timeout \n");


            }

        } else if (MMT_COMPARE_PROTOCOL_TO_BITMASK
                (src->detected_protocol_bitmask,
                PROTO_GADUGADU) != 0
                && packet->payload_packet_len == 8 &&
                (memcmp(src->gg_call_id[0], &packet->payload[0], 4) == 0 || (src->gg_call_id[1][0]
                &&
                (memcmp
                (src->gg_call_id[1],
                &packet->payload[0], 4)
                == 0)))) {
            if ((packet->tick_timestamp - src->gg_timeout) < gadugadu_peer_connection_timeout) {

                mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);

                MMT_LOG(PROTO_GADUGADU, 
                        MMT_LOG_DEBUG, "file transfer detetced %d\n", htons(packet->tcp->dest));
                return;
            } else {
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, " file transfer timeout \n");
            }
        }
    }

    if (packet->tcp != NULL && dst != NULL) {
        if (MMT_COMPARE_PROTOCOL_TO_BITMASK
                (dst->detected_protocol_bitmask, PROTO_GADUGADU) != 0
                && ((dst->gg_ft_ip_address == packet->iph->saddr && dst->gg_ft_port == packet->tcp->source)
                || (dst->gg_ft_ip_address == packet->iph->daddr && dst->gg_ft_port == packet->tcp->dest))) {
            if ((packet->tick_timestamp - dst->gg_timeout) < gadugadu_peer_connection_timeout) {

                mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);

                MMT_LOG(PROTO_GADUGADU, 
                        MMT_LOG_DEBUG, "file transfer detected %d\n", ntohs(packet->tcp->dest));
                return;
            } else {
                dst->gg_ft_ip_address = 0;
                dst->gg_ft_port = 0;
            }
        } else if (MMT_COMPARE_PROTOCOL_TO_BITMASK
                (dst->detected_protocol_bitmask, PROTO_GADUGADU) != 0 && (packet->tcp->dest == htons(80)
                || packet->tcp->source ==
                htons(80))
                && packet->payload_packet_len == 12 && (memcmp(dst->gg_call_id[0], &packet->payload[0], 4) == 0
                || (dst->gg_call_id[1][0]
                && (memcmp(dst->gg_call_id[1], &packet->payload[0], 4)
                == 0)))) {
            if ((packet->tick_timestamp - dst->gg_timeout) < gadugadu_peer_connection_timeout) {

                mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);

                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "http file transfer detetced \n");
                return;
            } else {
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, "http file transfer timeout \n");


            }

        } else if (MMT_COMPARE_PROTOCOL_TO_BITMASK
                (dst->detected_protocol_bitmask,
                PROTO_GADUGADU) != 0
                && packet->payload_packet_len == 8 &&
                (memcmp(dst->gg_call_id[0], &packet->payload[0], 4) == 0 || (dst->gg_call_id[1][0]
                &&
                (memcmp
                (dst->gg_call_id[1],
                &packet->payload[0], 4)
                == 0)))) {
            if ((packet->tick_timestamp - dst->gg_timeout) < gadugadu_peer_connection_timeout) {

                mmt_int_gadugadu_add_connection(ipacket, MMT_REAL_PROTOCOL);

                MMT_LOG(PROTO_GADUGADU, 
                        MMT_LOG_DEBUG, "file transfer detected %d\n", ntohs(packet->tcp->dest));
                return;
            } else {
                MMT_LOG(PROTO_GADUGADU, MMT_LOG_DEBUG, " file transfer timeout \n");
            }
        }
    }
    /** newly added start **/
    if (packet->tcp != NULL && ((ntohs(packet->tcp->dest) == 80) || (ntohs(packet->tcp->source) == 80))) {
        if (check_for_gadugadu_payload_pattern(ipacket)) {
            return;
        }
    }

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_GADUGADU);

}

void mmt_classify_me_gadugadu(ipacket_t * ipacket, unsigned index) {

    mmt_search_gadugadu_tcp(ipacket);
}

int mmt_check_gadugadu(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_search_gadugadu_tcp(ipacket); //BW: TODO: this seems to be only tcp, the bitmask is UDP as well, check this out
    }
    return 1;
}

void mmt_init_classify_me_gadugadu() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GADUGADU);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_GADUGADU);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_gadugadu_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_GADUGADU, PROTO_GADUGADU_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_gadugadu();
        
        return register_protocol(protocol_struct, PROTO_GADUGADU);
    } else {
        return 0;
    }
}


