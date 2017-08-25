#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_JABBER_STUN_TIMEOUT             30
#define MMT_JABBER_FT_TIMEOUT               5

/* unused
static uint32_t jabber_stun_timeout = MMT_JABBER_STUN_TIMEOUT * MMT_MICRO_IN_SEC;
*/
static uint32_t jabber_file_transfer_timeout = MMT_JABBER_FT_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_jabber_add_connection(ipacket_t * ipacket, uint32_t protocol, mmt_protocol_type_t protocol_type) {
    mmt_internal_add_connection(ipacket, protocol, protocol_type);
}

static void check_content_type_and_change_protocol(ipacket_t * ipacket, uint16_t x) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

#ifdef PROTO_TRUPHONE
    if (packet->payload_packet_len > x + 18 && packet->payload_packet_len > x && packet->payload_packet_len > 18) {
        const uint16_t lastlen = packet->payload_packet_len - 18;
        for (x = 0; x < lastlen; x++) {
            if (mmt_mem_cmp(&packet->payload[x], "=\"im.truphone.com\"", 18) == 0 ||
                    mmt_mem_cmp(&packet->payload[x], "='im.truphone.com'", 18) == 0) {
                MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_TRACE, "changed to TRUPHONE.\n");

                mmt_int_jabber_add_connection(ipacket, PROTO_TRUPHONE, MMT_CORRELATED_PROTOCOL);
            }
        }
    }
#endif

    return;
}

void mmt_classify_me_jabber_tcp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    uint16_t x;

    MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "search jabber.\n");

    /* search for jabber file transfer */
    /* this part is working asymmetrically */
    if (packet->tcp != NULL && packet->tcp->syn != 0 && packet->payload_packet_len == 0) {
        MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "check jabber syn\n");
        if (src != NULL && src->jabber_file_transfer_port[0] != 0) {
            MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG,
                    "src jabber ft port set, ports are: %u, %u\n", ntohs(src->jabber_file_transfer_port[0]),
                    ntohs(src->jabber_file_transfer_port[1]));
            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->jabber_stun_or_ft_ts)) >= jabber_file_transfer_timeout) {
                MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                        MMT_LOG_DEBUG, "JABBER src stun timeout %u %u\n", src->jabber_stun_or_ft_ts,
                        packet->tick_timestamp);
                src->jabber_file_transfer_port[0] = 0;
                src->jabber_file_transfer_port[1] = 0;
            } else if (src->jabber_file_transfer_port[0] == packet->tcp->dest
                    || src->jabber_file_transfer_port[0] == packet->tcp->source
                    || src->jabber_file_transfer_port[1] == packet->tcp->dest
                    || src->jabber_file_transfer_port[1] == packet->tcp->source) {
                MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG,
                        "found jabber file transfer.\n");

                mmt_int_jabber_add_connection(ipacket, PROTO_UNENCRYPED_JABBER, MMT_CORRELATED_PROTOCOL);
            }
        }
        if (dst != NULL && dst->jabber_file_transfer_port[0] != 0) {
            MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG,
                    "dst jabber ft port set, ports are: %u, %u\n", ntohs(dst->jabber_file_transfer_port[0]),
                    ntohs(dst->jabber_file_transfer_port[1]));
            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->jabber_stun_or_ft_ts)) >= jabber_file_transfer_timeout) {
                MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                        MMT_LOG_DEBUG, "JABBER dst stun timeout %u %u\n", dst->jabber_stun_or_ft_ts,
                        packet->tick_timestamp);
                dst->jabber_file_transfer_port[0] = 0;
                dst->jabber_file_transfer_port[1] = 0;
            } else if (dst->jabber_file_transfer_port[0] == packet->tcp->dest
                    || dst->jabber_file_transfer_port[0] == packet->tcp->source
                    || dst->jabber_file_transfer_port[1] == packet->tcp->dest
                    || dst->jabber_file_transfer_port[1] == packet->tcp->source) {
                MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG,
                        "found jabber file transfer.\n");

                mmt_int_jabber_add_connection(ipacket,
                        PROTO_UNENCRYPED_JABBER, MMT_CORRELATED_PROTOCOL);
            }
        }
        return;
    }

    if (packet->tcp != 0 && packet->payload_packet_len == 0) {
        return;
    }

    if (((packet->payload_packet_len > 22 && mmt_memcmp(packet->payload, "<message id=", 12) == 0)
                        || (packet->payload_packet_len > 12 && mmt_memcmp(packet->payload, "<iq id=", 7) == 0)
                        || (packet->payload_packet_len > 14 && mmt_memcmp(packet->payload, "<iq type=", 9) == 0))
                        && ((mmt_memcmp(&packet->payload[packet->payload_packet_len - 10], "</message>", 10) == 0)
                        || (mmt_memcmp(&packet->payload[packet->payload_packet_len - 5], "</iq>", 5) == 0))) {

        mmt_int_jabber_add_connection(ipacket,
                            PROTO_UNENCRYPED_JABBER, MMT_REAL_PROTOCOL);

    }


    /* this part parses a packet and searches for port=. it works asymmetrically. */
    if (packet->detected_protocol_stack[0] == PROTO_UNENCRYPED_JABBER) {
        uint16_t lastlen;
        uint16_t j_port = 0;
        /* check for google jabber voip connections ... */
        /* need big packet */
        if (packet->payload_packet_len < 100) {
            MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "packet too small, return.\n");
            return;
        }
        /* need message to or type for file-transfer */
        if (mmt_memcmp(packet->payload, "<iq from=\"", 8) == 0 || mmt_memcmp(packet->payload, "<iq from=\'", 8) == 0) {
            MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "JABBER <iq from=\".\n");
            lastlen = packet->payload_packet_len - 11;
            for (x = 10; x < lastlen; x++) {
                if (packet->payload[x] == 'p') {
                    if (mmt_mem_cmp(&packet->payload[x], "port=", 5) == 0) {
                        MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "port=\n");
                        if (src != NULL) {
                            src->jabber_stun_or_ft_ts = packet->tick_timestamp;
                        }

                        if (dst != NULL) {
                            dst->jabber_stun_or_ft_ts = packet->tick_timestamp;
                        }
                        x += 6;
                        j_port = ntohs_mmt_bytestream_to_number(&packet->payload[x], packet->payload_packet_len, &x);
                        MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                MMT_LOG_DEBUG, "JABBER port : %u\n", ntohs(j_port));
                        if (src != NULL) {
                            if (src->jabber_file_transfer_port[0] == 0 || src->jabber_file_transfer_port[0] == j_port) {
                                MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                        MMT_LOG_DEBUG, "src->jabber_file_transfer_port[0] = j_port = %u;\n",
                                        ntohs(j_port));
                                src->jabber_file_transfer_port[0] = j_port;
                            } else {
                                MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                        MMT_LOG_DEBUG, "src->jabber_file_transfer_port[1] = j_port = %u;\n",
                                        ntohs(j_port));
                                src->jabber_file_transfer_port[1] = j_port;
                            }
                        }
                        if (dst != NULL) {
                            if (dst->jabber_file_transfer_port[0] == 0 || dst->jabber_file_transfer_port[0] == j_port) {
                                MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                        MMT_LOG_DEBUG, "dst->jabber_file_transfer_port[0] = j_port = %u;\n",
                                        ntohs(j_port));
                                dst->jabber_file_transfer_port[0] = j_port;
                            } else {
                                MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                        MMT_LOG_DEBUG, "dst->jabber_file_transfer_port[1] = j_port = %u;\n",
                                        ntohs(j_port));
                                dst->jabber_file_transfer_port[1] = j_port;
                            }
                        }
                    }


                }
            }

        } else if (mmt_memcmp(packet->payload, "<iq to=\"", 8) == 0 || mmt_memcmp(packet->payload, "<iq to=\'", 8) == 0
                || mmt_memcmp(packet->payload, "<iq type=", 9) == 0) {
            MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "JABBER <iq to=\"/type=\"\n");
            lastlen = packet->payload_packet_len - 21;
            for (x = 8; x < lastlen; x++) {
                /* invalid character */
                if (packet->payload[x] < 32 || packet->payload[x] > 127) {
                    return;
                }
                if (packet->payload[x] == '@') {
                    MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "JABBER @\n");
                    break;
                }
            }
            if (x >= lastlen) {
                return;
            }

            lastlen = packet->payload_packet_len - 10;
            for (; x < lastlen; x++) {
                if (packet->payload[x] == 'p') {
                    if (mmt_mem_cmp(&packet->payload[x], "port=", 5) == 0) {
                        MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "port=\n");
                        if (src != NULL) {
                            src->jabber_stun_or_ft_ts = packet->tick_timestamp;
                        }

                        if (dst != NULL) {
                            dst->jabber_stun_or_ft_ts = packet->tick_timestamp;
                        }

                        x += 6;
                        j_port = ntohs_mmt_bytestream_to_number(&packet->payload[x], packet->payload_packet_len, &x);
                        MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                MMT_LOG_DEBUG, "JABBER port : %u\n", ntohs(j_port));

                        if (src != NULL && src->jabber_voice_stun_used_ports < JABBER_MAX_STUN_PORTS - 1) {
                            if (packet->payload[5] == 'o') {
                                src->jabber_voice_stun_port[src->jabber_voice_stun_used_ports++]
                                        = j_port;
                            } else {
                                if (src->jabber_file_transfer_port[0] == 0
                                        || src->jabber_file_transfer_port[0] == j_port) {
                                    MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG,
                                            "src->jabber_file_transfer_port[0] = j_port = %u;\n", ntohs(j_port));
                                    src->jabber_file_transfer_port[0] = j_port;
                                } else {
                                    MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                            MMT_LOG_DEBUG, "src->jabber_file_transfer_port[1] = j_port = %u;\n",
                                            ntohs(j_port));
                                    src->jabber_file_transfer_port[1] = j_port;
                                }
                            }
                        }

                        if (dst != NULL && dst->jabber_voice_stun_used_ports < JABBER_MAX_STUN_PORTS - 1) {
                            if (packet->payload[5] == 'o') {
                                dst->jabber_voice_stun_port[dst->jabber_voice_stun_used_ports++]
                                        = j_port;
                            } else {
                                if (dst->jabber_file_transfer_port[0] == 0
                                        || dst->jabber_file_transfer_port[0] == j_port) {
                                    MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG,
                                            "dst->jabber_file_transfer_port[0] = j_port = %u;\n", ntohs(j_port));
                                    dst->jabber_file_transfer_port[0] = j_port;
                                } else {
                                    MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                                            MMT_LOG_DEBUG, "dst->jabber_file_transfer_port[1] = j_port = %u;\n",
                                            ntohs(j_port));
                                    dst->jabber_file_transfer_port[1] = j_port;
                                }
                            }
                        }
                        return;
                    }
                }
            }
        }
        return;
    }


    /* search for jabber here */
    /* this part is working asymmetrically */
    if ((packet->payload_packet_len > 13 && mmt_memcmp(packet->payload, "<?xml version=", 14) == 0)
            || (packet->payload_packet_len >= 15
            && mmt_memcmp(packet->payload, "<stream:stream ", 15) == 0)) {

        if (packet->payload_packet_len > 47) {
            const uint16_t lastlen = packet->payload_packet_len - 47;
            for (x = 0; x < lastlen; x++) {
                if (mmt_mem_cmp
                        (&packet->payload[x],
                        "xmlns:stream='http://etherx.jabber.org/streams'", 47) == 0
                        || mmt_mem_cmp(&packet->payload[x], "xmlns:stream=\"http://etherx.jabber.org/streams\"", 47) == 0) {
                    MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_TRACE, "found JABBER.\n");
                    x += 47;

                    mmt_int_jabber_add_connection(ipacket,
                            PROTO_UNENCRYPED_JABBER, MMT_REAL_PROTOCOL);



                    /* search for other protocols: Truphone */
                    check_content_type_and_change_protocol(ipacket, x);

                    return;
                }
            }
        }
    }

    if (ipacket->session->data_packet_count < 3) {
        MMT_LOG(PROTO_UNENCRYPED_JABBER, 
                MMT_LOG_TRACE, "packet_counter: %u\n", flow->data_packet_count);
        return;
    }



    MMT_LOG(PROTO_UNENCRYPED_JABBER, MMT_LOG_DEBUG, "Excluding jabber connection\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_UNENCRYPED_JABBER);

#ifdef PROTO_TRUPHONE
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_TRUPHONE);
#endif
}

int mmt_check_jabber(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_jabber_tcp(ipacket, index); //BW: TODO: this seems to be limited to tcp, check this out
    }
    return 4;
}

void mmt_init_classify_me_jabber() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_UNENCRYPED_JABBER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SSL);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_UNENCRYPED_JABBER);
    MMT_ADD_PROTOCOL_TO_BITMASK(excluded_protocol_bitmask, PROTO_TRUPHONE);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_unencryped_jabber_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_UNENCRYPED_JABBER, PROTO_UNENCRYPED_JABBER_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_jabber();
        
        return register_protocol(protocol_struct, PROTO_UNENCRYPED_JABBER);
    } else {
        return 0;
    }
}


