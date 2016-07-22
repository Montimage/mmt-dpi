#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define DIRECT_CONNECT_TYPE_HUB  0
#define DIRECT_CONNECT_TYPE_PEER 1
#define DIRECT_CONNECT_ADC_PEER  2
#define MMT_DIRECTCONNECT_TIMEOUT           600

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static uint32_t directconnect_connection_ip_tick_timeout = MMT_DIRECTCONNECT_TIMEOUT * MMT_MICRO_IN_SEC;

static uint32_t skip_unknown_headers(const uint8_t * payload, uint32_t payload_len, uint32_t pos) {
    uint32_t i = pos;
    while (i < payload_len && payload[i] != 0x0a)
        i++;

    i++;
    return i;

}

static uint16_t parse_binf_message(const uint8_t * payload, int payload_len) {
    uint32_t i = 4;
    uint16_t bytes_read = 0;
    uint16_t ssl_port = 0;
    while (i < payload_len) {
        i = skip_unknown_headers(payload, payload_len, i);
        if ((i + 30) < payload_len) {
            if (memcmp(&payload[i], "DCTM", 4) == 0) {
                if (memcmp(&payload[i + 15], "ADCS", 4) == 0) {
                    ssl_port = ntohs_mmt_bytestream_to_number(&payload[i + 25], 5, &bytes_read);
                    MMT_LOG(PROTO_DIRECTCONNECT, 
                            MMT_LOG_DEBUG, "directconnect ssl port parsed %d", ssl_port);

                }
            }
        } else {
            break;
        }

    }
    return ssl_port;
}

static void mmt_int_directconnect_add_connection(ipacket_t * ipacket, const uint8_t connection_type) {
    
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_DIRECTCONNECT, MMT_REAL_PROTOCOL);

    if (src != NULL) {
        src->directconnect_last_safe_access_time = packet->tick_timestamp;
        if (connection_type == DIRECT_CONNECT_TYPE_PEER) {
            if (packet->tcp != NULL
                    && ipacket->session->setup_packet_direction != ipacket->session->last_packet_direction && src->detected_directconnect_port == 0) {
                src->detected_directconnect_port = packet->tcp->source;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "directconnect tcp PORT %u for src\n", ntohs(src->detected_directconnect_port));
            }
            if (packet->udp != NULL && src->detected_directconnect_udp_port == 0) {
                src->detected_directconnect_udp_port = packet->udp->source;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "directconnect udp PORT %u for src\n", ntohs(src->detected_directconnect_port));

            }
        }

    }
    if (dst != NULL) {
        dst->directconnect_last_safe_access_time = packet->tick_timestamp;
        if (connection_type == DIRECT_CONNECT_TYPE_PEER) {
            if (packet->tcp != NULL
                    && ipacket->session->setup_packet_direction == ipacket->session->last_packet_direction && dst->detected_directconnect_port == 0) {
                /* DST PORT MARKING CAN LEAD TO PORT MISSDETECTIONS
                 * seen at large customer http servers, where someone has send faked DC tcp packets
                 * to the server
                 */

                /*
                   dst->detected_directconnect_port = packet->tcp->dest;
                 */
            }
        }
    }
}

static void mmt_search_directconnect_tcp(ipacket_t * ipacket) {
    
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;

    if (flow->detected_protocol_stack[0] == PROTO_DIRECTCONNECT) {
        if (packet->payload_packet_len >= 40 && memcmp(&packet->payload[0], "BINF", 4) == 0) {
            uint16_t ssl_port = 0;
            ssl_port = parse_binf_message(&packet->payload[4], packet->payload_packet_len - 4);
            if (dst != NULL && ssl_port) {
                dst->detected_directconnect_ssl_port = ssl_port;
            }
            if (src != NULL && ssl_port) {
                src->detected_directconnect_ssl_port = ssl_port;
            }


        }
        if ((packet->payload_packet_len >= 38 && packet->payload_packet_len <= 42)
                && memcmp(&packet->payload[0], "DCTM", 4) == 0 && memcmp(&packet->payload[15], "ADCS", 4) == 0) {
            uint16_t bytes_read = 0;
            if (dst != NULL) {
                dst->detected_directconnect_ssl_port =
                        ntohs_mmt_bytestream_to_number(&packet->payload[25], 5, &bytes_read);
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "directconnect ssl port parsed %d", ntohs(dst->detected_directconnect_ssl_port));
            }
            if (src != NULL) {
                src->detected_directconnect_ssl_port =
                        ntohs_mmt_bytestream_to_number(&packet->payload[25], 5, &bytes_read);
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "directconnect ssl port parsed %d", ntohs(src->detected_directconnect_ssl_port));
            }


        }
        return;

    }
    if (src != NULL) {
        if (src->detected_directconnect_port == packet->tcp->source) {
            if ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    src->directconnect_last_safe_access_time) < directconnect_connection_ip_tick_timeout) {
                mmt_change_internal_flow_packet_protocol(ipacket, PROTO_DIRECTCONNECT, MMT_REAL_PROTOCOL);
                src->directconnect_last_safe_access_time = packet->tick_timestamp;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "marking using dc port\n %d", ntohs(src->detected_directconnect_port));
                return;
            } else {
                src->detected_directconnect_port = 0;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "resetting src port due to timeout");
                return;
            }
        }
        if (src->detected_directconnect_ssl_port == packet->tcp->dest) {
            if ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    src->directconnect_last_safe_access_time) < directconnect_connection_ip_tick_timeout) {
                mmt_change_internal_flow_packet_protocol(ipacket, PROTO_DIRECTCONNECT, MMT_REAL_PROTOCOL);
                src->directconnect_last_safe_access_time = packet->tick_timestamp;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "marking using dc port\n %d", ntohs(src->detected_directconnect_ssl_port));
                return;
            } else {
                src->detected_directconnect_ssl_port = 0;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "resetting src port due to timeout");
                return;
            }
        }

    }

    if (dst != NULL) {
        if (dst->detected_directconnect_port == packet->tcp->dest) {
            if ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    dst->directconnect_last_safe_access_time) < directconnect_connection_ip_tick_timeout) {
                mmt_internal_add_connection(ipacket, PROTO_DIRECTCONNECT, MMT_REAL_PROTOCOL);
                dst->directconnect_last_safe_access_time = packet->tick_timestamp;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "marking using dc port\n %d", ntohs(dst->detected_directconnect_port));
                return;
            } else {
                dst->detected_directconnect_port = 0;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "resetting dst port due to timeout");
                return;
            }
        }
        if (dst->detected_directconnect_ssl_port == packet->tcp->dest) {
            if ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    dst->directconnect_last_safe_access_time) < directconnect_connection_ip_tick_timeout) {
                mmt_internal_add_connection(ipacket, PROTO_DIRECTCONNECT, MMT_REAL_PROTOCOL);
                dst->directconnect_last_safe_access_time = packet->tick_timestamp;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "marking using dc port\n %d", ntohs(dst->detected_directconnect_ssl_port));

                return;
            } else {
                dst->detected_directconnect_ssl_port = 0;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "resetting dst port due to timeout");
                return;
            }
        }

    }

    if (flow->directconnect_stage == 0) {

        if (packet->payload_packet_len > 6) {
            if (packet->payload[0] == '$'
                    && packet->payload[packet->payload_packet_len - 1] == '|'
                    && (memcmp(&packet->payload[1], "Lock ", 5) == 0)) {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "maybe first dc connect to hub  detected\n");
                flow->directconnect_stage = 1;
                return;
            }
            if (packet->payload_packet_len > 7
                    && packet->payload[0] == '$'
                    && packet->payload[packet->payload_packet_len - 1] == '|'
                    && (memcmp(&packet->payload[1], "MyNick ", 7) == 0)) {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "maybe first dc connect between peers  detected\n");
                flow->directconnect_stage = 2;
                return;
            }

        }
        if (packet->payload_packet_len >= 11) {
            /* did not see this pattern in any trace */
            if (memcmp(&packet->payload[0], "HSUP ADBAS0", 11) == 0
                    || memcmp(&packet->payload[0], "HSUP ADBASE", 11) == 0) {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "found directconnect HSUP ADBAS0 E\n");
                mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_TYPE_HUB);
                return;
                /* did not see this pattern in any trace */
            } else if (memcmp(&packet->payload[0], "CSUP ADBAS0", 11) == 0 ||
                    memcmp(&packet->payload[0], "CSUP ADBASE", 11) == 0) {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "found directconnect CSUP ADBAS0 E\n");
                mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_ADC_PEER);
                return;

            }

        }

    } else if (flow->directconnect_stage == 1) {
        if (packet->payload_packet_len >= 11) {
            /* did not see this pattern in any trace */
            if (memcmp(&packet->payload[0], "HSUP ADBAS0", 11) == 0
                    || memcmp(&packet->payload[0], "HSUP ADBASE", 11) == 0) {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "found directconnect HSUP ADBAS E in second packet\n");
                mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_TYPE_HUB);

                return;
                /* did not see this pattern in any trace */
            } else if (memcmp(&packet->payload[0], "CSUP ADBAS0", 11) == 0 ||
                    memcmp(&packet->payload[0], "CSUP ADBASE", 11) == 0) {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "found directconnect HSUP ADBAS0 E in second packet\n");
                mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_ADC_PEER);


                return;

            }
        }
        /* get client hello answer or server message */
        if (packet->payload_packet_len > 6) {
            if ((packet->payload[0] == '$' || packet->payload[0] == '<')
                    && packet->payload[packet->payload_packet_len - 1] == '|') {
                MMT_LOG(PROTO_DIRECTCONNECT, MMT_LOG_DEBUG, "second dc detected\n");
                mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_TYPE_HUB);

                return;
            } else {
                MMT_LOG(PROTO_DIRECTCONNECT, MMT_LOG_DEBUG, "second dc not detected\n");
            }

        }
    } else if (flow->directconnect_stage == 2) {
        /* get client hello answer or server message */
        if (packet->payload_packet_len > 6) {
            if (packet->payload[0] == '$' && packet->payload[packet->payload_packet_len - 1] == '|') {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "second dc between peers detected\n");


                mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_TYPE_PEER);

                return;
            } else {
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "second dc between peers not detected\n");
            }
        }

    }


    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DIRECTCONNECT);

}

static void mmt_search_directconnect_udp(ipacket_t * ipacket) {
    
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;
    int pos, count = 0;


    if (dst != NULL && dst->detected_directconnect_udp_port == packet->udp->dest) {
        if ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp -
                dst->directconnect_last_safe_access_time) < directconnect_connection_ip_tick_timeout) {

            mmt_internal_add_connection(ipacket, PROTO_DIRECTCONNECT, MMT_REAL_PROTOCOL);
            dst->directconnect_last_safe_access_time = packet->tick_timestamp;
            MMT_LOG(PROTO_DIRECTCONNECT, 
                    MMT_LOG_DEBUG, "marking using dc udp port\n %d", ntohs(dst->detected_directconnect_udp_port));
            return;
        } else {
            dst->detected_directconnect_udp_port = 0;
            MMT_LOG(PROTO_DIRECTCONNECT, 
                    MMT_LOG_DEBUG, "resetting dst udp  port due to timeout");
            return;
        }
    }

    if (packet->payload_packet_len > 58) {
        if (src != NULL
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_DIRECTCONNECT)) {
            if (packet->payload[0] == '$'
                    && packet->payload[packet->payload_packet_len - 1] == '|'
                    && memcmp(&packet->payload[1], "SR ", 3) == 0) {
                pos = packet->payload_packet_len - 2;
                if (packet->payload[pos] == ')') {
                    while (pos > 0 && packet->payload[pos] != '(' && count < 21) {
                        pos--;
                        count++;
                    }
                    if (packet->payload[pos] == '(') {
                        pos = pos - 44;
                        if (pos > 2 && memcmp(&packet->payload[pos], "TTH:", 4) == 0) {
                            MMT_LOG(PROTO_DIRECTCONNECT, MMT_LOG_DEBUG, "dc udp detected\n");
                            mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_TYPE_PEER);
                            return;
                        }
                    }
                }
                flow->directconnect_stage++;

                if (flow->directconnect_stage < 3) {


                    return;
                }

            }

        }
        if (dst != NULL
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_DIRECTCONNECT)) {
            if (packet->payload[0] == '$'
                    && packet->payload[packet->payload_packet_len - 1] == '|'
                    && memcmp(&packet->payload[1], "SR ", 3) == 0) {
                pos = packet->payload_packet_len - 2;
                if (packet->payload[pos] == ')') {
                    while (pos > 0 && packet->payload[pos] != '(' && count < 21) {
                        pos--;
                        count++;
                    }
                    if (packet->payload[pos] == '(') {
                        pos = pos - 44;
                        if (pos > 2 && memcmp(&packet->payload[pos], "TTH:", 4) == 0) {
                            MMT_LOG(PROTO_DIRECTCONNECT, MMT_LOG_DEBUG, "dc udp detected\n");
                            mmt_int_directconnect_add_connection(ipacket, DIRECT_CONNECT_TYPE_PEER);
                            return;
                        }
                    }
                }
                flow->directconnect_stage++;
                if (flow->directconnect_stage < 3)
                    return;

            }
        }

    }
    MMT_LOG(PROTO_DIRECTCONNECT, MMT_LOG_DEBUG,
            "excluded at stage %d \n", flow->directconnect_stage);



    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DIRECTCONNECT);


}

void mmt_classify_me_directconnect(ipacket_t * ipacket, unsigned index) {
    
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;

    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;

    if (packet->detected_protocol_stack[0] == PROTO_DIRECTCONNECT) {
        if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp -
                src->directconnect_last_safe_access_time) <
                directconnect_connection_ip_tick_timeout)) {
            src->directconnect_last_safe_access_time = packet->tick_timestamp;

        } else if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp -
                dst->directconnect_last_safe_access_time) <
                directconnect_connection_ip_tick_timeout)) {
            dst->directconnect_last_safe_access_time = packet->tick_timestamp;
        } else {
            packet->detected_protocol_stack[0] = PROTO_UNKNOWN;
            MMT_LOG(PROTO_DIRECTCONNECT, 
                    MMT_LOG_DEBUG, "directconnect: skipping as unknown due to timeout\n");
        }
        return;
    }

    if (packet->tcp != NULL) {
        mmt_search_directconnect_tcp(ipacket);
    }
    if (packet->udp != NULL) {
        mmt_search_directconnect_udp(ipacket);
    }
}

int mmt_check_directconnect_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_id_struct *src = packet->src;
        struct mmt_internal_tcpip_id_struct *dst = packet->dst;

        if (packet->detected_protocol_stack[0] == PROTO_DIRECTCONNECT) {
            if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    src->directconnect_last_safe_access_time) <
                    directconnect_connection_ip_tick_timeout)) {
                src->directconnect_last_safe_access_time = packet->tick_timestamp;

            } else if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    dst->directconnect_last_safe_access_time) <
                    directconnect_connection_ip_tick_timeout)) {
                dst->directconnect_last_safe_access_time = packet->tick_timestamp;
            } else {
                packet->detected_protocol_stack[0] = PROTO_UNKNOWN;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "directconnect: skipping as unknown due to timeout\n");
            }
            return 4;
        }

        mmt_search_directconnect_tcp(ipacket);
    }
    return 4;
}

int mmt_check_directconnect_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_id_struct *src = packet->src;
        struct mmt_internal_tcpip_id_struct *dst = packet->dst;

        if (packet->detected_protocol_stack[0] == PROTO_DIRECTCONNECT) {
            if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    src->directconnect_last_safe_access_time) <
                    directconnect_connection_ip_tick_timeout)) {
                src->directconnect_last_safe_access_time = packet->tick_timestamp;

            } else if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp -
                    dst->directconnect_last_safe_access_time) <
                    directconnect_connection_ip_tick_timeout)) {
                dst->directconnect_last_safe_access_time = packet->tick_timestamp;
            } else {
                packet->detected_protocol_stack[0] = PROTO_UNKNOWN;
                MMT_LOG(PROTO_DIRECTCONNECT, 
                        MMT_LOG_DEBUG, "directconnect: skipping as unknown due to timeout\n");
            }
            return 4;
        }

        mmt_search_directconnect_udp(ipacket);
    }
    return 4;
}

void mmt_init_classify_me_directconnect() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_RDP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_directconnect_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DIRECTCONNECT, PROTO_DIRECTCONNECT_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_directconnect();
        
        return register_protocol(protocol_struct, PROTO_DIRECTCONNECT);
    } else {
        return 0;
    }
}


