#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_SOULSEEK_TIMEOUT                600

static uint32_t soulseek_connection_ip_tick_timeout = MMT_SOULSEEK_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_soulseek_add_connection(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_internal_add_connection(ipacket, PROTO_SOULSEEK, MMT_REAL_PROTOCOL);

    if (src != NULL) {
        src->soulseek_last_safe_access_time = packet->tick_timestamp;
    }
    if (dst != NULL) {
        dst->soulseek_last_safe_access_time = packet->tick_timestamp;
    }

    return;
}

int mmt_classify_me_soulseek_tcp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "Soulseek: search soulseec tcp \n");


    if (packet->detected_protocol_stack[0] == PROTO_SOULSEEK) {
        MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "packet marked as Soulseek\n");
        if (src != NULL)
            MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG,
                "  SRC bitmask: %u, packet tick %llu , last safe access timestamp: %llu\n",
                MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, PROTO_SOULSEEK)
                != 0 ? 1 : 0, (uint64_t) packet->tick_timestamp, (uint64_t) src->soulseek_last_safe_access_time);
        if (dst != NULL)
            MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG,
                "  DST bitmask: %u, packet tick %llu , last safe ts: %llu\n",
                MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, PROTO_SOULSEEK)
                != 0 ? 1 : 0, (uint64_t) packet->tick_timestamp, (uint64_t) dst->soulseek_last_safe_access_time);

        if (packet->payload_packet_len == 431) {
            if (dst != NULL) {
                dst->soulseek_last_safe_access_time = packet->tick_timestamp;
            }
            return 4;
        }
        if (packet->payload_packet_len == 12 && get_l32(packet->payload, 4) == 0x02) {
            if (src != NULL) {
                src->soulseek_last_safe_access_time = packet->tick_timestamp;
                if (packet->tcp != NULL && src->soulseek_listen_port == 0) {
                    src->soulseek_listen_port = get_l32(packet->payload, 8);
                    return 4;
                }
            }
        }

        if (src != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp -
                src->soulseek_last_safe_access_time) <
                soulseek_connection_ip_tick_timeout)) {
            MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG,
                    "Soulseek: SRC update last safe access time and SKIP_FOR_TIME \n");
            src->soulseek_last_safe_access_time = packet->tick_timestamp;
        }

        if (dst != NULL && ((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp -
                dst->soulseek_last_safe_access_time) <
                soulseek_connection_ip_tick_timeout)) {
            MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG,
                    "Soulseek: DST update last safe access time and SKIP_FOR_TIME \n");
            dst->soulseek_last_safe_access_time = packet->tick_timestamp;
        }
    }


    if (dst != NULL && dst->soulseek_listen_port != 0 && dst->soulseek_listen_port == ntohs(packet->tcp->dest)
            && ((MMT_INTERNAL_TIMESTAMP_TYPE)
            (packet->tick_timestamp - dst->soulseek_last_safe_access_time) <
            soulseek_connection_ip_tick_timeout)) {
        MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG,
                "Soulseek: Plain detection on Port : %u packet_tick_timestamp: %u soulseeek_last_safe_access_time: %u soulseek_connection_ip_ticktimeout: %u\n",
                dst->soulseek_listen_port, packet->tick_timestamp,
                dst->soulseek_last_safe_access_time, soulseek_connection_ip_tick_timeout);
        mmt_int_soulseek_add_connection(ipacket);
        return 1;
    }

    if (flow->l4.tcp.soulseek_stage == 0) {

        uint32_t index = 0;

        if (packet->payload_packet_len >= 12 && packet->payload_packet_len < 300 && get_l32(packet->payload, 4) == 1) {
            while (!get_u16(packet->payload, index + 2)
                    && (index + get_l32(packet->payload, index)) < packet->payload_packet_len - 4) {
                if (get_l32(packet->payload, index) < 8) /*Minimum soulsek  login msg is 8B */
                    break;

                if (index + get_l32(packet->payload, index) + 4 <= index) {
                    /* avoid overflow */
                    break;
                }

                index += get_l32(packet->payload, index) + 4;
            }
            if (index + get_l32(packet->payload, index) ==
                    packet->payload_packet_len - 4 && !get_u16(packet->payload, 10)) {
                /*This structure seems to be soulseek proto */
                index = get_l32(packet->payload, 8) + 12; // end of "user name"
                if ((index + 4) <= packet->payload_packet_len && !get_u16(packet->payload, index + 2)) // for passwd len
                {
                    index += get_l32(packet->payload, index) + 4; //end of  "Passwd"
                    if ((index + 4 + 4) <= packet->payload_packet_len && !get_u16(packet->payload, index + 6)) // to read version,hashlen
                    {
                        index += get_l32(packet->payload, index + 4) + 8; // enf of "hash value"
                        if (index == get_l32(packet->payload, 0)) {
                            MMT_LOG(PROTO_SOULSEEK,
                                    MMT_LOG_DEBUG, "Soulseek Login Detected\n");
                            mmt_int_soulseek_add_connection(ipacket);
                            return 1;
                        }
                    }
                }
            }
        }
        if (packet->payload_packet_len > 8
                && packet->payload_packet_len < 200 && get_l32(packet->payload, 0) == packet->payload_packet_len - 4) {
            //Server Messages:
            const uint32_t msgcode = get_l32(packet->payload, 4);

            if (msgcode == 0x7d) {
                flow->l4.tcp.soulseek_stage = 1 + ipacket->session->last_packet_direction;
                MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "Soulseek Messages Search\n");
                return 4;
            } else if (msgcode == 0x02 && packet->payload_packet_len == 12) {
                const uint32_t soulseek_listen_port = get_l32(packet->payload, 8);

                if (src != NULL) {
                    src->soulseek_last_safe_access_time = packet->tick_timestamp;

                    if (packet->tcp != NULL && src->soulseek_listen_port == 0) {
                        src->soulseek_listen_port = soulseek_listen_port;
                        MMT_LOG(PROTO_SOULSEEK, 
                                MMT_LOG_DEBUG, "\n Listen Port Saved : %u", src->soulseek_listen_port);
                        mmt_int_soulseek_add_connection(ipacket);
                        return 1;
                    }
                }

            }
            //Peer Messages  : Peer Init Message Detection
            if (get_l32(packet->payload, 0) == packet->payload_packet_len - 4) {
                const uint32_t typelen = get_l32(packet->payload, packet->payload_packet_len - 9);
                const uint8_t type = packet->payload[packet->payload_packet_len - 5];
                const uint32_t namelen = get_l32(packet->payload, 5);
                if (packet->payload[4] == 0x01 && typelen == 1
                        && namelen <= packet->payload_packet_len
                        && (4 + 1 + 4 + namelen + 4 + 1 + 4) ==
                        packet->payload_packet_len && (type == 'F' || type == 'P' || type == 'D')) {
                    MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "soulseek detected\n");
                    mmt_int_soulseek_add_connection(ipacket);
                    return 1;
                }
                MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "1\n");
            }
            MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "3\n");
            //Peer Message : Pierce Firewall
            if (packet->payload_packet_len == 9 && get_l32(packet->payload, 0) == 5
                    && packet->payload[4] <= 0x10 && get_u32(packet->payload, 5) != 0x00000000) {
                flow->l4.tcp.soulseek_stage = 1 + ipacket->session->last_packet_direction;
                MMT_LOG(PROTO_SOULSEEK, MMT_LOG_TRACE, "Soulseek Size 9 Pierce Firewall\n");
                return 4;
            }

        }

        if (packet->payload_packet_len > 25 && packet->payload[4] == 0x01 && !get_u16(packet->payload, 7)
                && !get_u16(packet->payload, 2)) {
            const uint32_t usrlen = get_l32(packet->payload, 5);

            if (usrlen <= packet->payload_packet_len - 4 + 1 + 4 + 4 + 1 + 4) {
                const uint32_t typelen = get_l32(packet->payload, 4 + 1 + 4 + usrlen);
                const uint8_t type = packet->payload[4 + 1 + 4 + usrlen + 4];
                if (typelen == 1 && (type == 'F' || type == 'P' || type == 'D')) {
                    MMT_LOG(PROTO_SOULSEEK, 
                            MMT_LOG_DEBUG, "soulseek detected Pattern command(D|P|F).\n");
                    mmt_int_soulseek_add_connection(ipacket);
                    return 1;
                }
            }
        }

    } else if (flow->l4.tcp.soulseek_stage == 2 - ipacket->session->last_packet_direction) {
        if (packet->payload_packet_len > 8) {
            if ((packet->payload[0] || packet->payload[1]) && get_l32(packet->payload, 4) == 9) {
                /* 9 is search result */
                MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "soulseek detected Second Pkt\n");
                mmt_int_soulseek_add_connection(ipacket);
                return 1;
            }
            if (get_l32(packet->payload, 0) == packet->payload_packet_len - 4) {
                const uint32_t msgcode = get_l32(packet->payload, 4);
                if (msgcode == 0x03 && packet->payload_packet_len >= 12) //Server Message : Get Peer Address
                {
                    const uint32_t usrlen = get_l32(packet->payload, 8);
                    if (usrlen <= packet->payload_packet_len && 4 + 4 + 4 + usrlen == packet->payload_packet_len) {
                        MMT_LOG(PROTO_SOULSEEK, 
                                MMT_LOG_DEBUG, "Soulseek Request Get Peer Address Detected\n");
                        mmt_int_soulseek_add_connection(ipacket);
                        return 1;
                    }
                }
            }
        }

        if (packet->payload_packet_len == 8 && get_l32(packet->payload, 4) == 0x00000004) {
            MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "soulseek detected\n");
            mmt_int_soulseek_add_connection(ipacket);
            return 1;
        }

        if (packet->payload_packet_len == 4
                && get_u16(packet->payload, 2) == 0x00 && get_u16(packet->payload, 0) != 0x00) {
            MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "soulseek detected\n");
            mmt_int_soulseek_add_connection(ipacket);
            return 1;
        } else if (packet->payload_packet_len == 4) {
            flow->l4.tcp.soulseek_stage = 3;
            return 4;
        }
    } else if (flow->l4.tcp.soulseek_stage == 1 + ipacket->session->last_packet_direction) {
        if (packet->payload_packet_len > 8) {
            if (packet->payload[4] == 0x03 && get_l32(packet->payload, 5) == 0x00000031) {
                MMT_LOG(PROTO_SOULSEEK, 
                        MMT_LOG_DEBUG, "soulseek detected Second Pkt with SIGNATURE :: 0x0331000000 \n");
                mmt_int_soulseek_add_connection(ipacket);
                return 1;
            }
        }
    }
    if (flow->l4.tcp.soulseek_stage == 3 && packet->payload_packet_len == 8 && !get_u32(packet->payload, 4)) {

        MMT_LOG(PROTO_SOULSEEK, MMT_LOG_DEBUG, "soulseek detected bcz of 8B  pkt\n");
        mmt_int_soulseek_add_connection(ipacket);
        return 1;
    }
    if (flow->l4.tcp.soulseek_stage && ipacket->session->data_packet_count < 11) {
        return 4;
    } else {
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SOULSEEK);
        return 0;
    }
}

int mmt_check_soulseek(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

       return mmt_classify_me_soulseek_tcp(ipacket, index);
    }
    return 4;
}

void mmt_init_classify_me_soulseek() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOULSEEK);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SOULSEEK);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_soulseek_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SOULSEEK, PROTO_SOULSEEK_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_soulseek();
        
        return register_protocol(protocol_struct, PROTO_SOULSEEK);
    } else {
        return 0;
    }
}


