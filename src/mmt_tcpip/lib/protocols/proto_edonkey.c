#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
/* debug defines */
#define MMT_PROTOCOL_SAFE_DETECTION    1
#define MMT_PROTOCOL_PLAIN_DETECTION   0
#define MMT_EDONKEY_UPPER_PORTS_ONLY   0

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static uint32_t edonkey_upper_ports_only = MMT_EDONKEY_UPPER_PORTS_ONLY;
/* unused - see below in mmt_int_edonkey_tcp()
static uint32_t edonkey_safe_mode = MMT_PROTOCOL_PLAIN_DETECTION; //BW TODO: Check this out
*/

static int mmt_edonkey_payload_check(const u_int8_t *data, u_int32_t len) {
  
  if ((len >= 4) && (data[0] == 0xe3) && (data[2] == 0x00) && (data[3] == 0x00))
    return 1;
  
  if ((len >= 4) && (data[0] == 0xc5) && (data[2] == 0x00) && (data[3] == 0x00))
    return 1;  
  
  if ((len >= 2) && (data[0] == 0xe5) && (data[1] == 0x43))
    return 1;
  
  if ((len >= 4) && (data[0] == 0xe5) && (data[1] == 0x08) && (data[2] == 0x78) && (data[3] == 0xda))
    return 1;

  if ((len >= 4) && (data[0] == 0xe5) && (data[1] == 0x28) && (data[2] == 0x78) && (data[3] == 0xda))
    return 1;

  if ((len >= 2) && (data[0] == 0xc5) && (data[1] == 0x90))
    return 1;

  if ((len >= 2) && (data[0] == 0xc5) && (data[1] == 0x91))
    return 1;

  if ((len == 2) && (data[0] == 0xc5) && (data[1] == 0x92))
    return 1;

  if ((len == 2) && (data[0] == 0xc5) && (data[1] == 0x93))
    return 1;

  if ((len >= 38 && len <= 70) && (data[0] == 0xc5) && (data[1] == 0x94))
    return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x9a))
    return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x9b))
    return 1;

  if ((len == 6) && (data[0] == 0xe3) && (data[1] == 0x96))
    return 1;

  if ((len <= 34 && ((len - 2) % 4 == 0)) && (data[0] == 0xe3) && (data[1] == 0x97))
    return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x92))
    return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x94))
    return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x98))
    return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0x99))
    return 1;

  if ((len == 6) && (data[0] == 0xe3) && (data[1] == 0xa2))
    return 1;

  if ((len >= 2) && (data[0] == 0xe3) && (data[1] == 0xa3))
    return 1;

  if ((len == 27) && (data[0] == 0xe4) && (data[1] == 0x00))
    return 1;

  if ((len == 529) && (data[0] == 0xe4) && (data[1] == 0x08))
    return 1;

  if ((len == 18) && (data[0] == 0xe4) && (data[1] == 0x01) && (data[2] == 0x00) && (data[3] == 0x00))
    return 1;

  if ((len == 523) && (data[0] == 0xe4) && (data[1] == 0x09))
    return 1;

  if ((len == 35) && (data[0] == 0xe4) && (data[1] == 0x21))
    return 1;

  if ((len == 19) && (data[0] == 0xe4) && (data[1] == 0x4b))
    return 1;

  if ((len >= 2) && (data[0] == 0xe4) && (data[1] == 0x11))
    return 1;

  if ((len == 22 || len == 38 || len == 28) && (data[0] == 0xe4) && (data[1] == 0x19))
    return 1;

  if ((len == 35) && (data[0] == 0xe4) && (data[1] == 0x20))
    return 1;

  if ((len == 27) && (data[0] == 0xe4) && (data[1] == 0x18))
    return 1;

  if ((len == 27) && (data[0] == 0xe4) && (data[1] == 0x10))
    return 1;

  if ((len == 6) && (data[0] == 0xe4) && (data[1] == 0x58))
    return 1;

  if ((len == 4) && (data[0] == 0xe4) && (data[1] == 0x50))
    return 1;

  if ((len == 36) && (data[0] == 0xe4) && (data[1] == 0x52))
    return 1;

  if ((len == 48) && (data[0] == 0xe4) && (data[1] == 0x40))
    return 1;

  if ((len == 225) && (data[0] == 0xe4) && (data[1] == 0x43))
    return 1;

  if ((len == 19) && (data[0] == 0xe4) && (data[1] == 0x48))
    return 1;

  if ((len == 119 || len == 69 || len == 294) && (data[0] == 0xe4) && (data[1] == 0x29))
    return 1;

  if ((len == 119 || len == 69 || len == 294 || len == 44 || len == 269) && (data[0] == 0xe4) && (data[1] == 0x28))
    return 1;

  return 0;
}

static void mmt_add_connection_as_edonkey(ipacket_t * ipacket, const uint8_t save_detection, const uint8_t encrypted_connection) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    mmt_change_internal_flow_packet_protocol(ipacket, PROTO_EDONKEY, MMT_REAL_PROTOCOL);

    if (packet->udp != NULL) {
        insert_to_local_protos(packet->udp->dest, PROTO_EDONKEY, 17 /*UDP*/, &dst->local_protos);
        insert_to_local_protos(packet->udp->source, PROTO_EDONKEY, 17 /*UDP*/, &src->local_protos);
    } else if (packet->tcp != NULL) {
        /* avoid implications of missclassification */
        if(get_proto_id_from_address(ipacket) != PROTO_UNKNOWN) return;

        uint16_t sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
        /* for source and dst port 80 & 443 avoid inserting eDonkey as local proto! avoid false positives */
        if (sport == 80 || sport == 443 || dport == 80 || dport == 443) return;

        insert_to_local_protos(packet->tcp->dest, PROTO_EDONKEY, 6 /*TCP*/, &dst->local_protos);
        insert_to_local_protos(packet->tcp->source, PROTO_EDONKEY, 6 /*TCP*/, &src->local_protos);
    }
}

static uint8_t check_edk_len(const uint8_t * payload, uint16_t payload_packet_len) {
    uint32_t edk_len_parsed = 0;
    // we use a do / while loop here, because we have checked the byte 0 for 0xe3 or 0xc5 already before this call
    do {
        uint32_t edk_len;
        edk_len = get_l32(payload, 1 + edk_len_parsed);

        /* if bigger, return here directly with an error... */
        if (edk_len > payload_packet_len)
            return 0;
        /* this is critical here:
         * if (edk_len + 5) provokes an overflow to zero, we will have an infinite loop...
         * the check above does prevent this, bcause the edk_len must be ((u32)-5), which is always bigger than the packet size
         */
        edk_len_parsed += 5 + edk_len;

        if (edk_len_parsed == payload_packet_len)
            return 1;
        if (edk_len_parsed > payload_packet_len)
            return 0;
    } while (payload[edk_len_parsed] == 0xe3 || payload[edk_len_parsed] == 0xc5 || payload[edk_len_parsed] == 0xd4);
    return 0;
}

int mmt_int_edonkey_tcp(ipacket_t * ipacket) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    /* unused
    int edk_stage2_len;
    */

    /*len range increase if safe mode and also only once */
    /* unused
    if (edonkey_safe_mode == 0)
        edk_stage2_len = 140;
    else if (!flow->l4.tcp.edk_ext || packet->payload_packet_len == 212) {
        edk_stage2_len = 300;

    } else
        edk_stage2_len = 140;
    */

    /* skip excluded connections */
    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_EDONKEY) != 0)
        return 0;

    /* source and dst port must be 80 443 or > 1024 */
    if (edonkey_upper_ports_only != 0) {
        uint16_t port;
        port = ntohs(packet->tcp->source);
        /* source and dst port must be 80 443 or > 1024 */
        if (port < 1024 && port != 80 && port != 443)
            goto exclude_edk_tcp;

        port = ntohs(packet->tcp->dest);
        if (port < 1024 && port != 80 && port != 443)
            goto exclude_edk_tcp;
    }

    /* return here for empty packets, we needed them only for bt port detection */
    if (packet->payload_packet_len == 0)
        return 4;

    /* skip marked packets */
    if (flow->edk_stage == 0 && packet->detected_protocol_stack[0] != PROTO_UNKNOWN)
        return 4;

    //Check with local protos
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    uint32_t app;
    app = check_local_proto_by_port_nb(packet->tcp->dest, &dst->local_protos);
    if (app == PROTO_EDONKEY) {
        mmt_add_connection_as_edonkey(ipacket, MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION);
        return 1; 
    }
    app = check_local_proto_by_port_nb(packet->tcp->source, &src->local_protos);
    if (app == PROTO_EDONKEY) {
        mmt_add_connection_as_edonkey(ipacket, MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION);
        return 1;
    }

    /* first: check for unencrypted traffic */
    if (flow->edk_stage == 0) {
        /* check for client hello */
        if (packet->payload_packet_len >= 32 && get_l32(packet->payload, 1) <= (packet->payload_packet_len - 5)
                && (packet->payload[0] == 0xe3 || packet->payload[0] == 0xc5)) {

            if (packet->payload[5] == 0x01 && ((packet->payload[6] == 0x10 && get_l32(packet->payload, 29) < 0x0F)
                    || (get_l32(packet->payload, 28) > 0x00
                    && get_l32(packet->payload, 28) < 0x0F))) {
                MMT_LOG_EDONKEY(PROTO_EDONKEY, MMT_LOG_DEBUG,
                        "edk hello meta tag recognized\n");
                flow->edk_stage = 16 + ipacket->session->last_packet_direction;
                return 4;
            }
        }
    }
    if ((17 - ipacket->session->last_packet_direction) == flow->edk_stage) {
        if ((packet->payload_packet_len >= 32 && get_l32(packet->payload, 1) == 9 && (packet->payload[0] == 0xe3)
                && packet->payload[5] == 0x40)
                || (packet->payload_packet_len >= 32 && (packet->payload[0] == 0xe3)
                && packet->payload[5] == 0x40 && check_edk_len(packet->payload, packet->payload_packet_len))
                || (packet->payload_packet_len >= 32 && packet->payload[0] == 0xe3
                && packet->payload[5] == 0x4c && (get_l32(packet->payload, 1) == (packet->payload_packet_len - 5)
                || check_edk_len(packet->payload, packet->payload_packet_len)))
                || (packet->payload_packet_len >= 32 && get_l32(packet->payload, 1) == (packet->payload_packet_len - 5)
                && packet->payload[0] == 0xe3 && packet->payload[5] == 0x38)
                || (packet->payload_packet_len >= 20 && get_l32(packet->payload, 1) == (packet->payload_packet_len - 5)
                && packet->payload[0] == 0xc5 && packet->payload[5] == 0x92)
                || (packet->payload_packet_len >= 20 && get_l32(packet->payload, 1) <= (packet->payload_packet_len - 5)
                && packet->payload[0] == 0xe3 && packet->payload[5] == 0x58)
                || (packet->payload_packet_len >= 20 && get_l32(packet->payload, 1) <= (packet->payload_packet_len - 5)
                && (packet->payload[0] == 0xe3 || packet->payload[0] == 0xc5)
                && packet->payload[5] == 0x01)) {
            MMT_LOG_EDONKEY(PROTO_EDONKEY,
                    MMT_LOG_DEBUG, "edk 17: detected plain detection\n");
            mmt_add_connection_as_edonkey(ipacket,
                    MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION);
            return 1;
        }

        MMT_LOG_EDONKEY(PROTO_EDONKEY, MMT_LOG_DEBUG,
                "edk 17: id: %u, %u, %u not detected\n",
                packet->payload[0], get_l32(packet->payload, 1), packet->payload[5]);
    }
exclude_edk_tcp:

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_EDONKEY);

    return 0;
}

int mmt_int_edonkey_udp(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* skip excluded connections */
    if (MMT_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_EDONKEY) != 0)
        return 0;

    /* source and dst port must be 80 443 or > 1024 */
    if (edonkey_upper_ports_only != 0) {
        uint16_t port;
        port = ntohs(packet->udp->source);
        /* source and dst port must be 80 443 or > 1024 */
        if (port < 1024 && port != 80 && port != 443)
            goto exclude_edk_udp;

        port = ntohs(packet->udp->dest);
        if (port < 1024 && port != 80 && port != 443)
            goto exclude_edk_udp;
    }

    /* return here for empty packets, we needed them only for bt port detection */
    if (packet->payload_packet_len == 0)
        return 4;

    /* skip marked packets */
    if (flow->edk_stage == 0 && packet->detected_protocol_stack[0] != PROTO_UNKNOWN)
        return 4;

    //Check with local protos
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    uint32_t app;
    app = check_local_proto_by_port_nb(packet->udp->dest, &dst->local_protos);
    if (app == PROTO_EDONKEY) {
        mmt_add_connection_as_edonkey(ipacket, MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION);
        return 1;
    }
    app = check_local_proto_by_port_nb(packet->udp->source, &src->local_protos);
    if (app == PROTO_EDONKEY) {
        mmt_add_connection_as_edonkey(ipacket, MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION);
        return 1;
    }

    if ((packet->payload_packet_len >= 19) && (packet->payload[0] == 0xe4)) {
        if ((packet->payload_packet_len == 35) && (packet->payload[1] == 0x21)) {
            flow->edk_stage += 2;
        } else if ((packet->payload_packet_len == 19) && ((packet->payload[1] == 0x4b) || (packet->payload[1] == 0x48) || (packet->payload[1] == 0x30))) {
            flow->edk_stage += 2;
        } else if ((packet->payload_packet_len == 35) && (packet->payload[1] == 0x20)) {
            flow->edk_stage += 2;
        } else if ((packet->payload_packet_len == 27) && (packet->payload[1] == 0x10 || packet->payload[1] == 0x18)) {
            flow->edk_stage += 2;
        } else if ((packet->payload_packet_len >= 19) && (packet->payload[1] == 0x29 || packet->payload[1] == 0x28) && (packet->payload_packet_len == (19 + packet->payload[18] * 25))) {
            flow->edk_stage += 1;
        } else if ((packet->payload_packet_len > 19) && ((packet->payload[1] == 0x43) || (packet->payload[1] == 0x38))) {
            flow->edk_stage += 1;
        } else if ((packet->payload_packet_len > 22) && ((packet->payload[1] == 0x11) || (packet->payload[1] == 0x19))) {
            flow->edk_stage += 1;
        }
    }

    if(packet->payload_packet_len == 6 && mmt_edonkey_payload_check(packet->payload,packet->payload_packet_len)){
        mmt_add_connection_as_edonkey(ipacket, MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION);
        return 1;
    }

    if (flow->edk_stage >= 6) { //This is edonkey flow
        mmt_add_connection_as_edonkey(ipacket, MMT_PROTOCOL_SAFE_DETECTION, MMT_PROTOCOL_PLAIN_DETECTION);
        return 1;
    }

    if (ipacket->session->data_packet_count > 10) {
        goto exclude_edk_udp;
    } else {
        return 4; //Wait next packet
    }

exclude_edk_udp:

    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_EDONKEY);

    return 0;
}

void mmt_classify_me_edonkey(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (packet->detected_protocol_stack[0] != PROTO_EDONKEY) {
        /* check for retransmission here */
        if (packet->tcp != NULL && packet->tcp_retransmission == 0)
            mmt_int_edonkey_tcp(ipacket);
    }
}

int mmt_check_edonkey(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        if (packet->detected_protocol_stack[0] != PROTO_EDONKEY) {
            /* check for retransmission here */
            if (packet->tcp != NULL && packet->tcp_retransmission == 0) {
                return mmt_int_edonkey_tcp(ipacket);
            } else if (packet->udp != NULL) {
                return mmt_int_edonkey_udp(ipacket);
            }
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(packet->flow->excluded_protocol_bitmask, PROTO_EDONKEY);
    }
    return 0;
}

void mmt_init_classify_me_edonkey() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_EDONKEY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BITTORRENT);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_EDONKEY);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_edonkey_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_EDONKEY, PROTO_EDONKEY_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_edonkey();

        return register_protocol(protocol_struct, PROTO_EDONKEY);
    } else {
        return 0;
    }
}


