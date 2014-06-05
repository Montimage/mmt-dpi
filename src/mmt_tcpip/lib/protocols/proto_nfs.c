#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_nfs_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_NFS, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_nfs(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint8_t offset = 0;
    if (packet->tcp != NULL)
        offset = 4;

    if (packet->payload_packet_len < (40 + offset))
        goto exclude_nfs;

    MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 1\n");


    if (offset != 0 && get_u32(packet->payload, 0) != htonl(0x80000000 + packet->payload_packet_len - 4))
        goto exclude_nfs;

    MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 2\n");

    if (get_u32(packet->payload, 4 + offset) != 0)
        goto exclude_nfs;

    MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 3\n");

    if (get_u32(packet->payload, 8 + offset) != htonl(0x02))
        goto exclude_nfs;

    MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match stage 3\n");

    if (get_u32(packet->payload, 12 + offset) != htonl(0x000186a5)
            && get_u32(packet->payload, 12 + offset) != htonl(0x000186a3)
            && get_u32(packet->payload, 12 + offset) != htonl(0x000186a0))
        goto exclude_nfs;

    MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match stage 4\n");

    if (ntohl(get_u32(packet->payload, 16 + offset)) > 4)
        goto exclude_nfs;

    MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match\n");

    mmt_int_nfs_add_connection(ipacket);
    return;

exclude_nfs:
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_NFS);
}

int mmt_check_nfs(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint8_t offset = 0;
        if (packet->tcp != NULL)
            offset = 4;

        if (packet->payload_packet_len < (40 + offset))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 1\n");

        if (offset != 0 && get_u32(packet->payload, 0) != htonl(0x80000000 + packet->payload_packet_len - 4))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 2\n");

        if (get_u32(packet->payload, 4 + offset) != 0)
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 3\n");

        if (get_u32(packet->payload, 8 + offset) != htonl(0x02))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match stage 3\n");

        if (get_u32(packet->payload, 12 + offset) != htonl(0x000186a5)
                && get_u32(packet->payload, 12 + offset) != htonl(0x000186a3)
                && get_u32(packet->payload, 12 + offset) != htonl(0x000186a0))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match stage 4\n");

        if (ntohl(get_u32(packet->payload, 16 + offset)) > 4)
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match\n");

        mmt_int_nfs_add_connection(ipacket);
        return 1;

exclude_nfs:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_NFS);
    }
    return 1;
}

void mmt_init_classify_me_nfs() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_NFS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_nfs_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NFS, PROTO_NFS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_nfs();

        return register_protocol(protocol_struct, PROTO_NFS);
    } else {
        return 0;
    }
}


