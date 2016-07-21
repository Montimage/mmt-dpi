#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define SSDP_HTTP "HTTP/1.1 200 OK\r\n"

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ssdp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SSDP, MMT_REAL_PROTOCOL);
}

/* this detection also works asymmetrically */
void mmt_classify_me_ssdp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "search ssdp.\n");
    if (packet->udp != NULL) {

        if (packet->payload_packet_len > 100) {
            if ((memcmp(packet->payload, "M-SEARCH * HTTP/1.1", 19) == 0)
                    || memcmp(packet->payload, "NOTIFY * HTTP/1.1", 17) == 0) {


                MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "found ssdp.\n");
                mmt_int_ssdp_add_connection(ipacket);
                return;
            }

            if (memcmp(packet->payload, SSDP_HTTP, strlen(SSDP_HTTP)) == 0) {
                MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "found ssdp.\n");
                mmt_int_ssdp_add_connection(ipacket);
                return;
            }
        }
    }

    MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "ssdp excluded.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SSDP);
}

int mmt_check_ssdp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "search ssdp.\n");
        if (packet->payload_packet_len > 100) {
            if ((memcmp(packet->payload, "M-SEARCH * HTTP/1.1", 19) == 0)
                    || memcmp(packet->payload, "NOTIFY * HTTP/1.1", 17) == 0) {
                MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "found ssdp.\n");
                mmt_int_ssdp_add_connection(ipacket);
                return 1;
            }

            if (memcmp(packet->payload, SSDP_HTTP, strlen(SSDP_HTTP)) == 0) {
                MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "found ssdp.\n");
                mmt_int_ssdp_add_connection(ipacket);
                return 1;
            }
        }

        MMT_LOG(PROTO_SSDP, MMT_LOG_DEBUG, "ssdp excluded.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SSDP);
    }
    return 0;
}

void mmt_init_classify_me_ssdp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SSDP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ssdp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SSDP, PROTO_SSDP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_ssdp();

        return register_protocol(protocol_struct, PROTO_SSDP);
    } else {
        return 0;
    }
}


