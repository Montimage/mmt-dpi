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

int mmt_check_ssdp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        // LN: Not sure about the length > 100 - there is a case that the SSDP packet have the payload len less than 100.
        // -> Use 50 as a temporary value -> can be changed after if there is another case
        if (packet->payload_packet_len > 50) {
            if ((mmt_memcmp(packet->payload, "M-SEARCH * HTTP/1.1", 19) == 0)
                    || mmt_memcmp(packet->payload, "NOTIFY * HTTP/1.1", 17) == 0) {
                mmt_int_ssdp_add_connection(ipacket);
                return 1;
            }

            if (mmt_memcmp(packet->payload, SSDP_HTTP, strlen(SSDP_HTTP)) == 0) {
                mmt_int_ssdp_add_connection(ipacket);
                return 1;
            }
        }

        MMT_EXCLUDE_PROTOCOL(flow, PROTO_SSDP);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ssdp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SSDP, PROTO_SSDP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_SSDP);

        return register_protocol(protocol_struct, PROTO_SSDP);
    } else {
        return 0;
    }
}
