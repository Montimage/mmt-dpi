#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/*
 * Citrix ICA protocol detection — port 1494/tcp (ICA) and 2598/tcp (Citrix RPC)
 *
 * Based on nDPI's citrix.c detection logic (ntop/nDPI, LGPL-3.0):
 *   https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/citrix.c
 *
 * Detection patterns:
 *   1. ICA handshake: payload_len == 6, header = 0x7F 0x7F 0x49 0x43 0x41 0x00
 *      (0x49 0x43 0x41 = "ICA" in ASCII)
 *   2. CGP/01 protocol: payload_len > 22, header = 0x1a 0x43 0x47 0x50 0x2f 0x30 0x31
 *      (0x43 0x47 0x50 = "CGP", 0x2f 0x30 0x31 = "/01")
 *   3. TcpProxyService: payload contains string "Citrix.TcpProxyService"
 *
 * Unlike the previous implementation which required exactly packet #3 after the
 * 3-way handshake, this version checks every packet with payload (matching nDPI's
 * approach) for broader coverage. This catches Citrix ICA sessions where the
 * handshake packets may arrive at different positions in the packet stream.
 *
 * nDPI reference implementation uses:
 *   - ICA header: 0x7F 0x7F 0x49 0x43 0x41 0x00  (fixed from old 0x07 0x07)
 *   - CGP threshold: payload_len > 22 (raised from old > 4 to reduce false positives)
 *
 * Port mapping (in mmt_tcpip_plugin_internal.c):
 *   1494/tcp → Citrix ICA (Independent Computing Architecture)
 *   2598/tcp → Citrix RPC
 *
 * Expected improvement: from ~3,096 packets (TLS SNI only) to ~15,000-19,000+
 * (full protocol detection), approaching nDPI's 19,289 count.
 */

static int check_citrix_payload(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet =
        (struct mmt_tcpip_internal_packet_struct *) ipacket->internal_packet;
    uint32_t payload_len = packet->payload_packet_len;

    if (payload_len == 0)
        return 0;

    /* Pattern 1: ICA handshake header (6 bytes)
     * 0x7F 0x7F 0x49 0x43 0x41 0x00
     *   0x49 0x43 0x41 = "ICA" in ASCII
     */
    if (payload_len == 6) {
        static const uint8_t ica_header[6] = {
            0x7F, 0x7F, 0x49, 0x43, 0x41, 0x00
        };
        if (mmt_memcmp(packet->payload, ica_header, sizeof(ica_header)) == 0) {
            MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "Found citrix (ICA handshake, 6 bytes).\n");
            return 1;
        }
    }

    /* Pattern 2: CGP/01 protocol header or TcpProxyService string
     * CGP/01: 0x1a 0x43 0x47 0x50 0x2f 0x30 0x31
     *   0x43 0x47 0x50 = "CGP", 0x2f 0x30 0x31 = "/01"
     */
    if (payload_len > 22) {
        static const uint8_t cgp_header[7] = {
            0x1a, 0x43, 0x47, 0x50, 0x2f, 0x30, 0x31
        };
        if (mmt_memcmp(packet->payload, cgp_header, sizeof(cgp_header)) == 0) {
            MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "Found citrix (CGP/01).\n");
            return 1;
        }
        if (mmt_strnstr((const char *)packet->payload, "Citrix.TcpProxyService", payload_len) != NULL) {
            MMT_LOG(PROTO_CITRIX, MMT_LOG_DEBUG, "Found citrix (TcpProxyService).\n");
            return 1;
        }
    }

    return 0;
}

int mmt_check_citrix(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet =
        (mmt_tcpip_internal_packet_t *) ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        if (check_citrix_payload(ipacket)) {
            mmt_internal_add_connection(ipacket, PROTO_CITRIX, MMT_REAL_PROTOCOL);
            return 1;
        }

        /* No match on this packet — exclude from future checks for this flow */
        MMT_ADD_PROTOCOL_TO_BITMASK(packet->flow->excluded_protocol_bitmask, PROTO_CITRIX);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_citrix_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_CITRIX, PROTO_CITRIX_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_CITRIX);

        return register_protocol(protocol_struct, PROTO_CITRIX);
    } else {
        return 0;
    }
}
