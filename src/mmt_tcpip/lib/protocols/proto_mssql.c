#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

// LN: TDS header
struct tds_packet_header {
  u_int8_t type;
  u_int8_t status;
  u_int16_t length;
  u_int16_t channel;
  u_int8_t number;
  u_int8_t window;
};
// end of TDS header

/*
 * Issue #59: this header overlays the byte-aligned packet->payload; reading
 * length/channel through a strict cast is a misaligned access (UB, aborts under
 * BUILD=asan -fsanitize=alignment). This view lowers the alignment requirement
 * to 1 for alignment-safe single-load reads. Mirrors PR #58 (#57).
 */
typedef struct tds_packet_header __attribute__((aligned(1))) mmt_una_tds_packet_header_t;
static void mmt_int_mssql_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MSSQL, MMT_REAL_PROTOCOL);
}

int mmt_check_mssql(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    { /* guard evaluated by the classifier walk (issue #561) */

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        if(ntohs(packet->tcp->dest)!=102 && ntohs(packet->tcp->source)!=102){ // port 102: for TPKT protocol (COTP protocols)
            // LN: Detect PROTO_MSSQL
            if(packet->payload_packet_len > sizeof(struct tds_packet_header)){
            
                mmt_una_tds_packet_header_t *h = (mmt_una_tds_packet_header_t*) packet->payload;

                if ((h->type >= 1 && h->type <= 8) || (h->type >= 14 && h->type <= 18)) {
                    if (h->status == 0x00 || h->status == 0x01 || h->status == 0x02 || h->status == 0x04 || h->status == 0x08 || h->status == 0x09 || h->status == 0x10) {
                        if (ntohs(h->length) == packet->payload_packet_len && h->window == 0x00) {
                            mmt_int_mssql_add_connection(ipacket);
                            return 1;
                        }
                    }
                }
            // end of LN: Detect PROTO_MSSQL            
            }
        }
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_MSSQL);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mssql_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MSSQL, PROTO_MSSQL_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_MSSQL);

        return register_protocol(protocol_struct, PROTO_MSSQL);
    } else {
        return 0;
    }
}
