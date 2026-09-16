#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#ifdef PROTO_REDIS

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_redis_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_REDIS, MMT_REAL_PROTOCOL);
}

/* IANA-registered Redis TCP port. */
#define REDIS_DEFAULT_PORT 6379

/* Returns non-zero if c is a valid RESP/RESP3 type-opener byte, i.e. the first
 * byte of a serialized Redis value. RESP2 openers are '+' (simple string),
 * '-' (error), ':' (integer), '$' (bulk string) and '*' (array); RESP3 adds
 * '#' (boolean), ',' (double), '_' (null), '(' (big number), '!' (bulk error),
 * '=' (verbatim string), '%' (map), '~' (set) and '>' (push). Keeping this
 * predicate pure (no flow/packet state) makes it directly unit-testable. */
int redis_is_resp_opener(uint8_t c) {
    switch (c) {
        /* RESP2 */
        case '+': case '-': case ':': case '$': case '*':
        /* RESP3 */
        case '#': case ',': case '_': case '(': case '!':
        case '=': case '%': case '~': case '>':
            return 1;
        default:
            return 0;
    }
}

/* Returns non-zero if the two recorded first-bytes (one per direction) form a
 * RESP-shaped request/reply exchange: one side is a client command array ('*')
 * and the other is any valid RESP/RESP3 reply opener. This is a strict superset
 * of the legacy check (which only accepted '+'/':'  as the reply opener), so it
 * never rejects a flow the old heuristic accepted. */
int redis_resp_exchange_match(uint8_t a, uint8_t b) {
    return ((a == '*') && redis_is_resp_opener(b))
        || ((b == '*') && redis_is_resp_opener(a));
}

int mmt_check_redis(ipacket_t * ipacket, unsigned index)
{
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
    	 
        MMT_LOG(PROTO_REDIS, MMT_LOG_DEBUG,"Redis detection...\n");
        /* skip marked packets */
        if (packet->detected_protocol_stack[0] != PROTO_REDIS) {
          if (packet->tcp_retransmission == 0) {
            /* Issue #192 (F-BUG-054): bound reads by what was captured, not by
             * payload_packet_len alone — it derives from the attacker-
             * controlled IPv4 tot_len and may exceed the captured buffer.
             * Same caplen-relative shape as http2_can_read() (F-BUG-059). */
            uint32_t payload_len = packet->payload_packet_len;
            const uint8_t *payload_end = ipacket->data + ipacket->p_hdr->caplen;
            if (packet->payload == NULL || packet->payload >= payload_end)
              payload_len = 0;
            else if (payload_len > (uint32_t)(payload_end - packet->payload))
              payload_len = (uint32_t)(payload_end - packet->payload);
            if(payload_len == 0) return 0; /* Shouldn't happen */
            /* Break after 20 packets. */
            if(ipacket->session->packet_count > 20) {
              MMT_LOG(PROTO_REDIS, MMT_LOG_DEBUG,"Exclude Redis.\n");
              MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_REDIS);
              return 0;
            }

            uint8_t first_char = packet->payload[0];

            if(ipacket->session->last_packet_direction == 0)
              flow->redis_s2d_first_char = first_char;
            else
              flow->redis_d2s_first_char = first_char;

            /* Port hint: on the IANA-registered Redis port (6379) a single
             * RESP type-opener byte is sufficient corroboration, so a flow is
             * recognized without waiting for both directions. */
            if((packet->tcp->dest == htons(REDIS_DEFAULT_PORT)
                || packet->tcp->source == htons(REDIS_DEFAULT_PORT))
               && redis_is_resp_opener(first_char)) {
                MMT_LOG(PROTO_REDIS, MMT_LOG_DEBUG,"Found Redis (port 6379).\n");
                mmt_int_redis_add_connection(ipacket);
                return 1;
            }

            if((flow->redis_s2d_first_char != '\0') && (flow->redis_d2s_first_char != '\0')) {
                if(redis_resp_exchange_match(flow->redis_s2d_first_char,
                                             flow->redis_d2s_first_char)) {
                    MMT_LOG(PROTO_REDIS, MMT_LOG_DEBUG,"Found Redis.\n");
                    mmt_int_redis_add_connection(ipacket);
                    return 1;
              } else {
                MMT_LOG(PROTO_REDIS, MMT_LOG_DEBUG,"Exclude Redis.\n");
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_REDIS);
              }
            } else
              return 0; /* Too early */
          }
        }
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_redis_struct() {
    
    debug("REDIS: init_proto_REDIS_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_REDIS, PROTO_REDIS_ALIAS);
    if (protocol_struct != NULL) {
        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_REDIS, PROTO_REDIS);

        return register_protocol(protocol_struct, PROTO_REDIS);
    } else {
        return 0;
    }
}

#endif