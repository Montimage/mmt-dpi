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
            uint32_t payload_len = packet->payload_packet_len;
            if(payload_len == 0) return 0; /* Shouldn't happen */
            /* Break after 20 packets. */
            if(ipacket->session->packet_count > 20) {
              MMT_LOG(PROTO_REDIS, MMT_LOG_DEBUG,"Exclude Redis.\n");
              MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_REDIS);
              return 0;
            }

            if(ipacket->session->last_packet_direction == 0)
              flow->redis_s2d_first_char = packet->payload[0];
            else
              flow->redis_d2s_first_char = packet->payload[0];

            if((flow->redis_s2d_first_char != '\0') && (flow->redis_d2s_first_char != '\0')) {
                if(((flow->redis_s2d_first_char == '*')
                   && ((flow->redis_d2s_first_char == '+') || (flow->redis_d2s_first_char == ':')))
                   || ((flow->redis_d2s_first_char == '*')
                   && ((flow->redis_s2d_first_char == '+') || (flow->redis_s2d_first_char == ':')))) {
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

void mmt_init_classify_me_redis() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_REDIS);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_REDIS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_redis_struct() {

    debug("REDIS: init_proto_REDIS_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_REDIS, PROTO_REDIS_ALIAS);
    if (protocol_struct != NULL) {
        // int i = 0;
        // for (; i < NDN_ATTRIBUTES_NB; i++) {
        //     register_attribute_with_protocol(protocol_struct, &ndn_attributes_metadata[i]);
        // }
        // register_pre_post_classification_functions(protocol_struct, NULL, NULL);
        // register_proto_context_init_cleanup_function(protocol_struct, setup_ndn_context, cleanup_ndn_context, NULL);
        // register_session_data_analysis_function(protocol_struct, ndn_session_data_analysis);
        mmt_init_classify_me_redis();

        return register_protocol(protocol_struct, PROTO_REDIS);
    } else {
        return 0;
    }
}

#endif
