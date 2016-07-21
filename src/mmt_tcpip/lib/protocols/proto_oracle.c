#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#ifdef PROTO_ORACLE

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_oracle_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_ORACLE, MMT_REAL_PROTOCOL);
}

int mmt_check_oracle(ipacket_t * ipacket, unsigned index)
{
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
    	
        if(packet->tcp != NULL){
        	uint16_t sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
        	
            debug("ORACLE: Calculating ORACLE over TCP");

        	/* Oracle Database 9g,10g,11g */
            if ((dport == 1521 || sport == 1521)
            &&  (((packet->payload[0] == 0x07) && (packet->payload[1] == 0xff) && (packet->payload[2] == 0x00))
                 || ((packet->payload_packet_len >= 232) && ((packet->payload[0] == 0x00) || (packet->payload[0] == 0x01)) 
                 && (packet->payload[1] != 0x00)
                 && (packet->payload[2] == 0x00)
                 && (packet->payload[3] == 0x00)))) {
              MMT_LOG(PROTO_ORACLE, MMT_LOG_DEBUG, "found oracle.\n");
              mmt_int_oracle_add_connection(ipacket);
              return 1;
            } else if (packet->payload_packet_len == 213 && packet->payload[0] == 0x00 &&
                       packet->payload[1] == 0xd5 && packet->payload[2] == 0x00 &&
                       packet->payload[3] == 0x00 ) {
              MMT_LOG(PROTO_ORACLE, MMT_LOG_DEBUG, "found oracle.\n");
              mmt_int_oracle_add_connection(ipacket);
              return 1;
            }
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_ORACLE);
        MMT_LOG(PROTO_ORACLE, MMT_LOG_DEBUG, "exclude ORACLE.\n");
        return 0;

    }
    return 0;
}

void mmt_init_classify_me_oracle() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ORACLE);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_ORACLE);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_oracle_struct() {
    
    debug("ORACLE: init_proto_ORACLE_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ORACLE, PROTO_ORACLE_ALIAS);
    if (protocol_struct != NULL) {
        // int i = 0;
        // for (; i < NDN_ATTRIBUTES_NB; i++) {
        //     register_attribute_with_protocol(protocol_struct, &ndn_attributes_metadata[i]);
        // }
        // register_pre_post_classification_functions(protocol_struct, NULL, NULL);
        // register_proto_context_init_cleanup_function(protocol_struct, setup_ndn_context, cleanup_ndn_context, NULL);
        // register_session_data_analysis_function(protocol_struct, ndn_session_data_analysis);
        mmt_init_classify_me_oracle();

        return register_protocol(protocol_struct, PROTO_ORACLE);
    } else {
        return 0;
    }
}

#endif