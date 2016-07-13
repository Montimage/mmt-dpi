#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

#ifdef PROTO_VMWARE

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_vmware_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_VMWARE, MMT_REAL_PROTOCOL);
}

int mmt_check_vmware(ipacket_t * ipacket, unsigned index)
{
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
    	
        if((packet->payload_packet_len == 66)
           && (ntohs(packet->udp->dest) == 902)
           && ((packet->payload[0] & 0xFF) == 0xA4)) {
            MMT_LOG(PROTO_VMWARE, MMT_LOG_DEBUG,"Found vmware.\n");
            mmt_int_vmware_add_connection(ipacket);
        } 
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_VMWARE);
        MMT_LOG(PROTO_VMWARE, MMT_LOG_DEBUG, "exclude vmware.\n");
        return 0;

    }
    return 0;
}

void mmt_init_classify_me_vmware() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VMWARE);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_VMWARE);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_vmware_struct() {
    
    debug("VMWARE: init_proto_vmware_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_VMWARE, PROTO_VMWARE_ALIAS);
    if (protocol_struct != NULL) {
        // int i = 0;
        // for (; i < NDN_ATTRIBUTES_NB; i++) {
        //     register_attribute_with_protocol(protocol_struct, &ndn_attributes_metadata[i]);
        // }
        // register_pre_post_classification_functions(protocol_struct, NULL, NULL);
        // register_proto_context_init_cleanup_function(protocol_struct, setup_ndn_context, cleanup_ndn_context, NULL);
        // register_session_data_analysis_function(protocol_struct, ndn_session_data_analysis);
        mmt_init_classify_me_vmware();

        return register_protocol(protocol_struct, PROTO_VMWARE);
    } else {
        return 0;
    }
}

#endif