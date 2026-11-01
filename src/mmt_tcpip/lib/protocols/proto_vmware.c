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

    { /* guard evaluated by the classifier walk (issue #561) */
    	
        if((packet->payload_packet_len == 66)
           && (ntohs(packet->udp->dest) == 902)
           && ((packet->payload[0] & 0xFF) == 0xA4)) {
            mmt_int_vmware_add_connection(ipacket);
            return 1;
        } 
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_VMWARE);
        return 0;

    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_vmware_struct() {
    
    debug("VMWARE: init_proto_vmware_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_VMWARE, PROTO_VMWARE_ALIAS);
    if (protocol_struct != NULL) {
        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                PROTO_VMWARE, PROTO_VMWARE);

        return register_protocol(protocol_struct, PROTO_VMWARE);
    } else {
        return 0;
    }
}

#endif