#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
struct mmt_vlan_struct {
    uint16_t code;
    uint16_t h_proto;
};

int ad_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    const struct mmt_vlan_struct *vl = (struct mmt_vlan_struct *) & ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;
    switch (ntohs(vl->h_proto)) // Layer 3 protocol identifier
    {
            /* PROTO_8021Q */
        case ETH_P_8021Q:
            retval.proto_id = PROTO_8021Q;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_8021ad_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_8021AD, PROTO_8021AD_ALIAS);
    if (protocol_struct != NULL) {
        register_classification_function(protocol_struct, ad_classify_next_proto);

        return register_protocol(protocol_struct, PROTO_8021AD);
    } else {
        return 0;
    }
}


