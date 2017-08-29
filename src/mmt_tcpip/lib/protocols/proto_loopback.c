#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "loopback.h"
#include "ip_session_id_management.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
int loopback_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    uint8_t loopback = *(uint8_t *) & ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;
    switch (loopback) // Layer 3 protocol identifier
    {
            /* IPv4 */
        case LOOPBACK_P_IP:
            retval.proto_id = PROTO_IP;
            retval.offset = 4;
            retval.status = Classified;
            break;
        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = 4;
            retval.status = Classified;
            break;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

classified_proto_t loopback_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = PROTO_LOOPBACK;
    retval.status = Classified;
    return retval;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_loopback_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_LOOPBACK, PROTO_LOOPBACK_ALIAS);

    if (protocol_struct != NULL) {

        register_classification_function(protocol_struct, loopback_classify_next_proto);

        // LOOPBACK is a major encapsulating protocol, register it as a stack
        // register_protocol_stack(DLT_EN10MB, PROTO_LOOPBACK_ALIAS, loopback_stack_classification); //TODO: check the return value of this
        //register_protocol_stack_full(DLT_EN10MB, PROTO_LOOPBACK_ALIAS, loopback_stack_classification, ehternet_stack_internal_cleanup, (void *) setup_tcpip_internal_packet(), (void *) setup_tcpip_internal_context()); //TODO: check the return value of this

        return register_protocol(protocol_struct, PROTO_LOOPBACK);
    } else {
        return 0;
    }
}
