#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_ctp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_CTP, PROTO_CTP_ALIAS);

    if (protocol_struct != NULL) {
        // register_classification_function(protocol_struct, loopback_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_CTP);
    } else {
        return 0;
    }
}
