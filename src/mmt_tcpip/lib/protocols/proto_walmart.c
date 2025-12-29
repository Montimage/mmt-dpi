#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_walmart_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_WALMART, PROTO_WALMART_ALIAS);
    if (protocol_struct != NULL) {
        return register_protocol(protocol_struct, PROTO_WALMART);
    } else {
        return 0;
    }
}
