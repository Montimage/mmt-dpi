#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_nvp_ii_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NVP_II, PROTO_NVP_II_ALIAS);
    if (protocol_struct != NULL) { 
        return register_protocol(protocol_struct, PROTO_NVP_II);
    } else {
        return 0;
    }
}


