#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_rambler_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RAMBLER, PROTO_RAMBLER_ALIAS);
    if (protocol_struct != NULL) { 
        return register_protocol(protocol_struct, PROTO_RAMBLER);
    } else {
        return 0;
    }
}


