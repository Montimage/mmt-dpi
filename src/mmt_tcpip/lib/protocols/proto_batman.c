#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "batman.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
int init_proto_batman() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_BATMAN, PROTO_BATMAN_ALIAS);

    if (protocol_struct != NULL) {

        return register_protocol(protocol_struct, PROTO_BATMAN);
    } else {
        return -1;
    }
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_batman_struct() {
    init_proto_batman();
    return 1;
}

