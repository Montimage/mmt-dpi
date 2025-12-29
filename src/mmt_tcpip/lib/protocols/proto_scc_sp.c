#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_scc_sp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SCC_SP, PROTO_SCC_SP_ALIAS);
    if (protocol_struct != NULL) {
        return register_protocol(protocol_struct, PROTO_SCC_SP);
    } else {
        return 0;
    }
}
