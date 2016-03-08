#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/**
 * Was generated automatically by MMTCrawler on 08/03/2016
 * Author @luongnv89  
 *
 */

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_owamp_control_struct() {
	 protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_OWAMP_CONTROL, PROTO_OWAMP_CONTROL_ALIAS);
	 if (protocol_struct != NULL) {  
		 return register_protocol(protocol_struct, PROTO_OWAMP_CONTROL);
	 } else {  
		 return 0;  
	 }  
}

