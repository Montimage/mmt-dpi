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

int init_proto_subntbcst_tftp_struct() {
	 protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SUBNTBCST_TFTP, PROTO_SUBNTBCST_TFTP_ALIAS);
	 if (protocol_struct != NULL) {  
		 return register_protocol(protocol_struct, PROTO_SUBNTBCST_TFTP);
	 } else {  
		 return 0;  
	 }  
}

