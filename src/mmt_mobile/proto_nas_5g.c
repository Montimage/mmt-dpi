/*
 * proto_nas_5g.c
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#include "mmt_mobile_internal.h"


static attribute_metadata_t _attributes_metadata[] = {
};

int init_proto_nas_5g_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_NAS5G, PROTO_NAS5G_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_NAS5G_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	return register_protocol(protocol_struct, PROTO_NAS5G);

}
