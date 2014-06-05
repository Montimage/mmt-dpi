#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "ospf.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static attribute_metadata_t ospf_attributes_metadata[OSPF_ATTRIBUTES_NB] = {
    {OSPF_VERSION, OSPF_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, general_char_extraction},
    {OSPF_TYPE, OSPF_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_char_extraction},
    {OSPF_PACKET_LENGTH, OSPF_PACKET_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {OSPF_ROUTER_ID, OSPF_ROUTER_ID_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {OSPF_AREA_ID, OSPF_AREA_ID_ALIAS, MMT_U32_DATA, sizeof (int), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {OSPF_CHECKSUM, OSPF_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 12, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {OSPF_INSTANCE_ID, OSPF_INSTANCE_ID_ALIAS, MMT_U8_DATA, sizeof (char), 14, SCOPE_PACKET, general_char_extraction},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_ospf_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_OSPF, PROTO_OSPF_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for(; i < OSPF_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &ospf_attributes_metadata[i]);
        }

        return register_protocol(protocol_struct, PROTO_OSPF);
    } else {
        return 0;
    }
}
