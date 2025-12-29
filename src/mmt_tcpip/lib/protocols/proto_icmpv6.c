#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "icmp6.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static attribute_metadata_t icmp6_attributes_metadata[ICMP6_ATTRIBUTES_NB] = {
    {ICMP6_TYPE, ICMP6_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, general_byte_to_byte_extraction},
    {ICMP6_CODE, ICMP6_CODE_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_byte_to_byte_extraction},
    {ICMP6_CHECKSUM, ICMP6_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_icmpv6_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ICMPV6, PROTO_ICMPV6_ALIAS);

    if (protocol_struct != NULL) {
        int i = 0;
        for(; i < ICMP6_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &icmp6_attributes_metadata[i]);
        }

        return register_protocol(protocol_struct, PROTO_ICMPV6);
    } else {
        return 0;
    }
}
