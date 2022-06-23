/* Generated with MMT Plugin Generator */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "./bnpb.h"

// /////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

int proto_btpb_classify_next_proto(ipacket_t *ipacket, unsigned index)
{
    /* If we get here, then the packet is not fragmented. */
    int offset = get_packet_offset_at_index(ipacket, index);
    const struct bnpb *str = (struct bnpb *)&ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = 4;
    retval.proto_id = PROTO_CAM;
    retval.status = Classified;

    return set_classified_proto(ipacket, index + 1, retval);
}

static attribute_metadata_t btpb_attributes_metadata[BTPB_ATTRIBUTES_NB] = {
    {BTPB_DESTINATION_PORT, BTPB_DESTINATION_PORT_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {BTPB_DESTINATION_PORT_INFO, BTPB_DESTINATION_PORT_INFO_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_btpb_struct()
{
    protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_BTPB, PROTO_BTPB_ALIAS);

    if (protocol_struct != NULL)
    {
        int i = 0;
        for (; i < BTPB_ATTRIBUTES_NB; i++)
        {
            register_attribute_with_protocol(protocol_struct, &btpb_attributes_metadata[i]);
        }
        register_classification_function(protocol_struct, proto_btpb_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_BTPB);
    }
    else
    {
        return -1;
    }
}
