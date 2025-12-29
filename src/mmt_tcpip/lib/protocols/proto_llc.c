/* Generated with MMT Plugin Generator */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "llc.h"
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

int llc_classify_next_proto(ipacket_t *ipacket, unsigned index)
{
    int offset = get_packet_offset_at_index(ipacket, index);

    llc_hdr_t * llc = (llc_hdr_t *)&ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    if (llc->dsap == 0x00 && llc->ssap == 0x01 && llc->cf == 0xAF)
    {
        retval.offset = offset + 3;
        retval.proto_id = PROTO_XID;
        retval.status = Classified;
    }
    else if (llc->dsap == 0x42 && llc->ssap == 0x42 && llc->cf == 0x03)
    {
        retval.offset = offset + 3;
        retval.proto_id = PROTO_STP;
        retval.status = Classified;
    }
    else if (llc->dsap == 0xaa && llc->ssap == 0xaa && llc->cf == 0x03)
    {
        uint16_t * pid = (uint16_t *)&ipacket->data[offset + 1 + 1 + 1 + 3];
        switch (ntohs(*pid)) // Layer 3 protocol identifier
        {
        case 0x2000:
            retval.offset = offset + 8;
            retval.proto_id = PROTO_CDP;
            retval.status = Classified;
            break;
        case 0x2004:
            retval.offset = offset + 8;
            retval.proto_id = PROTO_DTP;
            retval.status = Classified;
            break;
        default:
            retval.offset = offset + 8;
            retval.proto_id = PROTO_UNKNOWN;
            retval.status = Classified;
            break;
        }
    }
    return set_classified_proto(ipacket, index + 1, retval);
}

static attribute_metadata_t ethernet_attributes_metadata[LLC_ATTRIBUTES_NB] = {
    {LLC_DSAP, LLC_DSAP_ALIAS, MMT_U8_DATA, sizeof(char), 0, SCOPE_PACKET, general_byte_to_byte_extraction},
    {LLC_SSAP, LLC_SSAP_ALIAS, MMT_U8_DATA, sizeof(char), 1, SCOPE_PACKET, general_byte_to_byte_extraction},
    {LLC_CONTROL_FIELD, LLC_CONTROL_FIELD_ALIAS, MMT_U8_DATA, sizeof(char), 2, SCOPE_PACKET, general_byte_to_byte_extraction},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_llc_struct()
{
    protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_LLC, PROTO_LLC_ALIAS);
    int i = 0;
    for (; i < LLC_ATTRIBUTES_NB; i++)
    {
        register_attribute_with_protocol(protocol_struct, &ethernet_attributes_metadata[i]);
    }

    register_classification_function(protocol_struct, llc_classify_next_proto);

    if (protocol_struct != NULL)
    {
        return register_protocol(protocol_struct, PROTO_LLC);
    }
    else
    {
        return -1;
    }
}
