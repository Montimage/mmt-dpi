/* Generated with MMT Plugin Generator */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "./geo_networking.h"

// /////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

int proto_geo_networking_classify_next_proto(ipacket_t *ipacket, unsigned index)
{
    /* If we get here, then the packet is not fragmented. */
    int offset = get_packet_offset_at_index(ipacket, index);
    int next_proto_offset = 0;
    const struct gn_basic_header *gn_bh = (struct gn_basic_header *)&ipacket->data[offset];
    offset += 4;
    next_proto_offset += 4; // basic header
    // debug("[tcp_pre_classification_function_with_reassemble] packet %"PRIu64" at index: %d\n",ipacket->packet_id,index);
    debug("[proto_geo_networking_classify_next_proto] packet %" PRIu64 " at index: %d\n", ipacket->packet_id, index);
    if (gn_bh->nex_header == 1 || gn_bh->nex_header == 2)
    {
        if (gn_bh->nex_header == 2)
        {
            // next header is the secure packet
            const struct gn_secured_packet *gn_sp = (struct gn_secured_packet *)&ipacket->data[offset];
            offset += 2 + gn_sp->head_var_length;
            next_proto_offset += 2 + gn_sp->head_var_length;
            // const struct gn_secured_packet_payload *gn_spp = (struct gn_secured_packet_payload *)&ipacket->data[offset];
            offset += 2;            // payload header
            next_proto_offset += 2; // payload header
        }
        // else if (gn_bh == 1)
        // {
        //     // next header is the common header
        // }
        const struct gn_common_header *gn_ch = (struct gn_common_header *)&ipacket->data[offset];
        offset += 8;            // common header
        next_proto_offset += 8; // common header
        if (gn_ch->header_type == 80)
        {
            offset += 28; // Topologically Scoped Broadcast Packet
            next_proto_offset += 28;
        }

        classified_proto_t retval;
        retval.offset = next_proto_offset;
        retval.proto_id = PROTO_BTPB;
        retval.status = Classified;

        return set_classified_proto(ipacket, index + 1, retval);
    }
    else
    {
        classified_proto_t retval;
        retval.offset = -1;
        retval.proto_id = -1;
        retval.status = NonClassified;
    }
}

static attribute_metadata_t geo_networking_attributes_metadata[GN_ATTRIBUTES_NB] = {
    {GN_BASIC_HEADER_NEXT_HEADER, GN_BASIC_HEADER_NEXT_HEADER_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, general_byte_to_byte_extraction},
    // {GN_SECURED_PACKET_LENGTH, GN_SECURED_PACKET_LENGTH_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    // {GN_COMMON_HEADER_NEXT_HEADER, GN_COMMON_HEADER_NEXT_HEADER_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 4, SCOPE_PACKET, general_char_extraction},
    // {GN_COMMON_HEADER_HEADER_TYPE, GN_COMMON_HEADER_HEADER_TYPE_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 5, SCOPE_PACKET, general_char_extraction},
    // {GN_COMMON_HEADER_PAYLOAD_LENGTH, GN_COMMON_HEADER_PAYLOAD_LENGTH_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 6, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_geo_networking_struct()
{
    protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_GEO_NETWORKING, PROTO_GEO_NETWORKING_ALIAS);

    if (protocol_struct != NULL)
    {
        int i = 0;
        for (; i < GN_ATTRIBUTES_NB; i++)
        {
            register_attribute_with_protocol(protocol_struct, &geo_networking_attributes_metadata[i]);
        }
        register_classification_function(protocol_struct, proto_geo_networking_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_GEO_NETWORKING);
    }
    else
    {
        return -1;
    }
}
