/* Generated with MMT Plugin Generator */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "./cam.h"
// /////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

int proto_cam_classify_next_proto(ipacket_t *ipacket, unsigned index)
{
    /* If we get here, then the packet is not fragmented. */
    int offset = get_packet_offset_at_index(ipacket, index);
    const struct its_pdu_header *pdu_header = (struct its_pdu_header *)&ipacket->data[offset];
    offset += 6;
    const struct coop_awareness *ca = (struct coop_awareness *)&ipacket->data[offset];
    offset += 2;
    classified_proto_t retval;
    retval.offset = offset;
    retval.proto_id = -1;
    retval.status = NonClassified;
    return set_classified_proto(ipacket, index + 1, retval);
}

static attribute_metadata_t cam_attributes_metadata[CAM_ATTRIBUTES_NB] = {
    {CAM_ITS_PDU_HEADER_PROTOCOL_VERSION, CAM_ITS_PDU_HEADER_PROTOCOL_VERSION_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, general_char_extraction},
    {CAM_ITS_PDU_HEADER_MESSAGE_ID, CAM_ITS_PDU_HEADER_MESSAGE_ID_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 1, SCOPE_PACKET, general_char_extraction},
    {CAM_ITS_PDU_HEADER_STATION_ID, CAM_ITS_PDU_HEADER_STATION_ID_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 2, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {CAM_COOP_AWARENESS_GENERATION_DELTA_TIME, CAM_COOP_AWARENESS_GENERATION_DELTA_TIME_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 6, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_cam_struct()
{
    protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_CAM, PROTO_CAM_ALIAS);

    if (protocol_struct != NULL)
    {
        int i = 0;
        for (; i < CAM_ATTRIBUTES_NB; i++)
        {
            register_attribute_with_protocol(protocol_struct, &cam_attributes_metadata[i]);
        }
        register_classification_function(protocol_struct, proto_cam_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_CAM);
    }
    else
    {
        return -1;
    }
}
