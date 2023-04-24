/* Generated with MMT Plugin Generator */
#include "../mmt_common_internal_include.h"
#include "./cam.h"
// /////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

// int proto_cam_classify_next_proto(ipacket_t *ipacket, unsigned index)
// {
//     /* If we get here, then the packet is not fragmented. */
//     int offset = get_packet_offset_at_index(ipacket, index);
//     offset += 6;
//     offset += 2;
//     classified_proto_t retval;
//     retval.offset = offset;
//     retval.proto_id = -1;
//     retval.status = NonClassified;
//     return set_classified_proto(ipacket, index + 1, retval);
// }

classified_proto_t cam_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = PROTO_CAM;
    retval.status = Classified;
    return retval;
}

int mmt_check_cam_udp(ipacket_t * ipacket, unsigned index)
{
  printf("[inf] mmt_check_cam_udp: %lu - %d\n", ipacket->packet_id, index );
  int l4_offset = get_packet_offset_at_index(ipacket, index);
  // int l4_packet_len = ipacket->p_hdr->caplen - l4_offset;
  struct udphdr * udp = NULL;
  udp = (struct udphdr *) & ipacket->data[l4_offset];
  char * payload = (char*) &ipacket->data[l4_offset + sizeof(struct udphdr)];
  int cam_offset = sizeof(struct udphdr);
  if (udp != NULL) {
    // Settings without version. First check if PUBLIC FLAGS & SEQ bytes are 0x0. SEQ must be 1 at least.
    if (payload[0] == 0x02 && payload[1] == 0x02)
    {
         fprintf(stderr, "[PROTO_CAM] %lu mmt_check_cam_udp: FOUND CAM!\n", ipacket->packet_id);
      classified_proto_t cam_proto = cam_stack_classification(ipacket);
          cam_proto.offset = cam_offset;
            return set_classified_proto(ipacket, index + 1, cam_proto);
    } else {
      fprintf(stderr, "[PROTO_CAM] %lu mmt_check_cam_udp: Not CAM!\n", ipacket->packet_id);
    }
  }
  fprintf(stderr, "[PROTO_CAM] %lu mmt_check_cam_udp: Not CAM!\n", ipacket->packet_id);
  return 0;
}

static attribute_metadata_t cam_attributes_metadata[CAM_ATTRIBUTES_NB] = {
    {CAM_PROTOCOLVERSION, CAM_PROTOCOLVERSION_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, general_char_extraction},
    {CAM_MESSAGEID, CAM_MESSAGEID_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 1, SCOPE_PACKET, general_char_extraction},
    {CAM_STATIONID, CAM_STATIONID_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 2, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {CAM_GENERATIONTIME, CAM_GENERATIONTIME_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 6, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {CAM_BASIC_STATION_TYPE, CAM_BASIC_STATION_TYPE_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 8, SCOPE_PACKET, general_char_extraction},
    {CAM_BASIC_RP_LATITUDE, CAM_BASIC_RP_LATITUDE_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 9, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {CAM_BASIC_RP_LONGITUDE, CAM_BASIC_RP_LONGITUDE_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 13, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {CAM_BASIC_RP_PCE_MAJOR_CONF, CAM_BASIC_RP_PCE_MAJOR_CONF_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 17, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {CAM_BASIC_RP_PCE_MINOR_CONF, CAM_BASIC_RP_PCE_MINOR_CONF_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 18, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {CAM_BASIC_RP_PCE_MAJOR_ORIE, CAM_BASIC_RP_PCE_MAJOR_ORIE_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 20, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {CAM_BASIC_RP_ALTITUDE_VALUE, CAM_BASIC_RP_ALTITUDE_VALUE_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 22, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {CAM_BASIC_RP_ALTITUDE_CONF, CAM_BASIC_RP_ALTITUDE_CONF_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 24, SCOPE_PACKET, general_char_extraction},
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
        if (!register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_cam_udp, 50)) {
            fprintf(stderr, "[err] init_cam_proto_struct - cannot register_classification_function_with_parent_protocol\n");
        };
        // register_classification_function(protocol_struct, proto_cam_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_CAM);
    }
    else
    {
        return -1;
    }
}
