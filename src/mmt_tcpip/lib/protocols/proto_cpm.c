/* Generated with MMT Plugin Generator */
#include "../mmt_common_internal_include.h"
#include "cpm.h"
/*
 * CPM data extraction routines
 */

classified_proto_t cpm_stack_classification(ipacket_t * ipacket) {
  classified_proto_t retval;
  retval.offset = 0;
  retval.proto_id = PROTO_CPM;
  retval.status = Classified;
  return retval;
}

int mmt_check_cpm_udp(ipacket_t * ipacket, unsigned index)
{
  printf("[inf] mmt_check_cpm_udp: %lu - %d\n", ipacket->packet_id, index );
  int l4_offset = get_packet_offset_at_index(ipacket, index);
  // int l4_packet_len = ipacket->p_hdr->caplen - l4_offset;
  struct udphdr * udp = NULL;
  udp = (struct udphdr *) & ipacket->data[l4_offset];
  char * payload = (char*) &ipacket->data[l4_offset + sizeof(struct udphdr)];
  int cpm_offset = sizeof(struct udphdr);
  if (udp != NULL) {
    // Settings without version. First check if PUBLIC FLAGS & SEQ bytes are 0x0. SEQ must be 1 at least.
    if (payload[0] == 0x01 && payload[1] == 0x32)
    {
       fprintf(stderr, "[PROTO_CPM] %lu mmt_check_cpm_udp: FOUND CPM!\n", ipacket->packet_id);
      classified_proto_t cpm_proto = cpm_stack_classification(ipacket);
      cpm_proto.offset = cpm_offset;
      return set_classified_proto(ipacket, index + 1, cpm_proto);
    } else {
      fprintf(stderr, "[PROTO_CPM] %lu mmt_check_cpm_udp: Not CPM!\n", ipacket->packet_id);
    }
  }
  fprintf(stderr, "[PROTO_CPM] %lu mmt_check_cpm_udp: Not CPM!\n", ipacket->packet_id);
  return 0;
}

static attribute_metadata_t cpm_attributes_metadata[CPM_ATTRIBUTES_NB] = {
  {CPM_PROTOCOLVERSION, CPM_PROTOCOLVERSION_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 0, SCOPE_PACKET, general_char_extraction},
  {CPM_MESSAGEID, CPM_MESSAGEID_ALIAS, MMT_U8_DATA, sizeof(uint8_t), 1, SCOPE_PACKET, general_char_extraction},
  {CPM_STATIONID, CPM_STATIONID_ALIAS, MMT_U32_DATA, sizeof(uint32_t), 2, SCOPE_PACKET, general_int_extraction_with_ordering_change},
  {CPM_GENERATIONTIME, CPM_GENERATIONTIME_ALIAS, MMT_U16_DATA, sizeof(uint16_t), 6, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};


int init_proto_cpm_struct() {
  protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_CPM, PROTO_CPM_ALIAS);

  if (protocol_struct != NULL) {

    int i = 0;
    for(; i < CPM_ATTRIBUTES_NB; i ++) {
      register_attribute_with_protocol(protocol_struct, &cpm_attributes_metadata[i]);
    }

    if (!register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_cpm_udp, 50)) {
      fprintf(stderr, "[err] init_cpm_proto_struct - cannot register_classification_function_with_parent_protocol\n");
    };
    return register_protocol(protocol_struct, PROTO_CPM);
  } else {
    return -1;
  }
}
