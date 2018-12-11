#include "smb.h"

/////////////// IMPLEMENTATION OF smb.h ///////////////////
smb_session_t * smb_session_new(uint64_t session_id) {
    smb_session_t * new_session = (smb_session_t *) malloc(sizeof(smb_session_t));
    new_session->next = NULL;
    new_session->prev = NULL;
    new_session->nt_create_request = 1;
    new_session->write_request = 1;
    new_session->session_id = session_id;
    return new_session;
}
void * smb_session_free(smb_session_t * node) {
  if (node != NULL) {
    node->next = NULL;
    node->prev = NULL;
    node->nt_create_request = 0;
    node->write_request = 0;
    node->session_id = 0;
    free(node);
    node = NULL;
  }
}

int smb_insert_session(smb_session_t * root, smb_session_t * new_session) {
  if (!new_session) return 0;
  if (root == NULL) {
    root = new_session;
    return 1;
  }
  smb_session_t * head = root;
  while (head->next != NULL) {
    head = head->next;
  }
  head->next = new_session;
  new_session->prev = head;
  return 1;
}

smb_session_t * smb_find_session_by_id(smb_session_t * root, uint64_t session_id) {
  smb_session_t * head = root;
  while (head != NULL) {
    if (head->session_id == session_id) return head;
    head = head->next;
  }
  return NULL;
}

smb_session_t * smb_remove_session_by_id(smb_session_t * root, uint64_t session_id) {
  smb_session_t * head = root;
  while (head != NULL) {
    if (head->session_id == session_id) break;
    head = head->next;
  }
  if (head == NULL) return NULL;
  if (head->next != NULL) {
    head->next->prev = head->prev;
  }
  if (head->prev != NULL) {
    head->prev->next = head->next;
  }
  return head;
}

smb_session_t *smb_get_session_list(const ipacket_t *ipacket, unsigned index)
{
  protocol_instance_t *configured_protocol = &(ipacket->mmt_handler)
                                                  ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
  return (smb_session_t *)configured_protocol->args;
}


smb_session_t * smb_get_session_from_packet(ipacket_t *ipacket, unsigned index) {
  smb_session_t * root = smb_get_session_list(ipacket, index);
  if (root == NULL) {
    return NULL;
  }
  return smb_find_session_by_id(root, ipacket->session->session_id);
}


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static void mmt_int_smb_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_SMB, MMT_REAL_PROTOCOL);
}

int mmt_check_smb(ipacket_t * ipacket, unsigned index) {
    // debug("[PROTO_SMB] mmt_check_smb on ipacket: %lu at index: %d",ipacket->packet_id,index);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_SMB, MMT_LOG_DEBUG, "search SMB.\n");

        if (packet->tcp->dest == htons(445)
                && packet->payload_packet_len > (32 + 4 + 4)
                && (packet->payload_packet_len - 4) == ntohl(get_u32(packet->payload, 0))
                && get_u32(packet->payload, 4) == htonl(0xff534d42)) {
            MMT_LOG(PROTO_SMB, MMT_LOG_DEBUG, "found SMB.\n");
            mmt_int_smb_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_SMB, MMT_LOG_DEBUG, "exclude SMB.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SMB);
    }
    return 0;
}
const uint8_t * get_smb_payload(const ipacket_t * ipacket, unsigned proto_index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (packet->payload_packet_len == 0) return NULL;
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    if (*(uint8_t *)&ipacket->data[offset] == 0x00) {
        offset += 4;
    }
    if ((ipacket->data[offset]== 0xff || ipacket->data[offset]== 0xfd || ipacket->data[offset]== 0xfe )
        && ipacket->data[offset + 1] == 'S'
        && ipacket->data[offset + 2] == 'M'
        && ipacket->data[offset + 3] == 'B') {
        return &ipacket->data[offset];
    }
    return NULL;
}

uint8_t smb_version(const uint8_t *smb_payload)
{
  if (smb_payload[0] == 0xff)
  {
    return 1;
  }
  else if (smb_payload[0] == 0xfe)
  {
    return 2;
  }
  else if (smb_payload[0] == 0xfd)
  {
    return 3;
  }
  return 0;
}
int smb_version_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    const uint8_t * smb_payload = get_smb_payload(ipacket, proto_index + 1);
    if (smb_payload != NULL) {
      uint8_t version = smb_version(smb_payload);
      *(uint8_t *)extracted_data->data = version;
      return 1;
    }
    return 0;
}

uint8_t smb_command(const uint8_t *smb_payload)
{
  if (smb_payload[0] == 0xff)
  {
    return *(uint8_t *)&smb_payload[4];
  }
  if (smb_payload[0] == 0xfe)
  {
    return *(uint8_t *)&smb_payload[12];
  }
  return 0;
}

int smb_command_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    const uint8_t * smb_payload = get_smb_payload(ipacket, proto_index + 1);
    if (smb_payload != NULL) {
        if (smb_payload[0] == 0xff) {
            *(uint8_t *)extracted_data->data = *(uint8_t *)&smb_payload[4];
            return 1;
        }
        if (smb_payload[0] == 0xfe) {
            *(uint8_t *)extracted_data->data = *(uint8_t *)&smb_payload[12];
            return 1;
        }
    }
    return 0;
}

int smb_padding_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    smb_session_t * smb_session = smb_get_session_from_packet(ipacket, proto_index);
    if (smb_session == NULL) return 0;
    if (smb_session->write_request)  return 0;
    const uint8_t * smb_payload = get_smb_payload(ipacket, proto_index + 1);
    if (smb_payload != NULL) {
        if (smb_payload[0] == 0xff) {
            const uint8_t * write_request_payload = &smb_payload[32];
            uint16_t data_length_low = *(uint16_t *)&write_request_payload[21];
            uint16_t byte_count = *(uint16_t *)&write_request_payload[29];
            if (data_length_low < byte_count) {
                uint16_t padding_size = byte_count - data_length_low;
                mmt_header_line_t * padding = (mmt_header_line_t *) malloc(sizeof(mmt_header_line_t));
                padding->len = padding_size;
                padding->ptr = (const char *) &write_request_payload[31];
                extracted_data->data = (void*)padding;
                return 1;
            }
        }
    }
    return 0;
}

int smb_nt_create_file_name_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    smb_session_t * smb_session = smb_get_session_from_packet(ipacket, proto_index);
    if (smb_session == NULL) return 0;
    if (smb_session->nt_create_request)  return 0;
    const uint8_t * smb_payload = get_smb_payload(ipacket, proto_index + 1);
    if (smb_payload != NULL) {
        if (smb_payload[0] == 0xff) {
            const uint8_t * nt_create_payload = &smb_payload[32];
            uint16_t file_name_len = *(uint16_t *)&nt_create_payload[6];
            mmt_header_line_t * file_name = (mmt_header_line_t *) malloc(sizeof(mmt_header_line_t));
            file_name->len = file_name_len;
            file_name->ptr = (const char *) &nt_create_payload[52];
            extracted_data->data = (void*)file_name;
            return 1;
        }
    }
    return 0;
}

static attribute_metadata_t smb_attributes_metadata[SMB_ATTRIBUTES_NB] = {
    {SMB_VERSION,SMB_VERSION_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_version_extraction},
    {SMB_COMMAND,SMB_COMMAND_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_command_extraction},
    {SMB_PADDING,SMB_PADDING_ALIAS,MMT_HEADER_LINE,sizeof (void *),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_padding_extraction},
    {SMB_NT_CREATE_FILE_NAME,SMB_NT_CREATE_FILE_NAME_ALIAS,MMT_HEADER_LINE,sizeof (void *),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_nt_create_file_name_extraction},
};

void mmt_init_classify_me_smb() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SMB);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

void smb_setup_session_context(ipacket_t *ipacket, unsigned index, smb_session_t * root)
{
  protocol_instance_t *configured_protocol = &(ipacket->mmt_handler)
                                                  ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
  configured_protocol->args = (void*) root;
}

void * smb_context_cleanup(void *proto_context, void *args)
{
  smb_session_t * root = (smb_session_t*)((protocol_instance_t *) proto_context)->args;
  while( root!= NULL) {
    smb_session_t * to_be_deleted = root;
    root = root->next;
    smb_session_free(to_be_deleted);
  }
}

int smb_session_data_analysis(ipacket_t *ipacket, unsigned index)
{
  if (!ipacket->session) return MMT_CONTINUE;
  if (ipacket->internal_packet->payload_packet_len == 0) return MMT_CONTINUE;
  smb_session_t * root = smb_get_session_list(ipacket, index);
  if (root == NULL) {
    root = smb_session_new(ipacket->session->session_id);
    if (root) {
      smb_setup_session_context(ipacket,index,root);
    }
  }

  smb_session_t * current_session = smb_find_session_by_id(root, ipacket->session->session_id);
  if (current_session == NULL) {
    // Create a new session
    current_session = smb_session_new(ipacket->session->session_id);
    smb_insert_session(root, current_session);
  }

  // Start analysis the packet and update to the session
  const uint8_t * smb_payload = get_smb_payload(ipacket, index);
  if (smb_payload == NULL) return MMT_CONTINUE;
  uint8_t version = smb_version(smb_payload);
  if (version != 1) {
    return MMT_CONTINUE; // skip for now
  }
  uint8_t smb_cmd = smb_command(smb_payload);
  if (smb_cmd == 0x2f) {
    current_session->write_request = !current_session->write_request;
  }
  if (smb_cmd == 0xa2) {
    current_session->nt_create_request = !current_session->nt_create_request;
  }
  return MMT_CONTINUE;
}

int init_proto_smb_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SMB, PROTO_SMB_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < SMB_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &smb_attributes_metadata[i]);
        }
        mmt_init_classify_me_smb();

        register_session_data_analysis_function(protocol_struct, smb_session_data_analysis);

        register_proto_context_init_cleanup_function(protocol_struct, NULL, smb_context_cleanup, NULL);
        return register_protocol(protocol_struct, PROTO_SMB);
    } else {
        return 0;
    }
}


