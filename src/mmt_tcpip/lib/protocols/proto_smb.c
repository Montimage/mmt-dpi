#include "smb.h"

/////////////// IMPLEMENTATION OF smb.h ///////////////////
smb_file_t * smb_file_new(void) {
  smb_file_t * file = (smb_file_t * ) malloc(sizeof(smb_file_t));
  if (file) {
    file->file_id = 0;
    file->file_path = NULL;
    file->current_len = 0;
    file->current_seg_len = 0;
    file->next = NULL;
  }
  return file;
}

void smb_file_free(smb_file_t * file) {
  if (file) {
    file->file_id = 0;
    file->current_len = 0;
    file->current_seg_len = 0;
    free(file->file_path);
    file->next = NULL;
  }
}

smb_session_t * smb_session_new(uint64_t session_id) {
    smb_session_t * new_session = (smb_session_t *) malloc(sizeof(smb_session_t));
    new_session->session_id = session_id;
    new_session->smb1_cmd_nt_create = 0;
    new_session->smb1_cmd_nt_trans = 0;
    new_session->smb1_cmd_write = 0;
    new_session->smb1_cmd_close = 0;
    new_session->smb1_cmd_read = 0;
    new_session->smb1_cmd_trans2 = 0;
    new_session->sm1_file_transferring = 0;
    new_session->last_cmd = 0;
    new_session->current_file_id = 0;
    new_session->files = NULL;
    new_session->current_file = NULL;
    new_session->next = NULL;
    new_session->prev = NULL;
    return new_session;
}
void smb_session_free(smb_session_t * node) {
  if (node != NULL) {
    node->session_id = 0;
    node->smb1_cmd_nt_create = 0;
    node->smb1_cmd_nt_trans = 0;
    node->smb1_cmd_write = 0;
    node->smb1_cmd_close = 0;
    node->smb1_cmd_read = 0;
    node->smb1_cmd_trans2 = 0;
    node->sm1_file_transferring = 0;
    node->last_cmd = 0;
    node->current_file_id = 0;
    node->current_file = NULL;
    smb_file_t * file = node->files;
    while(file != NULL) {
      smb_file_t * to_be_deleted = file;
      file = file->next;
      smb_file_free(to_be_deleted);
    }
    node->next = NULL;
    node->prev = NULL;
    free(node);
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

int smb_session_insert_file(smb_session_t * smb_ss, smb_file_t * file) {
  if (!smb_ss || !file) return 0;
  if (smb_ss->files == NULL) {
    smb_ss->files = file;
    return 1;
  }
  smb_file_t * f = smb_ss->files;
  while(f->next != NULL) {
    f = f->next;
  }
  f->next = file;
  return 1;
}

smb_file_t * smb_session_find_file_by_id(smb_session_t * smb_ss, uint16_t file_id) {
  if (!smb_ss) return NULL;
  smb_file_t * f = smb_ss->files;
  while(f != NULL) {
    if (f->file_id == file_id) {
      return f;
    }
    f = f->next;
  }
  return NULL;
}

smb_file_t * smb_session_find_file(smb_session_t * smb_ss, uint16_t file_path_len, char * file_name) {
  if (!smb_ss) return NULL;
  smb_file_t * f = smb_ss->files;
  while(f != NULL) {
    if (f->file_path != NULL) {
      if (f->file_path->len == file_path_len) {
        if (strcmp(f->file_path->ptr, file_name) == 0) {
          return f;
        }
      }
    }
    f = f->next;
  }
  return NULL;
}

int smb_session_update_last_file_id(smb_session_t * smb_ss, uint16_t file_id) {
  if (!smb_ss) return 0;
  if (!smb_ss->files) return 0;
  smb_file_t * f_need_id = NULL;
  if (smb_ss->files->file_id == 0) {
    f_need_id = smb_ss->files;
  }
  smb_file_t * f = smb_ss->files;
  while(f->next != NULL) {
    f = f->next;
    if (f->file_id == 0) {
      f_need_id = f;
    }
  }
  if (f_need_id != NULL) {
    f_need_id->file_id = file_id;
    smb_ss->current_file = f_need_id;
    return 1;
  }
  return 0;
}

smb_session_t *smb_get_session_list(const ipacket_t *ipacket, unsigned index)
{
  protocol_instance_t *configured_protocol = &(ipacket->mmt_handler)
                                                  ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
  return (smb_session_t *)configured_protocol->args;
}


smb_session_t * smb_get_session_from_packet(const ipacket_t *ipacket, unsigned index) {
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
  return *(uint8_t *)smb_payload;
}
int smb_version_extraction(const ipacket_t *ipacket, unsigned proto_index,
                           attribute_t *extracted_data)
{
  const uint8_t *smb_payload = get_smb_payload(ipacket, proto_index + 1);
  if (smb_payload != NULL)
  {
    uint8_t version = smb_version(smb_payload);
    switch (version)
    {
    case SMB_VERSION_1:
      *(uint8_t *)extracted_data->data = 1;
      return 1;
    case SMB_VERSION_2:
      *(uint8_t *)extracted_data->data = 2;
      return 1;
    case SMB_VERSION_3:
      *(uint8_t *)extracted_data->data = 3;
      return 1;
    default:
      break;
    }
  }
  return 0;
}

uint8_t smb_command(const uint8_t *smb_payload)
{
  if (smb_payload[0] == SMB_VERSION_1)
  {
    return *(uint8_t *)&smb_payload[4];
  }
  if (smb_payload[0] == SMB_VERSION_2)
  {
    return *(uint8_t *)&smb_payload[12];
  }
  return 0;
}

int smb_command_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    const uint8_t * smb_payload = get_smb_payload(ipacket, proto_index + 1);
    if (smb_payload != NULL) {
        if (smb_payload[0] == SMB_VERSION_1) {
            *(uint8_t *)extracted_data->data = *(uint8_t *)&smb_payload[4];
            return 1;
        }
        if (smb_payload[0] == SMB_VERSION_2) {
            *(uint8_t *)extracted_data->data = *(uint8_t *)&smb_payload[12];
            return 1;
        }
    }
    return 0;
}

int smb_transfer_payload_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
  struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
  if (packet->payload_packet_len == 0) return 0;
  int offset = get_packet_offset_at_index(ipacket, proto_index);
  smb_session_t *smb_session = smb_get_session_from_packet(ipacket, proto_index);
  if (smb_session == NULL) return 0;
  if (smb_session->sm1_file_transferring == 1) {
    mmt_header_line_t * padding = (mmt_header_line_t *)malloc(sizeof(mmt_header_line_t));
    padding->len = packet->payload_packet_len;
    padding->ptr = (void *) packet->payload;
    extracted_data->data = (void *)padding;
    return 1;
  }

  const uint8_t *smb_payload = get_smb_payload(ipacket, proto_index + 1);
  if (!smb_payload) return 0;
  if (smb_version(smb_payload) != SMB_VERSION_1) return 0;// Only process SMB1 for now

  const uint8_t * cmd_payload = &smb_payload[32];
  uint8_t cmd = smb_command(smb_payload);
  uint16_t padding_size = 0;
  uint16_t padding_offset = 0;
  uint16_t byte_count_offset = 0;
  uint16_t byte_count = 0;
  uint16_t data_length_low = 0;
  uint16_t payload_offset = 0;
  switch (cmd)
  {
    case SMB1_CMD_READ:
      if (smb_session->smb1_cmd_read) return 0; // there is no padding in Read request
      data_length_low = *(uint16_t *) &cmd_payload[12];
      byte_count_offset = 26;
      byte_count = *(uint16_t *) &cmd_payload[byte_count_offset];
      if (byte_count > data_length_low) {
        // there is some padding
        padding_size = byte_count - data_length_low;
        padding_offset = byte_count_offset + 2;
        payload_offset = padding_offset + padding_size;
      } else {
        payload_offset = byte_count_offset + 2;
      }
      smb_session->sm1_file_transferring = 1;
      break;
    case SMB1_CMD_WRITE:
      if (!smb_session->smb1_cmd_write) return 0; // there is no payload in write response
      data_length_low = *(uint16_t *) &cmd_payload[21];
      byte_count_offset = 29;
      byte_count = *(uint16_t *) &cmd_payload[byte_count_offset];
      if (byte_count > data_length_low) {
        // there is some padding
        padding_size = byte_count - data_length_low;
        padding_offset = byte_count_offset + 2;
        payload_offset = padding_offset + padding_size;
      } else {
        payload_offset = byte_count_offset + 2;
      }
      smb_session->sm1_file_transferring = 1;
      break;
    default:
      break;
  }

  if (payload_offset > 0) {
    uint32_t payload_len = ipacket->p_hdr->caplen - offset - 32 - payload_offset;
    mmt_header_line_t * padding = (mmt_header_line_t *)malloc(sizeof(mmt_header_line_t));
    padding->len = payload_len;
    padding->ptr = (const char *)&cmd_payload[payload_offset];
    extracted_data->data = (void *)padding;
    return 1;
  }
  return 0;
}

int smb_padding_extraction(const ipacket_t *ipacket, unsigned proto_index,
                           attribute_t *extracted_data)
{
  const uint8_t *smb_payload = get_smb_payload(ipacket, proto_index + 1);
  if (!smb_payload) return 0;
  if (smb_version(smb_payload) != SMB_VERSION_1) return 0;// Only process SMB1 for now
  smb_session_t *smb_session = smb_get_session_from_packet(ipacket, proto_index);
  if (smb_session == NULL) return 0;

  const uint8_t * cmd_payload = &smb_payload[32];
  uint8_t cmd = smb_command(smb_payload);
  uint16_t padding_size = 0;
  uint16_t padding_offset = 0;
  uint16_t byte_count_offset = 0;
  uint16_t byte_count = 0;
  uint16_t data_length_low = 0;
  uint32_t total_param_count = 0;
  uint32_t total_data_count = 0;
  switch (cmd)
  {
  case SMB1_CMD_READ:
    if (!smb_session->smb1_cmd_read) return 0; // there is no padding in Read request
    data_length_low = *(uint16_t *) &cmd_payload[12];
    byte_count_offset = 26;
    byte_count = *(uint16_t *) &cmd_payload[byte_count_offset];
    if (byte_count > data_length_low) {
      // there is some padding
      padding_size = byte_count - data_length_low;
      padding_offset = byte_count_offset + 2;
    }
    break;
  case SMB1_CMD_WRITE:
    if (!smb_session->smb1_cmd_write) return 0; // there is no padding in write response
    data_length_low = *(uint16_t *) &cmd_payload[21];
    byte_count_offset = 29;
    byte_count = *(uint16_t *) &cmd_payload[byte_count_offset];
    if (byte_count > data_length_low) {
      // there is some padding
      padding_size = byte_count - data_length_low;
      padding_offset = byte_count_offset + 2;
    }
    break;
  case SMB1_CMD_TRANS2:
    // request
    total_param_count = *(uint16_t *) &cmd_payload[1];
    total_data_count = *(uint16_t *) &cmd_payload[3];
    byte_count_offset = 31;
    if (!smb_session->smb1_cmd_trans2) { // response
      byte_count_offset = 21;
    }
    byte_count = *(uint16_t *) &cmd_payload[byte_count_offset];
    if (byte_count > total_param_count + total_data_count ) {
      padding_size = byte_count - (total_param_count + total_data_count);
      if (smb_session->smb1_cmd_trans2) {
        uint16_t param_count = *(uint16_t *) &cmd_payload[19];
        uint16_t param_offset = *(uint16_t *) &cmd_payload[21];
        if (param_offset > 32 + byte_count_offset + 2) {
          uint16_t first_padding_len = param_offset - (32 + byte_count_offset + 2);
          padding_size = first_padding_len;
          padding_offset = byte_count_offset + 2;
        } else {
          padding_offset = byte_count_offset + 2 + param_count;
        }
      } else {
        padding_offset = byte_count_offset + 2;
      }
    }
    break;
  case SMB1_CMD_NT_TRANS:
    // request
    total_param_count = *(uint32_t *) &cmd_payload[4];
    total_data_count = *(uint32_t *) &cmd_payload[8];
    byte_count_offset = 37;
    if (!smb_session->smb1_cmd_nt_trans) {
      byte_count_offset = 47;
    }
    byte_count = *(uint16_t *) &cmd_payload[byte_count_offset];
    if (byte_count > total_param_count + total_data_count ) {
      padding_size = byte_count - (total_param_count + total_data_count);
      if (smb_session->smb1_cmd_nt_trans) {
        uint32_t param_count = *(uint32_t *) &cmd_payload[12];
        uint32_t param_offset = *(uint32_t *) &cmd_payload[16];
        if (param_offset > 32 + byte_count_offset + 2) {
          uint16_t first_padding_len = param_offset - (32 + byte_count_offset + 2);
          padding_size = first_padding_len;
          padding_offset = byte_count_offset + 2;
        } else {
          padding_offset = byte_count_offset + 2 + param_count;
        }
      } else {
        padding_offset = byte_count_offset + 2;
      }
    }
    break;
  default:
    return 0;
  }

  if (padding_size > 0) {
    mmt_header_line_t * padding = (mmt_header_line_t *)malloc(sizeof(mmt_header_line_t));
    padding->len = padding_size;
    padding->ptr = (const char *)&cmd_payload[padding_offset];
    extracted_data->data = (void *)padding;
    return 1;
  }
  return 0;
}

int smb_nt_create_file_name_extraction(const ipacket_t *ipacket, unsigned proto_index,
                                       attribute_t *extracted_data)
{
  smb_session_t *smb_session = smb_get_session_from_packet(ipacket, proto_index);
  if (smb_session == NULL)
    return 0;
  if (!smb_session->smb1_cmd_nt_create)
    return 0;
  const uint8_t *smb_payload = get_smb_payload(ipacket, proto_index + 1);
  if (smb_payload != NULL)
  {
    uint8_t smb_cmd = smb_command(smb_payload);
    if (smb_payload[0] == SMB_VERSION_1 && smb_cmd == 0xa2)
    {
      if (smb_session->current_file)
      {
        extracted_data->data = (void *)smb_session->current_file->file_path;
        return 1;
      }
    }
  }
  return 0;
}

static attribute_metadata_t smb_attributes_metadata[SMB_ATTRIBUTES_NB] = {
    {SMB_VERSION,SMB_VERSION_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_version_extraction},
    {SMB_COMMAND,SMB_COMMAND_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_command_extraction},
    {SMB_PADDING,SMB_PADDING_ALIAS,MMT_HEADER_LINE,sizeof (void *),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_padding_extraction},
    {SMB_TRANSFER_PAYLOAD,SMB_TRANSFER_PAYLOAD_ALIAS,MMT_DATA_POINTER,sizeof (void *),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_transfer_payload_extraction},
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

void smb_context_cleanup(void *proto_context, void *args)
{
  smb_session_t * root = (smb_session_t*)((protocol_instance_t *) proto_context)->args;
  while( root!= NULL) {
    smb_session_t * to_be_deleted = root;
    root = root->next;
    smb_session_free(to_be_deleted);
  }
}

int smb_path_builder(const char * payload, char * path, uint16_t length) {
  int i = 0;
  int k = 0;
  for (i = 0; i < length; i ++) {
    if (payload[i] != 0x00) {
      path[k] = payload[i];
      k++;
    }
    i++;
  }
  path[k] = '\0';
  return k + 1;
}

int smb_session_data_analysis(ipacket_t *ipacket, unsigned index)
{
  if (!ipacket->session)
    return MMT_CONTINUE;
  if (ipacket->internal_packet->payload_packet_len == 0)
    return MMT_CONTINUE;
  smb_session_t *root = smb_get_session_list(ipacket, index);
  if (root == NULL)
  {
    root = smb_session_new(ipacket->session->session_id);
    if (root)
    {
      smb_setup_session_context(ipacket, index, root);
    }
  }

  smb_session_t *current_session = smb_find_session_by_id(root, ipacket->session->session_id);
  if (current_session == NULL)
  {
    // Create a new session
    current_session = smb_session_new(ipacket->session->session_id);
    smb_insert_session(root, current_session);
  }

  // Start analysis the packet and update to the session
  const uint8_t *smb_payload = get_smb_payload(ipacket, index);
  if (smb_payload == NULL)
    return MMT_CONTINUE;
  uint8_t version = smb_version(smb_payload);
  if (version != SMB_VERSION_1)
  {
    return MMT_CONTINUE; // skip for now
  }
  uint8_t smb_cmd = smb_command(smb_payload);
  current_session->last_cmd = smb_cmd;
  const uint8_t *command_payload = &smb_payload[32];
  switch (smb_cmd)
  {
  case SMB1_CMD_READ:
    current_session->smb1_cmd_read = !current_session->smb1_cmd_read;
    break;
  case SMB1_CMD_NT_TRANS:
    current_session->smb1_cmd_nt_trans = !current_session->smb1_cmd_nt_trans;
    break;
  case SMB1_CMD_TRANS2:
    current_session->smb1_cmd_trans2 = !current_session->smb1_cmd_trans2;
    break;
  case SMB1_CMD_CLOSE:
    current_session->smb1_cmd_close = !current_session->smb1_cmd_close;
    if (current_session->smb1_cmd_close)
    {
      current_session->sm1_file_transferring = 0;
      // Close request
      uint16_t file_id = *(uint16_t *)&command_payload[1];
      current_session->current_file_id = file_id;
    }
    break;
  case SMB1_CMD_WRITE:
    current_session->smb1_cmd_write = !current_session->smb1_cmd_write;
    if (current_session->smb1_cmd_write)
    {
      // Write AndX request
      // Update file size
      uint16_t file_id = *(uint16_t *)&command_payload[5];
      current_session->current_file_id = file_id;
      uint32_t seg_offset = *(uint32_t *)&command_payload[7];
      uint16_t data_length_low = *(uint16_t *)&command_payload[21];
      smb_file_t *file = smb_session_find_file_by_id(current_session, file_id);
      if (file)
      {
        if (seg_offset != file->current_len)
        {
          // Trigger an event here
          fprintf(stderr, "\n[SMB] Segment offset missmatched: %lu - %d, %u\n", ipacket->packet_id, file->current_len, seg_offset);
        }
        else
        {
          current_session->current_file = file;
          file->current_seg_len = data_length_low;
        }
      }
    }
    else
    {
      // Write AndX response
      current_session->sm1_file_transferring = 0;
      uint16_t count_low = *(uint16_t *)&command_payload[5];
      if (current_session->current_file != NULL)
      {
        if (current_session->current_file->current_seg_len != count_low)
        {
          // Trigger an event here
          // fprintf(stderr, "\n[SMB] Segment length missmatched: %lu - %d, %d", ipacket->packet_id, current_session->current_file->current_seg_len, count_low);
        }
        else
        {
          current_session->current_file->current_len += count_low;
        }
      }
    }
    break;
  case SMB1_CMD_NT_CREATE:
    current_session->smb1_cmd_nt_create = !current_session->smb1_cmd_nt_create;
    if (current_session->smb1_cmd_nt_create)
    {
      // NT create AndX request
      // Update file path
      uint16_t file_path_len = *(uint16_t *)&command_payload[6];
      char *file_path = (char *)malloc((file_path_len / 2 + 1) * sizeof(char));
      int path_len = smb_path_builder((char* ) &command_payload[52], file_path, file_path_len);
      // memcpy(file_path, &command_payload[52], file_path_len );
      file_path[file_path_len / 2] = '\0';
      smb_file_t *file = smb_session_find_file(current_session, path_len, file_path);
      if (!file)
      {
        file = smb_file_new();
        if (file)
        {
          file->file_path = (mmt_header_line_t *)malloc(sizeof(mmt_header_line_t));
          if (file->file_path)
          {
            file->file_path->len = path_len;
            file->file_path->ptr = file_path;
          }
          current_session->current_file = file;
          smb_session_insert_file(current_session, file);
        }
      } else {
        free(file_path);
      }
    }
    else
    {
      // NT create AndX response
      uint16_t file_id = *(uint16_t *)&command_payload[6];
      current_session->current_file_id = file_id;
      smb_session_update_last_file_id(current_session, file_id);
    }
    break;

  default:
    break;
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


