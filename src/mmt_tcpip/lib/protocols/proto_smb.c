#include "smb.h"

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
int smb_version_extraction(const ipacket_t * ipacket, unsigned proto_index,
    attribute_t * extracted_data){
    uint8_t smb_version = 0;
    const uint8_t * smb_payload = get_smb_payload(ipacket, proto_index + 1);
    if (smb_payload != NULL) {
        if (smb_payload[0] == 0xff) {
            smb_version = 1;
        } else if (smb_payload[0] == 0xfe) {
            smb_version = 2;
        } else if (smb_payload[0] == 0xfd) {
            smb_version = 3;
        }
        *(uint8_t *)extracted_data->data = smb_version;
        return 1;
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
    const uint8_t * smb_payload = get_smb_payload(ipacket, proto_index + 1);
    if (smb_payload != NULL) {
        uint8_t write_request_seen = 0; // extract this value from session
        if (smb_payload[0] == 0xff && smb_payload[4] == 0x2f && !write_request_seen) {
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

static attribute_metadata_t smb_attributes_metadata[SMB_ATTRIBUTES_NB] = {
    {SMB_VERSION,SMB_VERSION_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_version_extraction},
    {SMB_COMMAND,SMB_COMMAND_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_command_extraction},
    {SMB_PADDING,SMB_PADDING_ALIAS,MMT_HEADER_LINE,sizeof (void *),POSITION_NOT_KNOWN,SCOPE_PACKET,smb_padding_extraction},
};

void mmt_init_classify_me_smb() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SMB);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_smb_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SMB, PROTO_SMB_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < SMB_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &smb_attributes_metadata[i]);
        }
        mmt_init_classify_me_smb();

        return register_protocol(protocol_struct, PROTO_SMB);
    } else {
        return 0;
    }
}


