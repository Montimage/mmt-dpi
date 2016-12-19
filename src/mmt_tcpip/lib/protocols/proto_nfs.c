#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "nfs.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

nfs_opcode_t * nfs_opcode_new(){
    nfs_opcode_t * nfs_opcode;
    nfs_opcode = (nfs_opcode_t*)sizeof(nfs_opcode_t);
    if(nfs_opcode){
        nfs_opcode->opcode = -1;
        nfs_opcode->data_offset = 0;
        // nfs_opcode->next = NULL;
    }
    return nfs_opcode;
}

void nfs_opcode_free(nfs_opcode_t* nfs_opcode){
    if(nfs_opcode){
        nfs_opcode->opcode = -1;
        nfs_opcode->data_offset = 0;
        // nfs_opcode->next = NULL;
        free(nfs_opcode);
        nfs_opcode = NULL;
    }
}

int nfs_is_file_operation(int opcode){
    switch(opcode){
        case NFS_OPCODE_LOOKUP:
        case NFS_OPCODE_OPEN:
        case NFS_OPCODE_REMOVE:
        case NFS_OPCODE_RENAME:
            return 1;
        default:
            return 0;
    }
    return 0;
}

nfs_opcode_t * nfs_extract_opcode(const ipacket_t *ipacket, int opcode_data_offset){
    nfs_opcode_t *opcode = nfs_opcode_new();
    if(opcode){
        opcode->data_offset = opcode_data_offset;
        int current_opcode = ntohl(*((unsigned int *) &ipacket->data[opcode_data_offset]));
        opcode->opcode = current_opcode;
        return opcode;
    }
    return opcode;
}

// NFS_OPCODE_ACCESS = 3, // = 4 + 8
//     NFS_OPCODE_CLOSE = 4, // = 4 + 4 + 4 + 12
//     NFS_DELEGRETURN = 8, // 4 + 4 + 12
//     NFS_OPCODE_GETATTR = 9, // = 4 + 4 + 4 + 4
//     NFS_OPCODE_GETFH = 10, // = 4
//     NFS_OPCODE_LOOKUP = 15,// 4 + (length 4) + 2
//     NFS_OPCODE_OPEN = 18,// = 4 + 4 +4 + 4 + (length 4) + 4 + 4 + length(4)+ 2
//     NFS_OPCODE_OPEN_CONFIRM = 20,
//     NFS_OPCODE_PUTFH = 22, // offset + 4 -> length + 8
//     NFS_OPCODE_READDIR = 26,
//     NFS_OPCODE_REMOVE = 28, // 4 + (length 4) + 2
//     NFS_OPCODE_RENAME = 29, // (old) 4 + (length 4) + 3 + (new) 4 + (length 4) + 2
//     NFS_OPCODE_SAVEFH = 32,
//     NFS_OPCODE_SETATTR = 34,// 4 + 4 + 12 + 4
//     NFS_OPCODE_SETCLIENTID = 35,
//     NFS_OPCODE_SETCLIENTID_CONFIRM = 36,
//     NFS_OPCODE_WRITE = 38, // 4 + 4 + 12 + 8 + 4 + length(4)

/**
 * Get total length of opcode to get the offset of next opcode
 * @param  ipacket    ipacket
 * @param  nfs_opcode current opcode
 * @return            total length of current opcode
 */
int nfs_opcode_length_extraction(const ipacket_t * ipacket, nfs_opcode_t *nfs_opcode){
    int opcode_length = 0;

}

char * nfs_extract_file_name_from_opcode(const ipacket_t * ipacket, int opcode_data_offset, int opcode){

}


static void mmt_int_nfs_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_NFS, MMT_REAL_PROTOCOL);
}

int nfs_rpc_version_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) &ipacket->data[nfs_payload_offset+8]));
    fprintf(stderr, "%lu - message_type: %d\n",ipacket->packet_id,message_type);
    if(message_type==0){
        // Call message
        *((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) &ipacket->data[nfs_payload_offset+12]));
        return 1;
    }
    return 0;
}

int nfs_program_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) &ipacket->data[nfs_payload_offset+8]));

    if(message_type==0){
        // Call message
        *((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) &ipacket->data[nfs_payload_offset+16]));
        return 1;
    }
    return 0;
}


int nfs_prog_version_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) &ipacket->data[nfs_payload_offset+8]));

    if(message_type==0){
        // Call message
        *((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) &ipacket->data[nfs_payload_offset+20]));
        return 1;
    }
    return 0;
}


int nfs_procedure_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 8]));

    if(message_type==0){
        // Call message
        *((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) &ipacket->data[nfs_payload_offset+24]));
        return 1;
    }
    return 0;
}

int get_nfs_data_offset(const ipacket_t * ipacket,int nfs_payload_offset,int is_call_msg){
    if(is_call_msg){
        int credential_length = ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 32]));
        int verifier_length =  ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 32 + 4 + credential_length + 4]));
        int nfs_data_offset = nfs_payload_offset + 32 + 4 + credential_length + 4 + verifier_length + 4;
        return nfs_data_offset;
    }else{
        return 0;
    }
}

int nfs_tag_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 8]));

    if(message_type==0){
        // Call message
        int nfs_data_offset = get_nfs_data_offset(ipacket,nfs_payload_offset,1);
        int tag_length = ntohl(*((unsigned int *) & ipacket->data[nfs_data_offset]));
        char * tag_value;
        tag_value = (char*)malloc((tag_length + 1)*sizeof(char));
        memcpy(tag_value,&ipacket->data[nfs_payload_offset+4],tag_length);
        tag_value[tag_length]='\0';
        extracted_data->data = (void *) tag_value;
        return 1;
    }
    return 0;
}

int nfs_minorversion_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 8]));

    if(message_type==0){
        // Call message
        int nfs_data_offset = get_nfs_data_offset(ipacket,nfs_payload_offset,1);
        int tag_length = ntohl(*((unsigned int *) & ipacket->data[nfs_data_offset]));
        *((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) &ipacket->data[nfs_data_offset + tag_length + 4]));
        return 1;
    }
    return 0;
}

int nfs_nb_operations_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 8]));

    if(message_type==0){
        // Call message
        int nfs_data_offset = get_nfs_data_offset(ipacket,nfs_payload_offset,1);
        int tag_length = ntohl(*((unsigned int *) & ipacket->data[nfs_data_offset]));
        *((unsigned int *) extracted_data->data) = ntohl(*((unsigned int *) &ipacket->data[nfs_data_offset + tag_length + 8]));
        return 1;
    }
    return 0;
}

int nfs_file_opcode_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 8]));

    if(message_type==0){
        // Call message
        int nfs_data_offset = get_nfs_data_offset(ipacket,nfs_payload_offset,1);
        int tag_length = ntohl(*((unsigned int *) & ipacket->data[nfs_data_offset]));
        int nb_opcodes = ntohl(*((unsigned int *) &ipacket->data[nfs_data_offset + tag_length + 8]));
        int current_offset = nfs_data_offset + tag_length + 8 + 4;
        int current_opcode_index = 0;
        while(current_opcode_index < nb_opcodes && current_offset < nfs_payload_offset + ipacket->internal_packet->payload_packet_len){
            current_opcode_index++;
            nfs_opcode_t * nfs_opcode = nfs_extract_opcode(ipacket,current_offset);

            if(nfs_opcode==NULL) return 0;
            
            if(nfs_is_file_operation(nfs_opcode->opcode)){
                *((unsigned int *) extracted_data->data) = current_opcode;
                return 1;
            }
            int current_opcode_length = nfs_opcode_length_extraction(ipacket,nfs_opcode);
            current_offset = current_offset + 4 + 4 + current_opcode_length;
        }
        return 0;
    }
    return 0;
}

int nfs_file_name_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    if (ipacket->internal_packet->payload_packet_len<=0){
        return 0;
    }
    int nfs_payload_offset = get_packet_offset_at_index(ipacket, proto_index);

    int message_type = ntohl(*((unsigned int *) & ipacket->data[nfs_payload_offset + 8]));

    if(message_type==0){
        // Call message
        int nfs_data_offset = get_nfs_data_offset(ipacket,nfs_payload_offset,1);
        int tag_length = ntohl(*((unsigned int *) & ipacket->data[nfs_data_offset]));
        int nb_opcodes = ntohl(*((unsigned int *) &ipacket->data[nfs_data_offset + tag_length + 8]));
        int current_offset = nfs_data_offset + tag_length + 8 + 4;
        int current_opcode_index = 0;
        while(current_opcode_index < nb_opcodes && current_offset < nfs_payload_offset + ipacket->internal_packet->payload_packet_len){
            current_opcode_index++;
            int current_opcode = ntohl(*((unsigned int *) &ipacket->data[current_offset]));
            if(nfs_is_file_operation(current_opcode)){
                char *file_name = nfs_extract_file_name_from_opcode(ipacket,current_offset + 4,current_opcode);
                if(file_name){
                    extracted_data->data = (void*)file_name;
                    return 1;
                }
            }
            int current_opcode_length = ntohl(*((unsigned int *) &ipacket->data[current_offset + 4]));
            current_offset = current_offset + 4 + 4 + current_opcode_length;
        }
        return 0;
    }
    return 0;
}

static attribute_metadata_t nfs_attributes_metadata[NFS_ATTRIBUTES_NB] = {
    {NFS_XID, NFS_XID_ALIAS, MMT_U32_DATA, sizeof (int), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {NFS_MESSAGE_TYPE, NFS_MESSAGE_TYPE_ALIAS, MMT_U32_DATA, sizeof (int), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    // Call packet attributes
    {NFS_RPC_VERSION, NFS_RPC_VERSION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_rpc_version_extraction},
    {NFS_PROGRAM, NFS_PROGRAM_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_program_extraction},
    {NFS_PROG_VERSION, NFS_PROG_VERSION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_prog_version_extraction},
    {NFS_PROCEDURE, NFS_PROCEDURE_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_procedure_extraction},
    // Reply packet attributes
    {NFS_TAG, NFS_TAG_ALIAS, MMT_STRING_DATA_POINTER, sizeof (char*), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_tag_extraction},
    {NFS_MINORVERSION, NFS_MINORVERSION_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_minorversion_extraction},
    {NFS_FILE_OPCODE, NFS_FILE_OPCODE_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_file_opcode_extraction},
    {NFS_FILE_NAME, NFS_FILE_NAME_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_file_name_extraction},
    {NFS_NB_OPERATIONS, NFS_NB_OPERATIONS_ALIAS, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, nfs_nb_operations_extraction},
};

int mmt_check_nfs(ipacket_t * ipacket, unsigned index) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint8_t offset = 0;
        if (packet->tcp != NULL)
            offset = 4;

        if (packet->payload_packet_len < (40 + offset))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 1\n");

        if (offset != 0 && get_u32(packet->payload, 0) != htonl(0x80000000 + packet->payload_packet_len - 4))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 2\n");

        if (get_u32(packet->payload, 4 + offset) != 0)
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS user match stage 3\n");

        if (get_u32(packet->payload, 8 + offset) != htonl(0x02))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match stage 3\n");

        if (get_u32(packet->payload, 12 + offset) != htonl(0x000186a5)
                && get_u32(packet->payload, 12 + offset) != htonl(0x000186a3)
                && get_u32(packet->payload, 12 + offset) != htonl(0x000186a0))
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match stage 4\n");

        if (ntohl(get_u32(packet->payload, 16 + offset)) > 4)
            goto exclude_nfs;

        MMT_LOG(PROTO_NFS, MMT_LOG_DEBUG, "NFS match\n");

        mmt_int_nfs_add_connection(ipacket);
        return 1;

exclude_nfs:
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_NFS);
    }
    return 0;
}

void mmt_init_classify_me_nfs() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_NFS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_nfs_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NFS, PROTO_NFS_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < NFS_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &nfs_attributes_metadata[i]);
        }
        mmt_init_classify_me_nfs();

        return register_protocol(protocol_struct, PROTO_NFS);
    } else {
        return 0;
    }
}


