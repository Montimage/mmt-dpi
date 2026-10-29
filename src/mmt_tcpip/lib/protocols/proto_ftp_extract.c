/*
 * proto_ftp_extract.c — FTP attribute extraction: the session attributes,
 * resolved through ftp_resolve_session(), the packet attributes and the
 * attribute table init_proto_ftp_struct() registers. Split out of
 * proto_ftp.c by issue #544.
 */
#include "plugin_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ftp.h"

/**
 * Check if a packet belongs to a control connection which is identified by server port number 21
 * @param  ipacket packet to check
 * @return         1 if the packet belongs to a control connection
 *                 2 if the packet doesn't belong to a control connection
 */
inline static int ftp_check_control_packet(const ipacket_t *ipacket) {
    if (ipacket->internal_packet->tcp) {
        return (ipacket->internal_packet->tcp->source == htons(21) || ipacket->internal_packet->tcp->dest == htons(21));
    }
    return 0;
}

/**
 * The FTP sessions a packet resolves to (issue #544).
 *
 * The packet's session_data slot holds a control session on the control
 * connection (server port 21) and a data session on a data connection; each
 * side reaches the other: control->current_data_session and
 * data->control_session. Either pointer is NULL when the session, or its
 * link to the other side, is absent.
 */
typedef struct ftp_session_ref_struct {
    ftp_control_session_t *control;
    ftp_data_session_t *data;
    int on_control;             // 1 when the packet is on the control connection
} ftp_session_ref_t;

/**
 * Resolve the control and data sessions of a packet — the one copy of the
 * resolution every session attribute extractor shares (issue #544).
 * @param  ipacket     packet
 * @param  proto_index protocol index
 * @return             the control and data sessions, either of them NULL
 */
static ftp_session_ref_t ftp_resolve_session(const ipacket_t *ipacket, unsigned proto_index) {
    ftp_session_ref_t ref = {NULL, NULL, 0};
    if (ftp_check_control_packet(ipacket)) {
        ref.on_control = 1;
        ref.control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if (ref.control) {
            ref.data = ref.control->current_data_session;
        }
    } else {
        ref.data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if (ref.data) {
            ref.control = ref.data->control_session;
        }
    }
    return ref;
}

//////////////////////////// EXTRACTION ///////////////////////////////////////

int ftp_get_packet_type(const ipacket_t *ipacket, unsigned index) {

    if (ipacket->internal_packet->payload_packet_len == 0) {
        return MMT_FTP_PACKET_TYPE_UNKNOWN;
    }

    ftp_tuple6_t *tuple6 = ftp_get_tuple6(ipacket);

    if (tuple6->conn_type == MMT_FTP_CONTROL_CONNECTION) {
        if (tuple6->direction == MMT_FTP_PACKET_SERVER) {
            free_ftp_tuple6(tuple6);
            return MMT_FTP_PACKET_RESPONSE;
        } else {
            free_ftp_tuple6(tuple6);
            return MMT_FTP_PACKET_COMMAND;
        }
    } else if (tuple6->conn_type == MMT_FTP_DATA_CONNECTION) {
        free_ftp_tuple6(tuple6);
        return MMT_FTP_PACKET_DATA;
    }
    free_ftp_tuple6(tuple6);
    return MMT_FTP_PACKET_TYPE_UNKNOWN;
}

////////////////////// SESSION ATTRIBUTE EXTRACTION ///////////////////////
/**
 * Extract connection type of which packet belongs to
 * @param  packet         packet
 * @param  proto_index    protocol index
 * @param  extracted_data extracted data
 * @return                1 if there is data
 *                        0 there is no data
 */
int ftp_session_conn_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                     attribute_t * extracted_data) {
    ftp_tuple6_t *t6;

    t6 = ftp_get_tuple6(ipacket);

    if (t6) {
        *((uint8_t*)extracted_data->data) = t6->conn_type;
        free_ftp_tuple6(t6);
        return 1;
    }

    return 0;
}

int ftp_server_contrl_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->contrl_conn && control->contrl_conn->s_addr) {
        *((uint32_t*)extracted_data->data) = control->contrl_conn->s_addr;
        return 1;
    }
    return 0;
}

int ftp_server_contrl_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->contrl_conn && control->contrl_conn->s_port) {
        *((uint16_t*)extracted_data->data) = control->contrl_conn->s_port;
        return 1;
    }
    return 0;
}

int ftp_client_contrl_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->contrl_conn && control->contrl_conn->c_addr) {
        *((uint32_t*)extracted_data->data) = control->contrl_conn->c_addr;
        return 1;
    }
    return 0;
}

int ftp_client_contrl_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->contrl_conn && control->contrl_conn->c_port) {
        *((uint16_t*)extracted_data->data) = control->contrl_conn->c_port;
        return 1;
    }
    return 0;
}

int ftp_contrl_ip_session_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                        attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->contrl_conn && control->contrl_conn->ip_session_id) {
        *((uint64_t*)extracted_data->data) = control->contrl_conn->ip_session_id;
        return 1;
    }
    return 0;
}

int ftp_username_extraction(const ipacket_t * ipacket, unsigned proto_index,
                            attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->user && control->user->username) {
        extracted_data->data = (void*)control->user->username;
        return 1;
    }
    return 0;
}

int ftp_password_extraction(const ipacket_t * ipacket, unsigned proto_index,
                            attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->user && control->user->password) {
        extracted_data->data = (void*)control->user->password;
        return 1;
    }
    return 0;
}

int ftp_features_extraction(const ipacket_t * ipacket, unsigned proto_index,
                            attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->session_feats) {
        extracted_data->data = (void*)control->session_feats;
        return 1;
    }
    return 0;
}

int ftp_status_extraction(const ipacket_t * ipacket, unsigned proto_index,
                          attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->status) {
        *((uint16_t*)extracted_data->data) = control->status;
        return 1;
    }
    return 0;
}

int ftp_syst_extraction(const ipacket_t * ipacket, unsigned proto_index,
                        attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->session_syst) {
        extracted_data->data = (void*)control->session_syst;
        return 1;
    }
    return 0;
}

int ftp_last_command_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->last_command) {
        extracted_data->data = (void*)control->last_command;
        return 1;
    }
    return 0;
}

int ftp_last_response_code_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->last_response) {
        extracted_data->data = (void*)control->last_response;
        return 1;
    }
    return 0;
}

int ftp_current_dir_extraction(const ipacket_t * ipacket, unsigned proto_index,
                               attribute_t * extracted_data) {
    ftp_control_session_t *control = ftp_resolve_session(ipacket, proto_index).control;
    if (control && control->current_dir) {
        extracted_data->data = (void*)control->current_dir;
        return 1;
    }
    return 0;
}

int ftp_server_data_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                    attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_conn && data->data_conn->s_addr) {
        *((uint32_t*)extracted_data->data) = data->data_conn->s_addr;
        return 1;
    }
    return 0;
}

int ftp_server_data_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                    attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_conn && data->data_conn->s_port) {
        *((uint16_t*)extracted_data->data) = data->data_conn->s_port;
        return 1;
    }
    return 0;
}

int ftp_client_data_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                    attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_conn && data->data_conn->c_addr) {
        *((uint32_t*)extracted_data->data) = data->data_conn->c_addr;
        return 1;
    }
    return 0;
}

int ftp_client_data_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                    attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_conn && data->data_conn->c_port) {
        *((uint16_t*)extracted_data->data) = data->data_conn->c_port;
        return 1;
    }
    return 0;
}

int ftp_data_ip_session_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_conn && data->data_conn->ip_session_id) {
        *((uint64_t*)extracted_data->data) = data->data_conn->ip_session_id;
        return 1;
    }
    return 0;
}

int ftp_data_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
                             attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_type) {
        *((uint8_t*)extracted_data->data) = data->data_type;
        return 1;
    }
    return 0;
}

int ftp_data_transfer_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_transfer_type) {
        extracted_data->data = data->data_transfer_type;
        return 1;
    }
    return 0;
}

int ftp_data_mode_extraction(const ipacket_t * ipacket, unsigned proto_index,
                             attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->data_conn_mode) {
        *((uint8_t*)extracted_data->data) = data->data_conn_mode;
        return 1;
    }
    return 0;
}

int ftp_data_direction_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                  attribute_t * extracted_data) {
    ftp_session_ref_t ref = ftp_resolve_session(ipacket, proto_index);
    ftp_data_session_t *data = ref.data;
    /* On the control connection the direction is reported whatever its
     * value, on a data connection only when non-zero. */
    if (data && (ref.on_control || data->data_direction)) {
        *((uint8_t*)extracted_data->data) = data->data_direction;
        return 1;
    }
    return 0;
}

int ftp_file_name_extraction(const ipacket_t * ipacket, unsigned proto_index,
                             attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->file && data->file->name) {
        extracted_data->data = (void*)data->file->name;
        return 1;
    }
    return 0;
}

int ftp_file_size_extraction(const ipacket_t * ipacket, unsigned proto_index,
                             attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->file && data->file->size) {
        *((uint32_t*)extracted_data->data) = data->file->size;
        return 1;
    }
    return 0;
}

int ftp_file_last_modified_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                      attribute_t * extracted_data) {
    ftp_data_session_t *data = ftp_resolve_session(ipacket, proto_index).data;
    if (data && data->file && data->file->last_modified) {
        extracted_data->data = (void*)data->file->last_modified;
        return 1;
    }
    return 0;
}

////////////////////// PACKET ATTRIBUTE EXTRACTION ///////////////////////
int ftp_packet_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
                               attribute_t * extracted_data) {
    uint8_t p_type = ftp_get_packet_type(ipacket, proto_index);
    *((uint8_t*)extracted_data->data) = p_type;
    return 1;
}

int ftp_packet_request_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                  attribute_t * extracted_data) {

    int packet_type = ftp_get_packet_type(ipacket, proto_index);
    if (packet_type == MMT_FTP_PACKET_COMMAND) {
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        /* Clamp the IP-derived length to the captured bytes and validate the
         * offset before touching payload (F-BUG-069/F-BUG-107, #195). */
        int payload_len = (int)ftp_effective_payload_len(ipacket, proto_index, NULL);
        if (payload_len <= 0) {
            return 0;
        }
        char *payload = (char*)&ipacket->data[offset];
        if (payload[0] == '\0') {
            return 0;
        }
        char * ret = ftp_get_command_str(payload,payload_len);
        /* Issue #506: the handler owns the string until the next packet. */
        if(mmt_packet_scratch_adopt(ipacket, ret, free)){
            extracted_data->data = (void*)ret;
            return 1;
        }
    }
    return 0;
}

int ftp_packet_request_parameter_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {

    int packet_type = ftp_get_packet_type(ipacket, proto_index);
    if (packet_type == MMT_FTP_PACKET_COMMAND) {
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        /* Clamp the IP-derived length to the captured bytes and validate the
         * offset before touching payload (F-BUG-069/F-BUG-107, #195). */
        int payload_len = (int)ftp_effective_payload_len(ipacket, proto_index, NULL);
        if (payload_len <= 0) {
            return 0;
        }
        char *payload = (char*)&ipacket->data[offset];
        if (payload[0] == '\0') {
            return 0;
        }
        char * ret = ftp_get_command_param(payload,payload_len);
        /* Issue #506: the handler owns the string until the next packet. */
        if(mmt_packet_scratch_adopt(ipacket, ret, free)){
            extracted_data->data = (void*)ret;
            return 1;
        }
    }
    return 0;
}

int ftp_packet_response_code_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                        attribute_t * extracted_data) {

    int packet_type = ftp_get_packet_type(ipacket, proto_index);
    if (packet_type == MMT_FTP_PACKET_RESPONSE) {
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        /* Clamp the IP-derived length to the captured bytes and validate the
         * offset before touching payload (F-BUG-069/F-BUG-107, #195). */
        int payload_len = (int)ftp_effective_payload_len(ipacket, proto_index, NULL);
        if (payload_len <= 0) {
            return 0;
        }
        char *payload = (char*)&ipacket->data[offset];
        if (payload[0] == '\0') {
            return 0;
        }
        *((uint16_t*)extracted_data->data) = ftp_get_response_code(payload,payload_len);
        return 1;
    }
    return 0;
}

int ftp_packet_response_value_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {

    int packet_type = ftp_get_packet_type(ipacket, proto_index);
    if (packet_type == MMT_FTP_PACKET_RESPONSE) {
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        /* Clamp the IP-derived length to the captured bytes and validate the
         * offset before touching payload (F-BUG-069/F-BUG-107, #195). */
        int payload_len = (int)ftp_effective_payload_len(ipacket, proto_index, NULL);
        if (payload_len <= 0) {
            return 0;
        }
        char *payload = (char*)&ipacket->data[offset];
        if (payload[0] == '\0') {
            return 0;
        }
        char * ret = ftp_get_response_value(payload,payload_len);
        /* Issue #506: the handler owns the string until the next packet. */
        if(mmt_packet_scratch_adopt(ipacket, ret, free)){
            extracted_data->data = (void*)ret;
            return 1;
        }
    }
    return 0;
}

int ftp_packet_data_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                   attribute_t * extracted_data) {

    int packet_type = ftp_get_packet_type(ipacket, proto_index);
    if (packet_type == MMT_FTP_PACKET_DATA) {
        int len = ipacket->internal_packet->payload_packet_len;
        *((uint32_t*)extracted_data->data) = len;
        // debug("FTP: extraction payload_packet_len: %d",*(uint32_t*)extracted_data->data);
        return 1;
    }
    return 0;
}

attribute_metadata_t ftp_attributes_metadata[FTP_ATTRIBUTES_NB] = {
    ////////////// SESSION ATTRIBUTES //////////////////////////////
    /// FTP CONTROL CONNECTION SESSION ATTRIBUTES ///
    {FTP_SESSION_CONN_TYPE, FTP_SESSION_CONN_TYPE_ALIAS, MMT_U8_DATA, sizeof(char), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_session_conn_type_extraction},
    {FTP_SERVER_CONT_ADDR, FTP_SERVER_CONT_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof(int), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_server_contrl_addr_extraction},
    {FTP_SERVER_CONT_PORT, FTP_SERVER_CONT_PORT_ALIAS, MMT_U16_DATA, sizeof(short), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_server_contrl_port_extraction},
    {FTP_CLIENT_CONT_PORT, FTP_CLIENT_CONT_PORT_ALIAS, MMT_U16_DATA, sizeof(short), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_client_contrl_port_extraction},
    {FTP_CLIENT_CONT_ADDR, FTP_CLIENT_CONT_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof(int), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_client_contrl_addr_extraction},
    {FTP_CONT_IP_SESSION_ID, FTP_CONT_IP_SESSION_ID_ALIAS, MMT_U64_DATA, sizeof(uint64_t), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_contrl_ip_session_id_extraction},
    {FTP_USERNAME, FTP_USERNAME_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ftp_username_extraction},
    {FTP_PASSWORD, FTP_PASSWORD_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ftp_password_extraction},
    {FTP_SESSION_FEATURES, FTP_SESSION_FEATURES_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ftp_features_extraction},
    {FTP_SYST, FTP_SYST_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_syst_extraction},
    {FTP_STATUS, FTP_STATUS_ALIAS, MMT_U16_DATA, sizeof(short), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ftp_status_extraction},
    {FTP_LAST_COMMAND, FTP_LAST_COMMAND_ALIAS, MMT_DATA_POINTER, sizeof(void*), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ftp_last_command_extraction},
    {FTP_LAST_RESPONSE_CODE, FTP_LAST_RESPONSE_CODE_ALIAS, MMT_DATA_POINTER, sizeof(void*), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ftp_last_response_code_extraction},
    {FTP_CURRENT_DIR, FTP_CURRENT_DIR_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ftp_current_dir_extraction},
    /// CURRENT FTP DATA CONNECTION SESSION ATTRIBUTES ///
    {FTP_SERVER_DATA_ADDR, FTP_SERVER_DATA_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof(int), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_server_data_addr_extraction},
    {FTP_SERVER_DATA_PORT, FTP_SERVER_DATA_PORT_ALIAS, MMT_U16_DATA, sizeof(short), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_server_data_port_extraction},
    {FTP_CLIENT_DATA_ADDR, FTP_CLIENT_DATA_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof(int), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_client_data_addr_extraction},
    {FTP_CLIENT_DATA_PORT, FTP_CLIENT_DATA_PORT_ALIAS, MMT_U16_DATA, sizeof(short), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_client_data_port_extraction},
    {FTP_DATA_IP_SESSION_ID, FTP_DATA_IP_SESSION_ID_ALIAS, MMT_U64_DATA, sizeof(uint64_t), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_data_ip_session_id_extraction},
    {FTP_DATA_TYPE, FTP_DATA_TYPE_ALIAS, MMT_U8_DATA, sizeof(char), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_data_type_extraction},
    {FTP_DATA_TRANSFER_TYPE, FTP_DATA_TRANSFER_TYPE_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_data_transfer_type_extraction},
    {FTP_DATA_MODE, FTP_DATA_MODE_ALIAS, MMT_U8_DATA, sizeof(char), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_data_mode_extraction},
    {FTP_DATA_DIRECTION, FTP_DATA_DIRECTION_ALIAS, MMT_U8_DATA, sizeof(char), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_data_direction_extraction},
    /// CURRENT FTP FILE ATTRIBUTES ///
    {FTP_FILE_NAME, FTP_FILE_NAME_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_file_name_extraction},
    {FTP_FILE_SIZE, FTP_FILE_SIZE_ALIAS, MMT_U32_DATA, sizeof(int), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_file_size_extraction},
    {FTP_FILE_LAST_MODIFIED, FTP_FILE_LAST_MODIFIED_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_SESSION, ftp_file_last_modified_extraction},
    ////////////// PACKET ATTRIBUTES //////////////////////////////
    {FTP_PACKET_TYPE, FTP_PACKET_TYPE_ALIAS, MMT_U8_DATA, sizeof(char), POSITION_NOT_KNOWN, SCOPE_PACKET, ftp_packet_type_extraction},
    {FTP_PACKET_REQUEST, FTP_PACKET_REQUEST_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_PACKET, ftp_packet_request_extraction},
    {FTP_PACKET_REQUEST_PARAMETER, FTP_PACKET_REQUEST_PARAMETER_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_PACKET, ftp_packet_request_parameter_extraction},
    {FTP_PACKET_RESPONSE_CODE, FTP_PACKET_RESPONSE_CODE_ALIAS, MMT_U16_DATA, sizeof(short), POSITION_NOT_KNOWN, SCOPE_PACKET, ftp_packet_response_code_extraction},
    {FTP_PACKET_RESPONSE_VALUE, FTP_PACKET_RESPONSE_VALUE_ALIAS, MMT_STRING_DATA_POINTER, sizeof(char*), POSITION_NOT_KNOWN, SCOPE_PACKET, ftp_packet_response_value_extraction},
    {FTP_PACKET_DATA_LEN, FTP_PACKET_DATA_LEN_ALIAS, MMT_U32_DATA, sizeof(int), POSITION_NOT_KNOWN, SCOPE_PACKET, ftp_packet_data_len_extraction}
};

//////////////////////////// END OF EXTRACTION /////////////////////////////////
