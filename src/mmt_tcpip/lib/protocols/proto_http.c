#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "http.h"
#include "rfc2822utils.h"
#include "packet_processing.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
int http_new_host_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->host_line.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->host_line;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_method_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->http_method.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->http_method;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_response_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->http_response.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->http_response;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_uri_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->http_url_name.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->http_url_name;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_referer_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->referer_line.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->referer_line;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_content_type_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->content_line.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->content_line;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_user_agent_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->user_agent_line.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->user_agent_line;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_content_len_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if (ipacket->internal_packet->packet_lines_parsed_complete != 0) {
            if (ipacket->internal_packet->http_contentlen.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->http_contentlen;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_server_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->server_line.ptr != NULL) {
                extracted_data->data = (void *) &ipacket->internal_packet->server_line;
                return 1;
            }
        }
    }
    return 0;
}

int http_new_xcdn_seen_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if ((ipacket->internal_packet->packet_lines_parsed_complete != 0)
            && (ipacket->internal_packet->packet_id == ipacket->packet_id)) {
            if (ipacket->internal_packet->has_x_cdn_hdr) {
                *(uint8_t *) extracted_data->data = 1;
                return 1;
            }
        }
    }
    return 0;
}

#define HTTP_NEW_ATTRIBUTES_NB 10

static attribute_metadata_t http_new_attributes_metadata[HTTP_NEW_ATTRIBUTES_NB] = {
    {RFC2822_HOST, RFC2822_HOST_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_host_extraction},
    {RFC2822_METHOD, RFC2822_METHOD_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_method_extraction},
    {RFC2822_RESPONSE, RFC2822_RESPONSE_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_response_extraction},
    {RFC2822_URI, RFC2822_URI_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_uri_extraction},
    {RFC2822_REFERER, RFC2822_REFERER_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_referer_extraction},
    {RFC2822_CONTENT_TYPE, RFC2822_CONTENT_TYPE_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_content_type_extraction},
    {RFC2822_USER_AGENT, RFC2822_USER_AGENT_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_user_agent_extraction},
    {RFC2822_CONTENT_LEN, RFC2822_CONTENT_LEN_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_content_len_extraction},
    {RFC2822_SERVER, RFC2822_SERVER_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_server_extraction},
    {RFC2822_XCDN_SEEN, RFC2822_XCDN_SEEN_ALIAS, MMT_U8_DATA, sizeof (uint8_t), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, http_new_xcdn_seen_extraction},
};

int http_internal_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    if (packet->payload_packet_len > 32) {
        if ((flow->l4.tcp.http_data_direction != ipacket->session->last_packet_direction)) {
            mmt_parse_packet_line_info(ipacket);
        }
        flow->l4.tcp.http_data_direction = ipacket->session->last_packet_direction;
    }
    return MMT_CONTINUE;
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_http_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_HTTP, PROTO_HTTP_ALIAS);

    if (protocol_struct != NULL) {
        int i = 0;

        for (; i < HTTP_NEW_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &http_new_attributes_metadata[i]);
        }

        mmt_init_classify_me_http();

        //BW
        register_session_data_analysis_function(protocol_struct, http_internal_session_data_analysis);

        return register_protocol(protocol_struct, PROTO_HTTP);
    } else {
        return 0;
    }
}


