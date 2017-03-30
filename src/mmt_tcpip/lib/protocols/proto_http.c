#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "../http_parser_integration.h"

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

static attribute_metadata_t http_new_attributes_metadata[RFC2822_ATTRIBUTES_NB] = {
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
    //BW: New attributes for EVENT based HTTP parsing
    {HTTP_MESSAGE_START, HTTP_MESSAGE_START_ALIAS, MMT_U32_DATA, sizeof (uint32_t), POSITION_NOT_KNOWN, SCOPE_EVENT, silent_extraction},
    {HTTP_HEADER, HTTP_HEADER_ALIAS, MMT_GENERIC_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_EVENT, silent_extraction},
    {HTTP_HEADERS_END, HTTP_HEADERS_END_ALIAS, MMT_U32_DATA, sizeof (uint32_t), POSITION_NOT_KNOWN, SCOPE_EVENT, silent_extraction},
    {HTTP_DATA, HTTP_DATA_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_EVENT, silent_extraction},
    {HTTP_MESSAGE_END, HTTP_MESSAGE_END_ALIAS, MMT_U32_DATA, sizeof (uint32_t), POSITION_NOT_KNOWN, SCOPE_EVENT, silent_extraction},
};

/**
 * this functions checks whether the packet begins with a valid http request
 * @param ipacket
 * @returnvalue 0 if no valid request has been found
 * @returnvalue >0 indicates start of filename but not necessarily in packet limit
 */
uint16_t http_request_url_offset(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* FIRST PAYLOAD PACKET FROM CLIENT */
    /* check if the packet starts with POST or GET */
    if (packet->payload_packet_len >= 4 && memcmp(packet->payload, "GET ", 4) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: GET FOUND\n");
        return 4;
    } else if (packet->payload_packet_len >= 5 && memcmp(packet->payload, "POST ", 5) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: POST FOUND\n");
        return 5;
    } else if (packet->payload_packet_len >= 8 && memcmp(packet->payload, "OPTIONS ", 8) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: OPTIONS FOUND\n");
        return 8;
    } else if (packet->payload_packet_len >= 5 && memcmp(packet->payload, "HEAD ", 5) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: HEAD FOUND\n");
        return 5;
    } else if (packet->payload_packet_len >= 4 && memcmp(packet->payload, "PUT ", 4) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: PUT FOUND\n");
        return 4;
    } else if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "DELETE ", 7) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: DELETE FOUND\n");
        return 7;
    } else if (packet->payload_packet_len >= 8 && memcmp(packet->payload, "CONNECT ", 8) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: CONNECT FOUND\n");
        return 8;
    } else if (packet->payload_packet_len >= 9 && memcmp(packet->payload, "PROPFIND ", 9) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: PROFIND FOUND\n");
        return 9;
    } else if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "REPORT ", 7) == 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: REPORT FOUND\n");
        return 7;
    }

    return 0;
}

/**
 * Initializes HTTP parser structure to be associated to the HTTP session data
 **/
void http_internal_session_data_init(ipacket_t * ipacket, unsigned index) {
    debug("[PROTO_HTTP-]> http_internal_session_data_init : %lu session %lu",ipacket->packet_id,ipacket->session->session_id);
    if(ipacket->session->session_data[index] == NULL){
        void * http_session_data = (void *) init_http_parser();
        ipacket->session->session_data[index] = http_session_data;
    }
}


/**
 * HTTP session data analysis function. 
 * Contains compatibility code plus new HTTP parser integration
 **/
int http_internal_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    // if(ipacket->session->session_data[index] == NULL){
    //     http_internal_session_data_init(ipacket,index);
    // }
    // Backward Compatibility code
    if (packet->payload_packet_len > 32) {
        if ((flow->l4.tcp.http_data_direction != ipacket->session->last_packet_direction)) {
            debug("[PROTO_HTTP-]> Hey man (0)");
            mmt_parse_packet_line_info(ipacket);
        }
        if (packet->parsed_lines > 1) {
            //If the packet contains a response, try to check the payload
            if (!packet->http_response.ptr) {
                //The packet is not a response! maybe this is a request
                uint16_t filename_start;
                filename_start = http_request_url_offset(ipacket);
                if (filename_start != 0 && packet->parsed_lines > 1 && packet->line[0].len >= (9 + filename_start)
                        && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
                    packet->http_url_name.ptr = &packet->payload[filename_start];
                    packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

                    packet->http_method.ptr = packet->line[0].ptr;
                    packet->http_method.len = filename_start - 1;
                }
            }
        }
        flow->l4.tcp.http_data_direction = ipacket->session->last_packet_direction;
    }

    // Feed the data to the HTTP parse.
    // As two parser exists for both client -> server and server -> client
    // directions, get the corresponding parser first, then feed it the payload data.
    if( ipacket->session->session_data[index] != NULL ) {
      size_t nparsed;
      http_parser_settings * settings = get_settings();
      http_parser * parser = &((stream_parser_t *) ipacket->session->session_data[index])->parser[ipacket->session->last_packet_direction];
      
      // update the parser internal data with the current index and ipacket
      ( (stream_processor_t *) parser->data)->index = index;
      ( (stream_processor_t *) parser->data)->ipacket = ipacket;

      // Feeds the HTTP parser with additional data to process.
      // Returns the length of successfully parsed data bytes. 
      // If the parsed data length is different than the provided 
      // data length, an error has occurred.
      nparsed = http_parser_execute(parser, settings, (const char *) packet->payload, packet->payload_packet_len);
      if (parser->upgrade) {
        // handle new protocol 
      } else if (nparsed != packet->payload_packet_len) {
        // Handle error. Usually just close the connection.
        //TODO: LN uncomment the next line please :p
        debug("[PROTO_HTTP-]> Error while parsing this HTTP message -Error %s\n", http_errno_description(HTTP_PARSER_ERRNO(parser)));
        ipacket->session->session_data[index] = close_http_parser(ipacket->session->session_data[index]);
      }
    }
    return MMT_CONTINUE;
}


/**
 * Cleanup the HTTP parser structure from the HTTP session data.
 **/
void http_internal_session_data_cleanup(mmt_session_t * session, unsigned index) {
    if (session->session_data[index] != NULL) {
        debug("[PROTO_HTTP-]> http_internal_session_data_cleanup session %lu",session->session_id);
        session->session_data[index] = close_http_parser(session->session_data[index]);
    }
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_http_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_HTTP, PROTO_HTTP_ALIAS);

    if (protocol_struct != NULL) {
        int i = 0;

        for (; i < RFC2822_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &http_new_attributes_metadata[i]);
        }

        mmt_init_classify_me_http();

        //BW: Add session data initialization, cleanup and analysis routines.
        //    This is mainly used for HTTP data parsing.
#ifndef LIGHTSDK        
        register_session_data_initialization_function(protocol_struct, http_internal_session_data_init);
        register_session_data_cleanup_function(protocol_struct, http_internal_session_data_cleanup);
        register_session_data_analysis_function(protocol_struct, http_internal_session_data_analysis);
#endif
        return register_protocol(protocol_struct, PROTO_HTTP);
    } else {
        return 0;
    }
}


