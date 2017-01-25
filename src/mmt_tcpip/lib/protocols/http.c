#include "mmt_common_internal_include.h"

#ifdef PROTO_HTTP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "http.h"
#include "rfc2822utils.h"
#include "extraction_lib.h"
#include "packet_processing.h"
#include "../mmt_common_internal_include.h"

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static char * http_header_fields[HTTP_HEADERS_NB] = {
    MMT_HEADER_HOST,
    MMT_HEADER_USER_AGENT,
    MMT_HEADER_ACCEPT,
    MMT_HEADER_ACCEPT_CHARSET,
    MMT_HEADER_ACCEPT_ENCODING,
    MMT_HEADER_ACCEPT_LANGUAGE,
    MMT_HEADER_AUTHORIZATION,
    MMT_HEADER_EXPECT,
    MMT_HEADER_FROM,
    MMT_HEADER_DATE,
    MMT_HEADER_P3P,
    MMT_HEADER_CACHE_CONTROL,
    MMT_HEADER_CONNECTION,
    MMT_HEADER_TRANSFER_ENCODING,
    MMT_HEADER_DNT,
    MMT_HEADER_COOKIE,
    MMT_HEADER_IF_MATCH,
    MMT_HEADER_IF_MODIFIED_SINCE,
    MMT_HEADER_IF_NONE_MATCH,
    MMT_HEADER_IF_RANGE,
    MMT_HEADER_IF_UNMODIFIED_SINCE,
    MMT_HEADER_MAX_FORWARDS,
    MMT_HEADER_PROXY_AUTHORIZATION,
    MMT_HEADER_RANGE,
    MMT_HEADER_REFERER,
    MMT_HEADER_TE,
    MMT_HEADER_ACCEPT_RANGES,
    MMT_HEADER_AGE,
    MMT_HEADER_ETAG,
    MMT_HEADER_LOCATION,
    MMT_HEADER_PROXY_AUTHENTICATE,
    MMT_HEADER_RETRY_AFTER,
    MMT_HEADER_SERVER,
    MMT_HEADER_VARY,
    MMT_HEADER_WWW_AUTHENTICATE,
    MMT_HEADER_ALLOW,
    MMT_HEADER_CONTENT_ENCODING,
    MMT_HEADER_CONTENT_LANGUAGE,
    MMT_HEADER_CONTENT_LENGTH,
    MMT_HEADER_CONTENT_LOCATION,
    MMT_HEADER_CONTENT_MD5,
    MMT_HEADER_CONTENT_RANGE,
    MMT_HEADER_CONTENT_TYPE,
    MMT_HEADER_EXPIRES,
    MMT_HEADER_LAST_MODIFIED,
    MMT_HEADER_SET_COOKIE,
    MMT_HEADER_SET_COOKIE2,
};

static char *http_methods[] = {
    "(unknown)",
    MMT_HTTP_GET,     MMT_HTTP_POST,     MMT_HTTP_OPTIONS,
    MMT_HTTP_HEAD,    MMT_HTTP_PUT,      MMT_HTTP_DELETE,
    MMT_HTTP_CONNECT, MMT_HTTP_PROPFIND, MMT_HTTP_REPORT
};

static inline int get_header_index_by_header_id(int header_id) {
    return header_id - 1;
}

static inline int get_header_id_by_field_name(const char * header_field, int max) {
    int count = 0;
    for (; count < HTTP_HEADERS_NB; count++) {
        if (mmt_strncasecmp(header_field, http_header_fields[count], max) == 0) { //TODO: this is consuming (calculating len every time)
            return count + 1; //The header indexes start at 1
        }
    }
    return 0; // This means the header is not defined for this protocol
}

static char * get_header_field_name_by_header_id(int header_id) {
    if ((header_id <= 0) || (header_id > HTTP_HEADERS_NB))
        return NULL;
    return http_header_fields[header_id - 1];
}

int http_header_field_value_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int header_index = get_header_index_by_header_id(extracted_data->field_id);

    if (((struct http_session_data_struct *) packet->session->session_data[proto_index])->session_field_values[header_index].value != NULL) {
        extracted_data->data = (char *) ((struct http_session_data_struct *) packet->session->session_data[proto_index])->session_field_values[header_index].value;

        //printf("FROM Extract function HOST = %s\n", ((struct http_session_data_struct *) packet->session->session_data[proto_index])->session_field_values[header_index].value);
        return 1;
    }
    return 0;
}

int http_version_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    if (((struct http_session_data_struct *) packet->session->session_data[proto_index])->http_version != NULL) {
        extracted_data->data = (char *) ((struct http_session_data_struct *) packet->session->session_data[proto_index])->http_version;
        return 1;
    }
    return 0;
}

int http_type_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    if (((struct http_session_data_struct *) packet->session->session_data[proto_index])->type != 0) {
        *(int *) extracted_data->data = ((struct http_session_data_struct *) packet->session->session_data[proto_index])->type;
        return 1;
    }
    return 0;
}

int http_method_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    struct http_session_data_struct *http = (struct http_session_data_struct *)packet->session->session_data[proto_index];

    if( http && MMT_HTTP_IS_VALID_METHOD( http->http_method )) {
        extracted_data->data = http_methods[ http->http_method ];
        return 1;
    }

    return 0;
}

int http_requested_uri_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    if (((struct http_session_data_struct *) packet->session->session_data[proto_index])->requested_uri != NULL) {
        extracted_data->data = (char *) ((struct http_session_data_struct *) packet->session->session_data[proto_index])->requested_uri;
        return 1;
    }
    return 0;
}

static field_value_attribute_information_t http_attributes_info[HTTP_ATTRIBUTES_NB] = {
    //{id, alias, type, len, scope, header_id, extract_fct}
    {HTTP_HOST, MMT_HEADER_HOST, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_HOST, http_header_field_value_extraction},
    {HTTP_USER_AGENT, MMT_HEADER_USER_AGENT, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_USER_AGENT, http_header_field_value_extraction},
    {HTTP_ACCEPT, MMT_HEADER_ACCEPT, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_ACCEPT, http_header_field_value_extraction},
    {HTTP_ACCEPT_Charset, MMT_HEADER_ACCEPT_CHARSET, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_ACCEPT_Charset, http_header_field_value_extraction},
    {HTTP_Accept_Encoding, MMT_HEADER_ACCEPT_ENCODING, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Accept_Encoding, http_header_field_value_extraction},
    {HTTP_Accept_Language, MMT_HEADER_ACCEPT_LANGUAGE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Accept_Language, http_header_field_value_extraction},
    {HTTP_Authorization, MMT_HEADER_AUTHORIZATION, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Authorization, http_header_field_value_extraction},
    {HTTP_Expect, MMT_HEADER_EXPECT, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Expect, http_header_field_value_extraction},
    {HTTP_From, MMT_HEADER_FROM, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_From, http_header_field_value_extraction},
    {HTTP_Date, MMT_HEADER_DATE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Date, http_header_field_value_extraction},
    {HTTP_P3P, MMT_HEADER_P3P, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_P3P, http_header_field_value_extraction},
    {HTTP_Cache_Control, MMT_HEADER_CACHE_CONTROL, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Cache_Control, http_header_field_value_extraction},
    {HTTP_Connection, MMT_HEADER_CONNECTION, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Connection, http_header_field_value_extraction},
    {HTTP_Transfer_Encoding, MMT_HEADER_TRANSFER_ENCODING, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Transfer_Encoding, http_header_field_value_extraction},
    {HTTP_DNT, MMT_HEADER_DNT, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_DNT, http_header_field_value_extraction},
    {HTTP_Cookie, MMT_HEADER_COOKIE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Cookie, http_header_field_value_extraction},
    {HTTP_If_Match, MMT_HEADER_IF_MATCH, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_If_Match, http_header_field_value_extraction},
    {HTTP_If_Modified_Since, MMT_HEADER_IF_MODIFIED_SINCE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_If_Modified_Since, http_header_field_value_extraction},
    {HTTP_If_None_Match, MMT_HEADER_IF_NONE_MATCH, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_If_None_Match, http_header_field_value_extraction},
    {HTTP_If_Range, MMT_HEADER_IF_RANGE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_If_Range, http_header_field_value_extraction},
    {HTTP_If_Unmodified_Since, MMT_HEADER_IF_UNMODIFIED_SINCE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_If_Unmodified_Since, http_header_field_value_extraction},
    {HTTP_Max_Forwards, MMT_HEADER_MAX_FORWARDS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Max_Forwards, http_header_field_value_extraction},
    {HTTP_Proxy_Authorization, MMT_HEADER_PROXY_AUTHORIZATION, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Proxy_Authorization, http_header_field_value_extraction},
    {HTTP_Range, MMT_HEADER_RANGE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Range, http_header_field_value_extraction},
    {HTTP_Referer, MMT_HEADER_REFERER, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Referer, http_header_field_value_extraction},
    {HTTP_TE, MMT_HEADER_TE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_TE, http_header_field_value_extraction},
    {HTTP_Accept_Ranges, MMT_HEADER_ACCEPT_RANGES, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Accept_Ranges, http_header_field_value_extraction},
    {HTTP_Age, MMT_HEADER_AGE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Age, http_header_field_value_extraction},
    {HTTP_ETag, MMT_HEADER_ETAG, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_ETag, http_header_field_value_extraction},
    {HTTP_Location, MMT_HEADER_LOCATION, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Location, http_header_field_value_extraction},
    {HTTP_Proxy_Authenticate, MMT_HEADER_PROXY_AUTHENTICATE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Proxy_Authenticate, http_header_field_value_extraction},
    {HTTP_Retry_After, MMT_HEADER_RETRY_AFTER, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Retry_After, http_header_field_value_extraction},
    {HTTP_Server, MMT_HEADER_SERVER, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Server, http_header_field_value_extraction},
    {HTTP_Vary, MMT_HEADER_VARY, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Vary, http_header_field_value_extraction},
    {HTTP_WWW_Authenticate, MMT_HEADER_WWW_AUTHENTICATE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_WWW_Authenticate, http_header_field_value_extraction},
    {HTTP_Allow, MMT_HEADER_ALLOW, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Allow, http_header_field_value_extraction},
    {HTTP_Content_Encoding, MMT_HEADER_CONTENT_ENCODING, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Content_Encoding, http_header_field_value_extraction},
    {HTTP_Content_Language, MMT_HEADER_CONTENT_LANGUAGE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Content_Language, http_header_field_value_extraction},
    {HTTP_Content_Length, MMT_HEADER_CONTENT_LENGTH, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Content_Length, http_header_field_value_extraction},
    {HTTP_Content_Location, MMT_HEADER_CONTENT_LOCATION, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Content_Location, http_header_field_value_extraction},
    {HTTP_Content_MD5, MMT_HEADER_CONTENT_MD5, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Content_MD5, http_header_field_value_extraction},
    {HTTP_Content_Range, MMT_HEADER_CONTENT_RANGE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Content_Range, http_header_field_value_extraction},
    {HTTP_Content_Type, MMT_HEADER_CONTENT_TYPE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Content_Type, http_header_field_value_extraction},
    {HTTP_Expires, MMT_HEADER_EXPIRES, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Expires, http_header_field_value_extraction},
    {HTTP_Last_Modified, MMT_HEADER_LAST_MODIFIED, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_Last_Modified, http_header_field_value_extraction},
    {HTTP_SET_COOKIE, MMT_HEADER_SET_COOKIE, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_SET_COOKIE, http_header_field_value_extraction},
    {HTTP_SET_COOKIE2, MMT_HEADER_SET_COOKIE2, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_SET_COOKIE2, http_header_field_value_extraction},

    {HTTP_VERSION, HTTP_VERSION_SHORT_LABEL, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION, HTTP_NOHEADER, http_version_extraction},
    {HTTP_TYPE, HTTP_TYPE_SHORT_LABEL, MMT_U32_DATA, sizeof (int), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, HTTP_NOHEADER, http_type_extraction},
    {HTTP_METHOD, HTTP_METHOD_SHORT_LABEL, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, HTTP_NOHEADER, http_method_extraction},
    {HTTP_URI, HTTP_URI_SHORT_LABEL, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, HTTP_NOHEADER, http_requested_uri_extraction},
    {HTTP_Referer_URL, HTTP_Referer_URL_SHORT_LABEL, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, HTTP_Referer, NULL},
    {HTTP_Response_TIME, HTTP_Response_TIME_SHORT_LABEL, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, HTTP_NOHEADER, NULL},
    {HTTP_Time_of_Request, HTTP_REQ_TIME_SHORT_LABEL, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, HTTP_NOHEADER, NULL},
    {HTTP_Time_of_response, HTTP_RESP_TIME_SHORT_LABEL, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, HTTP_NOHEADER, NULL},
};

int get_http_attribute_id_by_name(int proto_id, const char * attribute_name) {
    int i;
    for (i = 0; i < HTTP_ATTRIBUTES_NB; i++) {
        if (strcmp(http_attributes_info[i].alias, attribute_name) == 0) return http_attributes_info[i].id;
    }
    return 0;
}

const char * get_http_attribute_name_by_id(int proto_id, int attribute_id) {
    if (attribute_id && attribute_id <= HTTP_ATTRIBUTES_NB)
        return http_attributes_info[attribute_id - 1].alias;

    return NULL;
}

int get_http_attribute_data_type_by_id(int proto_id, int attribute_id) {
    if (attribute_id && attribute_id <= HTTP_ATTRIBUTES_NB)
        return http_attributes_info[attribute_id - 1].data_type;

    return MMT_UNDEFINED_TYPE;
}

int get_http_attribute_data_length_by_id(int proto_id, int attribute_id) {
    if (attribute_id && attribute_id <= HTTP_ATTRIBUTES_NB)
        return http_attributes_info[attribute_id - 1].data_len;

    return 0;
}

int get_http_attribute_position(int proto_id, int attribute_id) {
    if (attribute_id && attribute_id <= HTTP_ATTRIBUTES_NB)
        return http_attributes_info[attribute_id - 1].position_in_packet;

    return -1;
}

int is_http_valid_attribute(int proto_id, int attribute_id) {
    if (attribute_id && attribute_id <= HTTP_ATTRIBUTES_NB)
        return true;

    return false;
}

//TODO: needs to be changed to take the correct scope from the attribute information

int get_http_attribute_scope(int proto_id, int attribute_id) {
    return SCOPE_SESSION;
}

generic_attribute_extraction_function get_http_attribute_extraction_function(int proto_id, int attribute_id) {
    if (attribute_id && attribute_id <= HTTP_ATTRIBUTES_NB) {
        return http_attributes_info[attribute_id - 1].extraction_function;
        //return http_header_field_value_extraction;
    }
    switch (attribute_id) {
        case HTTP_VERSION:
        default:
            return silent_extraction;
    }
}

void http_session_data_init(ipacket_t * ipacket, unsigned index) {
    struct http_session_data_struct * http_session_data = (struct http_session_data_struct *) mmt_malloc(sizeof (struct http_session_data_struct));
    memset(http_session_data, 0, sizeof (struct http_session_data_struct));
    ipacket->session->session_data[index] = http_session_data;
}

/**
 * this functions checks whether the packet begins with a valid http request
 * @param msg the received message
 * @param msg_len length of the message request line in octets
 * @param method pointer to the method code to be set by this function
 * @return the offset of the uri if positive value, zero means the message is not a valid request
 */
static inline int get_request_method_uri_offset(const char *msg, int msg_len, int * method) {
    int uri_offset = 0;
    *method = 0;
    /* check if the packet starts with POST or GET or any other HTTP request method */
    if (msg_len >= 4 && mmt_strncmp(msg, "GET ", 4) == 0) {
        uri_offset = 4;
        *method = MMT_HTTP_GET_CODE;
    } else if (msg_len >= 5 && mmt_strncmp(msg, "POST ", 5) == 0) {
        uri_offset = 5;
        *method = MMT_HTTP_POST_CODE;
    } else if (msg_len >= 4 && mmt_strncmp(msg, "PUT ", 4) == 0) {
        uri_offset = 4;
        *method = MMT_HTTP_PUT_CODE;
    } else if (msg_len >= 7 && mmt_strncmp(msg, "DELETE ", 7) == 0) {
        uri_offset = 7;
        *method = MMT_HTTP_DELETE_CODE;
    } else if (msg_len >= 8 && mmt_strncmp(msg, "OPTIONS ", 8) == 0) {
        uri_offset = 8;
        *method = MMT_HTTP_OPTIONS_CODE;
    } else if (msg_len >= 5 && mmt_strncmp(msg, "HEAD ", 5) == 0) {
        uri_offset = 5;
        *method = MMT_HTTP_HEAD_CODE;
    } else if (msg_len >= 8 && mmt_strncmp(msg, "CONNECT ", 8) == 0) {
        uri_offset = 8;
        *method = MMT_HTTP_CONNECT_CODE;
    } else if (msg_len >= 9 && mmt_strncmp(msg, "PROPFIND ", 9) == 0) {
        uri_offset = 9;
        *method = MMT_HTTP_PROPFIND_CODE;
    } else if (msg_len >= 7 && mmt_strncmp(msg, "REPORT ", 7) == 0) {
        uri_offset = 7;
        *method = MMT_HTTP_REPORT_CODE;
    }

    while (isspace(msg[uri_offset])) {
        uri_offset++;
    }
    return uri_offset;
}

/**
 * this functions checks whether the packet begins with a valid http response
 * @param msg the received message
 * @param msg_len length of the message request line in octets
 * @return the offset of the response code if positive, zero incates this is not a valid response
 */
static inline int get_response_code_offset(const char *msg, int msg_len, char ** version) {
    int code_offset = 0;
    /* check if the packet starts with HTTP/1.1 or HTTP/1.0 */
    if (msg_len >= 9 && mmt_strncasecmp(msg, MHD_HTTP_VERSION_1_1, 9) == 0) {
        code_offset = 9;
        *version = (char *) MHD_HTTP_VERSION_1_1;
    } else if (msg_len >= 9 && mmt_strncasecmp(msg, MHD_HTTP_VERSION_1_0, 9) == 0) {
        code_offset = 9;
        *version = (char *) MHD_HTTP_VERSION_1_0;
    } else if (msg_len >= 9 && mmt_strncasecmp(msg, MHD_HTTP_VERSION_0_9, 9) == 0) {
        code_offset = 9;
        *version = (char *) MHD_HTTP_VERSION_0_9;
    }

    while (isspace(msg[code_offset])) {
        code_offset++;
    }

    return code_offset;
}

/**
 * Parse the HTTP HEADER.
 */
static inline int
parse_message_header_lines(ipacket_t * ipacket, unsigned index, int offset) { //TODO: optimization work required here! VERY IMPORTANT
    int code, hlen;

    //Get the length of the first http header line
    hlen = get_next_header_line_length((const char*)&ipacket->data[offset], ipacket->p_hdr->len - offset, & code);

    //if the header line is positive
    if (hlen) {
        //Check if this is a request header
        struct http_session_data_struct* http;
        int method, line_first_element_offset;
        char * version = NULL;

        http = ((struct http_session_data_struct *) ipacket->session->session_data[index]);
        line_first_element_offset = get_request_method_uri_offset((const char*)&ipacket->data[offset], ipacket->p_hdr->len - offset, &method);

        //This is a request; update the session context accordingly
        if (line_first_element_offset) {
            int uri_len = get_next_white_space_offset_no_limit((const char*)&ipacket->data[offset + line_first_element_offset]);
            http->http_method   = method;
            http->requested_uri = (char *) mmt_malloc(uri_len + 1);
            memcpy(http->requested_uri, &ipacket->data[offset + line_first_element_offset], uri_len);
            http->requested_uri[uri_len] = '\0';

            //printf("Method %i --- URI %s \n", http->http_method,
            //        http->requested_uri);
        } else if((line_first_element_offset = get_response_code_offset((const char*)&ipacket->data[offset], ipacket->p_hdr->len - offset, &version)) > 0) {
            //This is not a request; check if it is a response
            http->http_version = version;
            //printf("version %s \n", http->http_version);
        } else {
            //Not a request nor a reply --> not an HTTP header --> return
            return 0;
        }

        offset += hlen;
        hlen = get_next_header_line_length((const char*)&ipacket->data[offset], ipacket->p_hdr->len - offset, &code);
        while (hlen > 2) {
            int header_id, header_index, value_offset, value_len, field_len;
            line_first_element_offset = get_next_non_white_space_offset_no_limit((const char*)&ipacket->data[offset]);

            //printf("LFE_Offset %i - offset %i - hlen %i \n", line_first_element_offset, offset, hlen);
            // No need to include "line_first_element_offset" coz most probably it will be zero
            value_offset = get_value_offset((const char*)&ipacket->data[offset], hlen);

            field_len = get_field_len((const char*)&ipacket->data[offset + line_first_element_offset], hlen - line_first_element_offset);

            header_id = get_header_id_by_field_name((const char*)&ipacket->data[offset + line_first_element_offset], field_len);

            if (header_id && value_offset) {

                value_len = hlen - (value_offset + code);
                header_index = get_header_index_by_header_id(header_id);
                struct http_session_data_struct *http = (struct http_session_data_struct *)ipacket->session->session_data[index];
                http->session_field_values[header_index].field_id   = header_id;
                http->session_field_values[header_index].field      = get_header_field_name_by_header_id(header_id);
                http->session_field_values[header_index].header_len = hlen;
                http->session_field_values[header_index].value_len  = value_len;

                http->session_field_values[header_index].value = (char *) mmt_malloc(value_len + 1);
                memcpy(http->session_field_values[header_index].value,
                        &ipacket->data[offset + value_offset], value_len);
                http->session_field_values[header_index].value[value_len] = '\0';

                //printf("Hlen %i --- F_id %i --- Fval %s --- Vlen %i --- Fval %s\n",
                //        http->session_field_values[header_index].header_len,
                //        http->session_field_values[header_index].field_id,
                //        http->session_field_values[header_index].field,
                //        http->session_field_values[header_index].value_len,
                //        http->session_field_values[header_index].value);
            }
            offset += hlen;
            hlen = get_next_header_line_length((const char*)&ipacket->data[offset], ipacket->p_hdr->len - offset, &code);
        }
        return 1;
    }
    return 0;
}

int http_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    //printf("from http generic session data analysis\n");
    int offset = get_packet_offset_at_index(ipacket, index);

    //First we check if the message starts with leading CRLF --- normally this should never be the case
    offset += ignore_starting_crlf((const char*)&ipacket->data[offset], ipacket->p_hdr->len - offset);

    //Parse the first line line of the header (request or response line)
    parse_message_header_lines(ipacket, index, offset);
    return MMT_CONTINUE;
}

int init_http_proto_struct() {

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_HTTP, PROTO_HTTP_ALIAS);

    if (protocol_struct != NULL) {
        register_classification_function(protocol_struct, NULL);
        register_session_data_initialization_function(protocol_struct, http_session_data_init);
        register_session_data_analysis_function(protocol_struct, http_session_data_analysis);

        return register_protocol(protocol_struct, PROTO_HTTP);
    } else {
        return 0;
    }
}

static inline void mmt_int_http_add_connection(ipacket_t * ipacket, uint32_t protocol) {
    struct mmt_internal_tcpip_session_struct *flow = ipacket->internal_packet->flow;

    if (protocol != PROTO_HTTP) {
        mmt_internal_add_connection(ipacket, protocol, MMT_CORRELATED_PROTOCOL);
    } else {
        mmt_internal_add_connection(ipacket, protocol, MMT_REAL_PROTOCOL);
        set_session_timeout_delay(ipacket->session, ipacket->mmt_handler->long_session_timed_out);
    }
    flow->http_detected = 1;
}

/*
 * Beginning of functions to manage different MIME types
 */

static inline void check_packet_contents(ipacket_t * ipacket) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->content_line.ptr != NULL && packet->content_line.len != 0) {
        //The packet has content line
#ifdef MMT_CONTENT_FAMILY_APPLICATION
   	 switch( packet->content_line.ptr[sizeof("application/")] ){
        case 'a':
			  if (packet->content_line.len >= 20 && memcmp(packet->content_line.ptr, "application/atom+xml", 20) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/atom+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_ATOM_XML);
					return;
			  }
			  break;

        case 'e':
			  if (packet->content_line.len >= 22 && memcmp(packet->content_line.ptr, "application/ecmascript", 22) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/ecmascript found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_ECMASCRIPT);
					return;
			  }
        	  break;

        case 'j':
      	  if (packet->content_line.len >= 22 && memcmp(packet->content_line.ptr, "application/javascript", 22) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/javascript found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_JAVASCRIPT);
      		  return;
      	  }
      	  if (packet->content_line.len >= 16 && memcmp(packet->content_line.ptr, "application/json", 16) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/json found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_JSON);
      		  return;
      	  }
      	  break;

        case 'E':
			  if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "application/EDI-X12", 19) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/EDI-X12 found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_EDI_X12);
					return;
			  }
			  if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "application/EDIFACT", 19) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/EDIFACT found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_EDIFACT);
					return;
			  }
			  break;

        case 'o':
			  if (packet->content_line.len >= 24 && memcmp(packet->content_line.ptr, "application/octet-stream", 24) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/octet-stream found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_OCTET_STREAM);
					return;
			  }
			  if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "application/ogg", 15) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/ogg found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_OGG);
					return;
			  }
			  break;

        case 'p':
			  if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "application/pdf", 15) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/pdf found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_PDF);
					return;
			  }
			  if (packet->content_line.len >= 22 && memcmp(packet->content_line.ptr, "application/postscript", 22) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/postscript found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_POSTSCRIPT);
					return;
			  }
			  break;
        case 'r':
			  if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "application/rdf+xml", 19) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/rdf+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_RDF_XML);
					return;
			  }
			  if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "application/rss+xml", 19) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/rss+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_RSS_XML);
					return;
			  }
			  break;

        case 's':
			  if (packet->content_line.len >= 20 && memcmp(packet->content_line.ptr, "application/soap+xml", 20) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/soap+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_SOAP_XML);
					return;
			  }
			  break;

        case 'f':
      	  if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "application/flv", 15) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/flv found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FLV);
      		  return;
      	  }
			  if (packet->content_line.len >= 21 && memcmp(packet->content_line.ptr, "application/font-woff", 21) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/font-woff found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_FONT_WOFF);
					return;
			  }
			  break;
        case 'z':
			  if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "application/zip", 15) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/zip found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_ZIP);
					return;
			  }
			  break;

        case 'g':
      	  if (packet->content_line.len >= 16 && memcmp(packet->content_line.ptr, "application/gzip", 16) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/gzip found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_GZIP);
      		  return;
      	  }
      	  break;

        // For vendor-specific files : vnd prefix
        case 'v':
			  if (packet->content_line.len >= 28 && memcmp(packet->content_line.ptr, "application/vnd.rn-realmedia", 28) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.rn-realmedia found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_REALMEDIA);
					return;
			  }
			  if (packet->content_line.len >= 23 && memcmp(packet->content_line.ptr, "application/vnd.ms.wms-", 23) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.ms.wms- found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_MS_WMV);
					return;
			  }
			  if (packet->content_line.len >= 39 && memcmp(packet->content_line.ptr, "application/vnd.oasis.opendocument.text", 39) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.oasis.opendocument.text found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_TEXT);
					return;
			  }
			  if (packet->content_line.len >= 46 && memcmp(packet->content_line.ptr, "application/vnd.oasis.opendocument.spreadsheet", 46) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.oasis.opendocument.spreadsheet found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_SPREADSHEET);
					return;
			  }
			  if (packet->content_line.len >= 47 && memcmp(packet->content_line.ptr, "application/vnd.oasis.opendocument.presentation", 47) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.oasis.opendocument.presentation found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_PRESENTATION);
					return;
			  }
			  if (packet->content_line.len >= 43 && memcmp(packet->content_line.ptr, "application/vnd.oasis.opendocument.graphics", 43) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.oasis.opendocument.graphics found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_GRAPHICS);
					return;
			  }
			  if (packet->content_line.len >= 24 && memcmp(packet->content_line.ptr, "application/vnd.ms-excel", 24) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.ms-excel found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_MS_EXCEL);
					return;
			  }
			  if (packet->content_line.len >= 65 && memcmp(packet->content_line.ptr, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 65) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_SPREADSHEETML_SHEET);
					return;
			  }
			  if (packet->content_line.len >= 29 && memcmp(packet->content_line.ptr, "application/vnd.ms-powerpoint", 29) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.ms-powerpoint found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_MS_POWERPOINT);
					return;
			  }
			  if (packet->content_line.len >= 73 && memcmp(packet->content_line.ptr, "application/vnd.openxmlformats-officedocument.presentationml.presentation", 73) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.openxmlformats-officedocument.presentationml.presentation found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_PRESENTATIONML_PRESENTATION);
					return;
			  }
			  if (packet->content_line.len >= 71 && memcmp(packet->content_line.ptr, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 71) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_WORDPROCESSINGML_DOCUMENT);
					return;
			  }
			  if (packet->content_line.len >= 31 && memcmp(packet->content_line.ptr, "application/vnd.mozilla.xul+xml", 31) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.mozilla.xul+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_MOZILLA_XUL_XML);
					return;
			  }
			  if (packet->content_line.len >= 36 && memcmp(packet->content_line.ptr, "application/vnd.google-earth.kml+xml", 36) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/vnd.google-earth.kml+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_GOOGLE_EARTH_KML_XML);
					return;
			  }
			  break;
        //x
        case 'x':
      	  if (packet->content_line.len >= 17 && memcmp(packet->content_line.ptr, "application/x-fcs", 17) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-fcs found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FLV);
      		  return;
      	  }

      	  if (packet->content_line.len >= 23 && memcmp(packet->content_line.ptr, "application/x-font-woff", 23) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-font-woff found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FONT_WOFF);
      		  return;
      	  }
      	  if (packet->content_line.len >= 21 && memcmp(packet->content_line.ptr, "application/xhtml+xml", 21) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/xhtml+xml found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_XHTML_XML);
      		  return;
      	  }
      	  if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "application/xml-dtd", 19) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/xml-dtd found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_XML_DTD);
      		  return;
      	  }
      	  if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "application/xop+xml", 19) == 0) {
      		  MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/xop+xml found.\n");
      		  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_XOP_XML);
      		  return;
      	  }
      	  // For non-standard files : x prefix
			  if (packet->content_line.len >= 33 && memcmp(packet->content_line.ptr, "application/x-www-form-urlencoded", 33) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-www-form-urlencoded found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_WWW_FORM_URLENCODED);
					return;
			  }
			  if (packet->content_line.len >= 17 && memcmp(packet->content_line.ptr, "application/x-dvi", 17) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-dvi found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_DVI);
					return;
			  }
			  if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "application/x-latex", 19) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-latex found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_LATEX);
					return;
			  }
			  if (packet->content_line.len >= 22 && memcmp(packet->content_line.ptr, "application/x-font-ttf", 22) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-font-ttf found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FONT_TTF);
					return;
			  }
			  if (packet->content_line.len >= 29 && memcmp(packet->content_line.ptr, "application/x-shockwave-flash", 29) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-shockwave-flash found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_SHOCKWAVE_FLASH);
					return;
			  }
			  if (packet->content_line.len >= 21 && memcmp(packet->content_line.ptr, "application/x-stuffit", 21) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-stuffit found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_STUFFIT);
					return;
			  }
			  if (packet->content_line.len >= 28 && memcmp(packet->content_line.ptr, "application/x-rar-compressed", 28) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-rar-compressed found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_RAR_COMPRESSED);
					return;
			  }
			  if (packet->content_line.len >= 17 && memcmp(packet->content_line.ptr, "application/x-tar", 17) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-tar found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_TAR);
					return;
			  }
			  if (packet->content_line.len >= 24 && memcmp(packet->content_line.ptr, "application/x-javascript", 24) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-javascript found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_JAVASCRIPT);
					return;
			  }
			  if (packet->content_line.len >= 17 && memcmp(packet->content_line.ptr, "application/x-deb", 17) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-deb found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_DEB);
					return;
			  }
			  if (packet->content_line.len >= 21 && memcmp(packet->content_line.ptr, "application/x-mpegURL", 21) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-mpegURL found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_MPEG_URL);
					return;
			  }
			  // For PKCS standard files: x-pkcs prefix
			  if (packet->content_line.len >= 20 && memcmp(packet->content_line.ptr, "application/x-pkcs12", 20) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-pkcs12 found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS12);
					return;
			  }
			  if (packet->content_line.len >= 32 && memcmp(packet->content_line.ptr, "application/x-pkcs7-certificates", 32) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-pkcs7-certificates found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_CERTIFICATES);
					return;
			  }
			  if (packet->content_line.len >= 31 && memcmp(packet->content_line.ptr, "application/x-pkcs7-certreqresp", 31) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-pkcs7-certreqresp found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_CERTREQRESP);
					return;
			  }
			  if (packet->content_line.len >= 24 && memcmp(packet->content_line.ptr, "application/x-pkcs7-mime", 24) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-pkcs7-mime found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_MIME);
					return;
			  }
			  if (packet->content_line.len >= 29 && memcmp(packet->content_line.ptr, "application/x-pkcs7-signature", 29) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_APPLICATION, MMT_LOG_DEBUG, "APPLICATION: Content-Type: application/x-pkcs7-signature found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_SIGNATURE);
					return;
			  }
			  break;
   	 }
#endif //MMT_CONTENT_FAMILY_APPLICATION

#ifdef MMT_CONTENT_FAMILY_AUDIO
   	 switch( packet->content_line.ptr[ sizeof("audio/") ] ){
   	 case 'b':
   		 if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "audio/basic", 11) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/basic found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_BASIC);
   			 return;
   		 }
   		 break;

   	 case 'L':
   		 if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "audio/L24", 9) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/L24 found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_L24);
   			 return;
   		 }
   		 break;

   	 case 'm':
   		 if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "audio/mp4", 9) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/mp4 found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MP4);
   			 return;
   		 }
   		 if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "audio/mpeg", 10) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/mpeg found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG);
   			 return;
   		 }
   		 if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "audio/mpeg3", 11) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/mpeg3 found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG);
   			 return;
   		 }
   		 if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "audio/mp4a", 10) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/mp4a found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG);
   			 return;
   		 }
   		 break;

   	 case 'x':
   		 if (packet->content_line.len >= 12 && memcmp(packet->content_line.ptr, "audio/x-mpeg", 12) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/x-mpeg found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG);
   			 return;
   		 }
   		 if (packet->content_line.len >= 24 && mmt_mem_cmp(packet->content_line.ptr, "audio/x-wav", 11) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/x-wav found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_X_MS_WMV);
   			 return;
   		 }
   		 if (packet->content_line.len >= 20 && memcmp(packet->content_line.ptr, "audio/x-pn-realaudio", 20) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/x-pn-realaudio found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_REALAUDIO);
   			 return;
   		 }
   		 // For non-standard files : x prefix
   		 if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "audio/x-aac", 11) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/x-aac found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_X_AAC);
   			 return;
   		 }
   		 if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "audio/x-caf", 11) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/x-caf found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_X_CAF);
   			 return;
   		 }
   		 break;

   	 case 'o':
   		 if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "audio/ogg", 9) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/ogg found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_OGG);
   			 return;
   		 }
   		 break;

   	 case 'v':
   		 if (packet->content_line.len >= 12 && memcmp(packet->content_line.ptr, "audio/vorbis", 12) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/vorbis found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_VORBIS);
   			 return;
   		 }
   		 if (packet->content_line.len >= 22 && memcmp(packet->content_line.ptr, "audio/vnd.rn-realaudio", 22) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/vnd.rn-realaudio found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_VND_RN_REALAUDIO);
   			 return;
   		 }
   		 if (packet->content_line.len >= 14 && memcmp(packet->content_line.ptr, "audio/vnd.wave", 14) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/vnd.wave found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_VND_WAVE);
   			 return;
   		 }
   		 break;

   	 case 'w':
   		 if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "audio/webm", 10) == 0) {
   			 MMT_LOG(MMT_CONTENT_FAMILY_AUDIO, MMT_LOG_DEBUG, "AUDIO: Content-Type: audio/webm found.\n");
   			 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_WEBM);
   			 return;
   		 }
   		 break;
   	 }
#endif //MMT_CONTENT_FAMILY_AUDIO

#ifdef MMT_CONTENT_FAMILY_IMAGE
   	 switch( packet->content_line.ptr[ sizeof("image/") ]){
   	 case 'g':
			 if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "image/gif", 9) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/gif found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_GIF);
				 return;
			 }
			 break;

   	 case 'j':
			 if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "image/jpeg", 10) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/jpeg found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_JPEG);
				 return;
			 }
			 break;

   	 case 'p':
			 if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "image/pjpeg", 11) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/pjpeg found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_PJPEG);
				 return;
			 }
			 if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "image/png", 9) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/png found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_PNG);
				 return;
			 }
			 break;

   	 case 's':
			 if (packet->content_line.len >= 13 && memcmp(packet->content_line.ptr, "image/svg+xml", 13) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/svg+xml found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_SVG_XML);
				 return;
			 }
			 break;

   	 case 't':
			 if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "image/tiff", 10) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/tiff found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_TIFF);
				 return;
			 }
			 break;

   	 case 'v':
			 if (packet->content_line.len >= 24 && memcmp(packet->content_line.ptr, "image/vnd.microsoft.icon", 24) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/vnd.microsoft.icon found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_VND_MICROSOFT_ICON);
				 return;
			 }
			 break;

   	 case 'x':
			 // For non-standard files : x prefix
			 if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "image/x-xcf", 11) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_IMAGE, MMT_LOG_DEBUG, "IMAGE: Content-Type: image/x-xcf found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_X_XCF);
				 return;
			 }
			 break;
   	 }
#endif //MMT_CONTENT_FAMILY_IMAGE

#ifdef MMT_CONTENT_FAMILY_MESSAGE
   	 switch (packet->content_line.ptr[ sizeof("message/")] ){
   	 case 'h':
			  if (packet->content_line.len >= 12 && memcmp(packet->content_line.ptr, "message/http", 12) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MESSAGE, MMT_LOG_DEBUG, "MESSAGE: Content-Type: message/http found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_HTTP);
					return;
			  }
			  break;

   	 case 'i':
			  if (packet->content_line.len >= 16 && memcmp(packet->content_line.ptr, "message/imdn+xml", 16) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MESSAGE, MMT_LOG_DEBUG, "MESSAGE: Content-Type: message/imdn+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_IMDN_XML);
					return;
			  }
			  break;

   	 case 'p':
			  if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "message/partial", 15) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MESSAGE, MMT_LOG_DEBUG, "MESSAGE: Content-Type: message/partial found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_PARTIAL);
					return;
			  }
			  break;

   	 case 'r':
			  if (packet->content_line.len >= 14 && memcmp(packet->content_line.ptr, "message/rfc822", 14) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MESSAGE, MMT_LOG_DEBUG, "MESSAGE: Content-Type: message/rfc822 found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_RFC822);
					return;
			  }
			  break;
   	 }
#endif //MMT_CONTENT_FAMILY_MESSAGE

#ifdef MMT_CONTENT_FAMILY_MODEL
   	 switch (packet->content_line.ptr[ sizeof("model/")] ){
   	 case 'e':
			  if (packet->content_line.len >= 13 && memcmp(packet->content_line.ptr, "model/example", 13) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MODEL, MMT_LOG_DEBUG, "MODEL: Content-Type: model/example found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_EXAMPLE);
					return;
			  }
			  break;

   	 case 'i':
			  if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "model/iges", 10) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MODEL, MMT_LOG_DEBUG, "MODEL: Content-Type: model/iges found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_IGES);
					return;
			  }
			  break;

   	 case 'm':
			  if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "model/mesh", 10) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MODEL, MMT_LOG_DEBUG, "MODEL: Content-Type: model/mesh found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_MESH);
					return;
			  }
			  break;

   	 case 'v':
			  if (packet->content_line.len >= 13 && memcmp(packet->content_line.ptr, "model/vrml", 13) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MODEL, MMT_LOG_DEBUG, "MODEL: Content-Type: model/vrml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_VRML);
					return;
			  }
			  break;

   	 case 'x':
			  if (packet->content_line.len >= 16 && memcmp(packet->content_line.ptr, "model/x3d+binary", 16) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MODEL, MMT_LOG_DEBUG, "MODEL: Content-Type: model/x3d+binary found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_X3D_BINARY);
					return;
			  }

			  if (packet->content_line.len >= 14 && memcmp(packet->content_line.ptr, "model/x3d+vrml", 14) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MODEL, MMT_LOG_DEBUG, "MODEL: Content-Type: model/x3d+vrml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_X3D_VRML);
					return;
			  }
			  if (packet->content_line.len >= 13 && memcmp(packet->content_line.ptr, "model/x3d+xml", 13) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_MODEL, MMT_LOG_DEBUG, "MODEL: Content-Type: model/x3d+xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_X3D_XML);
					return;
			  }
			  break;
   	 }
#endif //MMT_CONTENT_FAMILY_MODEL

#ifdef MMT_CONTENT_FAMILY_MULTIPART
   	 switch (packet->content_line.ptr[ sizeof("multipart/")] ){
   	 case 'm':
			 if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "multipart/mixed", 15) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_MULTIPART, MMT_LOG_DEBUG, "MULTIPART: Content-Type: multipart/mixed found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_MIXED);
				 return;
			 }
			 break;

   	 case 'a':
			 if (packet->content_line.len >= 21 && memcmp(packet->content_line.ptr, "multipart/alternative", 21) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_MULTIPART, MMT_LOG_DEBUG, "MULTIPART: Content-Type: multipart/alternative found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_ALTERNATIVE);
				 return;
			 }
			 break;

   	 case 'r':
			 if (packet->content_line.len >= 17 && memcmp(packet->content_line.ptr, "multipart/related", 17) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_MULTIPART, MMT_LOG_DEBUG, "MULTIPART: Content-Type: multipart/related found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_RELATED);
				 return;
			 }
			 break;

   	 case 'f':
			 if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "multipart/form-data", 19) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_MULTIPART, MMT_LOG_DEBUG, "MULTIPART: Content-Type: multipart/form-data found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_FORM_DATA);
				 return;
			 }
			 break;

   	 case 's':
			 if (packet->content_line.len >= 16 && memcmp(packet->content_line.ptr, "multipart/signed", 16) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_MULTIPART, MMT_LOG_DEBUG, "MULTIPART: Content-Type: multipart/signed found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_SIGNED);
				 return;
			 }
			 break;

   	 case 'e':
			 if (packet->content_line.len >= 19 && memcmp(packet->content_line.ptr, "multipart/encrypted", 19) == 0) {
				 MMT_LOG(MMT_CONTENT_FAMILY_MULTIPART, MMT_LOG_DEBUG, "MULTIPART: Content-Type: multipart/encrypted found.\n");
				 mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_ENCRYPTED);
				 return;
			 }
			 break;
   	 }
#endif //MMT_CONTENT_FAMILY_MULTIPART

#ifdef MMT_CONTENT_FAMILY_TEXT
   	 switch (packet->content_line.ptr[ sizeof("text/")] ){
   	 case 'c':
			  if (packet->content_line.len >= 8 && memcmp(packet->content_line.ptr, "text/cmd", 8) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/cmd found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_CMD);
					return;
			  }
			  if (packet->content_line.len >= 8 && memcmp(packet->content_line.ptr, "text/css", 8) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/css found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_CSS);
					return;
			  }
			  if (packet->content_line.len >= 8 && memcmp(packet->content_line.ptr, "text/csv", 8) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/csv found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_CSV);
					return;
			  }
			  break;

   	 case 'h':
			  if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "text/html", 9) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/html found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_HTML);
					return;
			  }
			  break;

   	 case 'j':
			  if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "text/javascript", 15) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/javascript found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_JAVASCRIPT);
					return;
			  }
			  break;

   	 case 'p':
			  if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "text/plain", 9) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/plain found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_PLAIN);
					return;
			  }
			  break;

   	 case 'v':
			  if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "text/vcard", 10) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/vcard found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_VCARD);
					return;
			  }
			  break;

   	 case 'x':
			  if (packet->content_line.len >= 8 && memcmp(packet->content_line.ptr, "text/xml", 8) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/xml found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_XML);
					return;
			  }
			  // For non-standard files : x prefix
			  if (packet->content_line.len >= 14 && memcmp(packet->content_line.ptr, "text/x-gwt-rpc", 14) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/x-gwt-rpc found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_X_GWT_RPC);
					return;
			  }
			  if (packet->content_line.len >= 18 && memcmp(packet->content_line.ptr, "text/x-jquery-tmpl", 18) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_TEXT, MMT_LOG_DEBUG, "TEXT: Content-Type: text/x-jquery-tmpl found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_X_JQUERY_TMPL);
					return;
			  }
			  break;
   	 }
#endif //MMT_CONTENT_FAMILY_TEXT

#ifdef MMT_CONTENT_FAMILY_VIDEO
   	 switch (packet->content_line.ptr[ sizeof("video/")] ){
   	 case 'm':
			  if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "video/mpeg", 10) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/mpeg found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MPEG);
					return;
			  }
			  if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "video/mp4", 9) == 0) {
				  MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/mp4 found.\n");
				  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MP4);
				  return;
			  }
			  if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "video/m4v", 9) == 0) {
				  MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/m4v found.\n");
				  mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_M4V);
				  return;
			  }
			  break;

   	 case 'f':
			  if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "video/flash", 11) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/flash found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV);
					return;
			  }
			  if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "video/flv", 9) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/flv found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV);
					return;
			  }
			  break;

   	 case 'n':
			  if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "video/nsv", 9) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/nsv found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MPEG);
					return;
			  }
			  break;

   	 case 'o':
			  if (packet->content_line.len >= 9 && memcmp(packet->content_line.ptr, "video/ogg", 9) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/ogg found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_OGG);
					return;
			  }
			  break;

   	 case 'q':
			  if (packet->content_line.len >= 15 && memcmp(packet->content_line.ptr, "video/quicktime", 15) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/quicktime found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_QUICKTIME);
					return;
			  }
			  break;

   	 case 'w':
			  if (packet->content_line.len >= 10 && memcmp(packet->content_line.ptr, "video/webm", 10) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/webm found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_WEBM);
					return;
			  }
			  break;

   	 case 'x':
			  if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "video/x-m4v", 11) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/x-m4v found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_M4V);
					return;
			  }
			  if (packet->content_line.len >= 16 && memcmp(packet->content_line.ptr, "video/x-matroska", 16) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/x-matroska found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MATROSKA);
					return;
			  }
			  if (packet->content_line.len >= 14 && memcmp(packet->content_line.ptr, "video/x-ms-wmv", 14) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/x-ms-wmv found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV);
					return;
			  }
			  if (packet->content_line.len >= 14 && memcmp(packet->content_line.ptr, "video/x-ms-asf", 14) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/x-ms-asf found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV);
					return;
			  }
			  if (packet->content_line.len >= 24 && mmt_mem_cmp(packet->content_line.ptr, "video/x-msvideo", 15) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/x-msvideo found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV);
					return;
			  }
			  if (packet->content_line.len >= 14 && memcmp(packet->content_line.ptr, "video/x-ms-asx", 14) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/x-ms-asx found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV);
					return;
			  }
			  if (packet->content_line.len >= 11 && memcmp(packet->content_line.ptr, "video/x-flv", 11) == 0) {
					MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: video/x-flv found.\n");
					mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV);
					return;
			  }
			  break;
   	 }
#endif //MMT_CONTENT_FAMILY_VIDEO

#ifdef MMT_CONTENT_FAMILY_MISC
        if (packet->content_line.len >= 13 && memcmp(packet->content_line.ptr, "misc/ultravox", 13) == 0) {
            MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: misc/ultravox found.\n");
            mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MPEG);
            return;
        }
        if (packet->content_line.len >= 28 && memcmp(packet->content_line.ptr, "flv-application/octet-stream", 28) == 0) {
            MMT_LOG(MMT_CONTENT_FAMILY_VIDEO, MMT_LOG_DEBUG, "VIDEO: Content-Type: flv-application/octet-stream found.\n");
            mmt_add_content_type(ipacket, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV);
            return;
        }
#endif //MMT_CONTENT_FAMILY_MISC
    }
}

/**
 * End of functions to manage different MIME types
 */

#ifdef PROTO_QQ

static inline void qq_parse_packet_URL_and_hostname(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint32_t a;

    if (packet->payload_packet_len < 100 ||
            /*memcmp(&packet->payload[4], "/qzone", 6) != 0 || packet->host_line.len < 7 || */
            memcmp(&packet->host_line.ptr[packet->host_line.len - 6], "qq.com", 6) != 0) {

        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "did not find QQ.\n");
        return;
    }
    for (a = 0; a < packet->parsed_lines; a++) {
        if ((packet->line[a].len > 22 && memcmp(packet->line[a].ptr, "QzoneAuth: zzpaneluin=", 22) == 0) ||
                (packet->line[a].len > 19 && memcmp(packet->line[a].ptr, "Cookie: zzpanelkey=", 19) == 0) ||
                (packet->line[a].len > 13 && memcmp(packet->line[a].ptr, "Cookie: adid=", 13) == 0)) {
            MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "found QQ.\n");
            mmt_int_http_add_connection(ipacket, PROTO_QQ);
            return;
        }
    }

}
#endif

#ifdef PROTO_WINDOWSMEDIA

static inline void winmedia_parse_packet_useragentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (packet->user_agent_line.len >= 9 && memcmp(packet->user_agent_line.ptr, "NSPlayer/", 9) == 0) {
        MMT_LOG(PROTO_WINDOWSMEDIA, MMT_LOG_DEBUG, "username NSPlayer found\n");
        mmt_int_http_add_connection(ipacket, PROTO_WINDOWSMEDIA);
    }
}
#endif

#ifdef PROTO_SPOTIFY

static inline void spotify_parse_packet_useragentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (packet->user_agent_line.len >= 8 && memcmp(packet->user_agent_line.ptr, "Spotify-", 8) == 0) {
        MMT_LOG(PROTO_SPOTIFY, MMT_LOG_DEBUG, "useragent Spotify found\n");
        mmt_int_http_add_connection(ipacket, PROTO_SPOTIFY);
    }
}
#endif

#ifdef PROTO_MMS
//BW: Microsoft abandoned MMS in 2008! this should never be detected! However we continue to support it as Microsoft released
// the protocol specification and therefore many other 3rd party tools are being using it

static inline void mms_parse_packet_contentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->content_line.len >= 24 && mmt_mem_cmp(packet->content_line.ptr, "application/x-mms-framed", 24) == 0) {
        MMT_LOG(PROTO_MMS, MMT_LOG_DEBUG,
                "MMS: Content-Type: application/x-mms-framed found\n");
        mmt_int_http_add_connection(ipacket, PROTO_MMS);
    }
}
#endif


#ifdef PROTO_XBOX

static inline void xbox_parse_packet_useragentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->user_agent_line.len >= 17 && memcmp(packet->user_agent_line.ptr, "Xbox Live Client/", 17) == 0) {
        MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "XBOX: User Agent: Xbox Live Client found\n");
        mmt_int_http_add_connection(ipacket, PROTO_XBOX);
    }
}
#endif

#ifdef PROTO_WINDOWS_UPDATE

static inline void windows_update_packet_useragentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->user_agent_line.len >= 20 && memcmp(packet->user_agent_line.ptr, "Windows-Update-Agent", 20) == 0) {
        MMT_LOG(PROTO_WINDOWS_UPDATE, MMT_LOG_DEBUG, "WSUS: User Agent: Windows-Update-Agent\n");
        mmt_int_http_add_connection(ipacket, PROTO_WINDOWS_UPDATE);
    }
}
#endif

#ifdef PROTO_FLASH

static inline void flash_check_http_payload(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    const uint8_t *pos;

    if (packet->empty_line_position_set == 0 || (packet->empty_line_position + 10) > (packet->payload_packet_len))
        return;

    pos = &packet->payload[packet->empty_line_position] + 2;


    if (memcmp(pos, "FLV", 3) == 0 && pos[3] == 0x01 && (pos[4] == 0x01 || pos[4] == 0x04 || pos[4] == 0x05)
            && pos[5] == 0x00 && pos[6] == 0x00 && pos[7] == 0x00 && pos[8] == 0x09) {

        MMT_LOG(PROTO_FLASH, MMT_LOG_DEBUG, "Flash content in http detected\n");
        mmt_int_http_add_connection(ipacket, PROTO_FLASH);
    }
}
#endif

#ifdef PROTO_AVI

static inline void avi_check_http_payload(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_AVI, MMT_LOG_DEBUG, "called avi_check_http_payload: %u %u %u\n",
            packet->empty_line_position_set, flow->l4.tcp.http_empty_line_seen, packet->empty_line_position);

    if (packet->empty_line_position_set == 0 && flow->l4.tcp.http_empty_line_seen == 0)
        return;

    if (packet->empty_line_position_set != 0 && ((packet->empty_line_position + 20) > (packet->payload_packet_len))
            && flow->l4.tcp.http_empty_line_seen == 0) {
        flow->l4.tcp.http_empty_line_seen = 1;
        return;
    }

    if (flow->l4.tcp.http_empty_line_seen == 1) {
        if (packet->payload_packet_len > 20 && memcmp(packet->payload, "RIFF", 4) == 0
                && memcmp(packet->payload + 8, "AVI LIST", 8) == 0) {
            MMT_LOG(PROTO_AVI, MMT_LOG_DEBUG, "Avi content in http detected\n");
            mmt_int_http_add_connection(ipacket, PROTO_AVI);
        }
        flow->l4.tcp.http_empty_line_seen = 0;
        return;
    }

    if (packet->empty_line_position_set != 0) {
        // check for avi header
        // for reference see http://msdn.microsoft.com/archive/default.asp?url=/archive/en-us/directx9_c/directx/htm/avirifffilereference.asp
        uint32_t p = packet->empty_line_position + 2;

        MMT_LOG(PROTO_AVI, MMT_LOG_DEBUG, "p = %u\n", p);

        if ((p + 16) <= packet->payload_packet_len && memcmp(&packet->payload[p], "RIFF", 4) == 0
                && memcmp(&packet->payload[p + 8], "AVI LIST", 8) == 0) {
            MMT_LOG(PROTO_AVI, MMT_LOG_DEBUG, "Avi content in http detected\n");
            mmt_int_http_add_connection(ipacket, PROTO_AVI);
        }
    }
}
#endif

#ifdef PROTO_TEAMVIEWER

static inline void teamviewer_check_http_payload(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    //struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    const uint8_t *pos;

    MMT_LOG(PROTO_TEAMVIEWER, MMT_LOG_DEBUG, "called teamviewer_check_http_payload: %u %u %u\n",
            packet->empty_line_position_set, flow->l4.tcp.http_empty_line_seen, packet->empty_line_position);

    if (packet->empty_line_position_set == 0 || (packet->empty_line_position + 5) > (packet->payload_packet_len))
        return;

    pos = &packet->payload[packet->empty_line_position] + 2;

    if (pos[0] == 0x17 && pos[1] == 0x24) {
        MMT_LOG(PROTO_TEAMVIEWER, MMT_LOG_DEBUG, "TeamViewer content in http detected\n");
        mmt_int_http_add_connection(ipacket, PROTO_TEAMVIEWER);
    }
}
#endif

#ifdef PROTO_OFF

static inline void off_parse_packet_contentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->content_line.len >= 4 && memcmp(packet->content_line.ptr, "off/", 4) == 0) {
        MMT_LOG(PROTO_OFF, MMT_LOG_DEBUG, "off: Content-Type: off/ found\n");
        mmt_int_http_add_connection(ipacket, PROTO_OFF);
    }
}
#endif

#ifdef PROTO_MOVE

static inline void move_parse_packet_contentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->content_line.len == 15
            && (memcmp(packet->content_line.ptr, "application/qmx", 15) == 0
            || memcmp(packet->content_line.ptr, "application/qss", 15) == 0)) {
        MMT_LOG(PROTO_MOVE, MMT_LOG_DEBUG, "MOVE application qmx or qss detected\n");
        mmt_int_http_add_connection(ipacket, PROTO_MOVE);
    }
}
#endif

#ifdef PROTO_RTSP

static inline void rtsp_parse_packet_acceptline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->accept_line.len >= 28 && memcmp(packet->accept_line.ptr, "application/x-rtsp-tunnelled", 28) == 0) {
        MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "RTSP accept line detected\n");
        mmt_int_http_add_connection(ipacket, PROTO_RTSP);
    }
}
#endif

static inline void parseHttpSubprotocol(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint32_t proto;
    if (packet->detected_protocol_stack[0] != PROTO_HTTP)
        return;

    /* Check the protocol by hostname */
    proto = get_proto_id_by_hostname(ipacket, (char*) packet->host_line.ptr, packet->host_line.len);
    if (proto != PROTO_UNKNOWN) {
        mmt_int_http_add_connection(ipacket, proto);
        return;
    }

    /* Check the protocol by the IP addresses!!!*/
    proto = get_proto_id_from_address(ipacket);
    if (proto != PROTO_UNKNOWN) {
        mmt_int_http_add_connection(ipacket, proto);
        return;
    }
}

static inline void check_content_type_and_change_protocol(ipacket_t * ipacket) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;


    //Start by setting the content type
    check_packet_contents(ipacket);

#ifdef PROTO_AVI
#endif

    uint8_t a;

    if (packet->content_line.ptr != NULL && packet->content_line.len != 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "Content Type Line found %.*s\n",
                packet->content_line.len, packet->content_line.ptr);
#ifdef PROTO_MMS
        mms_parse_packet_contentline(ipacket);
#endif
#ifdef PROTO_OFF
        off_parse_packet_contentline(ipacket);
#endif
#ifdef PROTO_MOVE
        move_parse_packet_contentline(ipacket);
#endif
    }
    /* check user agent here too */
    if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len != 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "User Agent Type Line found %.*s\n",
                packet->user_agent_line.len, packet->user_agent_line.ptr);
#ifdef PROTO_XBOX
        xbox_parse_packet_useragentline(ipacket);
#endif
#ifdef PROTO_WINDOWS_UPDATE
        windows_update_packet_useragentline(ipacket);
#endif
#ifdef PROTO_WINDOWSMEDIA
        winmedia_parse_packet_useragentline(ipacket);
#endif
#ifdef PROTO_SPOTIFY
        spotify_parse_packet_useragentline(ipacket);
#endif

    }
    /* check for host line */
    if (packet->host_line.ptr != NULL) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HOST Line found %.*s\n",
                packet->host_line.len, packet->host_line.ptr);
#ifdef PROTO_QQ
        qq_parse_packet_URL_and_hostname(ipacket);
#endif

        parseHttpSubprotocol(ipacket);
    }

    /* check for accept line */
    if (packet->accept_line.ptr != NULL) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "Accept Line found %.*s\n",
                packet->accept_line.len, packet->accept_line.ptr);
#ifdef PROTO_RTSP
        rtsp_parse_packet_acceptline(ipacket);
#endif
    }
    /* search for line startin with "Icy-MetaData" */
#ifdef PROTO_MPEG
    for (a = 0; a < packet->parsed_lines; a++) {
        if (packet->line[a].len > 11 && memcmp(packet->line[a].ptr, "Icy-MetaData", 12) == 0) {
            MMT_LOG(PROTO_MPEG, MMT_LOG_DEBUG, "MPEG: Icy-MetaData found.\n");
            mmt_int_http_add_connection(ipacket, PROTO_MPEG);
            return;
        }
    }
#ifdef PROTO_AVI
#endif
#endif

}

static inline void check_http_payload(ipacket_t * ipacket) {

    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "called check_http_payload.\n");

#ifdef PROTO_FLASH
    flash_check_http_payload(ipacket);
#endif
#ifdef PROTO_AVI
    avi_check_http_payload(ipacket);
#endif
#ifdef PROTO_TEAMVIEWER
    teamviewer_check_http_payload(ipacket);
#endif
}

/**
 * this functions checks whether the packet begins with a valid http request
 * @param ipacket
 * @returnvalue 0 if no valid request has been found
 * @returnvalue >0 indicates start of filename but not necessarily in packet limit
 */
static inline uint16_t http_request_url_offset(ipacket_t * ipacket) {
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

static inline void http_bitmask_exclude(struct mmt_internal_tcpip_session_struct *flow) {
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_HTTP);
#ifdef PROTO_WINDOWS_UPDATE
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WINDOWS_UPDATE);
#endif
#ifdef PROTO_MPEG
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MPEG);
#endif
#ifdef PROTO_QUICKTIME
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QUICKTIME);
#endif
#ifdef PROTO_WINDOWSMEDIA
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_WINDOWSMEDIA);
#endif
#ifdef PROTO_REALMEDIA
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_REALMEDIA);
#endif
#ifdef PROTO_AVI
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_AVI);
#endif
#ifdef PROTO_OGG
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_OGG);
#endif
#ifdef PROTO_MOVE
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MOVE);
#endif
#ifdef PROTO_OFF
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_OFF);
#endif
#ifdef PROTO_XBOX
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_XBOX);
#endif
}

void mmt_init_classify_me_http() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD;

    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    // This list should not be updated 
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP_CONNECT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP_PROXY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_I23V5);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_POPO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_QUAKE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_REALMEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_USENET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WARCRAFT3);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WORLD_OF_KUNG_FU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MPEG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FLASH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_QUICKTIME);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WINDOWSMEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_OFF);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AVI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_OGG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MOVE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_RTSP);

    //////////// Start of HTTP based protocols /////////////////////
    /////// Needs to be updated when new protocols are added ///////
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_163);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_360);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_360BUY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_56);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_888);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ABOUT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ADCASH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ADDTHIS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ADF);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ADOBE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AFP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AIM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AIMINI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ALIBABA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ALIPAY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ALLEGRO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AMAZON);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AMEBLO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ANCESTRY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ANGRYBIRDS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ANSWERS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AOL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_APPLE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ASK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AVG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AWEBER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BABYLON);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BADOO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BAIDU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BANKOFAMERICA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BARNESANDNOBLE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BATTLEFIELD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BATTLENET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BBB);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BBC_ONLINE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BESTBUY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BETFAIR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BIBLEGATEWAY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BILD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BING);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BITTORRENT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BLEACHERREPORT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BLOGFA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BLOGGER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BLOGSPOT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BODYBUILDING);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BOOKING);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CBSSPORTS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CENT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CHANGE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CHASE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CHESS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CHINAZ);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CITRIXONLINE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CLICKSOR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CNN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CNZZ);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_COMCAST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CONDUIT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_COPYSCAPE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CORREIOS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CRAIGSLIST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CROSSFIRE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DAILYMAIL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DAILYMOTION);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DIRECT_DOWNLOAD_LINK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DEVIANTART);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DIGG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DIRECTCONNECT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DOFUS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DONANIMHABER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DOUBAN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DOUBLECLICK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DROPBOX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_EBAY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_EHOW);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_EKSISOZLUK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ELECTRONICSARTS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ESPN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ETSY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_EUROPA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_EUROSPORT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FACEBOOK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FC2);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FEIDIAN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FIVERR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FLICKR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FOX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FREE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GAMEFAQS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GAMESPOT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GAP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GARANTI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GAZETEVATAN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GIGAPETA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GITHUB);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GITTIGIDIYOR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GLOBO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GMAIL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GNUTELLA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GOOGLE_MAPS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GODADDY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GOO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GOOGLE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GOOGLE_USER_CONTENT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GROOVESHARK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GROUPON);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GTALK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GUARDIAN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_GUILDWARS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HABERTURK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HAO123);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HEPSIBURADA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HI5);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HOMEDEPOT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HOOTSUITE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HOTMAIL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HUFFINGTON_POST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HURRIYET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ICECAST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_APPLE_ICLOUD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IFENG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IGN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IKEA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_INTERNET_MOVIE_DATABASE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IMESH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IMGUR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_INCREDIBAR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_INDIATIMES);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_INSTAGRAM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IRS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_APPLE_ITUNES);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_UNENCRYPED_JABBER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_JAPANPOST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_KAT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_KAZAA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_KING);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_KOHLS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_KONGREGATE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_KONTIKI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LASTFM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LEAGUEOFLEGENDS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LEGACY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LETV);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LINKEDIN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVEDOOR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVEMAIL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVEINTERNET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVEJASMIN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVEJOURNAL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVESCORE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVINGSOCIAL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LOWES);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MACYS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MAIL_RU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MAPLESTORY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MATCH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MEDIAFIRE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MEEBO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MICROSOFT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MILLIYET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MINECRAFT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MINICLIP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MLBASEBALL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MMO_CHAMPION);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MMS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MOZILLA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MSN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MULTIPLY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MYNET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MYSPACE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MYWEBSEARCH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NBA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NEOBUX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NETFLIX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NEWEGG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NEWSMAX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NFL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NICOVIDEO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NIH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NORDSTROM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NYTIMES);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ODNOKLASSNIKI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ONET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ORANGEDONKEY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_OUTBRAIN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_OVERSTOCK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PAYPAL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PCH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PCONLINE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PHOTOBUCKET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PINTEREST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PLAYSTATION);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_POGO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PORNHUB);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PPLIVE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PPSTREAM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PREMIERLEAGUE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_QQ);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_QQLIVE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_R10);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_RAKUTEN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_REDDIT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_REDTUBE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_REFERENCE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_RENREN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ROBLOX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ROVIO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SABAHTR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SAHIBINDEN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SALESFORCE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SALON);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SEARCHNU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SEARCH_RESULTS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SEARS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SECONDLIFE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SECURESERVER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SHOUTCAST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SINA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SITEADVISOR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SKY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SKYPE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SKYROCK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SKYSPORTS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SLATE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SLIDESHARE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOFTONIC);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOGOU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOHU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOPCAST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOSO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOULSEEK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOUNDCLOUD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SOURGEFORGE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SPIEGEL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SPORX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SPOTIFY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SQUIDOO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_STACK_OVERFLOW);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_STATCOUNTER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_STEAM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_STUMBLEUPON);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SULEKHA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TAGGED);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TAOBAO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TARGET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TCO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_THEMEFOREST);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_THE_PIRATE_BAY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TIANYA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TMALL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TORRENTZ);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TRUPHONE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TUBE8);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TUDOU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TUENTI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TUMBLR);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TVANTS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_TWITTER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_UBI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_UCOZ);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_UOL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_USDEPARTMENTOFSTATE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HTTP_APPLICATION_VEOHTV);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VIADEO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VIBER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VIMEO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VKONTAKTE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WALMART);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WARRIORFORUM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WAYN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WEATHER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WEBEX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WEEKLYSTANDARD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WEIBO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WELLSFARGO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WHATSAPP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WIGETMEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WIKIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WIKIMEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WIKIPEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WILLIAMHILL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WINDOWSLIVE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WINUPDATE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WORDPRESS_ORG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WORLDOFWARCRAFT);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WOWHEAD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WWE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XBOX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XHAMSTER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XING);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XINHUANET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XNXX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_XVIDEOS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YAHOO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YAHOOGAMES);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YAHOOMAIL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YANDEX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YELP);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YOUKU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YOUPORN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_YOUTUBE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ZAPPOS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ZATTOO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ZEDO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ZOL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ZYNGA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BUZZNET);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_COMEDY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_RAMBLER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SMUGMUG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ARCHIEVE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CITYNEWS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SCIENCESTAGE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ONEWORLD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DISQUS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BLOGCU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_EKOLEY);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_500PX);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FOTKI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FOTOLOG);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_JALBUM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LOCKERZ);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_PANORAMIO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SNAPFISH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WEBSHOTS);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MEGA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VIDOOSH);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_AFREECA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_WILDSCREEN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BLOGTV);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_HULU);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MEVIO);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVESTREAM);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_LIVELEAK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DEEZER);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BLIPTV);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_BREAK);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_CITYTV);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_COMEDYCENTRAL);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_ENGAGEMEDIA);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SCREENJUNKIES);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_RUTUBE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SEVENLOAD);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_MUBI);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_IZLESENE);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_VIDEO_HOSTING);
    //////////// End of HTTP based protocols /////////////////////
    //MMT_DEL_PROTOCOL_FROM_BITMASK(excluded_protocol_bitmask, PROTO_UNKNOWN);
    //MMT_DEL_PROTOCOL_FROM_BITMASK(excluded_protocol_bitmask, PROTO_QQ);
    //MMT_DEL_PROTOCOL_FROM_BITMASK(excluded_protocol_bitmask, PROTO_FLASH);
    //MMT_DEL_PROTOCOL_FROM_BITMASK(excluded_protocol_bitmask, PROTO_MMS);
    //MMT_DEL_PROTOCOL_FROM_BITMASK(excluded_protocol_bitmask, PROTO_RTSP);
    //MMT_DEL_PROTOCOL_FROM_BITMASK(excluded_protocol_bitmask, PROTO_XBOX);
    MMT_BITMASK_RESET(excluded_protocol_bitmask);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SSL); //Exclude processing when ssl is detected! Obvious no?
}

void mmt_classify_me_http(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint16_t filename_start;

    /* BW: TODO: the following strategy should be enforced! No?
     * HTTP stages: 0 means no request no response seen, expecting a request or response
     *              1 means request seen, expecting response now
     *              2 means resposne seen, expecting request now
     *
     * Exclude strategy: If we have seen payload data on both directions, then this is not HTTP!
     */

    //First parse the packet to check if it contains any: field: value lines
    packet->empty_line_position = 0; 
    if(packet->payload_packet_len < 32) {
        return;
    }

    mmt_parse_packet_line_info(ipacket);

    if (packet->parsed_lines > 1) {
        //If the packet contains a response, try to check the payload
        if (packet->http_response.ptr) {
            if (!flow->http_detected) {
                mmt_int_http_add_connection(ipacket, PROTO_HTTP);
            }
            check_content_type_and_change_protocol(ipacket);
            if (packet->empty_line_position_set) {
                check_http_payload(ipacket);
            }
        } else {
            //The packet is not a response! maybe this is a request
            filename_start = http_request_url_offset(ipacket);
            if (filename_start != 0 && packet->parsed_lines > 1 && packet->line[0].len >= (9 + filename_start)
                    && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
                packet->http_url_name.ptr = &packet->payload[filename_start];
                packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

                packet->http_method.ptr = packet->line[0].ptr;
                packet->http_method.len = filename_start - 1;

                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "next http action, "
                        "resetting to http and search for other protocols later.\n");
                if (!flow->http_detected) {
                    mmt_int_http_add_connection(ipacket, PROTO_HTTP);
                }
            }
            check_content_type_and_change_protocol(ipacket);
        }
    }

    return;

    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "search http\n");

    /* set client-server_direction */
    if (flow->l4.tcp.http_setup_dir == 0) {
        const struct tcphdr *l4ptr = packet->tcp;
        if (l4ptr->syn) {
            //This is still the TCP handshake, do nothing
            return;
        }
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "initializes http to stage: 1 \n");
        flow->l4.tcp.http_setup_dir = 1 + ipacket->session->last_packet_direction;
    }

    if (MMT_COMPARE_PROTOCOL_TO_BITMASK
            (detection_bitmask, packet->detected_protocol_stack[0]) != 0) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                "protocol might be detected earlier as http jump to payload type detection\n");
        goto http_parse_detection;
    }

    if (flow->l4.tcp.http_setup_dir == 1 + ipacket->session->last_packet_direction) {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "http stage: 1\n");

        if (flow->l4.tcp.http_wait_for_retransmission) {
            if (!packet->tcp_retransmission) {
                if (ipacket->session->data_packet_count <= 5) {
                    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "still waiting for retransmission\n");
                    return;
                } else {
                    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "retransmission not found, exclude\n");
                    fprintf(stdout, "retransmission not found, exclude\n");
                    http_bitmask_exclude(flow);
                    return;
                }
            }
        }

        if (flow->l4.tcp.http_stage == 0) {
            filename_start = http_request_url_offset(ipacket);
            if (filename_start == 0) {
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "filename not found, exclude\n");
                fprintf(stdout, "filename not found, exclude\n");
                http_bitmask_exclude(flow);
                return;
            }
            // parse packet
            mmt_parse_packet_line_info(ipacket);

            if (packet->parsed_lines <= 1) {
                /* parse one more packet .. */
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "just one line, search next packet\n");
                flow->l4.tcp.http_stage = 1;
                return;
            }
            // parsed_lines > 1 here
            if (packet->line[0].len >= (9 + filename_start)
                    && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
                packet->http_url_name.ptr = &packet->payload[filename_start];
                packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

                packet->http_method.ptr = packet->line[0].ptr;
                packet->http_method.len = filename_start - 1;

                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "http structure detected, adding\n");

                //BW: TODO: What the hell is HTTP_CONNECT ?????
                //mmt_int_http_add_connection(ipacket, (filename_start == 8) ? PROTO_HTTP_CONNECT : PROTO_HTTP);
                mmt_int_http_add_connection(ipacket, PROTO_HTTP);

                check_content_type_and_change_protocol(ipacket);
                /* HTTP found, look for host... */
                if (packet->host_line.ptr != NULL) {
                    /* aaahh, skip this direction and wait for a server reply here */
                    flow->l4.tcp.http_stage = 2;
                    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP START HOST found\n");
                    return;
                }
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP START HOST found\n");

                /* host not found, check in next packet after */
                flow->l4.tcp.http_stage = 1;
                return;
            }
        } else if (flow->l4.tcp.http_stage == 1) {
            /* SECOND PAYLOAD TRAFFIC FROM CLIENT, FIRST PACKET MIGHT HAVE BEEN HTTP... */
            /* UNKNOWN TRAFFIC, HERE FOR HTTP again.. */
            // parse packet
            mmt_parse_packet_line_info(ipacket);

            if (packet->parsed_lines <= 1) {

                /* wait some packets in case request is split over more than 2 packets */
                if (ipacket->session->data_packet_count < 5) {
                    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                            "line still not finished, search next packet\n");
                    return;
                } else {
                    /* stop parsing here */
                    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                            "HTTP: PACKET DOES NOT HAVE A LINE STRUCTURE\n");
                    fprintf(stdout, "HTTP: PACKET DOES NOT HAVE A LINE STRUCTURE\n");
                    http_bitmask_exclude(flow);
                    return;
                }
            }

            if (packet->line[0].len >= 9 && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
                mmt_int_http_add_connection(ipacket, PROTO_HTTP);
                check_content_type_and_change_protocol(ipacket);
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                        "HTTP START HTTP found in 2. packet, check host here...\n");
                /* HTTP found, look for host... */
                flow->l4.tcp.http_stage = 2;

                return;
            }
        }
    }
    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: REQUEST NOT HTTP CONFORM\n");
    fprintf(stdout, "HTTP: REQUEST NOT HTTP CONFORM\n");
    http_bitmask_exclude(flow);
    return;

http_parse_detection:
    if (flow->l4.tcp.http_setup_dir == 1 + ipacket->session->last_packet_direction) {
        /* we have something like http here, so check for host and content type if possible */
        if (flow->l4.tcp.http_stage == 0 || flow->l4.tcp.http_stage == 3) {
            MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP RUN MAYBE NEXT GET/POST...\n");
            // parse packet
            mmt_parse_packet_line_info(ipacket);
            /* check for url here */
            filename_start = http_request_url_offset(ipacket);
            if (filename_start != 0 && packet->parsed_lines > 1 && packet->line[0].len >= (9 + filename_start)
                    && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
                packet->http_url_name.ptr = &packet->payload[filename_start];
                packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

                packet->http_method.ptr = packet->line[0].ptr;
                packet->http_method.len = filename_start - 1;

                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "next http action, "
                        "resetting to http and search for other protocols later.\n");
                mmt_int_http_add_connection(ipacket, PROTO_HTTP);
            }
            check_content_type_and_change_protocol(ipacket);
            /* HTTP found, look for host... */
            if (packet->host_line.ptr != NULL) {
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                        "HTTP RUN MAYBE NEXT HOST found, skipping all packets from this direction\n");
                /* aaahh, skip this direction and wait for a server reply here */
                flow->l4.tcp.http_stage = 2;
                return;
            }
            MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                    "HTTP RUN MAYBE NEXT HOST NOT found, scanning one more packet from this direction\n");
            flow->l4.tcp.http_stage = 1;
        } else if (flow->l4.tcp.http_stage == 1) {
            // parse packet and maybe find a packet info with host ptr,...
            mmt_parse_packet_line_info(ipacket);
            check_content_type_and_change_protocol(ipacket);
            MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP RUN second packet scanned\n");
            /* HTTP found, look for host... */
            flow->l4.tcp.http_stage = 2;
        }
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                "HTTP skipping client packets after second packet\n");
        return;
    }
    /* server response */
    if (flow->l4.tcp.http_stage > 0) {
        /* first packet from server direction, might have a content line */
        mmt_parse_packet_line_info(ipacket);
        check_content_type_and_change_protocol(ipacket);


        if (packet->empty_line_position_set != 0 || flow->l4.tcp.http_empty_line_seen == 1) {
            MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "empty line. check_http_payload.\n");
            check_http_payload(ipacket);
        }
        if (flow->l4.tcp.http_stage == 2) {
            flow->l4.tcp.http_stage = 3;
        } else {
            flow->l4.tcp.http_stage = 0;
        }
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG,
                "HTTP response first or second packet scanned,new stage is: %u\n", flow->l4.tcp.http_stage);
        return;
    } else {
        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP response next packet skipped\n");
    }
}

int mmt_check_http(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
            mmt_classify_me_http(ipacket, index);
    }
    return 4;
}
#endif
