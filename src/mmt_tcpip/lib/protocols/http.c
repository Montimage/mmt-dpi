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
    MMT_HTTP_CONNECT, MMT_HTTP_PROPFIND, MMT_HTTP_REPORT,
    MMT_HTTP_PATCH,   MMT_HTTP_MKCOL,    MMT_HTTP_LOCK
};

static inline int get_header_index_by_header_id(int header_id) {
    return header_id - 1;
}

static inline int get_header_id_by_field_name(const char * header_field, int max) {
    int count = 0;
    for (; count < HTTP_HEADERS_NB; count++) {
        if (mmt_strncasecmp(header_field, http_header_fields[count], max) == 0) { //TODO(#330): this is consuming (calculating len every time)
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

//TODO(#331): needs to be changed to take the correct scope from the attribute information

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
    if (!http_session_data) {
        return;
    }
    memset(http_session_data, 0, sizeof (struct http_session_data_struct));
    ipacket->session->session_data[index] = http_session_data;
}

/* issue #204 (F-BUG-053): session cleanup for HTTP session data. The struct
 * owns requested_uri plus one malloc'd value per recognised header field —
 * without this callback every HTTP session leaked all of them.
 * session_field_values[].field points at the static http_header_fields[]
 * strings and must NOT be freed; ->header and ->next are never allocated. */
void http_session_data_cleanup(mmt_session_t * session, unsigned index) {
    struct http_session_data_struct *http =
        (struct http_session_data_struct *) session->session_data[index];
    int i;
    if (http == NULL) {
        return;
    }
    mmt_free(http->requested_uri);
    for (i = 0; i < HTTP_HEADERS_NB; i++) {
        mmt_free(http->session_field_values[i].value);
        http->session_field_values[i].value = NULL;
    }
    mmt_free(http);
    session->session_data[index] = NULL;
}

/**
 * this functions checks whether the packet begins with a valid http request
 * @param msg the received message
 * @param msg_len length of the message request line in octets
 * @param method pointer to the method code to be set by this function
 * @return the offset of the uri if positive value, zero means the message is not a valid request
 *
 * Not static: issue #101's regression test (tools/phase0/tests/
 * http_method_classification_test.c) links against this symbol directly, the
 * same convention already used for http2.c's extraction functions. It is not
 * declared in any public header, so it remains internal to the SDK's API
 * surface.
 */
int get_request_method_uri_offset(const char *msg, int msg_len, int * method) {
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
    } else if (msg_len >= 6 && mmt_strncmp(msg, "PATCH ", 6) == 0) {
        uri_offset = 6;
        *method = MMT_HTTP_PATCH_CODE;
    } else if (msg_len >= 6 && mmt_strncmp(msg, "MKCOL ", 6) == 0) {
        uri_offset = 6;
        *method = MMT_HTTP_MKCOL_CODE;
    } else if (msg_len >= 5 && mmt_strncmp(msg, "LOCK ", 5) == 0) {
        uri_offset = 5;
        *method = MMT_HTTP_LOCK_CODE;
    }

    while (uri_offset < msg_len && isspace((unsigned char) msg[uri_offset])) {
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

    while (code_offset < msg_len && isspace((unsigned char) msg[code_offset])) {
        code_offset++;
    }

    return code_offset;
}

/**
 * Parse the HTTP HEADER.
 */
static inline int
parse_message_header_lines(ipacket_t * ipacket, unsigned index, int offset) { //TODO(#330): optimization work required here! VERY IMPORTANT
    int code, hlen;
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int base_offset = get_packet_offset_at_index(ipacket, index);
    int remaining = packet->payload_packet_len - (offset - base_offset);
    if (remaining < 0) remaining = 0;
    if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset;
    if (remaining < 0) remaining = 0;

    //Get the length of the first http header line
    hlen = get_next_header_line_length((const char*)&ipacket->data[offset], remaining, & code);

    //if the header line is positive
    if (hlen) {
        //Check if this is a request header
        struct http_session_data_struct* http;
        int method, line_first_element_offset;
        char * version = NULL;

        http = ((struct http_session_data_struct *) ipacket->session->session_data[index]);
        if (!http) return 0;
        line_first_element_offset = get_request_method_uri_offset((const char*)&ipacket->data[offset], remaining, &method);

        //This is a request; update the session context accordingly
        if (line_first_element_offset) {
            int uri_len = get_next_white_space_offset_no_limit((const char*)&ipacket->data[offset + line_first_element_offset], hlen - line_first_element_offset);
            if (uri_len < 0) uri_len = 0;
            http->http_method   = method;
            /* issue #204 (F-BUG-053): free the previous request's URI before
             * overwriting the pointer — one leak per request otherwise. */
            mmt_free(http->requested_uri);
            http->requested_uri = (char *) mmt_malloc(uri_len + 1);
            if (!http->requested_uri) return 0;
            memcpy(http->requested_uri, &ipacket->data[offset + line_first_element_offset], uri_len);
            http->requested_uri[uri_len] = '\0';

            //printf("Method %i --- URI %s \n", http->http_method,
            //        http->requested_uri);
        } else if((line_first_element_offset = get_response_code_offset((const char*)&ipacket->data[offset], remaining, &version)) > 0) {
            //This is not a request; check if it is a response
            http->http_version = version;
            //printf("version %s \n", http->http_version);
        } else {
            //Not a request nor a reply --> not an HTTP header --> return
            return 0;
        }

        offset += hlen;
        remaining = packet->payload_packet_len - (offset - base_offset);
        if (remaining < 0) remaining = 0;
        if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset;
        if (remaining < 0) remaining = 0;
        hlen = get_next_header_line_length((const char*)&ipacket->data[offset], remaining, &code);
        while (hlen > 2) {
            int header_id, header_index, value_offset, value_len, field_len;
            line_first_element_offset = get_next_non_white_space_offset_no_limit((const char*)&ipacket->data[offset], hlen);

            //printf("LFE_Offset %i - offset %i - hlen %i \n", line_first_element_offset, offset, hlen);
            // No need to include "line_first_element_offset" coz most probably it will be zero
            value_offset = get_value_offset((const char*)&ipacket->data[offset], hlen);

            field_len = get_field_len((const char*)&ipacket->data[offset + line_first_element_offset], hlen - line_first_element_offset);

            /* issue #204 (F-BUG-052): get_field_len() returns -1 when the
             * line has no colon; passing that to get_header_id_by_field_name
             * converted to SIZE_MAX inside mmt_strncasecmp and read past the
             * field. A zero field length also yields a spurious max=0 match.
             * Skip malformed lines, mirroring the value_offset validation. */
            if (field_len <= 0) { offset += hlen; remaining = packet->payload_packet_len - (offset - base_offset); if (remaining < 0) remaining = 0; if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset; if (remaining < 0) remaining = 0; hlen = get_next_header_line_length((const char*)&ipacket->data[offset], remaining, &code); continue; }

            header_id = get_header_id_by_field_name((const char*)&ipacket->data[offset + line_first_element_offset], field_len);

            if (header_id && value_offset >= 0 && value_offset < hlen) {

                value_len = hlen - (value_offset + code);
                if (value_len < 0) { offset += hlen; remaining = packet->payload_packet_len - (offset - base_offset); if (remaining < 0) remaining = 0; if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset; if (remaining < 0) remaining = 0; hlen = get_next_header_line_length((const char*)&ipacket->data[offset], remaining, &code); continue; }
                header_index = get_header_index_by_header_id(header_id);
                struct http_session_data_struct *http = (struct http_session_data_struct *)ipacket->session->session_data[index];
                if (!http) { offset += hlen; remaining = packet->payload_packet_len - (offset - base_offset); if (remaining < 0) remaining = 0; if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset; if (remaining < 0) remaining = 0; hlen = get_next_header_line_length((const char*)&ipacket->data[offset], remaining, &code); continue; }
                http->session_field_values[header_index].field_id   = header_id;
                http->session_field_values[header_index].field      = get_header_field_name_by_header_id(header_id);
                http->session_field_values[header_index].header_len = hlen;
                http->session_field_values[header_index].value_len  = value_len;

                /* issue #204 (F-BUG-053): a repeated header overwrote the
                 * previously malloc'd value — free it first. */
                mmt_free(http->session_field_values[header_index].value);
                http->session_field_values[header_index].value = (char *) mmt_malloc(value_len + 1);
                if (!http->session_field_values[header_index].value) { offset += hlen; remaining = packet->payload_packet_len - (offset - base_offset); if (remaining < 0) remaining = 0; if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset; if (remaining < 0) remaining = 0; hlen = get_next_header_line_length((const char*)&ipacket->data[offset], remaining, &code); continue; }
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
            remaining = packet->payload_packet_len - (offset - base_offset);
            if (remaining < 0) remaining = 0;
            if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset;
            if (remaining < 0) remaining = 0;
            hlen = get_next_header_line_length((const char*)&ipacket->data[offset], remaining, &code);
        }
        return 1;
    }
    return 0;
}

int http_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    //printf("from http generic session data analysis\n");
    int offset = get_packet_offset_at_index(ipacket, index);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int remaining = packet->payload_packet_len;
    if (remaining > (int)ipacket->p_hdr->caplen - offset) remaining = (int)ipacket->p_hdr->caplen - offset;
    if (remaining < 0) remaining = 0;

    //First we check if the message starts with leading CRLF --- normally this should never be the case
    offset += ignore_starting_crlf((const char*)&ipacket->data[offset], remaining);

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
        /* issue #204 (F-BUG-053): free HTTP session data at session teardown. */
        register_session_data_cleanup_function(protocol_struct, http_session_data_cleanup);
        /* issue #204 (F-BUG-048): assert the MIME tables' min_len >= cmp_len
         * invariant before the protocol can be used. */
        if (mmt_http_content_tables_check() != 0) {
            return 0;
        }

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

#define LEN(x ) (sizeof( x ) - 1)

struct mmt_content_type_entry {
    const char *mime;
    uint16_t cmp_len;
    uint16_t min_len;
    int family;
    int type;
};

static inline const char *mmt_content_family_label(int family) {
    switch (family) {
        case MMT_CONTENT_FAMILY_APPLICATION: return "APPLICATION";
        case MMT_CONTENT_FAMILY_AUDIO:       return "AUDIO";
        case MMT_CONTENT_FAMILY_IMAGE:       return "IMAGE";
        case MMT_CONTENT_FAMILY_VIDEO:       return "VIDEO";
        case MMT_CONTENT_FAMILY_MESSAGE:     return "MESSAGE";
        case MMT_CONTENT_FAMILY_MODEL:       return "MODEL";
        case MMT_CONTENT_FAMILY_MULTIPART:   return "MULTIPART";
        case MMT_CONTENT_FAMILY_TEXT:        return "TEXT";
        default:                             return "UNKNOWN";
    }
}

#define MMT_CT_ENTRY(m, fam, typ) { m, (uint16_t)(sizeof(m)-1), (uint16_t)(sizeof(m)-1), fam, typ }

#ifdef MMT_CONTENT_FAMILY_APPLICATION
static const struct mmt_content_type_entry mmt_application_table[] = {
    MMT_CT_ENTRY("application/atom+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_ATOM_XML),
    MMT_CT_ENTRY("application/ecmascript", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_ECMASCRIPT),
    MMT_CT_ENTRY("application/javascript", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_JAVASCRIPT),
    MMT_CT_ENTRY("application/json", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_JSON),
    MMT_CT_ENTRY("application/EDI-X12", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_EDI_X12),
    MMT_CT_ENTRY("application/EDIFACT", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_EDIFACT),
    MMT_CT_ENTRY("application/octet-stream", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_OCTET_STREAM),
    MMT_CT_ENTRY("application/ogg", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_OGG),
    MMT_CT_ENTRY("application/pdf", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_PDF),
    MMT_CT_ENTRY("application/postscript", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_POSTSCRIPT),
    MMT_CT_ENTRY("application/rdf+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_RDF_XML),
    MMT_CT_ENTRY("application/rss+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_RSS_XML),
    MMT_CT_ENTRY("application/soap+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_SOAP_XML),
    MMT_CT_ENTRY("application/flv", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FLV),
    MMT_CT_ENTRY("application/font-woff", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_FONT_WOFF),
    MMT_CT_ENTRY("application/zip", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_ZIP),
    MMT_CT_ENTRY("application/gzip", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_GZIP),
    MMT_CT_ENTRY("application/vnd.rn-realmedia", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_REALMEDIA),
    MMT_CT_ENTRY("application/vnd.ms.wms-", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_MS_WMV),
    MMT_CT_ENTRY("application/vnd.oasis.opendocument.text", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_TEXT),
    MMT_CT_ENTRY("application/vnd.oasis.opendocument.spreadsheet", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_SPREADSHEET),
    MMT_CT_ENTRY("application/vnd.oasis.opendocument.presentation", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_PRESENTATION),
    MMT_CT_ENTRY("application/vnd.oasis.opendocument.graphics", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_GRAPHICS),
    MMT_CT_ENTRY("application/vnd.ms-excel", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_MS_EXCEL),
    MMT_CT_ENTRY("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_SPREADSHEETML_SHEET),
    MMT_CT_ENTRY("application/vnd.ms-powerpoint", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_MS_POWERPOINT),
    MMT_CT_ENTRY("application/vnd.openxmlformats-officedocument.presentationml.presentation", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_PRESENTATIONML_PRESENTATION),
    MMT_CT_ENTRY("application/vnd.openxmlformats-officedocument.wordprocessingml.document", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_WORDPROCESSINGML_DOCUMENT),
    MMT_CT_ENTRY("application/vnd.mozilla.xul+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_MOZILLA_XUL_XML),
    MMT_CT_ENTRY("application/vnd.google-earth.kml+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_VND_GOOGLE_EARTH_KML_XML),
    MMT_CT_ENTRY("application/x-fcs", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FLV),
    MMT_CT_ENTRY("application/x-font-woff", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FONT_WOFF),
    MMT_CT_ENTRY("application/xhtml+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_XHTML_XML),
    MMT_CT_ENTRY("application/xml-dtd", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_XML_DTD),
    MMT_CT_ENTRY("application/xop+xml", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_XOP_XML),
    MMT_CT_ENTRY("application/x-www-form-urlencoded", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_WWW_FORM_URLENCODED),
    MMT_CT_ENTRY("application/x-dvi", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_DVI),
    MMT_CT_ENTRY("application/x-latex", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_LATEX),
    MMT_CT_ENTRY("application/x-font-ttf", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_FONT_TTF),
    MMT_CT_ENTRY("application/x-shockwave-flash", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_SHOCKWAVE_FLASH),
    MMT_CT_ENTRY("application/x-stuffit", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_STUFFIT),
    MMT_CT_ENTRY("application/x-rar-compressed", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_RAR_COMPRESSED),
    MMT_CT_ENTRY("application/x-tar", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_TAR),
    MMT_CT_ENTRY("application/x-javascript", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_JAVASCRIPT),
    MMT_CT_ENTRY("application/x-deb", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_DEB),
    MMT_CT_ENTRY("application/x-mpegURL", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_MPEG_URL),
    MMT_CT_ENTRY("application/x-pkcs12", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS12),
    MMT_CT_ENTRY("application/x-pkcs7-certificates", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_CERTIFICATES),
    MMT_CT_ENTRY("application/x-pkcs7-certreqresp", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_CERTREQRESP),
    MMT_CT_ENTRY("application/x-pkcs7-mime", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_MIME),
    MMT_CT_ENTRY("application/x-pkcs7-signature", MMT_CONTENT_FAMILY_APPLICATION, MMT_CONTENT_TYPE_X_PKCS7_SIGNATURE),
};
#endif

#ifdef MMT_CONTENT_FAMILY_AUDIO
static const struct mmt_content_type_entry mmt_audio_table[] = {
    MMT_CT_ENTRY("audio/basic", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_BASIC),
    MMT_CT_ENTRY("audio/L24", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_L24),
    MMT_CT_ENTRY("audio/mp4", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MP4),
    MMT_CT_ENTRY("audio/mpeg", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG),
    MMT_CT_ENTRY("audio/mpeg3", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG),
    { "audio/mp4a", 10, 11, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG },
    MMT_CT_ENTRY("audio/x-mpeg", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_MPEG),
    { "audio/x-wav", 11, 24, MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_X_MS_WMV },
    MMT_CT_ENTRY("audio/x-pn-realaudio", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_REALAUDIO),
    MMT_CT_ENTRY("audio/x-aac", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_X_AAC),
    MMT_CT_ENTRY("audio/x-caf", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_X_CAF),
    MMT_CT_ENTRY("audio/ogg", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_OGG),
    MMT_CT_ENTRY("audio/vorbis", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_VORBIS),
    MMT_CT_ENTRY("audio/vnd.rn-realaudio", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_VND_RN_REALAUDIO),
    MMT_CT_ENTRY("audio/vnd.wave", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_VND_WAVE),
    MMT_CT_ENTRY("audio/webm", MMT_CONTENT_FAMILY_AUDIO, MMT_CONTENT_TYPE_WEBM),
};
#endif

#ifdef MMT_CONTENT_FAMILY_IMAGE
static const struct mmt_content_type_entry mmt_image_table[] = {
    MMT_CT_ENTRY("image/gif", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_GIF),
    MMT_CT_ENTRY("image/jpeg", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_JPEG),
    MMT_CT_ENTRY("image/pjpeg", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_PJPEG),
    MMT_CT_ENTRY("image/png", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_PNG),
    MMT_CT_ENTRY("image/svg+xml", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_SVG_XML),
    MMT_CT_ENTRY("image/tiff", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_TIFF),
    MMT_CT_ENTRY("image/vnd.microsoft.icon", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_VND_MICROSOFT_ICON),
    MMT_CT_ENTRY("image/x-xcf", MMT_CONTENT_FAMILY_IMAGE, MMT_CONTENT_TYPE_X_XCF),
};
#endif

#ifdef MMT_CONTENT_FAMILY_MESSAGE
static const struct mmt_content_type_entry mmt_message_table[] = {
    MMT_CT_ENTRY("message/http", MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_HTTP),
    MMT_CT_ENTRY("message/imdn+xml", MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_IMDN_XML),
    MMT_CT_ENTRY("message/partial", MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_PARTIAL),
    MMT_CT_ENTRY("message/rfc822", MMT_CONTENT_FAMILY_MESSAGE, MMT_CONTENT_TYPE_RFC822),
};
#endif

#ifdef MMT_CONTENT_FAMILY_MODEL
static const struct mmt_content_type_entry mmt_model_table[] = {
    MMT_CT_ENTRY("model/example", MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_EXAMPLE),
    MMT_CT_ENTRY("model/iges", MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_IGES),
    MMT_CT_ENTRY("model/mesh", MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_MESH),
    { "model/vrml", 10, 13, MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_VRML },
    MMT_CT_ENTRY("model/x3d+binary", MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_X3D_BINARY),
    MMT_CT_ENTRY("model/x3d+vrml", MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_X3D_VRML),
    MMT_CT_ENTRY("model/x3d+xml", MMT_CONTENT_FAMILY_MODEL, MMT_CONTENT_TYPE_X3D_XML),
};
#endif

#ifdef MMT_CONTENT_FAMILY_MULTIPART
static const struct mmt_content_type_entry mmt_multipart_table[] = {
    MMT_CT_ENTRY("multipart/mixed", MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_MIXED),
    MMT_CT_ENTRY("multipart/alternative", MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_ALTERNATIVE),
    MMT_CT_ENTRY("multipart/related", MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_RELATED),
    MMT_CT_ENTRY("multipart/form-data", MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_FORM_DATA),
    MMT_CT_ENTRY("multipart/signed", MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_SIGNED),
    MMT_CT_ENTRY("multipart/encrypted", MMT_CONTENT_FAMILY_MULTIPART, MMT_CONTENT_TYPE_ENCRYPTED),
};
#endif

#ifdef MMT_CONTENT_FAMILY_TEXT
static const struct mmt_content_type_entry mmt_text_table[] = {
    MMT_CT_ENTRY("text/cmd", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_CMD),
    MMT_CT_ENTRY("text/css", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_CSS),
    MMT_CT_ENTRY("text/csv", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_CSV),
    MMT_CT_ENTRY("text/html", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_HTML),
    MMT_CT_ENTRY("text/javascript", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_JAVASCRIPT),
    /* issue #204 (F-BUG-048): this row used to be { "text/plain", 10, 9, ... }
     * (min_len 9 < cmp_len 10), so a 9-byte Content-Type value passed the
     * length guard and the 10-byte memcmp read one byte past it. Every row
     * must satisfy min_len >= cmp_len — enforced at init by
     * mmt_http_content_tables_check(). */
    MMT_CT_ENTRY("text/plain", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_PLAIN),
    MMT_CT_ENTRY("text/vcard", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_VCARD),
    MMT_CT_ENTRY("text/xml", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_XML),
    MMT_CT_ENTRY("text/x-gwt-rpc", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_X_GWT_RPC),
    MMT_CT_ENTRY("text/x-jquery-tmpl", MMT_CONTENT_FAMILY_TEXT, MMT_CONTENT_TYPE_X_JQUERY_TMPL),
};
#endif

#ifdef MMT_CONTENT_FAMILY_VIDEO
static const struct mmt_content_type_entry mmt_video_table[] = {
    MMT_CT_ENTRY("video/mpeg", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MPEG),
    MMT_CT_ENTRY("video/mp4", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MP4),
    MMT_CT_ENTRY("video/m4v", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_M4V),
    MMT_CT_ENTRY("video/flash", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV),
    MMT_CT_ENTRY("video/flv", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV),
    MMT_CT_ENTRY("video/nsv", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MPEG),
    MMT_CT_ENTRY("video/ogg", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_OGG),
    MMT_CT_ENTRY("video/quicktime", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_QUICKTIME),
    MMT_CT_ENTRY("video/webm", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_WEBM),
    MMT_CT_ENTRY("video/x-m4v", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_M4V),
    MMT_CT_ENTRY("video/x-matroska", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MATROSKA),
    MMT_CT_ENTRY("video/x-ms-wmv", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV),
    MMT_CT_ENTRY("video/x-ms-asf", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV),
    { "video/x-msvideo", 15, 24, MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV },
    MMT_CT_ENTRY("video/x-ms-asx", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_MS_WMV),
    MMT_CT_ENTRY("video/x-flv", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV),
};
#endif

#ifdef MMT_CONTENT_FAMILY_MISC
static const struct mmt_content_type_entry mmt_misc_table[] = {
    MMT_CT_ENTRY("misc/ultravox", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_MPEG),
    MMT_CT_ENTRY("flv-application/octet-stream", MMT_CONTENT_FAMILY_VIDEO, MMT_CONTENT_TYPE_X_FLV),
};
#endif

/*
 * issue #204 (F-BUG-048): the match loop only guarantees
 * content_line.len >= min_len bytes before comparing cmp_len of them, so
 * any row with min_len < cmp_len reads past the captured value. Verify the
 * invariant for every row of every table; returns the number of offending
 * rows (0 = tables are safe). Exposed (non-static) so the phase0 regression
 * test can exercise it directly.
 */
static inline int mmt_http_check_table(const struct mmt_content_type_entry *table, size_t n) {
    size_t i;
    int bad = 0;
    for (i = 0; i < n; i++) {
        const struct mmt_content_type_entry *e = &table[i];
        if (e->min_len < e->cmp_len || e->cmp_len > strlen(e->mime)) {
            mmt_stderr_log( "mmt_http: MIME table row '%s' has min_len=%u < cmp_len=%u (or cmp_len > mime length)\n",
                    e->mime, (unsigned) e->min_len, (unsigned) e->cmp_len);
            bad++;
        }
    }
    return bad;
}

int mmt_http_content_tables_check(void) {
    int bad = 0;
#ifdef MMT_CONTENT_FAMILY_APPLICATION
    bad += mmt_http_check_table(mmt_application_table, sizeof(mmt_application_table)/sizeof(mmt_application_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_AUDIO
    bad += mmt_http_check_table(mmt_audio_table, sizeof(mmt_audio_table)/sizeof(mmt_audio_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_IMAGE
    bad += mmt_http_check_table(mmt_image_table, sizeof(mmt_image_table)/sizeof(mmt_image_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_MESSAGE
    bad += mmt_http_check_table(mmt_message_table, sizeof(mmt_message_table)/sizeof(mmt_message_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_MODEL
    bad += mmt_http_check_table(mmt_model_table, sizeof(mmt_model_table)/sizeof(mmt_model_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_MULTIPART
    bad += mmt_http_check_table(mmt_multipart_table, sizeof(mmt_multipart_table)/sizeof(mmt_multipart_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_TEXT
    bad += mmt_http_check_table(mmt_text_table, sizeof(mmt_text_table)/sizeof(mmt_text_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_VIDEO
    bad += mmt_http_check_table(mmt_video_table, sizeof(mmt_video_table)/sizeof(mmt_video_table[0]));
#endif
#ifdef MMT_CONTENT_FAMILY_MISC
    bad += mmt_http_check_table(mmt_misc_table, sizeof(mmt_misc_table)/sizeof(mmt_misc_table[0]));
#endif
    return bad;
}

static inline void check_packet_contents(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    size_t i;
    if (packet->content_line.ptr == NULL || packet->content_line.len == 0) {
        return;
    }
#ifdef MMT_CONTENT_FAMILY_APPLICATION
    for (i = 0; i < sizeof(mmt_application_table)/sizeof(mmt_application_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_application_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_AUDIO
    for (i = 0; i < sizeof(mmt_audio_table)/sizeof(mmt_audio_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_audio_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_IMAGE
    for (i = 0; i < sizeof(mmt_image_table)/sizeof(mmt_image_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_image_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_MESSAGE
    for (i = 0; i < sizeof(mmt_message_table)/sizeof(mmt_message_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_message_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_MODEL
    for (i = 0; i < sizeof(mmt_model_table)/sizeof(mmt_model_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_model_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_MULTIPART
    for (i = 0; i < sizeof(mmt_multipart_table)/sizeof(mmt_multipart_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_multipart_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_TEXT
    for (i = 0; i < sizeof(mmt_text_table)/sizeof(mmt_text_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_text_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_VIDEO
    for (i = 0; i < sizeof(mmt_video_table)/sizeof(mmt_video_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_video_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
#ifdef MMT_CONTENT_FAMILY_MISC
    for (i = 0; i < sizeof(mmt_misc_table)/sizeof(mmt_misc_table[0]); i++) {
        const struct mmt_content_type_entry *e = &mmt_misc_table[i];
        if (packet->content_line.len >= e->min_len && mmt_memcmp(packet->content_line.ptr, e->mime, e->cmp_len) == 0) {
            MMT_LOG(e->family, MMT_LOG_DEBUG, "%s: Content-Type: %s found.\n", mmt_content_family_label(e->family), e->mime);
            mmt_add_content_type(ipacket, e->family, e->type);
            return;
        }
    }
#endif
}
/**
 * End of functions to manage different MIME types
 */

#ifdef PROTO_QQ

static inline void qq_parse_packet_URL_and_hostname(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint32_t a;

    /* issue #204 (F-BUG-050): host_line.len is uint16_t — subtracting 6 when
     * len < 6 wraps to ~65530 and reads wild memory (and a NULL host ptr
     * crashes). The length guard was commented out; restore it. */
    if (packet->payload_packet_len < 100 ||
            /*mmt_memcmp(&packet->payload[4], "/qzone", 6) != 0 ||*/ packet->host_line.len < 7 ||
            mmt_memcmp(&packet->host_line.ptr[packet->host_line.len - 6], "qq.com", 6) != 0) {

        MMT_LOG(PROTO_QQ, MMT_LOG_DEBUG, "did not find QQ.\n");
        return;
    }
    for (a = 0; a < packet->parsed_lines; a++) {
        if ((packet->line[a].len > 22 && mmt_memcmp(packet->line[a].ptr, "QzoneAuth: zzpaneluin=", 22) == 0) ||
                (packet->line[a].len > 19 && mmt_memcmp(packet->line[a].ptr, "Cookie: zzpanelkey=", 19) == 0) ||
                (packet->line[a].len > 13 && mmt_memcmp(packet->line[a].ptr, "Cookie: adid=", 13) == 0)) {
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
    if (packet->user_agent_line.len >= 9 && mmt_memcmp(packet->user_agent_line.ptr, "NSPlayer/", 9) == 0) {
        MMT_LOG(PROTO_WINDOWSMEDIA, MMT_LOG_DEBUG, "username NSPlayer found\n");
        mmt_int_http_add_connection(ipacket, PROTO_WINDOWSMEDIA);
    }
}
#endif

#ifdef PROTO_SPOTIFY

static inline void spotify_parse_packet_useragentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (packet->user_agent_line.len >= 8 && mmt_memcmp(packet->user_agent_line.ptr, "Spotify-", 8) == 0) {
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

    if (packet->user_agent_line.len >= 17 && mmt_memcmp(packet->user_agent_line.ptr, "Xbox Live Client/", 17) == 0) {
        MMT_LOG(PROTO_XBOX, MMT_LOG_DEBUG, "XBOX: User Agent: Xbox Live Client found\n");
        mmt_int_http_add_connection(ipacket, PROTO_XBOX);
    }
}
#endif

#ifdef PROTO_WINDOWS_UPDATE

static inline void windows_update_packet_useragentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->user_agent_line.len >= 20 && mmt_memcmp(packet->user_agent_line.ptr, "Windows-Update-Agent", 20) == 0) {
        MMT_LOG(PROTO_WINDOWS_UPDATE, MMT_LOG_DEBUG, "WSUS: User Agent: Windows-Update-Agent\n");
        mmt_int_http_add_connection(ipacket, PROTO_WINDOWS_UPDATE);
    }
}
#endif

#ifdef PROTO_FLASH

static inline void flash_check_http_payload(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    const uint8_t *pos;

    /* issue #204 (F-BUG-051): pos = payload + empty_line_position + 2 and the
     * signature reads pos[0..8], i.e. up to payload[empty_line_position+10].
     * The old `+10 > len` guard admitted the exact-end case and read one
     * byte past the payload. Require the full 11-byte window. */
    if (packet->empty_line_position_set == 0 || (packet->empty_line_position + 10) >= (packet->payload_packet_len))
        return;

    pos = &packet->payload[packet->empty_line_position] + 2;


    if (mmt_memcmp(pos, "FLV", 3) == 0 && pos[3] == 0x01 && (pos[4] == 0x01 || pos[4] == 0x04 || pos[4] == 0x05)
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
        if (packet->payload_packet_len > 20 && mmt_memcmp(packet->payload, "RIFF", 4) == 0
                && mmt_memcmp(packet->payload + 8, "AVI LIST", 8) == 0) {
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

        if ((p + 16) <= packet->payload_packet_len && mmt_memcmp(&packet->payload[p], "RIFF", 4) == 0
                && mmt_memcmp(&packet->payload[p + 8], "AVI LIST", 8) == 0) {
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

    if (packet->content_line.len >= 4 && mmt_memcmp(packet->content_line.ptr, "off/", 4) == 0) {
        MMT_LOG(PROTO_OFF, MMT_LOG_DEBUG, "off: Content-Type: off/ found\n");
        mmt_int_http_add_connection(ipacket, PROTO_OFF);
    }
}
#endif

#ifdef PROTO_MOVE

static inline void move_parse_packet_contentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->content_line.len == 15
            && (mmt_memcmp(packet->content_line.ptr, "application/qmx", 15) == 0
            || mmt_memcmp(packet->content_line.ptr, "application/qss", 15) == 0)) {
        MMT_LOG(PROTO_MOVE, MMT_LOG_DEBUG, "MOVE application qmx or qss detected\n");
        mmt_int_http_add_connection(ipacket, PROTO_MOVE);
    }
}
#endif

#ifdef PROTO_OGG

static inline void ogg_parse_packet_contentline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* issue #204 (F-BUG-049): pair each accepted length with its own
     * comparison — the old code ran the 15-byte "application/ogg" memcmp
     * even when content_line.len was 9, reading 6 bytes past the value. */
    if ((packet->content_line.len == 15 && mmt_memcmp(packet->content_line.ptr, "application/ogg", 15) == 0)
            || (packet->content_line.len == 9 && mmt_memcmp(packet->content_line.ptr, "video/ogg", 9) == 0)
            || (packet->content_line.len == 9 && mmt_memcmp(packet->content_line.ptr, "audio/ogg", 9) == 0)) {
        MMT_LOG(PROTO_OGG, MMT_LOG_DEBUG, "OGG application detected\n");
        mmt_int_http_add_connection(ipacket, PROTO_OGG);
    }
}
#endif

#ifdef PROTO_RTSP

static inline void rtsp_parse_packet_acceptline(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->accept_line.len >= 28 && mmt_memcmp(packet->accept_line.ptr, "application/x-rtsp-tunnelled", 28) == 0) {
        MMT_LOG(PROTO_RTSP, MMT_LOG_DEBUG, "RTSP accept line detected\n");
        mmt_int_http_add_connection(ipacket, PROTO_RTSP);
    }
}
#endif

static inline void parseHttpSubprotocol(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint32_t proto = PROTO_UNKNOWN;
    if (packet->detected_protocol_stack[0] != PROTO_HTTP)
        return;

    /* Check the protocol by hostname */
    if(ipacket->mmt_handler->hostname_classify == 1){
        proto = get_proto_id_by_hostname(ipacket, (char *)packet->host_line.ptr, packet->host_line.len);
    }

    if (proto != PROTO_UNKNOWN) {
        mmt_int_http_add_connection(ipacket, proto);
        return;
    }

    /* Check the protocol by the IP addresses!!!*/
    if(ipacket->mmt_handler->ip_address_classify == 1){
        proto = get_proto_id_from_address(ipacket);
        if (proto != PROTO_UNKNOWN)
        {
            mmt_int_http_add_connection(ipacket, proto);
            return;
        }
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
#ifdef PROTO_OGG
        ogg_parse_packet_contentline(ipacket);
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
        if (packet->line[a].len > 11 && mmt_memcmp(packet->line[a].ptr, "Icy-MetaData", 12) == 0) {
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

    if(packet->payload_packet_len < 4) return 0;
    /* FIRST PAYLOAD PACKET FROM CLIENT */
    /* check if the packet starts with POST or GET */
    switch(packet->payload[0]){
        case 'G':
            if(mmt_memcmp(packet->payload, "GET ", 4) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: GET FOUND\n");
                return 4;
            }
        break;
        case 'P':
            switch(packet->payload[1]){
                case 'O':
                    if(packet->payload_packet_len >= 5 && mmt_memcmp(packet->payload, "POST ", 5) == 0){
                        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: POST FOUND\n");
                        return 5;
                    }
                break;
                case 'U':
                    if(mmt_memcmp(packet->payload, "PUT ", 4) == 0){
                        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: PUT FOUND\n");
                        return 4;
                    }
                break;
                case 'R':
                    if(packet->payload_packet_len >= 9 && mmt_memcmp(packet->payload, "PROPFIND ", 9) == 0){
                        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: PROPFIND FOUND\n");
                        return 9;
                    }
                break;
                case 'A':
                    /* issue #101: PATCH was missing from this table, so any
                     * flow whose first request used PATCH was permanently
                     * excluded from HTTP classification. */
                    if(packet->payload_packet_len >= 6 && mmt_memcmp(packet->payload, "PATCH ", 6) == 0){
                        MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: PATCH FOUND\n");
                        return 6;
                    }
                break;
            }
        break;
        case 'M':
            /* issue #101: WebDAV MKCOL was missing from this table. */
            if(packet->payload_packet_len >= 6 && mmt_memcmp(packet->payload, "MKCOL ", 6) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: MKCOL FOUND\n");
                return 6;
            }
        break;
        case 'L':
            /* issue #101: WebDAV LOCK was missing from this table. */
            if(packet->payload_packet_len >= 5 && mmt_memcmp(packet->payload, "LOCK ", 5) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: LOCK FOUND\n");
                return 5;
            }
        break;
        case 'O':
            if(packet->payload_packet_len >= 8 && mmt_memcmp(packet->payload, "OPTIONS ", 8) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: OPTIONS FOUND\n");
                return 8;
            }
        break;
        case 'H':
            if(packet->payload_packet_len >= 5 && mmt_memcmp(packet->payload, "HEAD ", 5) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: HEAD FOUND\n");
                return 5;
            }
        break;
        case 'D':
            if(packet->payload_packet_len >= 7 && mmt_memcmp(packet->payload, "DELETE ", 7) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: DELETE FOUND\n");
                return 7;
            }
        break;
        case 'C':
            if(packet->payload_packet_len >= 8 && mmt_memcmp(packet->payload, "CONNECT ", 8) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: CONNECT FOUND\n");
                return 8;
            }
        break;
        case 'R':
            if(packet->payload_packet_len >= 7 && mmt_memcmp(packet->payload, "REPORT ", 7) == 0){
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP: REPORT FOUND\n");
                return 7;
            }
        break;
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

/* Issue #227: http keeps a genuinely distinct init — it seeds the detection
 * bitmask with the HTTP-based protocol list (hundreds of protocols observed
 * over HTTP), far beyond the single-add shape of mmt_init_classify_bitmasks(),
 * which here covers only the selection value, the PROTO_UNKNOWN detection
 * reset and the excluded mask. Stays in this TU because the bitmasks are
 * file-scope; called from init_proto_http_struct() in proto_http.c. */
void mmt_http_init_detection_bitmask() {
    mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
            &excluded_protocol_bitmask,
            MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
            PROTO_UNKNOWN, PROTO_HTTP);

    /* Protocols reachable over HTTP — the detection_bitmask built here is
     * what lets mmt_classify_http() claim a flow already detected as one of
     * these ids. The first group is fixed: do not update it. The second
     * group MUST be updated when a new HTTP-based protocol is registered —
     * otherwise that protocol's flows keep being reported as plain
     * PROTO_HTTP and are never attributed to it (issue #238, F-CLEAN-018). */
    static const int http_detected_protocols[] = {
        /* Fixed set — do not update */
        PROTO_HTTP,
        PROTO_REUTERS,
        PROTO_HTTP_PROXY,
        PROTO_I23V5,
        PROTO_POPO,
        PROTO_QUAKE,
        PROTO_REALMEDIA,
        PROTO_USENET,
        PROTO_WARCRAFT3,
        PROTO_WORLD_OF_KUNG_FU,
        PROTO_MPEG,
        PROTO_FLASH,
        PROTO_WINDOWSMEDIA,
        PROTO_OFF,
        PROTO_AVI,
        PROTO_OGG,
        PROTO_MOVE,
        PROTO_RTSP,
        /* HTTP-based protocols — update when new protocols are added */
        PROTO_163,
        PROTO_360,
        PROTO_JD,
        PROTO_56,
        PROTO_888POKER,
        PROTO_ABOUT,
        PROTO_ADCASH,
        PROTO_ADDTHIS,
        PROTO_ADF,
        PROTO_ADOBE,
        PROTO_AFP,
        PROTO_AIM,
        PROTO_AIMINI,
        PROTO_ALIBABA,
        PROTO_ALIPAY,
        PROTO_ALLEGRO,
        PROTO_AMAZON,
        PROTO_AMEBLO,
        PROTO_ANCESTRY,
        PROTO_ANGRYBIRDS,
        PROTO_ANSWERS,
        PROTO_AOL,
        PROTO_APPLE,
        PROTO_ASK,
        PROTO_AVG,
        PROTO_AWEBER,
        PROTO_BABYLON,
        PROTO_BADOO,
        PROTO_BAIDU,
        PROTO_BANKOFAMERICA,
        PROTO_BARNESANDNOBLE,
        PROTO_BATTLEFIELD,
        PROTO_BATTLENET,
        PROTO_BBB,
        PROTO_BBC_ONLINE,
        PROTO_BESTBUY,
        PROTO_BETFAIR,
        PROTO_BIBLEGATEWAY,
        PROTO_BILD,
        PROTO_BING,
        PROTO_BITTORRENT,
        PROTO_BLEACHERREPORT,
        PROTO_BLOGFA,
        PROTO_BLOGGER,
        PROTO_BLOGSPOT,
        PROTO_BODYBUILDING,
        PROTO_BOOKING,
        PROTO_CBSSPORTS,
        PROTO_CNET,
        PROTO_CHANGE,
        PROTO_CHASE,
        PROTO_CHESS,
        PROTO_CHINAZ,
        PROTO_CITRIXONLINE,
        PROTO_CLICKSOR,
        PROTO_CNN,
        PROTO_CNZZ,
        PROTO_COMCAST,
        PROTO_CONDUIT,
        PROTO_COPYSCAPE,
        PROTO_CORREIOS,
        PROTO_CRAIGSLIST,
        PROTO_CROSSFIRE,
        PROTO_DAILYMAIL,
        PROTO_DAILYMOTION,
        PROTO_DIRECT_DOWNLOAD_LINK,
        PROTO_DEVIANTART,
        PROTO_DIGG,
        PROTO_DIRECTCONNECT,
        PROTO_DOFUS,
        PROTO_DONANIMHABER,
        PROTO_DOUBAN,
        PROTO_DOUBLECLICK,
        PROTO_DROPBOX,
        PROTO_EBAY,
        PROTO_EHOW,
        PROTO_EKSISOZLUK,
        PROTO_ELECTRONICSARTS,
        PROTO_ESPN,
        PROTO_ETSY,
        PROTO_EUROPA,
        PROTO_EUROSPORT,
        PROTO_FACEBOOK,
        PROTO_FC2,
        PROTO_FEIDIAN,
        PROTO_FIVERR,
        PROTO_FLICKR,
        PROTO_FOX,
        PROTO_FREE,
        PROTO_GAMEFAQS,
        PROTO_GAMESPOT,
        PROTO_GAP,
        PROTO_GARANTI,
        PROTO_GAZETEVATAN,
        PROTO_GIGAPETA,
        PROTO_GITHUB,
        PROTO_GITTIGIDIYOR,
        PROTO_GLOBO,
        PROTO_GMAIL,
        PROTO_GNUTELLA,
        PROTO_GOOGLE_MAPS,
        PROTO_GO,
        PROTO_GODADDY,
        PROTO_GOO,
        PROTO_GOOGLE,
        PROTO_GOOGLE_USER_CONTENT,
        PROTO_GROOVESHARK,
        PROTO_GROUPON,
        PROTO_GTALK,
        PROTO_GUARDIAN,
        PROTO_GUILDWARS,
        PROTO_HABERTURK,
        PROTO_HAO123,
        PROTO_HEPSIBURADA,
        PROTO_HI5,
        PROTO_HOMEDEPOT,
        PROTO_HOOTSUITE,
        PROTO_HOTMAIL,
        PROTO_HUFFINGTONPOST,
        PROTO_HURRIYET,
        PROTO_ICECAST,
        PROTO_APPLE_ICLOUD,
        PROTO_IFENG,
        PROTO_IGN,
        PROTO_IKEA,
        PROTO_IMDB,
        PROTO_IMESH,
        PROTO_IMGUR,
        PROTO_LEBONCOIN,
        PROTO_INDIATIMES,
        PROTO_INSTAGRAM,
        PROTO_IRS,
        PROTO_APPLE_ITUNES,
        PROTO_UNENCRYPED_JABBER,
        PROTO_JAPANPOST,
        PROTO_KAT,
        PROTO_ORANGEFR,
        PROTO_KING,
        PROTO_KOHLS,
        PROTO_KONGREGATE,
        PROTO_KONTIKI,
        PROTO_LASTFM,
        PROTO_LEAGUEOFLEGENDS,
        PROTO_LEGACY,
        PROTO_LETV,
        PROTO_LINKEDIN,
        PROTO_LIVE,
        PROTO_LIVEDOOR,
        PROTO_LIVEMAIL,
        PROTO_LIVEINTERNET,
        PROTO_LIVEJASMIN,
        PROTO_LIVEJOURNAL,
        PROTO_LIVESCORE,
        PROTO_LIVINGSOCIAL,
        PROTO_LOWES,
        PROTO_MACYS,
        PROTO_MAIL_RU,
        PROTO_MAPLESTORY,
        PROTO_MATCH,
        PROTO_MEDIAFIRE,
        PROTO_MEEBO,
        PROTO_MICROSOFT,
        PROTO_MILLIYET,
        PROTO_MINECRAFT,
        PROTO_MINICLIP,
        PROTO_MLBASEBALL,
        PROTO_MMO_CHAMPION,
        PROTO_MMS,
        PROTO_MOZILLA,
        PROTO_MSN,
        PROTO_MULTIPLY,
        PROTO_MYNET,
        PROTO_MYSPACE,
        PROTO_MYWEBSEARCH,
        PROTO_NBA,
        PROTO_NEOBUX,
        PROTO_NETFLIX,
        PROTO_NEWEGG,
        PROTO_NEWSMAX,
        PROTO_NFL,
        PROTO_NICOVIDEO,
        PROTO_NIH,
        PROTO_NORDSTROM,
        PROTO_NYTIMES,
        PROTO_ODNOKLASSNIKI,
        PROTO_ONET,
        PROTO_ORANGEDONKEY,
        PROTO_OUTBRAIN,
        PROTO_OVERSTOCK,
        PROTO_PAYPAL,
        PROTO_PCH,
        PROTO_PCONLINE,
        PROTO_PHOTOBUCKET,
        PROTO_PINTEREST,
        PROTO_PLAYSTATION,
        PROTO_POGO,
        PROTO_PORNHUB,
        PROTO_PPLIVE,
        PROTO_PPSTREAM,
        PROTO_PREMIERLEAGUE,
        PROTO_QQ,
        PROTO_QQLIVE,
        PROTO_R10,
        PROTO_RAKUTEN,
        PROTO_REDDIT,
        PROTO_REDTUBE,
        PROTO_REFERENCE,
        PROTO_RENREN,
        PROTO_ROBLOX,
        PROTO_ROVIO,
        PROTO_SABAH,
        PROTO_SAHIBINDEN,
        PROTO_SALESFORCE,
        PROTO_SALON,
        PROTO_SEARCHNU,
        PROTO_SEARCH_RESULTS,
        PROTO_SEARS,
        PROTO_SECONDLIFE,
        PROTO_SECURESERVER,
        PROTO_SHOUTCAST,
        PROTO_SINA,
        PROTO_SITEADVISOR,
        PROTO_SKY,
        PROTO_SKYPE,
        PROTO_SKYROCK,
        PROTO_SKYSPORTS,
        PROTO_SLATE,
        PROTO_SLIDESHARE,
        PROTO_SOFTONIC,
        PROTO_SOGOU,
        PROTO_SOHU,
        PROTO_SOPCAST,
        PROTO_SOSO,
        PROTO_SOULSEEK,
        PROTO_SOUNDCLOUD,
        PROTO_SOURCEFORGE,
        PROTO_SPIEGEL,
        PROTO_SPORX,
        PROTO_SPOTIFY,
        PROTO_SQUIDOO,
        PROTO_STACK_OVERFLOW,
        PROTO_STATCOUNTER,
        PROTO_STEAM,
        PROTO_STUMBLEUPON,
        PROTO_SULEKHA,
        PROTO_TAGGED,
        PROTO_TAOBAO,
        PROTO_TARGET,
        PROTO_TCO,
        PROTO_THEMEFOREST,
        PROTO_THE_PIRATE_BAY,
        PROTO_TIANYA,
        PROTO_TMALL,
        PROTO_TORRENTZ,
        PROTO_TRUPHONE,
        PROTO_TUBE8,
        PROTO_TUDOU,
        PROTO_TUENTI,
        PROTO_TUMBLR,
        PROTO_TVANTS,
        PROTO_TWITTER,
        PROTO_UBI,
        PROTO_UCOZ,
        PROTO_UOL,
        PROTO_USDEPARTMENTOFSTATE,
        PROTO_HTTP_APPLICATION_VEOHTV,
        PROTO_VIADEO,
        PROTO_VIBER,
        PROTO_VIMEO,
        PROTO_VK,
        PROTO_VKONTAKTE,
        PROTO_WALMART,
        PROTO_WARRIORFORUM,
        PROTO_WAYN,
        PROTO_WEATHER,
        PROTO_WEBEX,
        PROTO_WEEKLYSTANDARD,
        PROTO_WEIBO,
        PROTO_WELLSFARGO,
        PROTO_WHATSAPP,
        PROTO_WIGETMEDIA,
        PROTO_WIKIA,
        PROTO_WIKIMEDIA,
        PROTO_WIKIPEDIA,
        PROTO_WILLIAMHILL,
        PROTO_WINDOWSLIVE,
        PROTO_WINUPDATE,
        PROTO_WORDPRESS_ORG,
        PROTO_WORLDOFWARCRAFT,
        PROTO_WOWHEAD,
        PROTO_WWE,
        PROTO_XBOX,
        PROTO_XHAMSTER,
        PROTO_XING,
        PROTO_XINHUANET,
        PROTO_XNXX,
        PROTO_XVIDEOS,
        PROTO_YAHOO,
        PROTO_ALLOCINE,
        PROTO_YAHOOMAIL,
        PROTO_YANDEX,
        PROTO_YELP,
        PROTO_YOUKU,
        PROTO_YOUPORN,
        PROTO_YOUTUBE,
        PROTO_ZAPPOS,
        PROTO_ZATTOO,
        PROTO_ZEDO,
        PROTO_ZOL,
        PROTO_ZYNGA,
        PROTO_BUZZNET,
        PROTO_COMEDY,
        PROTO_RAMBLER,
        PROTO_SMUGMUG,
        PROTO_ARCHIEVE,
        PROTO_CITYNEWS,
        PROTO_SCIENCESTAGE,
        PROTO_ONEWORLD,
        PROTO_DISQUS,
        PROTO_BLOGCU,
        PROTO_EKOLAY,
        PROTO_500PX,
        PROTO_FOTKI,
        PROTO_FOTOLOG,
        PROTO_JALBUM,
        PROTO_LEMONDE,
        PROTO_PANORAMIO,
        PROTO_SNAPFISH,
        PROTO_WEBSHOTS,
        PROTO_MEGA,
        PROTO_VIDOOSH,
        PROTO_AFREECA,
        PROTO_WILDSCREEN,
        PROTO_BLOGTV,
        PROTO_HULU,
        PROTO_MEVIO,
        PROTO_LIVESTREAM,
        PROTO_LIVELEAK,
        PROTO_DEEZER,
        PROTO_BLIPTV,
        PROTO_BREAK,
        PROTO_CITYTV,
        PROTO_COMEDYCENTRAL,
        PROTO_ENGAGEMEDIA,
        PROTO_SCREENJUNKIES,
        PROTO_RUTUBE,
        PROTO_SEVENLOAD,
        PROTO_MUBI,
        PROTO_IZLESENE,
        PROTO_VIDEO_HOSTING,
    };
    for (size_t i = 0; i < sizeof(http_detected_protocols) / sizeof(http_detected_protocols[0]); i++) {
        /* every HTTP-based id joins detection_bitmask — a multi-hundred add
         * the single-add generic helpers cannot express */
        MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, http_detected_protocols[i]);
    }
}

void mmt_classify_http(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    uint16_t filename_start;

    /* Open question moved to issue #334: whether the stage-based
     * "payload seen on both directions ⇒ not HTTP" exclude strategy
     * should be enforced. */

    MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "search http\n");

    /* set client-server_direction */
    if (flow->l4.tcp.http_setup_dir == 0) {
        const mmt_una_tcphdr_t *l4ptr = packet->tcp; /* issue #57: alignment-safe view */
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
                    http_bitmask_exclude(flow);
                    return;
                }
            }
        }

        if (flow->l4.tcp.http_stage == 0) {
            filename_start = http_request_url_offset(ipacket);
            if (filename_start == 0) {
                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "filename not found, exclude\n");
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
                    && mmt_memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
                packet->http_url_name.ptr = &packet->payload[filename_start];
                packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

                packet->http_method.ptr = packet->line[0].ptr;
                packet->http_method.len = filename_start - 1;

                MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "http structure detected, adding\n");

                /* Whether CONNECT should classify as a distinct PROTO_HTTP_CONNECT
                 * is an open question — see issue #334. */
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
                    http_bitmask_exclude(flow);
                    return;
                }
            }

            if (packet->line[0].len >= 9 && mmt_memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
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
    http_bitmask_exclude(flow);
    return;

http_parse_detection:
    if (flow->l4.tcp.http_setup_dir == 1 + ipacket->session->last_packet_direction) {
        /* we have something like http here, so check for host and content type if possible */
        if (flow->l4.tcp.http_stage == 0 || flow->l4.tcp.http_stage == 3) {
            MMT_LOG(PROTO_HTTP, MMT_LOG_DEBUG, "HTTP RUN MAYBE NEXT GET/POST...\n");
            // parse packet
            mmt_parse_packet_line_info(ipacket);
            if (packet->http_response.ptr) {
                if (!flow->http_detected) {
                    mmt_int_http_add_connection(ipacket, PROTO_HTTP);
                }
                check_content_type_and_change_protocol(ipacket);
                if (packet->empty_line_position_set) {
                    check_http_payload(ipacket);
                }
                flow->l4.tcp.http_stage = 1;
            }else{
                /* check for url here */
                filename_start = http_request_url_offset(ipacket);
                if (filename_start != 0 && packet->parsed_lines > 1 && packet->line[0].len >= (9 + filename_start)
                        && mmt_memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {
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
            }
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
            mmt_classify_http(ipacket, index);
    }
    return 4;
}
#endif
