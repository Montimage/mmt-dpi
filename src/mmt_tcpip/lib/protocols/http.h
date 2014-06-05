/* 
 * File:   http.h
 * Author: montimage
 *
 * Created on 20 septembre 2011, 14:09
 */

#ifndef MMT_HTTP_H
#define	MMT_HTTP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"
#include "rfc2822utils.h"

enum {
    HTTP_NOHEADER = 0,
    HTTP_HOST,
    HTTP_USER_AGENT,
    HTTP_ACCEPT,
    HTTP_ACCEPT_Charset,
    HTTP_Accept_Encoding,
    HTTP_Accept_Language,
    HTTP_Authorization,
    HTTP_Expect,
    HTTP_From,
    HTTP_Date,
    HTTP_P3P,
    HTTP_Cache_Control,
    HTTP_Connection,
    HTTP_Transfer_Encoding,
    HTTP_DNT,
    HTTP_Cookie,
    HTTP_If_Match,
    HTTP_If_Modified_Since,
    HTTP_If_None_Match,
    HTTP_If_Range,
    HTTP_If_Unmodified_Since,
    HTTP_Max_Forwards,
    HTTP_Proxy_Authorization,
    HTTP_Range,
    HTTP_Referer,
    HTTP_TE,
    HTTP_Accept_Ranges,
    HTTP_Age,
    HTTP_ETag,
    HTTP_Location,
    HTTP_Proxy_Authenticate,
    HTTP_Retry_After,
    HTTP_Server,
    HTTP_Vary,
    HTTP_WWW_Authenticate,
    HTTP_Allow,
    HTTP_Content_Encoding,
    HTTP_Content_Language,
    HTTP_Content_Length,
    HTTP_Content_Location,
    HTTP_Content_MD5,
    HTTP_Content_Range,
    HTTP_Content_Type,
    HTTP_Expires,
    HTTP_Last_Modified,
    HTTP_SET_COOKIE,
    HTTP_SET_COOKIE2,
};

#define HTTP_HEADERS_NB HTTP_SET_COOKIE2

enum {
   HTTP_VERSION = HTTP_HEADERS_NB + 1,
   HTTP_TYPE,
   HTTP_METHOD,
   HTTP_RESPONSE,
   HTTP_URI,
   HTTP_Referer_URL,
   HTTP_RESPONSE_TIME,
   HTTP_Time_of_Request,
   HTTP_Time_of_response,
};

    //TODO: update this when the http attributes are defined
#define HTTP_ATTRIBUTES_NB HTTP_Time_of_response

#define HTTP_VERSION_LABEL "VERSION"
#define HTTP_TYPE_LABEL "TYPE"
#define HTTP_METHOD_LABEL "METHOD"
#define HTTP_RESPONSE_LABEL "RESPONSE"
#define HTTP_URI_LABEL "URI"
#define HTTP_Referer_URL_LABEL "REFERER_URI"
#define HTTP_RESPONSE_TIME_LABEL "RESPONSE_TIME"
#define HTTP_REQ_TIME_LABEL "REQ_TIME"
#define HTTP_RESP_TIME_LABEL "RESP_TIME"

#define HTTP_VERSION_SHORT_LABEL "version"
#define HTTP_TYPE_SHORT_LABEL "type"
#define HTTP_METHOD_SHORT_LABEL "method"
#define HTTP_RESPONSE_SHORT_LABEL "response"
#define HTTP_URI_SHORT_LABEL "uri"
#define HTTP_Referer_URL_SHORT_LABEL "ref_uri"
#define HTTP_RESPONSE_TIME_SHORT_LABEL "response_time"
#define HTTP_REQ_TIME_SHORT_LABEL "time_of_request"
#define HTTP_RESP_TIME_SHORT_LABEL "time_of_response"

    /**
     * HTTP versions (used to match against the first line of the
     * HTTP header as well as in the response code).
     */
#define MHD_HTTP_VERSION_0_9 "HTTP/0.9 "
#define MHD_HTTP_VERSION_1_0 "HTTP/1.0 "
#define MHD_HTTP_VERSION_1_1 "HTTP/1.1 "

    /**
     * HTTP request methods
     */

#define MMT_HTTP_GET_CODE       1
#define MMT_HTTP_POST_CODE      2
#define MMT_HTTP_OPTIONS_CODE   3
#define MMT_HTTP_HEAD_CODE      4
#define MMT_HTTP_PUT_CODE       5
#define MMT_HTTP_DELETE_CODE    6
#define MMT_HTTP_CONNECT_CODE   7
#define MMT_HTTP_PROPFIND_CODE  8
#define MMT_HTTP_REPORT_CODE    9

#define MMT_HTTP_GET            "GET "
#define MMT_HTTP_POST           "POST "
#define MMT_HTTP_OPTIONS        "OPTIONS "
#define MMT_HTTP_HEAD           "HEAD "
#define MMT_HTTP_PUT            "PUT "
#define MMT_HTTP_DELETE         "DELETE "
#define MMT_HTTP_CONNECT        "CONNECT "
#define MMT_HTTP_PROPFIND       "PROPFIND "
#define MMT_HTTP_REPORT         "REPORT "

#define MMT_HTTP_IS_VALID_METHOD( m ) \
    (((m) >= MMT_HTTP_GET_CODE) && ((m) <= MMT_HTTP_REPORT_CODE))

    /**
     * HTTP response codes.
     */

#define MMT_HTTP_CONTINUE 100
#define MMT_HTTP_SWITCHING_PROTOCOLS 101
#define MMT_HTTP_PROCESSING 102

#define MMT_HTTP_OK 200
#define MMT_HTTP_CREATED 201
#define MMT_HTTP_ACCEPTED 202
#define MMT_HTTP_NON_AUTHORITATIVE_INFORMATION 203
#define MMT_HTTP_NO_CONTENT 204
#define MMT_HTTP_RESET_CONTENT 205
#define MMT_HTTP_PARTIAL_CONTENT 206
#define MMT_HTTP_MULTI_STATUS 207

#define MMT_HTTP_MULTIPLE_CHOICES 300
#define MMT_HTTP_MOVED_PERMANENTLY 301
#define MMT_HTTP_FOUND 302
#define MMT_HTTP_SEE_OTHER 303
#define MMT_HTTP_NOT_MODIFIED 304
#define MMT_HTTP_USE_PROXY 305
#define MMT_HTTP_SWITCH_PROXY 306
#define MMT_HTTP_TEMPORARY_REDIRECT 307

#define MMT_HTTP_BAD_REQUEST 400
#define MMT_HTTP_UNAUTHORIZED 401
#define MMT_HTTP_PAYMENT_REQUIRED 402
#define MMT_HTTP_FORBIDDEN 403
#define MMT_HTTP_NOT_FOUND 404
#define MMT_HTTP_METHOD_NOT_ALLOWED 405
#define MMT_HTTP_METHOD_NOT_ACCEPTABLE 406
#define MMT_HTTP_PROXY_AUTHENTICATION_REQUIRED 407
#define MMT_HTTP_REQUEST_TIMEOUT 408
#define MMT_HTTP_CONFLICT 409
#define MMT_HTTP_GONE 410
#define MMT_HTTP_LENGTH_REQUIRED 411
#define MMT_HTTP_PRECONDITION_FAILED 412
#define MMT_HTTP_REQUEST_ENTITY_TOO_LARGE 413
#define MMT_HTTP_REQUEST_URI_TOO_LONG 414
#define MMT_HTTP_UNSUPPORTED_MEDIA_TYPE 415
#define MMT_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE 416
#define MMT_HTTP_EXPECTATION_FAILED 417
#define MMT_HTTP_UNPROCESSABLE_ENTITY 422
#define MMT_HTTP_LOCKED 423
#define MMT_HTTP_FAILED_DEPENDENCY 424
#define MMT_HTTP_UNORDERED_COLLECTION 425
#define MMT_HTTP_UPGRADE_REQUIRED 426
#define MMT_HTTP_RETRY_WITH 449

#define MMT_HTTP_INTERNAL_SERVER_ERROR 500
#define MMT_HTTP_NOT_IMPLEMENTED 501
#define MMT_HTTP_BAD_GATEWAY 502
#define MMT_HTTP_SERVICE_UNAVAILABLE 503
#define MMT_HTTP_GATEWAY_TIMEOUT 504
#define MMT_HTTP_HTTP_VERSION_NOT_SUPPORTED 505
#define MMT_HTTP_VARIANT_ALSO_NEGOTIATES 506
#define MMT_HTTP_INSUFFICIENT_STORAGE 507
#define MMT_HTTP_BANDWIDTH_LIMIT_EXCEEDED 509
#define MMT_HTTP_NOT_EXTENDED 510

struct http_session_data_struct {
    int type; /**< indicates if this is a REQUEST or RESPONSE */
    char * http_version;
    char * requested_uri;
    char * http_code_reason;
    int http_code;
    int http_method;
    field_value_t session_field_values[HTTP_HEADERS_NB];
};

void mmt_init_classify_me_http();
int init_http_proto_struct();
int init_http_proto_struct_new();

#ifdef	__cplusplus
}
#endif

#endif	/* MMT_HTTP_H */

