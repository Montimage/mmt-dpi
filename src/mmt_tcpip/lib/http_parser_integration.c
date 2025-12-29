#include "http_parser_integration.h"
#include "mmt_common_internal_include.h"
#include <assert.h>

/**
 * Callback function that will be called when the HTTP parser
 * starts parsing an HTTP message. This is the first callback
 * to be called.
 **/
int message_begin_cb (http_parser *p)
{
  int end = 1; // Just to return a positive value :)
  stream_processor_t * sp = (stream_processor_t *) p->data;
  // if (sp) printf("Start a HTTP message: %lu, %d \n", ((ipacket_t *)sp->ipacket)->packet_id, sp->index);
  fire_attribute_event(sp->ipacket, PROTO_HTTP, HTTP_MESSAGE_START, sp->index, (void *) &end);
  //fprintf(stdout, "Message Begin CB called\n");
  return 0;
}

/**
 * Callback function that will be called when the HTTP parser
 * detected a header field. We copy this header field into the
 * temporary processing store to keep trace of it waiting for
 * the header value.
 **/
int header_field_cb (http_parser *p, const char *buf, size_t len)
{
  stream_processor_t * sp = (stream_processor_t *) p->data;

  // if(len>=1024){
  //   fprintf(stderr, "[error] Header field length is too big: %zu - %s\n", len,buf);
  //   return 0;
  // }
  if(sp->hfield!=NULL){
    free(sp->hfield);
  }
  sp->hfield = malloc((len+1)*sizeof(char));
  if(sp->hfield == NULL) return 0;
  strncpy(sp->hfield, buf, len);
  sp->hfield[len] = '\0';
  //fprintf(stdout, "Header: %s : ", sp->hfield);
  return 0;
}

/**
 * Callback function that will be called when the HTTP parser
 * detected a header value. We copy this header value into the
 * temporary processing store before firing an event into MMT.
 **/
int header_value_cb (http_parser *p, const char *buf, size_t len)
{
  stream_processor_t * sp = (stream_processor_t *) p->data;
  if(sp->hvalue!=NULL){
    free(sp->hvalue);
  }
  sp->hvalue = malloc((len+1)*sizeof(char));
  if (sp->hvalue == NULL)
    return 0;
  strncpy(sp->hvalue, buf, len);
  sp->hvalue[len] = '\0';

  mmt_generic_header_line_t hdr; // Just to return a positive value :)
  hdr.hfield = sp->hfield;
  hdr.hvalue = sp->hvalue;
  // if (sp) printf("Start a found a HEADER: %lu, %d \n", ((ipacket_t *)sp->ipacket)->packet_id, sp->index);
  fire_attribute_event(sp->ipacket, PROTO_HTTP, HTTP_HEADER, sp->index, (void *) &hdr);
  return 0;
}

/**
 * Callback function that will be called when the HTTP parser
 * detected a URL of an HTTP request.
 **/
int request_url_cb (http_parser *p, const char *buf, size_t len)
{
  // char temp[20408 + 1];
  // char *temp;
  // temp = malloc((len+1)*sizeof(char));
  // strncpy(temp, buf, len);
  // temp[len] = '\0';
  //fprintf(stdout, "URL: %s\n", temp);
  // fire_attribute_event(sp->ipacket, PROTO_HTTP, HTTP_HEADER, sp->index, (void *) &temp);
  stream_processor_t * sp = (stream_processor_t *) p->data;
  // if (sp) printf("Start a HTTP request: %lu, %d \n", ((ipacket_t *)sp->ipacket)->packet_id, sp->index);
  return 0;
}

int response_status_cb (http_parser *p, const char *buf, size_t len)
{
  // char *temp;
  // temp = malloc((len+1)*sizeof(char));
  // strncpy(temp, buf, len);
  // temp[len] = '\0';
  // printf("Status: %s\n", temp);
  stream_processor_t * sp = (stream_processor_t *) p->data;
  // if (sp) printf("Start a HTTP response: %lu, %d \n", ((ipacket_t *)sp->ipacket)->packet_id, sp->index);
  return 0;
}

/**
 * Callback function that will be called when the HTTP parser
 * detects a new HTTP data chunk. The parser will not
 * reconstruct data, it is up to the user to reconstruct data
 * if this is useful for her application.
 **/
int count_body_cb (http_parser *p, const char *buf, size_t len)
{
  mmt_header_line_t attr;
  stream_processor_t * sp = (stream_processor_t *) p->data;
  attr.len = len;
  attr.ptr = buf;
  fire_attribute_event(sp->ipacket, PROTO_HTTP, HTTP_DATA, sp->index, (void *) &attr);

  //fprintf(stdout, "Body CB called --- %u\n", len);
  //check_body_is_final(p);

  return 0;
}

/**
 * Callback function that will be called when the HTTP parser
 * finishes parsing the headers. This will be called once per
 * HTTP request or response, and it will be just before the
 * body callback if there is any data.
 **/
int headers_complete_cb (http_parser *p)
{
  int end = 1; // Just to return a positive value :)
  stream_processor_t * sp = (stream_processor_t *) p->data;
  fire_attribute_event(sp->ipacket, PROTO_HTTP, HTTP_HEADERS_END, sp->index, (void *) &end);
  //fprintf(stdout, "Headers complete CB calledi\n");
  //http_should_keep_alive(parser);

  return 0;
}

/**
 * Callback function that will be called when the HTTP parser
 * detects the end of a message. This will be called once per
 * HTTP message and it will be the last callback. This is
 * useful when the user is reconstructing message data for
 * instance.
 **/
int message_complete_cb (http_parser *p)
{
  int end = 1; // Just to return a positive value :)
  stream_processor_t * sp = (stream_processor_t *) p->data;
  // if (sp) printf("End of a HTTP message: %lu, %d \n", ((ipacket_t *)sp->ipacket)->packet_id, sp->index);
  fire_attribute_event(sp->ipacket, PROTO_HTTP, HTTP_MESSAGE_END, sp->index, (void *) &end);
  //fprintf(stdout, "Message Complete CB calledi\n");

  return 0;
}

/**
 * Array of HTTP parser callbacks.
 **/
static http_parser_settings settings =
{
  .on_header_field = header_field_cb
  ,.on_message_begin = message_begin_cb
  ,.on_header_value = header_value_cb
  ,.on_url = request_url_cb
  ,.on_status = response_status_cb
  ,.on_body = count_body_cb
  ,.on_headers_complete = headers_complete_cb
  ,.on_message_complete = message_complete_cb
};

/** Returns a pointer to the HTTP parser settings (callback array) **/
http_parser_settings * get_settings() {
  return & settings;
}
