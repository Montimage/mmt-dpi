#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include "llhttp.h"
#include "mmt_core.h"

/**
 * Defines an HTTP parser structure. Two seperate parsers are needed.
 * One parser for Client -> Server communication and the second for
 * Server -> Client communications.
 **/
typedef struct
{
  llhttp_t parser[2]; /** Array of two HTTP parsers. **/
} stream_parser_t;

/**
 * Defines an internal temporary HTTP parsing processing store.
 * This structure ill be attached to the HTTP parser and serves 
 * to hold extracted header field/value. 
 * New header/field will flush the older one. This MUST not be 
 * used for any other reason than holding temporary data. The data
 * should be considered stale when the corresponding event (header value)
 * is fired. 
 **/
typedef struct 
{
  // char hfield[1024]; /**> temporary store for header field **/
  // char hvalue[16 * 1024]; /**> temporary store for header value **/
  char *hfield; /**> temporary store for header field **/
  char *hvalue; /**> temporary store for header value **/
  int hfield_valid; /**> 0 when hfield does not hold the name of the value being
                    parsed — set by header_field_cb, cleared when the pair is
                    consumed or when storing the field failed, so a stale field
                    name is never paired with a new value (issue #204,
                    F-BUG-056) **/
  int index; /**> index of the current protocol in the protocol path **/
  ipacket_t * ipacket; /**> pointer to the ipacket under processing **/ 
  int upgrade_offered; /**> 1 once this direction's 101 Switching Protocols was
                       offered to the upgrade classifiers (issue #116) **/
} stream_processor_t;

/**
 * Returns a pointer to the HTTP parser settings.
 * The settings is a pointer to an array of callbacks
 * for specific HTTP events.
 **/
const llhttp_settings_t * get_settings();

/**
 * Initializes internal HTTP parsing processor store.
 **/
inline static void * init_stream_processor()
{
  stream_processor_t * sp = (stream_processor_t *) mmt_malloc( sizeof( stream_processor_t ) );
  if(sp!=NULL){
    sp->hvalue = NULL;
    sp->hfield = NULL;
    sp->hfield_valid = 0;
    sp->upgrade_offered = 0;
  }
  return (void *) sp;
}

/**
 * Frees an internal HTTP parsing processor store.
 **/
inline static void * close_stream_processor(stream_processor_t * sp) {
  // Issue #20 (M5): hfield/hvalue are now allocated via mmt_realloc(), so they
  // must be released with mmt_free() (reconciled malloc/free -> mmt_*).
  if(sp->hfield!=NULL) mmt_free(sp->hfield);
  if(sp->hvalue!=NULL) mmt_free(sp->hvalue);
  mmt_free( sp );
  return NULL;
}

inline static void * close_http_parser(stream_parser_t * sp);

/**
 * Initializes an HTTP stream parser and returns a pointer to the initialized structure,
 * or NULL when an allocation failed (nothing is left allocated then).
 **/
inline static stream_parser_t * init_http_parser() {
  // printf("[HTTP_PARSER] init_http_parser\n");
  stream_parser_t * parser = (stream_parser_t *) mmt_malloc(sizeof(stream_parser_t));
  /* Issue #505 (F-BUG-015): mmt_malloc() returns NULL on OOM (memory.c:8-17).
   * Fail as a whole — the session keeps session_data NULL, which
   * http_internal_session_data_analysis() already skips. */
  if (parser == NULL) return NULL;
  /* llhttp_init() zeroes the whole parser struct (issue #222): data must be
   * assigned AFTER init, and the settings table is bound at init time —
   * get_settings() returns a static object that outlives every parser. */
  llhttp_init(& parser->parser[0], HTTP_BOTH, get_settings());
  llhttp_init(& parser->parser[1], HTTP_BOTH, get_settings());
  parser->parser[0].data = init_stream_processor();
  parser->parser[1].data = init_stream_processor();
  if (parser->parser[0].data == NULL || parser->parser[1].data == NULL)
    return (stream_parser_t *) close_http_parser(parser); /* frees what was made, returns NULL */
  return parser;
}

/**
 * Frees an HTTP stream parser structure.
 **/
inline static void * close_http_parser(stream_parser_t * sp) {
  // printf("[HTTP_PARSER] close_http_parser\n");
  if( sp->parser[0].data ) sp->parser[0].data = close_stream_processor(sp->parser[0].data);
  if( sp->parser[1].data ) sp->parser[1].data = close_stream_processor(sp->parser[1].data);
  mmt_free( sp );
  return NULL;
}


/**
 * Issue #116: called where llhttp reports an upgrade
 * (http_internal_session_data_analysis()). On the response that answers an
 * Upgrade request with 101 Switching Protocols, HTTP offers the session once
 * to the upgrade classifiers registered for PROTO_HTTP; one that claims it
 * calls mmt_session_handover(). llhttp is not resumed: after an upgrade both
 * parsers stay paused as before, so a refused upgrade (another status, or
 * no classifier claiming it) leaves HTTP's output unchanged. The paused
 * parser keeps returning HPE_PAUSED_UPGRADE, hence the once-only flag.
 **/
inline static void mmt_http_offer_upgrade(ipacket_t * ipacket, unsigned index, llhttp_t * parser, llhttp_errno_t err) {
  stream_processor_t * sp = (stream_processor_t *) parser->data;
  if (err != HPE_PAUSED_UPGRADE || sp == NULL || sp->upgrade_offered) return;
  if (llhttp_get_type(parser) != HTTP_RESPONSE || llhttp_get_status_code(parser) != 101) return;
  sp->upgrade_offered = 1;
  (void) mmt_session_offer_upgrade(ipacket, index);
}
