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
#include <stdarg.h>
#include <htmlstreamparser.h>
#include "zlib.h"

/**
 * HTTP content processing structure
 */
typedef struct 
{
  int status; //indicates if we can process data or not, not used but can be if we wish to limit processing to one direction client-> server or server->client
  int interaction_count; //number of HTTP messages seen on the same session
  int content_type; //set to 1 if the content type is html
  int content_encoding; //set to 1 if the content encoding is gzip
  void * pre_processor; //opaque pointer to the pre-processor (in this case gzip parser)
  void * processor; //opaque pointer to the processor (in this case: html parse)
} http_content_processor_t;

/**
 * HTML stream parser structure
 */
typedef struct
{
  char tag[64]; //last detected HTML tag
  char attr[64]; //last detected HTML tag attribute
  char val[2048 + 1]; //last detected tag attribute calue
  HTMLSTREAMPARSER * hsp; //html stream parser handler
} html_parser_t;

// MAX chunk size
#define CHUNK 16384

/**
 * GZIP stream processor structure
 */
typedef struct 
{
  int ret; //status
  unsigned char out[CHUNK]; //decompression output
  z_stream strm; //gzip stream 
} gzip_processor_t;

/**
 * copies into @fname the file name given session identifier and interaction count
 */
inline static int get_file_name(char * fname, int len, int session_id, int count) {
  return snprintf(fname, len, "file_%i_%i", session_id, count);
}

/**
 * Returns a positive value if @found starts with @expected, 0 otherwise
 */
inline static int check_str_eq (const char *expected, const char *found) {
  if ((expected == NULL) != (found == NULL)) {
    return 0;
  }

  if (strlen(expected) > strlen(found)) return 0;

  int len = strlen(expected);
  for (; len > 0; expected ++, found++) {
    int d = tolower(*expected) - tolower(*found);
    len --;
    if (d != 0)
      return 0;
  }
  return 1;
}

/**
 * Initializes the HTML parser structure and handler
 */
inline static void * init_html_parser() {
  html_parser_t * hp = (html_parser_t *) calloc( 1, sizeof(html_parser_t));
  hp->hsp = html_parser_init();

  html_parser_set_tag_to_lower(hp->hsp, 1);
  html_parser_set_attr_to_lower(hp->hsp, 1);
  html_parser_set_tag_buffer(hp->hsp, hp->tag, sizeof(hp->tag));
  html_parser_set_attr_buffer(hp->hsp, hp->attr, sizeof(hp->attr));
  html_parser_set_val_buffer(hp->hsp, hp->val, sizeof(hp->val)-1);

  return (void *) hp;
}

/**
 * Resets the HTML parser
 */
inline static void reset_html_parser(html_parser_t * hp) {
  html_parser_reset(hp->hsp);
}

/**
 * Sends a data chunk for processing by the html parser
 */
void html_parse(const char * chunck, size_t len, html_parser_t * hp, http_content_processor_t * sp);

/**
 * Closes and cleans the HTML parser
 */
inline static void * clean_html_parser(html_parser_t * hp) {
  if( hp == NULL) return NULL;
  html_parser_cleanup(hp->hsp);
  free (hp);
  return NULL;
}

/**
 * Initializes the GZIP processor. See zlib library for initialization options.
 */
inline static void * init_gzip_processor() {
  gzip_processor_t * gzp = (gzip_processor_t *) calloc( 1, sizeof( gzip_processor_t ) );
  gzp->strm.zalloc = Z_NULL;
  gzp->strm.zfree = Z_NULL;
  gzp->strm.opaque = Z_NULL;
  gzp->strm.avail_in = 0;
  gzp->strm.next_in = Z_NULL;
  gzp->ret = inflateInit2(& gzp->strm, 16+MAX_WBITS);
  if (gzp->ret != Z_OK) {
    free( gzp );
    return NULL;
  }
  return gzp;
}

/**
 * Sends a data chunk for processing by the gzip processor
 */
void gzip_process( const char * chunck, size_t len, gzip_processor_t * hp, http_content_processor_t * sp );

/**
 * Cleans and closes the GZIP processor
 */
inline static void * clean_gzip_processor( gzip_processor_t * gzp ) {
  if( gzp == NULL ) return NULL;
  (void)inflateEnd(& gzp->strm);
  free( gzp );
  return NULL;
}

/**
 * Initializes the HTTP content processing structure
 */
inline static void * init_http_content_processor()
{
  http_content_processor_t * sp = (http_content_processor_t *) calloc( 1, sizeof( http_content_processor_t ) );
  return (void *) sp;
}

/**
 * Cleans and closes the HTTP content processing structure
 */
inline static void * close_http_content_processor(http_content_processor_t * sp) {
  if( sp->processor ) sp->processor = clean_html_parser( (html_parser_t *) sp->processor );
  if( sp->pre_processor ) clean_gzip_processor( (gzip_processor_t *) sp->pre_processor);


  sp->content_type = 0;
  sp->content_encoding = 0;

  free( sp );
  return NULL;
}

/**
 * Cleans the HTTP content processing structure. It will be ready for processing another HTTP message
 * after this method is called.
 */
inline static void clean_http_content_processor(http_content_processor_t * sp) {
  if( sp->content_type ) sp->processor = clean_html_parser( (html_parser_t *) sp->processor );
  if( sp->content_encoding ) sp->pre_processor = clean_gzip_processor( (gzip_processor_t *) sp->pre_processor);


  sp->content_type = 0;
  sp->content_encoding = 0;
  sp->status = 0;
  sp->interaction_count += 1;
}

/**
 * Writes @len bytes from @content to the filename @path.
 */
int write_data_to_file (const char * path, const char * content, size_t len);

