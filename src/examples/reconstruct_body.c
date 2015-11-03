#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "mmt_core.h"
#include "html_integration.h" 
#include <assert.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)

/** Dependencies
 *  HTML parser
 *    git clone https://github.com/luongnv89/htmlstreamparser.git
 *    cd htmlstreamparser/
 *    ./configure 
 *    make 
 *    sudo make install
 *
 *  zlib
 *    sudo apt-get install zlib1g zlib1g-dev
 */

// COMPILE with
// gcc -g -o reconstruct_body reconstruct_body.c html_integration.c -lmmt_core -ldl -lpcap -lhtmlstreamparser -lz -lpthread

//TODOs: content reconstruction
// - add user data at session detection - OK
// - check it content encoding is gzip, and initialize gzip decoder if yes - OK
// - initialize (including creating the file) reconstruction at headers end event - OK
// - reconstruct into the initialized file handler at http.data events - OK
// - close file handler and gzip decoder (if any) at message end event, and cleanup reconstruction - OK
// - cleanup and free user data at session expiry - OK


//TODOs: html parsing
// - add user data at session detection - OK
// - check if content type is text/html and initialize html parser - OK
// - check it content encoding is gzip, and initialize gzip decoder if yes - OK
// - initialize processing at headers end event - OK
// - process data chunk at http.data events - OK
// - close html parser and gzip decoder (if any) and cleanup at message end event - OK
// - cleanup and free user data at session expiry - OK

/**
 * Prints the usage help instructions
 */
void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/**
 * Parses command line options and performes pre-initialization
 */
void parseOptions(int argc, char ** argv, char * filename, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:h")) != EOF) {
        switch (opt) {
            case 't':
                optcount++;
                if (optcount > 1) {
                    usage(argv[0]);
                }
                strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
                *type = TRACE_FILE;
                break;
            case 'i':
                optcount++;
                if (optcount > 1) {
                    usage(argv[0]);
                }
                strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
                *type = LIVE_INTERFACE;
                break;
            case 'h':
            default: usage(argv[0]);
        }
    }

    if (filename == NULL || strcmp(filename, "") == 0) {
        if (*type == TRACE_FILE) {
            fprintf(stderr, "Missing trace file name\n");
        }
        if (*type == LIVE_INTERFACE) {
            fprintf(stderr, "Missing network interface name\n");
        }
        usage(argv[0]);
    }
    return;
}

/**
 * Attribute handle for IP new sessions.
 * Will be called every time a new session is detected.
 * Initializes an HTTP content processing structure and attaches it
 * to the MMT session.
 */
void new_session_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    mmt_session_t * session = get_session_from_packet(ipacket);
    if(session == NULL) return;

    if (attribute->data == NULL) {
        return; //This should never happen! check it anyway
    }

    http_content_processor_t * temp_session = init_http_content_processor();

    if (temp_session == NULL) {
        return;
    }

    set_user_session_context(session, temp_session);
}

/**
 * Attribute handler that will be called every time an HTTP message start event is detected
 */
void http_message_start_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    printf("%s.%s: %i\n",
      get_protocol_name_by_id(attribute->proto_id),
      get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
      *((uint32_t *) attribute->data)
    );
}

/**
 * Attribute handler that will be called every time an HTTP header is detected
 * Checks if the content encoding iz gzip to initialize the gzip pre processor
 * and checks if the content type is htmp to initialize the html parser
 */
void generic_header_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    mmt_session_t * session = get_session_from_packet(ipacket);
    if(session == NULL) return;
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if(sp == NULL) return;

    if( check_str_eq( "Content-Encoding", ((mmt_generic_header_line_t *) attribute->data)->hfield) &&
        check_str_eq( "gzip", ((mmt_generic_header_line_t *) attribute->data)->hvalue) ) {
      sp->content_encoding = 1; //Content encoding is gzip
    }

    if( check_str_eq( "Content-Type", ((mmt_generic_header_line_t *) attribute->data)->hfield) &&
        check_str_eq( "text/html", ((mmt_generic_header_line_t *) attribute->data)->hvalue)) {
      sp->content_type = 1; // Content type is html 
    }

    printf("%s.%s: %s: %s\n", 
      get_protocol_name_by_id(attribute->proto_id),
      get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
      ((mmt_generic_header_line_t *) attribute->data)->hfield,
      ((mmt_generic_header_line_t *) attribute->data)->hvalue
    );
}

/**
 * Attribute handler that will be called every time HTTP en of headers is detected
 * Initializes the gzip pre processor and the html parser if content encoding is gzip
 * and content type is html respectively.
 */
void http_headers_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    mmt_session_t * session = get_session_from_packet(ipacket);
    if(session == NULL) return;

    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if(sp == NULL) return;

    if( sp->content_encoding == 1 ) sp->pre_processor = (void *) init_gzip_processor();

    if( sp->content_type == 1 ) sp->processor = (void *) init_html_parser();

    printf("%s.%s: %i\n",
      get_protocol_name_by_id(attribute->proto_id),
      get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
      *((uint32_t *) attribute->data)
    );
}

/**
 * Attribute handle that will be called every time an HTTP message end is detected
 * Cleans up the HTTP content processing structure and prepares it to a new message eventually. 
 */
void http_message_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    mmt_session_t * session = get_session_from_packet(ipacket);
    if(session == NULL) return;

    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if(sp == NULL) return;

    clean_http_content_processor(sp);

    printf("%s.%s: %i\n",
      get_protocol_name_by_id(attribute->proto_id),
      get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
      *((uint32_t *) attribute->data)
    );
}

/**
 * Attribute handle that will be called for every HTTP body data chunk
 * The chunk will be process to by the gzip pre processor if content encoding 
 * is gzip, then it will be processed by the html parser.
 * In all cases, the chunk will be saved into a file whose name containes the session ID
 * and the interaction number in the session to take into account keep alive HTTP sessions
 */
void data_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    mmt_session_t * session = get_session_from_packet(ipacket);

    char fname[128];

    if(session == NULL) return;

    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context_from_packet(ipacket);
    if(sp == NULL) return;

    //Process body
    if( sp->content_encoding ) {
      if( sp->pre_processor ) {
        gzip_processor_t * gzp = (gzip_processor_t *) sp->pre_processor;
        gzip_process(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, gzp, sp);
      }
    } else if( sp->content_type && sp->processor ) {
      html_parser_t * hp = (html_parser_t *) sp->processor;
      html_parse(((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len, hp, sp);
    }

    get_file_name(fname, 128, get_session_id(session), sp->interaction_count);

    write_data_to_file (fname, ((mmt_header_line_t *) attribute->data)->ptr, ((mmt_header_line_t *) attribute->data)->len);

    printf("%s.%s: %i\n",
      get_protocol_name_by_id(attribute->proto_id),
      get_attribute_name_by_protocol_and_attribute_ids(attribute->proto_id, attribute->field_id),
      ((mmt_header_line_t *) attribute->data)->len
    );
}

/**
 * Session expiry handler that will be called every time MMT core detects a session expiry
 * Close the HTTP content processing structure
 */
void classification_expiry_session(const mmt_session_t * expired_session, void * args) {
    //fprintf(stdout, "Test from expiry session\n");
    http_content_processor_t * sp = (http_content_processor_t *) get_user_session_context(expired_session);
    if (sp == NULL) return;

    sp = close_http_content_processor(sp);
}

/**
 * Pcap live capture callback
 */
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    if (!packet_process( mmt, &header, data )) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

int main(int argc, char** argv) {
    mmt_handler_t *mmt_handler;
    char mmt_errbuf[1024];

    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr p_pkthdr;
    char errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1];
    int type;

    struct pkthdr header;

    parseOptions(argc, argv, filename, &type);

    init_extraction();

    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }

    // Register attribute handlers
    register_attribute_handler_by_name(mmt_handler, "http", "msg_start", http_message_start_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "header", generic_header_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "headers_end", http_headers_end_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "data", data_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "http", "msg_end", http_message_end_handle, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "ip", "session", new_session_handle, NULL, NULL);

    // register session expiry handler
    register_session_timeout_handler(mmt_handler, classification_expiry_session, NULL);

    if (type == TRACE_FILE) {
        pcap = pcap_open_offline(filename, errbuf); // open offline trace
        if (!pcap) { /* pcap error ? */
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
    } else {
        pcap = pcap_open_live(filename, MTU_BIG, 1, 1000, errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }

    // We're done, close and cleanup
    mmt_close_handler(mmt_handler);

    close_extraction();

    pcap_close(pcap);

    return EXIT_SUCCESS;
}

