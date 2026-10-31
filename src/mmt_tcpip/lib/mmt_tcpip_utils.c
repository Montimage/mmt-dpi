#include "mmt_common_internal_include.h"

uint32_t mmt_bytestream_to_number(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint32_t val;
    val = 0;
    // cancel if eof, ' ' or line end chars are reached
    /* Issue #201 (F-BUG-024): check the byte budget BEFORE dereferencing *str —
     * the old order read one byte past the captured buffer when
     * max_chars_to_read == 0. */
    while (max_chars_to_read > 0 && *str >= '0' && *str <= '9') {
        val *= 10;
        val += *str - '0';
        str++;
        max_chars_to_read = max_chars_to_read - 1;
        *bytes_read = *bytes_read + 1;
    }
    return (val);
}

uint32_t mmt_bytestream_to_ipv4(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint32_t val;
    uint16_t read = 0;
    uint16_t oldread;
    uint32_t c;
    /* ip address must be X.X.X.X with each X between 0 and 255 */
    /* Issue #502 (F-BUG-106): every str[read] below is preceded by its own
     * `read >= max_chars_to_read` bound — the dereference no longer relies on
     * an `==` disjunct short-circuiting earlier in the same condition. */
    oldread = read;
    c = mmt_bytestream_to_number(str, max_chars_to_read, &read);
    if (c > 255 || oldread == read || read >= max_chars_to_read)
        return 0;
    if (str[read] != '.')
        return 0;
    read++;
    val = c << 24;
    oldread = read;
    c = mmt_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
    if (c > 255 || oldread == read || read >= max_chars_to_read)
        return 0;
    if (str[read] != '.')
        return 0;
    read++;
    val = val + (c << 16);
    oldread = read;
    c = mmt_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
    if (c > 255 || oldread == read || read >= max_chars_to_read)
        return 0;
    if (str[read] != '.')
        return 0;
    read++;
    val = val + (c << 8);
    oldread = read;
    c = mmt_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
    if (c > 255 || oldread == read || read >= max_chars_to_read)
        return 0;
    val = val + c;

    *bytes_read = *bytes_read + read;

    return htonl(val);
}

/* Issue #547: the per-call reset of _mmt_parse_packet_line_info() — every
 * header field it can set starts empty and line 0 starts at the payload. */
static void parse_line_info_reset(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    packet->packet_lines_parsed_complete = 1;
    packet->parsed_lines = 0;

    packet->empty_line_position_set = 0;
    packet->empty_line_position = 0;

    /* Attribute need to extract for classification */
    packet->host_line.ptr = NULL; // Need for classification
    packet->host_line.len = 0;
    packet->referer_line.ptr = NULL; // Need for classification
    packet->referer_line.len = 0;
    packet->content_line.ptr = NULL;// Need for classification
    packet->content_line.len = 0;
    packet->accept_line.ptr = NULL; // Need for classification
    packet->accept_line.len = 0;
    packet->user_agent_line.ptr = NULL; // Need for classification
    packet->user_agent_line.len = 0;
    packet->http_url_name.ptr = NULL; // Need for classification
    packet->http_url_name.len = 0;
    packet->server_line.ptr = NULL; // Need for classification
    packet->server_line.len = 0;
    packet->http_response.ptr = NULL; // Need for classification
    packet->http_response.len = 0;

    /* Attribute need to extract only for information*/
    packet->upgrade_line.ptr = NULL;
    packet->upgrade_line.len = 0;
    packet->connection_line.ptr = NULL;
    packet->connection_line.len = 0;
    // End of LN
    packet->http_encoding.ptr = NULL;
    packet->http_encoding.len = 0;
    packet->http_transfer_encoding.ptr = NULL;
    packet->http_transfer_encoding.len = 0;
    packet->http_contentlen.ptr = NULL;
    packet->http_contentlen.len = 0;
    packet->http_cookie.ptr = NULL;
    packet->http_cookie.len = 0;
    packet->http_x_session_type.ptr = NULL;
    packet->http_x_session_type.len = 0;

    packet->http_method.ptr = NULL;
    packet->http_method.len = 0;

    packet->has_x_cdn_hdr = 0;

    packet->line[packet->parsed_lines].ptr = packet->payload;
    packet->line[packet->parsed_lines].len = 0;
    packet->packet_id = ipacket->packet_id;
}

/* Issue #547: one non-empty header line of _mmt_parse_packet_line_info() —
 * records where the value of a recognised header (or the response status)
 * starts in str, a line_length-byte line of packet's payload. */
static void parse_line_info_header(struct mmt_tcpip_internal_packet_struct *packet,
        const uint8_t *str, uint16_t line_length) {
    /*
     * HTTP header-NAME matching is case-insensitive (issue #24 / M8).
     * RFC 7230 §3.2 defines field names as case-insensitive, so
     * lower- and mixed-case headers ("host:", "content-type:") must
     * be recognised exactly like their canonical-cased forms. We
     * dispatch on the upper-cased first byte and compare the rest of
     * the name with mmt_strncasecmp(). Value byte-offsets depend only
     * on the (case-independent) name length, so they are unchanged:
     * this only ADDS recognition of differently-cased headers and
     * never alters an already-matching header, so the classification
     * fingerprint is preserved. The response status line ("HTTP/1.x")
     * is always upper-case per RFC 7230 §3.1.2 and is kept byte-exact.
     */
    switch ( mmt_toupper(str[0]) ) {
    case 'H':
        if (str[0] == 'H' && str[1] == 'T') {
            if (packet->parsed_lines == 0 && line_length >= 9 && str[2] == 'T' && str[3] == 'P' && str[4] == '/' && str[5] == '1' && str[6] == '.') {
                // Start of response
                // printf("start RESPONSE: %lu, %lu\n", ipacket->session->session_id, packet->packet_id);
                packet->http_response.ptr = &str[9];
                packet->http_response.len = packet->line[0].len - 9;
            }
        } else if (mmt_strncasecmp((const char *)(str + 1), "ost:", 4) == 0) {
            if (str[5] == ' ') {
                packet->host_line.ptr = &str[6];
                packet->host_line.len = line_length - 6;
            } else {
                packet->host_line.ptr = &str[5];
                packet->host_line.len = line_length - 5;
            }
        }
        break;
    case 'S':
        if (
            mmt_strncasecmp((const char *)(str + 1), "erver:", 6) == 0)
        {
            if (str[7] == ' ') {
                packet->server_line.ptr = &str[8];
                packet->server_line.len = line_length - 8;
            } else {
                packet->server_line.ptr = &str[7];
                packet->server_line.len = line_length - 7;
            }
        }
        break;
    case 'C':
        // str[8] is the discriminating byte for the Content-*/Connection/
        // Cookie headers; guard the read so a truncated "C" line cannot
        // dereference past the parsed line (and its trailing CRLF).
        if (line_length < 9) {
            break;
        }
        switch ( mmt_toupper(str[8]) ) {
        case 'T':
            if (
                mmt_strncasecmp((const char *)(str + 1), "ontent-Type: ", 13) == 0) {
                packet->content_line.ptr = &str[14];
                packet->content_line.len = line_length - 14;
            }
            break;
        case 'E':
            if (
                mmt_strncasecmp((const char *)(str + 1), "ontent-Encoding: ", 17) == 0) {
                packet->http_encoding.ptr = &str[18];
                packet->http_encoding.len = line_length - 18;
            }
            break;
        case 'L':
            if (
                (mmt_strncasecmp((const char *)(str + 1), "ontent-Length: ", 15) == 0) ) {
                packet->http_contentlen.ptr = &str[16];
                packet->http_contentlen.len = line_length - 16;
            }
            break;
        case 'O':
            if (
                (mmt_strncasecmp((const char *)(str + 1), "onnection: ", 11) == 0)) {
                packet->connection_line.ptr = &str[12];
                packet->connection_line.len = line_length - 12;
            }
            break;
        default:
            if (
                mmt_strncasecmp((const char *)(str + 1), "ookie: ", 7) == 0) {
                packet->http_cookie.ptr = &str[8];
                packet->http_cookie.len = line_length - 8;
            }
            break;
        }
        break;
    case 'A':
        if (
            mmt_strncasecmp((const char *)(str + 1), "ccept: ", 7) == 0)
        {
            packet->accept_line.ptr = &str[8];
            packet->accept_line.len = line_length - 8;
        }
        break;

    case 'R':
        if (
            mmt_strncasecmp((const char *)(str + 1), "eferer: ", 8) == 0)
        {
            packet->referer_line.ptr = &str[9];
            packet->referer_line.len = line_length - 9;
        }
        break;
    case 'U':
        if (mmt_toupper(str[1]) == 'S') {
            if (
                (mmt_strncasecmp((const char *)(str + 2), "er-Agent: ", 10) == 0))
            {
                packet->user_agent_line.ptr = &str[12];
                packet->user_agent_line.len = line_length - 12;
            }
        } else if (mmt_toupper(str[1]) == 'P') {
            if (
                (mmt_strncasecmp((const char *)(str + 2), "grade: ", 7) == 0))
            {
                packet->upgrade_line.ptr = &str[9];
                packet->upgrade_line.len = line_length - 9;
            }
        }
        break;
    case 'T':
        if (
            mmt_strncasecmp((const char *)(str + 1), "ransfer-Encoding: ", 18) == 0) {
            packet->http_transfer_encoding.ptr = &str[19];
            packet->http_transfer_encoding.len = line_length - 19;
        }

        break;
    case 'X':
        if (
            mmt_strncasecmp((const char *)(str + 1), "-Session-Type: ", 15) == 0) {
            packet->http_x_session_type.ptr = &str[16];
            packet->http_x_session_type.len = line_length - 16;
        } else if (
            mmt_strncasecmp((const char *)(str + 1), "-CDN", 4) == 0) {
            packet->has_x_cdn_hdr = 1;
        }
        break;
    default:
        break;
    }// End of switch
}

void _mmt_parse_packet_line_info(ipacket_t * ipacket){
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* Issue #212 (F-BUG-043): this helper is exported and computes
     * payload_packet_len - 1 below — on a zero-length payload that uint16
     * underflowed to 65535 and the line loop read out of bounds. The only
     * in-tree caller (mmt_parse_packet_line_info) already guards, but the
     * guard belongs here for direct callers. */
    if ( unlikely( packet->payload_packet_len == 0 ))
        return;

    uint32_t a;
    uint16_t line_length;
    const uint8_t *str;

    uint16_t end = packet->payload_packet_len - 1;

    parse_line_info_reset(ipacket);

    for (a = 0; likely( a < end ); a++) {
        /* Issue #558: jump to the next CR with memchr() instead of testing
         * every byte; a payload without one (binary data) ends the scan.
         * The CRLF test stays byte-wise: the previous get_u16() read a uint16
         * at an attacker-controlled (often odd) offset, which is an unaligned
         * load (ctype/alignment UB). Comparing the two bytes individually is
         * endian-independent and alignment-safe. Both bytes are in bounds:
         * memchr() searches [a, end) only (end == payload_packet_len - 1), so
         * the CR found is at a < end and a + 1 <= payload_packet_len - 1. */
        const uint8_t *cr = (const uint8_t *) memchr(&packet->payload[a], 0x0d, end - a);
        if ( cr == NULL )
            break;
        a = (uint32_t) (cr - packet->payload);
        if ( packet->payload[a + 1] == 0x0a ) {

            line_length =  &packet->payload[a] - packet->line[packet->parsed_lines].ptr;
            packet->line[packet->parsed_lines].len = line_length;

            if ( unlikely( line_length == 0 )) {
                packet->empty_line_position     = a;
                packet->empty_line_position_set = 1;
            } else {

                str = packet->line[packet->parsed_lines].ptr;
                parse_line_info_header(packet, str, line_length);
            }// End of unlikely( line_length == 0 )
            if ( unlikely( packet->parsed_lines >= (MMT_MAX_PARSE_LINES_PER_PACKET - 1))) {
                return;
            }

            packet->parsed_lines++;
            packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
            packet->line[packet->parsed_lines].len = 0;

            if ( packet->empty_line_position != 0 || (a + 2) >= packet->payload_packet_len ) {
                return;
            }
        } // End of CRLF match (payload[a] == 0x0d && payload[a + 1] == 0x0a)
    }// End of for loop
    if (packet->parsed_lines > 0) {
        packet->line[packet->parsed_lines].len =
            &packet->payload[packet->payload_packet_len] - packet->line[packet->parsed_lines].ptr;
        packet->parsed_lines++;
    }
}

/* internal function for every detection to parse one packet and to increase the info buffer */
void mmt_parse_packet_line_info(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if ( unlikely( packet->payload_packet_len == 0 ))
        return;

    if (packet->packet_lines_parsed_complete != 0)
        return;
    _mmt_parse_packet_line_info(ipacket);

}

void mmt_parse_packet_line_info_unix(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint32_t a;
    uint16_t end = packet->payload_packet_len;
    if (packet->packet_unix_lines_parsed_complete != 0)
        return;

    packet->packet_unix_lines_parsed_complete = 1;
    packet->parsed_unix_lines = 0;

    if (packet->payload_packet_len == 0)
        return;

    packet->unix_line[packet->parsed_unix_lines].ptr = packet->payload;
    packet->unix_line[packet->parsed_unix_lines].len = 0;

    for (a = 0; a < end; a++) {
        if (packet->payload[a] == 0x0a) {
            packet->unix_line[packet->parsed_unix_lines].len =
                &packet->payload[a] - packet->unix_line[packet->parsed_unix_lines].ptr;

            if (packet->parsed_unix_lines >= (MMT_MAX_PARSE_LINES_PER_PACKET - 1)) {
                break;
            }

            packet->parsed_unix_lines++;
            packet->unix_line[packet->parsed_unix_lines].ptr = &packet->payload[a + 1];
            packet->unix_line[packet->parsed_unix_lines].len = 0;

            if ((a + 1) >= packet->payload_packet_len) {
                break;
            }
            //a++;
        }
    }
}

#define is_minus( x )  (x >='a'&& x<='z')
#define is_majus( x )  (x>='A' && x<='Z')
#define is_number( x ) (x>='0' && x<='9')
#define is_separa( x)  (x==' ' || x==';')
#define is_letter( x ) (is_minus(x) || is_majus(x) || is_number(x) || x == '-' || x == '_')


uint16_t mmt_check_for_email_address(ipacket_t * ipacket, uint16_t counter) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    bool is_exist = false;

    //a.Nghia8.Nguyen@montimage.eu.fr
    //a
    if ( counter < packet->payload_packet_len && is_letter( packet->payload[counter] ) ) {
        counter++;
        //.Nghia8.Nguyen
        while ( packet->payload_packet_len > counter  &&
                (is_letter( packet->payload[counter] ) || packet->payload[counter] == '.') ) {
            counter ++;
        }

        //@
        if (packet->payload_packet_len > counter && packet->payload[counter] == '@') {
            counter++;

            //montimage
            is_exist = false;
            while ( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ) {
                counter ++;
                is_exist = true;
            }

            //.
            if ( is_exist && packet->payload_packet_len > counter && packet->payload[counter] == '.') {
                counter++;

                //com
                is_exist = false;
                while ( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ) {
                    counter ++;
                    is_exist = true;
                }

                //optional: .xxx.net.fr
                while ( is_exist && packet->payload_packet_len > counter && packet->payload[counter] == '.') {
                    counter++;

                    is_exist = false;
                    while ( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ) {
                        counter ++;
                        is_exist = true;
                    }
                }

                //has a separator
                if ( packet->payload_packet_len > counter  && is_separa( packet->payload[counter] ) )
                    return counter;
            }
        }
    }
    return 0;
}

