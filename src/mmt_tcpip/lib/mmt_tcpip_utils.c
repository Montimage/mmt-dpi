#include "mmt_common_internal_include.h"

uint32_t mmt_bytestream_to_number(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint32_t val;
    val = 0;
    // cancel if eof, ' ' or line end chars are reached
    while (*str >= '0' && *str <= '9' && max_chars_to_read > 0) {
        val *= 10;
        val += *str - '0';
        str++;
        max_chars_to_read = max_chars_to_read - 1;
        *bytes_read = *bytes_read + 1;
    }
    return (val);
}

uint32_t mmt_bytestream_dec_or_hex_to_number(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint32_t val;
    val = 0;
    if (max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
        return mmt_bytestream_to_number(str, max_chars_to_read, bytes_read);
    } else {
        /*use base 16 system */
        str += 2;
        max_chars_to_read -= 2;
        *bytes_read = *bytes_read + 2;
        while (max_chars_to_read > 0) {

            if (*str >= '0' && *str <= '9') {
                val *= 16;
                val += *str - '0';
            } else if (*str >= 'a' && *str <= 'f') {
                val *= 16;
                val += *str + 10 - 'a';
            } else if (*str >= 'A' && *str <= 'F') {
                val *= 16;
                val += *str + 10 - 'A';
            } else {
                break;
            }
            str++;
            max_chars_to_read = max_chars_to_read - 1;
            *bytes_read = *bytes_read + 1;
        }
    }
    return (val);
}

uint64_t mmt_bytestream_to_number64(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint64_t val;
    val = 0;
    // cancel if eof, ' ' or line end chars are reached
    while (max_chars_to_read > 0 && *str >= '0' && *str <= '9') {
        val *= 10;
        val += *str - '0';
        str++;
        max_chars_to_read = max_chars_to_read - 1;
        *bytes_read = *bytes_read + 1;
    }
    return (val);
}

uint64_t mmt_bytestream_dec_or_hex_to_number64(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint64_t val;
    val = 0;
    if (max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
        return mmt_bytestream_to_number64(str, max_chars_to_read, bytes_read);
    } else {
        /*use base 16 system */
        str += 2;
        max_chars_to_read -= 2;
        *bytes_read = *bytes_read + 2;
        while (max_chars_to_read > 0) {

            if (*str >= '0' && *str <= '9') {
                val *= 16;
                val += *str - '0';
            } else if (*str >= 'a' && *str <= 'f') {
                val *= 16;
                val += *str + 10 - 'a';
            } else if (*str >= 'A' && *str <= 'F') {
                val *= 16;
                val += *str + 10 - 'A';
            } else {
                break;
            }
            str++;
            max_chars_to_read = max_chars_to_read - 1;
            *bytes_read = *bytes_read + 1;
        }
    }
    return (val);
}

uint32_t mmt_bytestream_to_ipv4(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint32_t val;
    uint16_t read = 0;
    uint16_t oldread;
    uint32_t c;
    /* ip address must be X.X.X.X with each X between 0 and 255 */
    oldread = read;
    c = mmt_bytestream_to_number(str, max_chars_to_read, &read);
    if (c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
        return 0;
    read++;
    val = c << 24;
    oldread = read;
    c = mmt_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
    if (c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
        return 0;
    read++;
    val = val + (c << 16);
    oldread = read;
    c = mmt_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
    if (c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
        return 0;
    read++;
    val = val + (c << 8);
    oldread = read;
    c = mmt_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
    if (c > 255 || oldread == read || max_chars_to_read == read)
        return 0;
    val = val + c;

    *bytes_read = *bytes_read + read;

    return htonl(val);
}

static const uint16_t NEW_LINE = ntohs(0x0d0a);

/* internal function for every detection to parse one packet and to increase the info buffer */
void mmt_parse_packet_line_info(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if ( unlikely( packet->payload_packet_len == 0 ))
        return;

    if (packet->packet_lines_parsed_complete != 0)
        return;

    uint32_t a;
    uint16_t line_length;
    const uint8_t *str;
    int http_data_analyser = ipacket->mmt_handler->configured_protocols[PROTO_HTTP].protocol->data_analyser.status ;
    int skip_parsing = 0;
    uint16_t end = packet->payload_packet_len - 1;

    packet->packet_lines_parsed_complete = 1;
    packet->parsed_lines = 0;

    packet->empty_line_position_set = 0;
    packet->empty_line_position = 0;

    packet->host_line.ptr = NULL;
    packet->host_line.len = 0;
    packet->referer_line.ptr = NULL;
    packet->referer_line.len = 0;
    packet->content_line.ptr = NULL;
    packet->content_line.len = 0;
    packet->accept_line.ptr = NULL;
    packet->accept_line.len = 0;
    packet->user_agent_line.ptr = NULL;
    packet->user_agent_line.len = 0;
    // LN
    packet->upgrade_line.ptr = NULL;
    packet->upgrade_line.len = 0;
    packet->connection_line.ptr = NULL;
    packet->connection_line.len = 0;
    // End of LN
    packet->http_url_name.ptr = NULL;
    packet->http_url_name.len = 0;
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
    packet->server_line.ptr = NULL;
    packet->server_line.len = 0;
    packet->http_method.ptr = NULL;
    packet->http_method.len = 0;
    packet->http_response.ptr = NULL;
    packet->http_response.len = 0;
    packet->has_x_cdn_hdr = 0;
    packet->line[packet->parsed_lines].ptr = packet->payload;
    packet->line[packet->parsed_lines].len = 0;
    packet->packet_id = ipacket->packet_id;

    for (a = 0; likely( a < end ); a++) {
        if ( get_u16(packet->payload, a) == NEW_LINE ) {

            line_length =  &packet->payload[a] - packet->line[packet->parsed_lines].ptr;
            packet->line[packet->parsed_lines].len = line_length;

            if ( unlikely( line_length == 0 )) {
                packet->empty_line_position     = a;
                packet->empty_line_position_set = 1;
            } else {

                str = packet->line[packet->parsed_lines].ptr;
                // printf("%lu: %s\n",ipacket->packet_id,str);
                if (str[0] == 'H') {
                    if (str[1] == 'T') {
                        if (packet->parsed_lines == 0 && str[2] == 'T' && str[3] == 'P' && str[4] == '/' && str[5] == '1' && str[6] == '.') {
                            packet->http_response.ptr = &str[9];
                            packet->http_response.len = packet->line[0].len - 9;
                            MMT_LOG(PROTO_UNKNOWN, MMT_LOG_DEBUG,
                                    "mmt_parse_packet_line_info: HTTP response parsed: \"%.*s\"\n",
                                    packet->http_response.len, packet->http_response.ptr);
                            skip_parsing = 1;
                        }
                    } else if (str[1] == 'o') {
                        if (str[2] == 's' && str[3] == 't' && str[4] == ':') {
                            if (str[5] == ' ') {
                                packet->host_line.ptr = &str[6];
                                packet->host_line.len = line_length - 6;
                            } else {
                                packet->host_line.ptr = &str[5];
                                packet->host_line.len = line_length - 5;
                            }
                            skip_parsing = 1;
                        }
                    }
                } else {
                    if (http_data_analyser == 1) {
                        switch ( str[0] ) {
                        case 'S':
                            if (
                                memcmp(str+1, "erver:", 6) == 0)
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
                        case 'c':
                            switch ( str[8] ) {
                            case 'T':
                                if (
                                    memcmp (str+1, "ontent-Type: ", 13) == 0) {
                                    packet->content_line.ptr = &str[14];
                                    packet->content_line.len = line_length - 14;
                                }
                                break;
                            case 't':
                                if (
                                    memcmp(str + 1, "ontent-type: ", 13) == 0) {
                                    packet->content_line.ptr = &str[14];
                                    packet->content_line.len = line_length - 14;
                                }
                                break;
                            case 'E':
                                if (
                                    memcmp(str + 1, "ontent-Encoding: ", 17) == 0) {
                                    packet->http_encoding.ptr = &str[18];
                                    packet->http_encoding.len = line_length - 18;
                                }
                                break;
                            case 'L':
                                if (
                                    (memcmp(str + 1, "ontent-Length: ", 15) == 0) ) {
                                    packet->http_contentlen.ptr = &str[16];
                                    packet->http_contentlen.len = line_length - 16;
                                }
                                break;
                            case 'l':
                                if (
                                    (memcmp(str + 1, "ontent-length: ", 15) == 0)) {
                                    packet->http_contentlen.ptr = &str[16];
                                    packet->http_contentlen.len = line_length - 16;
                                }
                                break;
                            case 'o':
                                if (
                                    (memcmp(str + 1, "onnection: ", 11) == 0)) {
                                    packet->connection_line.ptr = &str[12];
                                    packet->connection_line.len = line_length - 12;
                                }
                                break;
                            default:
                                if (
                                    memcmp(str + 1, "ookie: ", 7) == 0) {
                                    packet->http_cookie.ptr = &str[8];
                                    packet->http_cookie.len = line_length - 8;
                                }
                            }
                            break;
                        case 'A':
                        case 'a':
                            if (
                                memcmp(str + 1, "ccept: ", 7) == 0)
                            {
                                packet->accept_line.ptr = &str[8];
                                packet->accept_line.len = line_length - 8;
                            }
                            break;

                        case 'R':
                            if (
                                memcmp(str + 1, "eferer: ", 8) == 0)
                            {
                                packet->referer_line.ptr = &str[9];
                                packet->referer_line.len = line_length - 9;
                            }
                            break;

                        case 'U':
                        case 'u':
                            if (str[1] == 's') {
                                if (
                                    (memcmp(str + 2, "er-Agent: ", 10) == 0 ||
                                     memcmp(str + 2, "er-agent: ", 10) == 0))
                                {
                                    packet->user_agent_line.ptr = &str[12];
                                    packet->user_agent_line.len = line_length - 12;
                                }
                            } else if (str[1] == 'p') {
                                if (
                                    (memcmp(str + 2, "grade: ", 7) == 0))
                                {
                                    packet->upgrade_line.ptr = &str[9];
                                    packet->upgrade_line.len = line_length - 9;
                                }
                            }
                            break;
                        case 'T':
                            if (
                                memcmp(str + 1, "ransfer-Encoding: ", 18) == 0) {
                                packet->http_transfer_encoding.ptr = &str[19];
                                packet->http_transfer_encoding.len = line_length - 19;
                            }

                            break;
                        case 'X':
                            if (
                                memcmp(str + 1, "-Session-Type: ", 15) == 0) {
                                packet->http_x_session_type.ptr = &str[16];
                                packet->http_x_session_type.len = line_length - 16;
                            }
                        case 'x':
                            if (
                                mmt_strncasecmp((const char *)str, "X-CDN", 5) == 0) {
                                packet->has_x_cdn_hdr = 1;
                            }
                            break;
                        default:
                            break;
                        }// End of switch
                    } else {
                        debug("PROTO_HTTP: Do not parse HTTP header");
                    }// End of http_data_analyser == 1
                }// End of str[0] == 'H'
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
            if (http_data_analyser == 0 && skip_parsing == 1) {
                break;
            }
        } // End of get_u16(packet->payload, a) == NEW_LINE 
    }// End of for loop

    if (packet->parsed_lines >= 1) {
        packet->line[packet->parsed_lines].len =
            &packet->payload[packet->payload_packet_len] - packet->line[packet->parsed_lines].ptr;
        packet->parsed_lines++;
    }
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

//static inline bool is_minus( x ) { return  (x >='a'&& x<='z'); }
//static inline bool is_majus( x ) { return  (x>='A' && x<='Z'); }
//static inline bool is_number( x ){ return  (x>='0' && x<='9'); }
//static inline bool is_separa( x) { return  (x==' ' || x==';'); }
//static inline bool is_letter( x ){ return  (is_minus(x) || is_majus(x) || is_number(x) || x == '-' || x == '_'); }

uint16_t mmt_check_for_email_address(ipacket_t * ipacket, uint16_t counter) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    bool is_exist = false;

    //a.Nghia8.Nguyen@montimage.com.fr
    MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "called mmt_check_for_email_address\n");
    //a
    if ( packet->payload_packet_len && is_letter( packet->payload[counter] ) ) {
        MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "first letter\n");
        counter++;
        //.Nghia8.Nguyen
        while ( packet->payload_packet_len > counter  &&
                (is_letter( packet->payload[counter] ) || packet->payload[counter] == '.') ) {
            MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "further letter\n");
            counter ++;
        }

        //@
        if (packet->payload_packet_len > counter && packet->payload[counter] == '@') {
            MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "@\n");
            counter++;

            //montimage
            is_exist = false;
            while ( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ) {
                MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "domain name\n");
                counter ++;
                is_exist = true;
            }

            //.
            if ( is_exist && packet->payload_packet_len > counter && packet->payload[counter] == '.') {
                MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, ".\n");
                counter++;

                //com
                is_exist = false;
                while ( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ) {
                    MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "subdomain name\n");
                    counter ++;
                    is_exist = true;
                }

                //optional: .xxx.net.fr
                while ( is_exist && packet->payload_packet_len > counter && packet->payload[counter] == '.') {
                    MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, ".\n");
                    counter++;

                    is_exist = false;
                    while ( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ) {
                        MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "subdomain name\n");
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

uint16_t _mmt_check_for_email_address(ipacket_t * ipacket, uint16_t counter) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "called mmt_check_for_email_address\n");

    if (packet->payload_packet_len > counter && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
            || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
            || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
            || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
        MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "first letter\n");
        counter++;
        while (packet->payload_packet_len > counter
                && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
                    || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
                    || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
                    || packet->payload[counter] == '-' || packet->payload[counter] == '_'
                    || packet->payload[counter] == '.')) {
            MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "further letter\n");
            counter++;
            if (packet->payload_packet_len > counter && packet->payload[counter] == '@') {
                MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "@\n");
                counter++;
                while (packet->payload_packet_len > counter
                        && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
                            || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
                            || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
                            || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
                    MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "letter\n");
                    counter++;
                    if (packet->payload_packet_len > counter && packet->payload[counter] == '.') {
                        MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, ".\n");
                        counter++;
                        if (packet->payload_packet_len > counter + 1
                                && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
                                    && (packet->payload[counter + 1] >= 'a' && packet->payload[counter + 1] <= 'z'))) {
                            MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "two letters\n");
                            counter += 2;
                            if (packet->payload_packet_len > counter
                                    && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
                                MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "whitespace1\n");
                                return counter;
                            } else if (packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
                                       && packet->payload[counter] <= 'z') {
                                MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "one letter\n");
                                counter++;
                                if (packet->payload_packet_len > counter
                                        && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
                                    MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "whitespace2\n");
                                    return counter;
                                } else if (packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
                                           && packet->payload[counter] <= 'z') {
                                    counter++;
                                    if (packet->payload_packet_len > counter
                                            && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
                                        MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "whitespace3\n");
                                        return counter;
                                    } else {
                                        return 0;
                                    }
                                } else {
                                    return 0;
                                }
                            } else {
                                return 0;
                            }
                        } else {
                            return 0;
                        }
                    }
                }
                return 0;
            }
        }
    }
    return 0;
}

