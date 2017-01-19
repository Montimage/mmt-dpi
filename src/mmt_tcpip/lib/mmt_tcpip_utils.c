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

/* internal function for every detection to parse one packet and to increase the info buffer */
void mmt_parse_packet_line_info(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint32_t a;
    uint16_t end = packet->payload_packet_len - 1;
    if (packet->packet_lines_parsed_complete != 0)
        return;

    packet->packet_lines_parsed_complete = 1;
    packet->parsed_lines = 0;

    packet->empty_line_position_set = 0;
    packet->empty_line_position = 0;

    packet->empty_line_position = 0;

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

    if (packet->payload_packet_len == 0)
        return;

    packet->line[packet->parsed_lines].ptr = packet->payload;
    packet->line[packet->parsed_lines].len = 0;
    packet->packet_id = ipacket->packet_id;

    uint16_t val = ntohs(0x0d0a);

    for (a = 0; a < end && packet->parsed_lines < MMT_MAX_PARSE_LINES_PER_PACKET; a++) {
    // search for an empty line position: 0x0d0a
        if (get_u16(packet->payload, a) == val ) {
            packet->line[packet->parsed_lines].len =
                &packet->payload[a] - packet->line[packet->parsed_lines].ptr;

            // Check for response packet
            if (packet->parsed_lines == 0 && packet->line[0].len >= MMT_STATICSTRING_LEN("HTTP/1.1 200 ") &&
                    packet->line[0].ptr[MMT_STATICSTRING_LEN("HTTP/1.1 ")] > '0' &&
                    packet->line[0].ptr[MMT_STATICSTRING_LEN("HTTP/1.1 ")] < '6' &&
						  memcmp(packet->line[0].ptr, "HTTP/1.", MMT_STATICSTRING_LEN("HTTP/1.")) == 0
						  ) {
                packet->http_response.ptr = &packet->line[0].ptr[MMT_STATICSTRING_LEN("HTTP/1.1 ")];
                packet->http_response.len = packet->line[0].len - MMT_STATICSTRING_LEN("HTTP/1.1 ");

                // printf("[HTTP] HTTP response detected! %lu\n", ipacket->packet_id);
                MMT_LOG(PROTO_UNKNOWN, MMT_LOG_DEBUG,
                        "mmt_parse_packet_line_info: HTTP response parsed: \"%.*s\"\n",
                        packet->http_response.len, packet->http_response.ptr);
                continue;
            }

            // check for request packet
            
            // It is not http packet
            // if(packet->http_response.ptr== NULL && ( 
            //     memcmp(packet->line[0].ptr, "GET", MMT_STATICSTRING_LEN("GET")) != 0 && 
            //     memcmp(packet->line[0].ptr, "POST", MMT_STATICSTRING_LEN("POST")) != 0 &&
            //     memcmp(packet->line[0].ptr, "PUT", MMT_STATICSTRING_LEN("PUT")) != 0 && 
            //     memcmp(packet->line[0].ptr, "DELETE", MMT_STATICSTRING_LEN("DELETE")) != 0 && 
            //     memcmp(packet->line[0].ptr, "OPTIONS", MMT_STATICSTRING_LEN("OPTIONS")) != 0 && 
            //     memcmp(packet->line[0].ptr, "HEAD", MMT_STATICSTRING_LEN("HEAD")) != 0 && 
            //     memcmp(packet->line[0].ptr, "TRACE", MMT_STATICSTRING_LEN("TRACE")) != 0 && 
            //     memcmp(packet->line[0].ptr, "CONNECT", MMT_STATICSTRING_LEN("CONNECT")) != 0)){
            //     return;
            // }
            if (packet->line[packet->parsed_lines].len > MMT_STATICSTRING_LEN("Server:") + 1
                    && memcmp(packet->line[packet->parsed_lines].ptr, "Server:", MMT_STATICSTRING_LEN("Server:")) == 0) {
                // some stupid clients omit a space and place the servername directly after the colon
                if (packet->line[packet->parsed_lines].ptr[MMT_STATICSTRING_LEN("Server:")] == ' ') {
                    packet->server_line.ptr =
                            &packet->line[packet->parsed_lines].ptr[MMT_STATICSTRING_LEN("Server:") + 1];
                    packet->server_line.len =
                            packet->line[packet->parsed_lines].len - (MMT_STATICSTRING_LEN("Server:") + 1);
                    continue;
                } else {
                    packet->server_line.ptr = &packet->line[packet->parsed_lines].ptr[MMT_STATICSTRING_LEN("Server:")];
                    packet->server_line.len = packet->line[packet->parsed_lines].len - MMT_STATICSTRING_LEN("Server:");
                    continue;
                }
            }

            if (packet->line[packet->parsed_lines].len > 6
                    && memcmp(packet->line[packet->parsed_lines].ptr, "Host:", 5) == 0) {
                // some stupid clients omit a space and place the hostname directly after the colon
                if (packet->line[packet->parsed_lines].ptr[5] == ' ') {
                    packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[6];
                    packet->host_line.len = packet->line[packet->parsed_lines].len - 6;
                    continue;
                } else {
                    packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[5];
                    packet->host_line.len = packet->line[packet->parsed_lines].len - 5;
                    continue;
                }
            }

            if (packet->line[packet->parsed_lines].len > 14
                    &&
                    (memcmp
                    (packet->line[packet->parsed_lines].ptr, "Content-Type: ",
                    14) == 0 || memcmp(packet->line[packet->parsed_lines].ptr, "Content-type: ", 14) == 0)) {
                packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[14];
                packet->content_line.len = packet->line[packet->parsed_lines].len - 14;
                continue;
            }

            if (packet->line[packet->parsed_lines].len > 13
                    && memcmp(packet->line[packet->parsed_lines].ptr, "content-type:", 13) == 0) {
                packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[13];
                packet->content_line.len = packet->line[packet->parsed_lines].len - 13;
                continue;
            }

            if (packet->line[packet->parsed_lines].len > 8
                    && memcmp(packet->line[packet->parsed_lines].ptr, "Accept: ", 8) == 0) {
                packet->accept_line.ptr = &packet->line[packet->parsed_lines].ptr[8];
                packet->accept_line.len = packet->line[packet->parsed_lines].len - 8;
                continue;
            }

            if (packet->line[packet->parsed_lines].len > 9
                    && memcmp(packet->line[packet->parsed_lines].ptr, "Referer: ", 9) == 0) {
                packet->referer_line.ptr = &packet->line[packet->parsed_lines].ptr[9];
                packet->referer_line.len = packet->line[packet->parsed_lines].len - 9;
                continue;
            }

            if (packet->line[packet->parsed_lines].len > 12
                    && (memcmp(packet->line[packet->parsed_lines].ptr, "User-Agent: ", 12) == 0 ||
                        memcmp(packet->line[packet->parsed_lines].ptr, "User-agent: ", 12) == 0)) {
                packet->user_agent_line.ptr = &packet->line[packet->parsed_lines].ptr[12];
                packet->user_agent_line.len = packet->line[packet->parsed_lines].len - 12;
                continue;
            }

            if (packet->line[packet->parsed_lines].len > 18
                    && memcmp(packet->line[packet->parsed_lines].ptr, "Content-Encoding: ", 18) == 0) {
                packet->http_encoding.ptr = &packet->line[packet->parsed_lines].ptr[18];
                packet->http_encoding.len = packet->line[packet->parsed_lines].len - 18;
                continue;
            }

            if (packet->line[packet->parsed_lines].len > 19
                    && memcmp(packet->line[packet->parsed_lines].ptr, "Transfer-Encoding: ", 19) == 0) {
                packet->http_transfer_encoding.ptr = &packet->line[packet->parsed_lines].ptr[19];
                packet->http_transfer_encoding.len = packet->line[packet->parsed_lines].len - 19;
                continue;
            }
            if (packet->line[packet->parsed_lines].len > 16
                    && ((memcmp(packet->line[packet->parsed_lines].ptr, "Content-Length: ", 16) == 0)
                    ||  (memcmp(packet->line[packet->parsed_lines].ptr, "content-length: ", 16) == 0))) {
                packet->http_contentlen.ptr = &packet->line[packet->parsed_lines].ptr[16];
                packet->http_contentlen.len = packet->line[packet->parsed_lines].len - 16;
                continue;
            }
            if (packet->line[packet->parsed_lines].len > 8
                    && memcmp(packet->line[packet->parsed_lines].ptr, "Cookie: ", 8) == 0) {
                packet->http_cookie.ptr = &packet->line[packet->parsed_lines].ptr[8];
                packet->http_cookie.len = packet->line[packet->parsed_lines].len - 8;
                continue;
            }
            if (packet->line[packet->parsed_lines].len > 5
                    && mmt_strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "X-CDN", 5) == 0) {
                packet->has_x_cdn_hdr = 1;
                continue;
            }
            if (packet->line[packet->parsed_lines].len > 16
                    && memcmp(packet->line[packet->parsed_lines].ptr, "X-Session-Type: ", 16) == 0) {
                packet->http_x_session_type.ptr = &packet->line[packet->parsed_lines].ptr[16];
                packet->http_x_session_type.len = packet->line[packet->parsed_lines].len - 16;
                continue;
            }


            if (packet->line[packet->parsed_lines].len == 0) {
                packet->empty_line_position = a;
                packet->empty_line_position_set = 1;
                continue;
            }

            if (packet->parsed_lines >= (MMT_MAX_PARSE_LINES_PER_PACKET - 1)) {
                return;
            }

            packet->parsed_lines++;
            packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
            packet->line[packet->parsed_lines].len = 0;

            if ((a + 2) >= packet->payload_packet_len) {

                return;
            }
            a++;
        }
    }

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

uint16_t mmt_check_for_email_address(ipacket_t * ipacket, uint16_t counter) {

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

