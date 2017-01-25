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

//    memset( &packet->host_line, 0, sizeof( struct mmt_int_one_line_struct ) * 14 );
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

    const uint16_t new_line   = ntohs(0x0d0a);
//    const uint8_t lower_byte  = new_line;
//    const uint8_t higher_byte = new_line >> 8;
    uint16_t line_length;
    const uint8_t *str;

    //for each byte in packet payload
    for (a = 0; likely( a < end ); a++){
    // search for an empty line position: 0x0d0a
       if ( get_u16(packet->payload, a) == new_line ){
//   	 if( packet->payload[ a ] == higher_byte && packet->payload[ a+1 ] == lower_byte ){

      	   line_length =  &packet->payload[a] - packet->line[packet->parsed_lines].ptr;
            packet->line[packet->parsed_lines].len = line_length;
            //empty line => end of HTTP header
            if (line_length == 0) {
            	packet->empty_line_position     = a;
            	packet->empty_line_position_set = 1;
            }else{

            	// Check for response packet
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
            	str = packet->line[packet->parsed_lines].ptr;
            	switch( str[0] ){
            	case 'H':
            		switch( str[1] ){
            		case 'T':
							//HTTP/1.1 200
							if ( packet->parsed_lines == 0
									&& packet->line[0].len >= MMT_STATICSTRING_LEN("HTTP/1.1 200 ") &&
									str[MMT_STATICSTRING_LEN("HTTP/1.1 ")] > '0' &&
									str[MMT_STATICSTRING_LEN("HTTP/1.1 ")] < '6' &&
									memcmp( str, "HTTP/1.", MMT_STATICSTRING_LEN("HTTP/1.")) == 0
							) {
								packet->http_response.ptr = &str[MMT_STATICSTRING_LEN("HTTP/1.1 ")];
								packet->http_response.len = packet->line[0].len - MMT_STATICSTRING_LEN("HTTP/1.1 ");

								// printf("[HTTP] HTTP response detected! %lu\n", ipacket->packet_id);
								MMT_LOG(PROTO_UNKNOWN, MMT_LOG_DEBUG,
										"mmt_parse_packet_line_info: HTTP response parsed: \"%.*s\"\n",
										packet->http_response.len, packet->http_response.ptr);
							}
							break;
            		case 'o':
							if ( //line_length > 6 &&
									memcmp(str, "Host:", 5) == 0)
							{
								// some stupid clients omit a space and place the hostname directly after the colon
								if (str[5] == ' ') {
									packet->host_line.ptr = &str[6];
									packet->host_line.len = line_length - 6;
								} else {
									packet->host_line.ptr = &str[5];
									packet->host_line.len = line_length - 5;
								}
							}
							break;
            		}//end of switch of 'H'

            		break;
            	case 'S':
            		if ( //line_length > 8 &&
            				memcmp(str, "Server:", 7) == 0)
            		{
            			// some stupid clients omit a space and place the servername directly after the colon
            			if (str[7] == ' ') {
            				packet->server_line.ptr = &str[8];
            				packet->server_line.len = line_length - 8;
            			} else {
            				packet->server_line.ptr = &str[7];
            				packet->server_line.len = line_length - 7;
            			}
            		}
            		break;

            	case 'c':
            		if ( //line_length > 13 &&
            				memcmp(str, "content-type:", 13) == 0)
            		{
            			packet->content_line.ptr = &str[13];
            			packet->content_line.len = line_length - 13;
            		}
            		break;

            	case 'A':
            		if ( //line_length > 8 &&
            				memcmp(str, "Accept: ", 8) == 0)
            		{
            			packet->accept_line.ptr = &str[8];
            			packet->accept_line.len = line_length - 8;
            		}
            		break;

            	case 'R':
            		if ( //line_length > 9 &&
            				memcmp(str, "Referer: ", 9) == 0)
            		{
            			packet->referer_line.ptr = &str[9];
            			packet->referer_line.len = line_length - 9;
            		}
            		break;

            	case 'U':
            		if ( //line_length > 12 &&
            				(memcmp(str, "User-Agent: ", 12) == 0 ||
            				 memcmp(str, "User-agent: ", 12) == 0))
            		{
            			packet->user_agent_line.ptr = &str[12];
            			packet->user_agent_line.len = line_length - 12;
            		}
            		break;

            	case 'C':
            		switch( str[8] ){
            		case 'T':
							if ( //line_length > 14 &&
									memcmp (str, "Content-Type: ", 14) == 0) {
								packet->content_line.ptr = &str[14];
								packet->content_line.len = line_length - 14;
							}
							break;
            		case 't':
            			if ( //line_length > 14 &&
            					memcmp(str, "Content-type: ", 14) == 0) {
            				packet->content_line.ptr = &str[14];
            				packet->content_line.len = line_length - 14;
            			}
            			break;
            		case 'E':
							if ( //line_length > 18 &&
									memcmp(str, "Content-Encoding: ", 18) == 0) {
								packet->http_encoding.ptr = &str[18];
								packet->http_encoding.len = line_length - 18;
							}
							break;
            		case 'L':
							if ( //line_length > 16 &&
									(memcmp(str, "Content-Length: ", 16) == 0) ) {
								packet->http_contentlen.ptr = &str[16];
								packet->http_contentlen.len = line_length - 16;
							}
							break;
            		case 'l':
            			if ( //line_length > 16 &&
            					(memcmp(str, "content-length: ", 16) == 0)) {
            				packet->http_contentlen.ptr = &str[16];
            				packet->http_contentlen.len = line_length - 16;
            			}
            			break;
            		default:
							if ( //line_length > 8 &&
									memcmp(str, "Cookie: ", 8) == 0) {
								packet->http_cookie.ptr = &str[8];
								packet->http_cookie.len = line_length - 8;
							}
            		}//end of switch of 'C'
            		break;

            	case 'T':
            		if ( //line_length > 19 &&
								memcmp(str, "Transfer-Encoding: ", 19) == 0) {
            			packet->http_transfer_encoding.ptr = &str[19];
            			packet->http_transfer_encoding.len = line_length - 19;
            		}

            		break;
            	case 'X':
            		if ( //line_length > 16 &&
            				memcmp(str, "X-Session-Type: ", 16) == 0) {
            			packet->http_x_session_type.ptr = &str[16];
            			packet->http_x_session_type.len = line_length - 16;
            		}
            		//no break;
            	case 'x':
            		if ( //line_length > 5 &&
            				mmt_strncasecmp((const char *)str, "X-CDN", 5) == 0) {
            			packet->has_x_cdn_hdr = 1;
            		}
            		break;

            	}//end of switch
            }

            //we parse maximally 200 lines
            if( unlikely( packet->parsed_lines >= (MMT_MAX_PARSE_LINES_PER_PACKET - 1))) {
                return;
            }


            packet->parsed_lines++;
            packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
            packet->line[packet->parsed_lines].len = 0;

            if ( packet->empty_line_position != 0 || (a + 2) >= packet->payload_packet_len ) {
            	//printf("%lld  parsed lines: %3d\n", packet->packet_id, packet->parsed_lines );
               return;
            }
            //jump over new_line
//            a ++;
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
   if( packet->payload_packet_len && is_letter( packet->payload[counter] ) ){
   	MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "first letter\n");
   	counter++;
   	//.Nghia8.Nguyen
   	while( packet->payload_packet_len > counter  &&
   			(is_letter( packet->payload[counter] ) || packet->payload[counter] == '.') ){
   		MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "further letter\n");
   		counter ++;
   	}

   	//@
   	if (packet->payload_packet_len > counter && packet->payload[counter] == '@') {
   		MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "@\n");
   		counter++;

   		//montimage
   		is_exist = false;
   		while( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ){
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
   			while( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ){
   				MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "subdomain name\n");
   				counter ++;
   				is_exist = true;
   			}

   			//optional: .xxx.net.fr
   			while( is_exist && packet->payload_packet_len > counter && packet->payload[counter] == '.') {
   				MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, ".\n");
   				counter++;

   				is_exist = false;
   				while( packet->payload_packet_len > counter  && is_letter( packet->payload[counter] ) ){
   					MMT_LOG(PROTO_MSN, MMT_LOG_DEBUG, "subdomain name\n");
   					counter ++;
   					is_exist = true;
   				}
   			}

   			//has a separator
   			if( packet->payload_packet_len > counter  && is_separa( packet->payload[counter] ) )
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

