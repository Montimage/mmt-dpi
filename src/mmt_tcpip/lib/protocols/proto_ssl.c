#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "plugin_defs.h"
#include "mmt_core.h"

#include <ctype.h>

/*
Content types
Hex Dec Type
0x14    20  ChangeCipherSpec
0x15    21  Alert
0x16    22  Handshake
0x17    23  Application
0x18    24  Heartbeat


Versions
Major
version Minor
version Version type
3   0   SSL 3.0
3   1   TLS 1.0
3   2   TLS 1.1
3   3   TLS 1.2
 */

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_MAX_SSL_REQUEST_SIZE 10000

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

struct ssl_extension_struct {
    uint16_t type;
    uint16_t len;
    uint8_t val;
};

int ssl_is_tls_record_header(const uint8_t * payload, int payload_len){
    if(payload_len == 0) return 0;
    uint8_t content_type = payload[0];
    if(content_type <20 || content_type > 24){
        // Incorrect content type
        return 0;
    }
    uint16_t version = ntohs(get_u16(payload, 1));
    if(version < 768 || version > 771){
        // Incorrect version: 3.0 (768), 1.0 (769), 1.1 (770), 1.2 (771)
        return 0;
    }
    
    uint16_t length = ntohs(get_u16(payload, 3));
    if(payload_len < length){
        // Invalid payload length
        return 0;
    }
    return 1;
}

int tls_get_number_records(const ipacket_t * ipacket){
    int nb_record = 0;
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int payload_len = packet->payload_packet_len;
    if(payload_len <= 0) return 0;
    int offset = packet->payload_packet_len - payload_len;
    if(ssl_is_tls_record_header(packet->payload + offset,payload_len)){
        // SSL packet
        while(payload_len > 0){
            nb_record++;
            int tls_total_length = ntohs(get_u16(packet->payload + offset, 3)) + 5;
            offset += tls_total_length;
            payload_len -= tls_total_length;
            if(ssl_is_tls_record_header(packet->payload + offset,payload_len)!=1){
                break;
            }
        }
    }
    return nb_record;
}

/**
 * Check if a message_type value is a valid one
 * 
    Message types
    Code    Description
    0   HelloRequest
    1   ClientHello
    2   ServerHello
    4   NewSessionTicket
    11  Certificate
    12  ServerKeyExchange
    13  CertificateRequest
    14  ServerHelloDone
    15  CertificateVerify
    16  ClientKeyExchange
    20  Finished
 * @param  message_type [description]
 * @return              [description]
 */
int ssl_is_tls_message_type(int message_type){
    return !(message_type < 0 
        || message_type > 20 
        || (message_type > 4 && message_type < 11)
        || (message_type > 16 && message_type < 20));
}
//////////////// SSL attributes extraction routines.

int ssl_server_name_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if (ipacket->internal_packet->packet_id == ipacket->packet_id) {
            if (ipacket->internal_packet->https_server_name.ptr != NULL && ((mmt_tcpip_internal_packet_t *) ipacket->internal_packet)->https_server_name.len > 0) {
                extracted_data->data = (void *) &ipacket->internal_packet->https_server_name;
                return 1;
            }
        }
    }
    return 0;
}

int tls_content_type_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    int tcp_index = get_protocol_index_by_id(ipacket,PROTO_TCP);
    int tcp_offset = get_packet_offset_at_index(ipacket,tcp_index + 1);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int ssl_offset = get_packet_offset_at_index(ipacket, proto_index);
    int ssl_payload_len = tcp_offset + packet->payload_packet_len - ssl_offset;
    if(ssl_is_tls_record_header(&ipacket->data[ssl_offset],ssl_payload_len)!=1){
        return 0;
    }
    return general_char_extraction(ipacket,proto_index,extracted_data);
}

int tls_version_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    int tcp_index = get_protocol_index_by_id(ipacket,PROTO_TCP);
    int tcp_offset = get_packet_offset_at_index(ipacket,tcp_index + 1);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int ssl_offset = get_packet_offset_at_index(ipacket, proto_index);
    int ssl_payload_len = tcp_offset + packet->payload_packet_len - ssl_offset;
    if(ssl_is_tls_record_header(&ipacket->data[ssl_offset],ssl_payload_len)!=1){
        return 0;
    }
    return general_short_extraction_with_ordering_change(ipacket,proto_index,extracted_data);
}


int tls_length_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    int tcp_index = get_protocol_index_by_id(ipacket,PROTO_TCP);
    int tcp_offset = get_packet_offset_at_index(ipacket,tcp_index + 1);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int ssl_offset = get_packet_offset_at_index(ipacket, proto_index);
    int ssl_payload_len = tcp_offset + packet->payload_packet_len - ssl_offset;
    if(ssl_is_tls_record_header(&ipacket->data[ssl_offset],ssl_payload_len)!=1){
        return 0;
    }
    return general_short_extraction_with_ordering_change(ipacket,proto_index,extracted_data);
}

int tls_number_record_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    int nb_record = tls_get_number_records(ipacket);
    if(nb_record){
        *((uint16_t *) extracted_data->data) = nb_record;
        return 1;
    }
    return 0;
}


///////// Extract Handshake protocol
// Message types
// Code    Description
// 0   HelloRequest
// 1   ClientHello
// 2   ServerHello
// 4   NewSessionTicket
// 11  Certificate
// 12  ServerKeyExchange
// 13  CertificateRequest
// 14  ServerHelloDone
// 15  CertificateVerify
// 16  ClientKeyExchange
// 20  Finished

//////////////// End of SSL attributes extraction routines

static void mmt_int_ssl_add_connection(ipacket_t * ipacket, uint32_t protocol) {
    if (protocol != PROTO_SSL) {
        mmt_internal_add_connection(ipacket, protocol, MMT_CORRELATED_PROTOCOL);
    } else {
        mmt_internal_add_connection(ipacket, protocol, MMT_REAL_PROTOCOL);
        set_session_timeout_delay(ipacket->session, ipacket->mmt_handler->long_session_timed_out);
    }
}

static inline int mmt_ssl_min(uint32_t a, uint32_t b) {
    return (a < b ? a : b);
}

static void stripCertificateTrailer(char *buffer, int buffer_len) {
    int i;

    for (i = 0; i < buffer_len; i++) {
        if ((buffer[i] != '.')
                && (buffer[i] != '-')
                && (!isalpha(buffer[i]))
                && (!isdigit(buffer[i]))) {
            buffer[i] = '\0';
            break;
        }
    }
}

int getServerNameFromServerHello(ipacket_t * ipacket, char *buffer, int buffer_len) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (10 > packet->payload_packet_len) {
        return PROTO_UNKNOWN;
    }

    uint16_t offset = 0, total_len = ntohs(get_u16(packet->payload, 7)) + 9 /* SSL Header */;

    if (((total_len + 15) < packet->payload_packet_len) && (packet->payload[total_len] == 0x16) && (packet->payload[total_len + 1] == 0x03)
            && (packet->payload[total_len + 2] == 0x00 || packet->payload[total_len + 2] == 0x01 || packet->payload[total_len + 2] == 0x02 || packet->payload[total_len + 2] == 0x03)
            && (ntohs(get_u16(packet->payload, total_len + 3)) - ntohs(get_u16(packet->payload, total_len + 7)) == 4)
            && (ntohs(get_u16(packet->payload, total_len + 7)) - ntohs(get_u16(packet->payload, total_len + 10)) == 3) /* Record len is 3 bytes longer than the certificates len */
            && (packet->payload[total_len + 5] == 11 /* Server Certificate */)
            ) {
        //printf("Test from Get Server Name From Server Hello tolen = %i\n", total_len);
        offset = total_len + 15; //This is the offset of the beginning of the certificate.
	}else if(((total_len + 15) < packet->payload_packet_len) && (packet->payload[total_len] == 0x11 /* Server certificate */)
            && (ntohs(get_u16(packet->payload, total_len + 2)) - ntohs(get_u16(packet->payload, total_len + 5)) == 3) /* Record len is 3 bytes longer than the certificates len */
            ) {
        //printf("Test from Get Server Name From Server Hello tolen = %i\n", total_len);
        offset = total_len + 10; //This is the offset of the beginning of the certificate.
	}

	if(offset) {
        if (offset + 2 > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }
        //printf("Offset = %u --- val at offset = %u\n", offset, (uint32_t) packet->payload[offset]);
        //The objective is not to parse the certificate, rather to get the subject CN text from the first one
        uint8_t nb_offset = 1; //This is the '30' value
        if (packet->payload[offset + nb_offset] & 0x80) {
            nb_offset += (packet->payload[offset + nb_offset] & 0xF) + 1;
        } else {
            nb_offset += 1;
        }
        offset += nb_offset; // start of the signed certificate
        //printf("Offset = %u --- val at offset = %u\n", offset, (uint32_t) packet->payload[offset]);
        if (offset + 4 > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }

        nb_offset = 1;
        if (packet->payload[offset + nb_offset] & 0x80) {
            nb_offset += (packet->payload[offset + nb_offset] & 0xF) + 1;
        } else {
            nb_offset += 1;
        }
        offset += nb_offset; //len of the serial number
        //printf("Offset = %u --- val at offset = %u\n", offset, (uint32_t) packet->payload[offset]);
        if (offset + 4 > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }
        offset += 6 /* 4 octets + version field + next octet */; //len of the serial number
        if (offset > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }

        uint8_t sn_len = packet->payload[offset], items_nb = 0;

        offset += sn_len + 1; //+1 for the len field on 1 byte
        while ((offset + 4 < packet->payload_packet_len) && items_nb < 4) {
            uint32_t item_offset;
            nb_offset = 1;
            //printf("Test 1\n");
            if (packet->payload[offset + nb_offset] & 0x80) {
                nb_offset += (packet->payload[offset + nb_offset] & 0xF) + 1;
                if (nb_offset == 3) {
                    item_offset = packet->payload[offset + nb_offset - 1];
                } else {
                    item_offset = ntohs(get_u16(packet->payload, offset + nb_offset - 2));
                }
            } else {
                item_offset = packet->payload[offset + nb_offset];
                nb_offset += 1;
            }
            offset += nb_offset;
            items_nb += 1;
            if (items_nb == 4 /* Subject part of the certificate */ && (offset + item_offset < packet->payload_packet_len)) {
                //printf("item 4\n");
                uint16_t sub_offset = 0;
                uint16_t current_offset = offset;
                while (sub_offset < item_offset) {
                    uint16_t sub_item_offset;
                    nb_offset = 1;
                    if (offset + nb_offset + 4 > packet->payload_packet_len) {
                        return PROTO_UNKNOWN;
                    }

                    if (packet->payload[current_offset + nb_offset] & 0x80) {
                        nb_offset += (packet->payload[current_offset + nb_offset] & 0xF) + 1;
                        if (nb_offset == 3) {
                            sub_item_offset = packet->payload[current_offset + nb_offset - 1];
                        } else {
                            sub_item_offset = ntohs(get_u16(packet->payload, current_offset + nb_offset - 2));
                        }
                    } else {
                        sub_item_offset = packet->payload[current_offset + nb_offset];
                        nb_offset += 1;
                    }
                    char subject_CN_pattern[] = {0x55, 0x04, 0x03};
                    if ((current_offset + nb_offset * 2 + 2 + 3 + 2 < packet->payload_packet_len) && memcmp(&packet->payload[current_offset + nb_offset * 2 + 2], subject_CN_pattern, 3) == 0) {
                        uint8_t CN_len = packet->payload[current_offset + nb_offset * 2 + 2 + 3 + 1];
                        /* unused
                        uint8_t CN_ecoding_type = packet->payload[current_offset + nb_offset * 2 + 2 + 3];
                        uint8_t min_len = mmt_ssl_min(CN_len, buffer_len - 1);
                        */
                        if(CN_len + current_offset + nb_offset * 2 + 2 + 3 + 2 >= packet->payload_packet_len) {
                            return 0;
                        }

                        u_int begin = 0, len;
                        char *server_name = (char*) &packet->payload[current_offset + nb_offset * 2 + 2 + 3 + 2];

                        while (begin < CN_len) {
                            if ((!isprint(server_name[begin]))
                                    || ispunct(server_name[begin])
                                    || isspace(server_name[begin]))
                                begin++;
                            else
                                break;
                        }

                        len = mmt_ssl_min(CN_len - begin, buffer_len - 1);
                        strncpy(buffer, &server_name[begin], len);
                        buffer[len] = '\0';
                        stripCertificateTrailer(buffer, buffer_len);
                        packet->https_server_name.ptr = (const uint8_t*)buffer;
                        //packet->https_server_name.ptr = &server_name[begin];
                        packet->https_server_name.len = len;
                        packet->packet_id = ipacket->packet_id;
                        return 1;
                    }
                    sub_offset += sub_item_offset + nb_offset;
                    current_offset += sub_item_offset + nb_offset;
                }
            }
            offset += item_offset;
        }
    }
    return (0); /* Not found */
}

int getServerNameFromClientHello(ipacket_t * ipacket, char *buffer, int buffer_len) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    uint16_t cap_total_len = packet->payload_packet_len;
    uint16_t total_len = ntohs(*((uint16_t *) & packet->payload[3])) + 5 /* SSL Header */;

    memset(buffer, 0, buffer_len);

    uint16_t offset, base_offset = 43;
    if(base_offset >= cap_total_len) {
        return 0;
    }

    uint8_t session_id_len = packet->payload[base_offset];

    if((session_id_len + base_offset + 3) >= cap_total_len) {
        return 0;
    }
    uint16_t cypher_len = ntohs(*((uint16_t *) & packet->payload[session_id_len + base_offset + 1]));

    offset = base_offset + session_id_len + 1 + cypher_len + 2;

    if (offset < total_len && offset < cap_total_len) {
        uint8_t compression_len;
        uint16_t extensions_len;

        compression_len = packet->payload[offset];
        offset += compression_len + 1;
        if (offset + 2 /* 2 for the extensions len */ < total_len && offset + 2 < cap_total_len) {
            extensions_len = ntohs(*((uint16_t *) & packet->payload[offset]));
            if ((extensions_len + offset) <= total_len && (extensions_len + offset) <= cap_total_len) {
                uint16_t extension_offset = 2; /* Move to the first extension */

                while (extension_offset + 4 < extensions_len) {
                    if(offset + extension_offset > cap_total_len) {
                        return 0;
                    }

                    struct ssl_extension_struct * ext = (struct ssl_extension_struct *) &packet->payload[offset + extension_offset];
                    uint16_t extension_id, extension_len;

                    extension_id = ntohs(ext->type);
                    extension_len = ntohs(ext->len);
                    extension_offset += 4;
                    if (extension_id == 0) {
                        if(offset + extension_offset + extension_len > cap_total_len) {
                            return 0;
                        }
                        u_int begin = 0, len;
                        if(offset + extension_offset > cap_total_len) {
                            return 0;
                        }

                        char *server_name = (char*) &packet->payload[offset + extension_offset];

                        while (begin < extension_len) {
                            if ((!isprint(server_name[begin]))
                                    || ispunct(server_name[begin])
                                    || isspace(server_name[begin]))
                                begin++;
                            else
                                break;
                        }

                        len = mmt_ssl_min(extension_len - begin, buffer_len - 1);
                        strncpy(buffer, &server_name[begin], len);
                        buffer[len] = '\0';
                        stripCertificateTrailer(buffer, buffer_len);
                        packet->https_server_name.ptr = (const uint8_t*)buffer;
                        //packet->https_server_name.ptr = &server_name[begin];
                        packet->https_server_name.len = len;
                        //printf("FROM INSIDE SERVER NAME is %s\n", buffer);
                        packet->packet_id = ipacket->packet_id;
                        return (2 /* Client Certificate */);
                    }

                    extension_offset += extension_len;
                }
            }
        }
    }
    return (0); /* Not found */
}

uint32_t sslDetectProtocolFromClientHello(ipacket_t * ipacket) {
    /* unused
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    */

    static __thread char certificate[64];
    certificate[0] = '\0';
    int rc = getServerNameFromClientHello(ipacket, certificate, sizeof (certificate));
    //int rc = 0;

    if (rc > 0) {
        /* Check the protocol by hostname */
        uint32_t proto = get_proto_id_by_hostname(ipacket, certificate, strlen(certificate));
        //printf("From detect proto from certificate = %s ---- len = %i\n", certificate, strlen(certificate));
        if (proto != PROTO_UNKNOWN) {
            mmt_int_ssl_add_connection(ipacket, proto);
            return proto;
        }else {
            if(memcmp((void *) certificate, (void *) "pop.", 4) == 0) {
                mmt_int_ssl_add_connection(ipacket, PROTO_POPS);
                return PROTO_POPS;
            } else if(memcmp((void *) certificate, (void *) "imap.", 5) == 0) {
                mmt_int_ssl_add_connection(ipacket, PROTO_IMAPS);
                return PROTO_IMAPS;
            } else if(memcmp((void *) certificate, (void *) "pop3.", 5) == 0) {
                mmt_int_ssl_add_connection(ipacket, PROTO_POPS);
                return PROTO_POPS;
            } else if(memcmp((void *) certificate, (void *) "smtp.", 5) == 0) {
                mmt_int_ssl_add_connection(ipacket, PROTO_SMTPS);
                return PROTO_SMTPS;
            }
        }
    }

    return PROTO_UNKNOWN;
}

uint32_t sslDetectProtocolFromServerHello(ipacket_t * ipacket) {
    //printf("Test from Detect From Server Hello\n");
    /* unused
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    */

    static __thread char certificate[64];
    certificate[0] = '\0';
    int rc = getServerNameFromServerHello(ipacket, certificate, sizeof (certificate));
    //int rc = 0;

    if (rc > 0) {
        /* Check the protocol by hostname */
        uint32_t proto = get_proto_id_by_hostname(ipacket, certificate, strlen(certificate));
        //printf("Protocol detected has id = %u --- Server: %s --- %u \n", proto, certificate, strlen(certificate));
        if (proto != PROTO_UNKNOWN) {
            mmt_int_ssl_add_connection(ipacket, proto);
            return proto;
        }
    }

    return PROTO_UNKNOWN;
}

uint32_t sslDetectProtocolFromServerCertificate(ipacket_t * ipacket) {
    //printf("Test from Detect From Server Certificate\n");
    return PROTO_UNKNOWN;
}

int check_whatsapp(ipacket_t * ipacket) {
    //Whatsapp signatures are all orthogonal with SSL signature! If we detect any valid Whatsapp signature return a positive value
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* whatsapp runs over port 443 */
    if (packet->tcp->source == htons(443) || packet->tcp->dest == htons(443)) {

        if (packet->iph /* IPv4 only */) {
            /*
             * Whatsapp IM IPs 50.22.231.32/27. This is not the only range but it seems this is for the IM.
             * Anyway, if this is not the case, check the signatures.
             */
            if (((ntohl(packet->iph->saddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x3216E720 /* 50.22.231.32 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x3216E720 /* 50.22.231.32 */)) {
                mmt_internal_add_connection(ipacket, PROTO_WHATSAPP, MMT_REAL_PROTOCOL);
                return 1;
            }
        }

        char whatsapp_pattern[] = {0x57, 0x41, 0x01, 0x02, 0x00};

        if ((flow->l4.tcp.whatsapp_conn_stage == 2 && flow->l4.tcp.whatsapp_stage >= 2) || (flow->l4.tcp.whatsapp_stage >= 6)) {
            mmt_internal_add_connection(ipacket, PROTO_WHATSAPP, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (flow->l4.tcp.whatsapp_conn_stage == 0 && packet->payload_packet_len >= 1 && packet->payload[0] == 0x57) {
            if (packet->payload_packet_len > 5 && (memcmp(packet->payload, whatsapp_pattern, sizeof (whatsapp_pattern)) == 0)) {
                flow->l4.tcp.whatsapp_conn_stage = 2;
                return 1;
            }
            flow->l4.tcp.whatsapp_conn_stage = 1;
            return 1;
        }
        if ((flow->l4.tcp.whatsapp_conn_stage == 1) && (packet->payload_packet_len > 5) &&
                (memcmp(packet->payload, &whatsapp_pattern[1], sizeof (whatsapp_pattern) - 1) == 0)) {
            flow->l4.tcp.whatsapp_conn_stage = 2;
            return 1;
        }
        if ((packet->payload[0] == 0x10) && (packet->payload_packet_len == 1)) {
            flow->l4.tcp.whatsapp_stage += 1;
            return 1;
        }
        if (((packet->payload[0] == 0x10 || packet->payload[0] == 0x80) && (packet->payload_packet_len > 3) &&
                (ntohs(get_u16(packet->payload, 1)) == packet->payload_packet_len)) ||
                (packet->payload[0] == 0x00 && (packet->payload_packet_len > 3) && (ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len))) {
            flow->l4.tcp.whatsapp_stage += 1;
            return 1;
        }
    }
    return 0;
}

int check_viber_tcp(ipacket_t * ipacket) {
    //Viber signatures are all orthogonal with SSL signature! If we detect any valid vider signature return a positive value
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* viber runs over tcp port 4244 or 5242 */
    if (packet->tcp->source == htons(5242) || packet->tcp->dest == htons(5242) || packet->tcp->source == htons(4244) || packet->tcp->dest == htons(4244)) {
        if (packet->iph /* IPv4 only */) {
            /*
                Viber Media AWS-VIBER-MEDIA (NET-54-169-63-160-1) 54.169.63.160 - 54.169.63.191
                Viber Media S a r l AWS-VIBER-MEDIA-S-A-R-L (NET-54-93-255-64-1) 54.93.255.64 - 54.93.255.127
                Crittercism AWS-VIBER-MEDIA (NET-52-0-252-0-1) 52.0.252.0 - 52.0.255.255
                54.169.63.160/27
                54.93.255.64/26
                52.0.252.0/22
              */
            /*
             * Viber is hosted over Amazon cloud
             * Check if this is the case
             * 50.16.0.0/14
             * 107.20.0.0/14
             * 23.20.0.0/14
             * 54.224.0.0/11
             * 46.51.0.0/16
             * 46.137.0.0/16
             * 176.34.0.0/16
             * These are not the only ranges but the most consequent ones
             */
            if (((ntohl(packet->iph->saddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x36A93FA0 /* 54.169.63.160 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x36A93FA0 /* 54.169.63.160 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x3400FC00 /* 52.0.252.0 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x3400FC00 /* 52.0.252.0 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFFFFC0 /* 255.255.255.192 */) == 0x365DFF40 /* 54.93.255.64 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFC0 /* 255.255.255.192 */) == 0x365DFF40 /* 54.93.255.64 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x32100000 /* 50.16.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x32100000 /* 50.16.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x6B140000 /* 107.20.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x6B140000 /* 107.20.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x17140000 /* 23.20.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x17140000 /* 23.20.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFE00000 /* 255.224.0.0 */) == 0x36E00000 /* 54.224.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFE00000 /* 255.224.0.0 */) == 0x36E00000 /* 54.224.0.0/14 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E330000 /* 46.51.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E330000 /* 46.51.0.0/16 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E890000 /* 46.137.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E890000 /* 46.137.0.0/16 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xB0220000 /* 176.34.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xB0220000 /* 176.34.0.0/16 */)) {
                mmt_internal_add_connection(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
    }
    return 0;
}

int check_gameforge_tcp(ipacket_t * ipacket) {
    //Gameforge may use SSL port 443, skip it when this is the case
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* Skip TCP port 443 */
    if (packet->tcp->source != htons(443) && packet->tcp->dest != htons(443) && packet->tcp->source != htons(80) && packet->tcp->dest != htons(80)) {
        if (packet->iph /* IPv4 only */) {
            /*
             * Gameforge has 79.110.80.0 - 79.110.95.255 (79.110.80.0/22) IP range
             */
            if (((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0x4F6E5000 /* 79.110.80.0 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0x4F6E5000 /* 79.110.80.0 */)) {
                mmt_internal_add_connection(ipacket, PROTO_GAMEFORGE, MMT_REAL_PROTOCOL);
                return 1;
            }
        }
    }
    return 0;
}

int mmt_classify_me_ssl(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    packet->https_server_name.ptr = NULL;
    packet->https_server_name.len = 0;

	if (check_whatsapp(ipacket) || check_viber_tcp(ipacket) || check_gameforge_tcp(ipacket)) {
		return 0;
	}

    if (packet->payload_packet_len <= 12) {
        return 0;
    }

	/*
	 * BW: stage 3 = detected SSL like messages process this as SSL
	 */
	if (flow->l4.tcp.ssl_stage >= 3) {
		mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
		//try to guess from IP address! this is the only way now!
		uint32_t proto = get_proto_id_from_address(ipacket);
		if (proto != PROTO_UNKNOWN) {
			mmt_int_ssl_add_connection(ipacket, proto);
		}
		return 1;
	}

    if (packet->payload[0] == 0x16 && packet->payload[1] == 0x03
            && (packet->payload[2] == 0x00 || packet->payload[2] == 0x01 || packet->payload[2] == 0x02 || packet->payload[2] == 0x03)) {
        if ((packet->payload_packet_len - ntohs(get_u16(packet->payload, 3)) == 5) /* Client Hello contains no other part in the message */
                && (packet->payload[5] == 1 /* Client Hello */) && packet->payload[9] == 0x03
                && (packet->payload[10] == 0x00 || packet->payload[10] == 0x01 || packet->payload[10] == 0x02 || packet->payload[10] == 0x03)
                && (packet->payload_packet_len - ntohs(get_u16(packet->payload, 7)) == 9)) {
            //This is a client hello! process it as so
            mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
            //Now try to get the server from this packet
            uint32_t emb_proto = sslDetectProtocolFromClientHello(ipacket);
            if (emb_proto != PROTO_UNKNOWN) {
                //mmt_int_ssl_add_connection(ipacket, emb_proto);
            }
            return 1;
        } else if ((ntohs(get_u16(packet->payload, 3)) - ntohs(get_u16(packet->payload, 7)) == 4) /* Server Hello may contain different
																									TLS records. compare the record length
																									with the handshake protocol message len */
                && (packet->payload[5] == 2 /* Server Hello */) && (packet->payload[9] == 0x03)
                && (packet->payload[10] == 0x00 || packet->payload[10] == 0x01 || packet->payload[10] == 0x02 || packet->payload[10] == 0x03)) {
            //This is a server hello! process it as so
            mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
            //Now try to parse this message to check if it contains a certificate record
            uint32_t emb_proto = sslDetectProtocolFromServerHello(ipacket);
            if (emb_proto != PROTO_UNKNOWN) {
                //mmt_int_ssl_add_connection(ipacket, emb_proto);
            }
            return 1;
        } else if ( /* Multiple handshake messages. We have seen the Client Hello the Server sends multiple handshake messages */
				(packet->detected_protocol_stack[0] == PROTO_SSL)
                && (packet->payload[5] == 2 /* Server Hello */) && (packet->payload[9] == 0x03)
                && (packet->payload[10] == 0x00 || packet->payload[10] == 0x01 || packet->payload[10] == 0x02 || packet->payload[10] == 0x03)) {
            //This is a server hello! process it as so
            mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
            //Now try to parse this message to check if it contains a certificate record
            uint32_t emb_proto = sslDetectProtocolFromServerHello(ipacket);
            if (emb_proto != PROTO_UNKNOWN) {
                //mmt_int_ssl_add_connection(ipacket, emb_proto);
            }
            return 1;
        } else if ((ntohs(get_u16(packet->payload, 3)) - ntohs(get_u16(packet->payload, 7)) == 4) /* Certificate may contain different
																									TLS records. compare the record length
																									with the handshake protocol message len */
                && (ntohs(get_u16(packet->payload, 7)) - ntohs(get_u16(packet->payload, 10)) == 3) /* Record len is 3 bytes longer than the certificates len */
                && (packet->payload[5] == 11 /* Server Certificate */)
                ) {
            //This is a server certificate! process it as so
            mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
            //Now try to parse this certificate to get the subject and try to get the corresonding protocol
            uint32_t emb_proto = sslDetectProtocolFromServerCertificate(ipacket);
            if (emb_proto != PROTO_UNKNOWN) {
                //mmt_int_ssl_add_connection(ipacket, emb_proto);
            }
            return 1;
        } else {
            // SSLv3 Record
            MMT_LOG(PROTO_SSL, MMT_LOG_DEBUG, "sslv3 len match\n");
            flow->l4.tcp.ssl_stage += 1;
        }
    }

	// SSLv2 Record
	/* BW: Who the hell is still using SSL2.0 !!!!! */
	if (packet->payload[2] == 0x01 && packet->payload[3] == 0x03
		&& (packet->payload[4] == 0x00 || packet->payload[4] == 0x01 || packet->payload[4] == 0x02)
		&& (packet->payload_packet_len - packet->payload[1] == 2)) {
	  MMT_LOG(PROTO_SSL, MMT_LOG_DEBUG, "sslv2 len match\n");
	  flow->l4.tcp.ssl_stage += 1;
	  return 4;
	}

	/* BW: Who the hell is still using SSL2.0 !!!!! */
	if (packet->payload[2] == 0x01 && packet->payload[3] == 0x03
		&& (packet->payload[4] == 0x00 || packet->payload[4] == 0x01 || packet->payload[4] == 0x02)
		&& (packet->payload_packet_len - 2) >= packet->payload[1]
		&& (flow->l4.tcp.ssl_stage > 0)) {

		MMT_LOG(PROTO_SSL, MMT_LOG_DEBUG, "sslv2 server len match\n");
   	    flow->l4.tcp.ssl_stage += 1;
	  return 4;
	}

	/* BW: I saw TLS packets less than 40 bytes!
	 * TLS application: 0x17 followed by version (3.0 or 3.1 or 3.2) followed by len */
	if (packet->payload[0] == 0x17 && packet->payload[1] == 0x03
			&& (packet->payload[2] == 0x00 || packet->payload[2] == 0x01 || packet->payload[2] == 0x02 || packet->payload[10] == 0x03)
			&& (packet->payload_packet_len <= (ntohs(get_u16(packet->payload, 3)) + 5))) {
		// SSLv3 Record
		MMT_LOG(PROTO_SSL, MMT_LOG_DEBUG, "sslv3 len match\n");
		flow->l4.tcp.ssl_stage += 1;
		return 4;
	}

	/* BW:
	 * TLS application: 0x15 (encrypted alert) followed by version (3.0 or 3.1 or 3.2) followed by len
	 * TLS encrypted alert! This is SSL
	 * TODO: can we detect the encrypeted alert in stage 0? I don't think so!!!
	 */
	if (packet->payload[0] == 0x15 && packet->payload[1] == 0x03
			&& (packet->payload[2] == 0x00 || packet->payload[2] == 0x01 || packet->payload[2] == 0x02 || packet->payload[10] == 0x03)
			&& (packet->payload_packet_len - ntohs(get_u16(packet->payload, 3)) == 5)) {
		// SSLv3 Record
		MMT_LOG(PROTO_SSL, MMT_LOG_DEBUG, "sslv3 len match\n");
		flow->l4.tcp.ssl_stage += 1;
		return 4;
	}

    if (ipacket->session->data_packet_count_direction[ipacket->session->last_packet_direction] < 8) {
		//Wait for more packets before deciding this is not SSL
        return 4;
    }

    MMT_LOG(PROTO_SSL, MMT_LOG_DEBUG, "exclude ssl\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_SSL);
    return 0;
}

void mmt_init_classify_me_ssl() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SSL);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SSL); //Exclude processing when http is detected! Obvious no?
    //MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_SSL);
}

int mmt_check_ssl(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
        return mmt_classify_me_ssl(ipacket, index);
    }
    return 4;
}

//////////////// SSL attributes
static attribute_metadata_t ssl_attributes_metadata[SSL_ATTRIBUTES_NB] = {
    {SSL_SERVER_NAME, SSL_SERVER_NAME_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ssl_server_name_extraction},
    {TLS_NUMBER_RECORD, TLS_NUMBER_RECORD_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, tls_number_record_extraction},
    {TLS_CONTENT_TYPE, TLS_CONTENT_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, tls_content_type_extraction},
    {TLS_VERSION, TLS_VERSION_ALIAS, MMT_U16_DATA, sizeof (short), 1, SCOPE_PACKET, tls_version_extraction},
    {TLS_LENGTH, TLS_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 3, SCOPE_PACKET, tls_length_extraction},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ssl_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SSL, PROTO_SSL_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;

        for (; i < SSL_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ssl_attributes_metadata[i]);
        }

        mmt_init_classify_me_ssl();

        return register_protocol(protocol_struct, PROTO_SSL);
    } else {
        return 0;
    }
}

