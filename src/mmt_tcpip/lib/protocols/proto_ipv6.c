#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "ipv6.h"
#include "ip_session_id_management.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
/** macro to compare 2 IPv6 addresses with each other to identify the "smaller" IPv6 address  */

bool ipv6_session_comp(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    // both flows of the same type
    int comp_val = memcmp(&l_session->next_proto, &r_session->next_proto, 5);
    if (comp_val == 0) {
   	 comp_val = memcmp(l_session->lower_ip, r_session->lower_ip, IPv6_ALEN);
   	 if (comp_val == 0) {
   		 comp_val = memcmp(l_session->higher_ip, r_session->higher_ip, IPv6_ALEN);
   	 }
    }
    return comp_val < 0;
}

static inline
int is_extention_header(uint8_t next_header) {
    switch (next_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
        case IPPROTO_AH:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH:
            return 1;
        default:
            return 0;
    }
}

static inline
uint32_t get_next_header_offset(uint8_t current_header, const uint8_t * packet, uint8_t * next_hdr) {
    struct ext_hdr_generic * exthdr;
    switch (current_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_AH:
        case IPPROTO_DSTOPTS:
            exthdr = (struct ext_hdr_generic *) packet;
            *next_hdr = exthdr->nexthdr;
            return 8 + ((uint32_t) (exthdr->ext_len) * 8); // The length is provided as the number of 8 octet words not including the first 8 octets
        case IPPROTO_FRAGMENT:
            exthdr = (struct ext_hdr_generic *) packet;
            *next_hdr = exthdr->nexthdr;
            return 8; // The fragment extention header has a fixed length
        case IPPROTO_MH:
        default:
            *next_hdr = IPPROTO_NONE;
            return 0;
    }
}

int ip6_version_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    struct ipv6hdr * ip6_hdr = (struct ipv6hdr *) & packet->data[proto_offset];

    *((unsigned char *) extracted_data->data) = ip6_hdr->l1_1.version;
    return 1;
}

int ip6_traffic_class_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    struct ipv6hdr * ip6_hdr = (struct ipv6hdr *) & packet->data[proto_offset];
    uint8_t tc = (uint8_t) ((ip6_hdr->l1_2.short_word_1 & 0x0FF0) >> 4);
    *((unsigned char *) extracted_data->data) = tc;
    return 1;
}

int ip6_flow_label_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    struct ipv6hdr * ip6_hdr = (struct ipv6hdr *) & packet->data[proto_offset];

    *((unsigned int *) extracted_data->data) = (ip6_hdr->l1_2.short_word_1 & 0x000FFFFF);
    return 1;
}

int ip6_next_proto_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    struct ipv6hdr * ip6_hdr = (struct ipv6hdr *) & packet->data[proto_offset];

    uint8_t  next_hdr    = ip6_hdr->nexthdr;
    uint16_t next_offset = sizeof (struct ipv6hdr);

    while (is_extention_header(next_hdr) && (packet->p_hdr->caplen >= (proto_offset + next_offset + 2))) {
        next_offset += get_next_header_offset(next_hdr, & packet->data[proto_offset + next_offset], & next_hdr);
    }

    // At this level we have either an extention header, NO header or a protocol id header
    if (!is_extention_header(next_hdr) && next_hdr != IPPROTO_NONE) {
        *((unsigned char *) extracted_data->data) = next_hdr;
        return 1;
    }

    return 0;
}

int ip6_client_port_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client)?s_key->lower_ip_port:s_key->higher_ip_port;
        return 1;
    }
    return 0;
}

int ip6_server_port_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client)?s_key->higher_ip_port:s_key->lower_ip_port;
        return 1;
    }
    return 0;
}

int ip6_client_addr_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        if(s_key->is_lower_client) {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->lower_ip)->ip, IPv6_ALEN);
        }else {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->higher_ip)->ip, IPv6_ALEN);
        }
        return 1;
    }
    return 0;
}

int ip6_server_addr_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        if(s_key->is_lower_client) {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->higher_ip)->ip, IPv6_ALEN);
        }else {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->lower_ip)->ip, IPv6_ALEN);
        }
        return 1;
    }
    return 0;
}


int build_ipv6_session_key(ipacket_t * ipacket, int offset, mmt_session_key_t * ipv6_session) {
    int retval;
    struct ipv6hdr * ip6h = (struct ipv6hdr *) (struct ipv6hdr *) & ipacket->data[offset];

    uint8_t next_hdr = ip6h->nexthdr;
    uint16_t next_offset = sizeof (struct ipv6hdr);

    while (is_extention_header(next_hdr) && (ipacket->p_hdr->caplen >= (offset + next_offset + 2))) {
        next_offset += get_next_header_offset(next_hdr, & ipacket->data[offset + next_offset], & next_hdr);
    }
    // ipv6_session->lower_ip = (void*)mmt_malloc(sizeof(ip6h->saddr));
    // ipv6_session->higher_ip = (void*)mmt_malloc(sizeof(ip6h->daddr));
    if (MMT_COMPARE_IPV6_ADDRESSES(&ip6h->saddr, &ip6h->daddr)) {
        // memcpy(ipv6_session->lower_ip,&ip6h->saddr,sizeof(ip6h->saddr));
        // memcpy(ipv6_session->higher_ip,&ip6h->daddr,sizeof(ip6h->daddr));
        ipv6_session->lower_ip = &ip6h->saddr;
        ipv6_session->higher_ip = &ip6h->daddr;
        ipv6_session->is_lower_initiator = L2H_DIRECTION;
        ipv6_session->is_lower_client = L2H_DIRECTION;
        retval = L2H_DIRECTION;
    } else {
        // memcpy(ipv6_session->lower_ip,&ip6h->daddr,sizeof(ip6h->daddr));
        // memcpy(ipv6_session->higher_ip,&ip6h->saddr,sizeof(ip6h->saddr));
        ipv6_session->lower_ip = &ip6h->daddr;
        ipv6_session->higher_ip = &ip6h->saddr;
        ipv6_session->is_lower_initiator = H2L_DIRECTION;
        ipv6_session->is_lower_client = H2L_DIRECTION;
        retval = H2L_DIRECTION;
    }

    ipv6_session->ip_type = 6;

    ipv6_session->next_proto = next_hdr;

    if (ipacket->p_hdr->caplen >= (offset + next_offset + 2)) { //The packet contains the first 2 octets of the next header (sufficient to get port numbers)
        // tcp / udp detection
        if (ipv6_session->next_proto == 6) {
            const struct tcphdr *tcph = (struct tcphdr *) & ipacket->data[offset + next_offset];
            if (ipv6_session->is_lower_initiator) {
                ipv6_session->lower_ip_port = ntohs(tcph->source);
                ipv6_session->higher_ip_port = ntohs(tcph->dest);
            } else {
                ipv6_session->lower_ip_port = ntohs(tcph->dest);
                ipv6_session->higher_ip_port = ntohs(tcph->source);
            }
        } else if (ipv6_session->next_proto == 17) {
            const struct udphdr *udph = (struct udphdr *) & ipacket->data[offset + next_offset];
            if (ipv6_session->is_lower_initiator) {
                ipv6_session->lower_ip_port = ntohs(udph->source);
                ipv6_session->higher_ip_port = ntohs(udph->dest);
            } else {
                ipv6_session->lower_ip_port = ntohs(udph->dest);
                ipv6_session->higher_ip_port = ntohs(udph->source);
            }
        } else {
            // non tcp/udp protocols, one connection between two ip addresses
            ipv6_session->lower_ip_port = 0;
            ipv6_session->higher_ip_port = 0;
        }
    } else {
        // Next header does not exist!
        ipv6_session->lower_ip_port = 0;
        ipv6_session->higher_ip_port = 0;
    }

    return retval;
}

int ip6_session_cleanup_on_timeout(void * protocol_context, mmt_session_t * timedout_session, void * args) {
    //Remove the session from the sessions hash
    delete_session_from_protocol_context(protocol_context, timedout_session->session_key); //TODO: we are not verifying the return of the delete

    // free session allocated memory. be careful about multiple free of the same data.
    // In the closup some session data are freed. These should not be the same as here.
    free_session_data(timedout_session->session_key, timedout_session, ((protocol_instance_t *) protocol_context)->args);

    return 0;
}

void * ip6_sessionizer(void * protocol_context, ipacket_t * ipacket, unsigned index, int * is_new_session) {
    int offset = get_packet_offset_at_index(ipacket, index);
    mmt_session_key_t ipv6_session_key;
    int packet_direction;

    // Get the session of this packet and set it to the packet's session
    packet_direction = build_ipv6_session_key(ipacket, offset, &ipv6_session_key);

    mmt_session_t * session = get_session(protocol_context, &ipv6_session_key, ipacket, is_new_session);
    if(session) {
        if(session->last_packet_direction != packet_direction && session->packet_count>0){
            ip_rtt_t ip_rtt;
            ip_rtt.direction = session->last_packet_direction;
            ip_rtt.session = session;
            ip_rtt.rtt.tv_sec = ipacket->p_hdr->ts.tv_sec - session->s_last_activity_time.tv_sec;
            ip_rtt.rtt.tv_usec = ipacket->p_hdr->ts.tv_usec - session->s_last_activity_time.tv_usec;
            if((int) ip_rtt.rtt.tv_usec < 0) {
                ip_rtt.rtt.tv_usec += 1000000;
                ip_rtt.rtt.tv_sec -= 1;
            }
            fire_attribute_event(ipacket, PROTO_IPV6, IP6_RTT, index, (void *) &(ip_rtt));
        }
        
        // Fix proto_path , only fix til IP
        if (session->proto_path.proto_path[index] != PROTO_IPV6) {
            // debug("[IP6] Fixing proto_path of session: %lu", session->session_id);
            // Get PROTO_IPV6 index in current proto_path
            int j, ip_index = 0;
            for (j = 0; j < session->proto_path.len; j++) {
                if (session->proto_path.proto_path[j] == PROTO_IPV6) {
                    ip_index = j;
                    break;
                }
            }

            // debug("[IP6] Current index of PROTO_IPV6: %d / (packet)%d", ip_index, index);
            if (ip_index != 0) {
                if (ip_index > index) {
                    // debug("[IP6] Current protocol_path need to remove some protocol");
                    int pre_path = 0, post_path = ip_index + 1;

                    for (pre_path = 0; pre_path <= index; pre_path++)
                    {
                        session->proto_path.proto_path[pre_path] = ipacket->proto_hierarchy->proto_path[pre_path];
                        session->proto_headers_offset.proto_path[pre_path] = ipacket->proto_headers_offset->proto_path[pre_path];
                        session->proto_classif_status.proto_path[pre_path] = ipacket->proto_classif_status->proto_path[pre_path];
                    }
                    for (post_path = ip_index + 1; post_path < session->proto_path.len; post_path++, pre_path++) {
                        session->proto_path.proto_path[pre_path] = session->proto_path.proto_path[post_path];
                        session->proto_headers_offset.proto_path[pre_path] = session->proto_headers_offset.proto_path[post_path];
                        session->proto_classif_status.proto_path[pre_path] = session->proto_classif_status.proto_path[post_path];
                    }
                    session->proto_path.len = pre_path;
                    session->proto_headers_offset.len = pre_path;
                    session->proto_classif_status.len = pre_path;
                    // debug("[IP6] New protocol_path len %d", pre_path);
                } else {
                    // debug("[IP6] Current protocol_path need to add some protocol from packet hierarchy");
                    int delta = index - ip_index;
                    int new_len = session->proto_path.len + delta;
                    int pre_path = 0, post_path = new_len - 1;

                    for (post_path = new_len - 1; post_path > ip_index; post_path--) {
                        session->proto_path.proto_path[post_path] = session->proto_path.proto_path[post_path - delta];
                        session->proto_headers_offset.proto_path[post_path] = session->proto_headers_offset.proto_path[post_path - delta];
                        session->proto_classif_status.proto_path[post_path] = session->proto_classif_status.proto_path[post_path - delta];
                    }

                    for (pre_path = 0; pre_path <= index; pre_path++)
                    {
                        session->proto_path.proto_path[pre_path] = ipacket->proto_hierarchy->proto_path[pre_path];
                        session->proto_headers_offset.proto_path[pre_path] = ipacket->proto_headers_offset->proto_path[pre_path];
                        session->proto_classif_status.proto_path[pre_path] = ipacket->proto_classif_status->proto_path[pre_path];
                    }

                    session->proto_path.len = new_len;
                    session->proto_headers_offset.len = new_len;
                    session->proto_classif_status.len = new_len;
                    // debug("[IP6] New protocol_path len %d", new_len);
                }
            }

        }
        session->last_packet_direction = packet_direction;
    }

    return (void *) session;
}

int ip6_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);
    struct ipv6hdr * ip6_hdr = (struct ipv6hdr *) & ipacket->data[offset];

    uint8_t next_hdr = ip6_hdr->nexthdr;
    uint16_t next_offset = sizeof (struct ipv6hdr);

    while (is_extention_header(next_hdr) && (ipacket->p_hdr->caplen >= (offset + next_offset + 2))) {
        next_offset += get_next_header_offset(next_hdr, & ipacket->data[offset + next_offset], & next_hdr);
    }

    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    switch (next_hdr) // Layer 4 protocol identifier
    {
            /* ICMPv4 */
        case 1:
            retval.proto_id = PROTO_ICMP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* IPv4 */
        case 4:
            retval.proto_id = PROTO_IP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* TCP */
        case 6:
            retval.proto_id = PROTO_TCP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* EGP */
        case 8:
            retval.proto_id = PROTO_EGP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* UDP */
        case 17:
            retval.proto_id = PROTO_UDP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* IPv6 */
        case 41:
            retval.proto_id = PROTO_IPV6;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            // GRE
        case 47:
            retval.proto_id = PROTO_GRE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
        case 50:
            retval.proto_id = PROTO_ESP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
        case 51:
            retval.proto_id = PROTO_AH;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
        case 58:
            retval.proto_id = PROTO_ICMPV6;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            //OSPF IGP
        case 89:
            retval.proto_id = PROTO_OSPF;
            retval.offset = next_offset;
            //ipacket->session->tcp_udp_index = index + 1;
            retval.status = Classified;
            break;
            /* // Not valid for IPv6
                   case 94:
                            retval.proto_id = PROTO_IP_IN_IP;
                            retval.offset = next_offset;
                            retval.status = Classified;
                            break;
             */
        case 115:
            retval.proto_id = PROTO_L2TP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
        case 132:
            retval.proto_id = PROTO_SCTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
        case 136:
            retval.proto_id = PROTO_UDPLITE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_GGP */
        case 0x03:
            retval.proto_id = PROTO_GGP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ST */
        case 0x05:
            retval.proto_id = PROTO_ST;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_CBT */
        case 0x07:
            retval.proto_id = PROTO_CBT;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IGP */
        case 0x09:
            retval.proto_id = PROTO_IGP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_BBN_RCC_MON */
        case 0x0A:
            retval.proto_id = PROTO_BBN_RCC_MON;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_NVP_II */
        case 0x0B:
            retval.proto_id = PROTO_NVP_II;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PUP */
        case 0x0C:
            retval.proto_id = PROTO_PUP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ARGUS */
        case 0x0D:
            retval.proto_id = PROTO_ARGUS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_EMCON */
        case 0x0E:
            retval.proto_id = PROTO_EMCON;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_XNET */
        case 0x0F:
            retval.proto_id = PROTO_XNET;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_CHAOS */
        case 0x10:
            retval.proto_id = PROTO_CHAOS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MUX */
        case 0x12:
            retval.proto_id = PROTO_MUX;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_DCN_MEAS */
        case 0x13:
            retval.proto_id = PROTO_DCN_MEAS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_HMP */
        case 0x14:
            retval.proto_id = PROTO_HMP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PRM */
        case 0x15:
            retval.proto_id = PROTO_PRM;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_XNS_IDP */
        case 0x16:
            retval.proto_id = PROTO_XNS_IDP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_TRUNK_1 */
        case 0x17:
            retval.proto_id = PROTO_TRUNK_1;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_TRUNK_2 */
        case 0x18:
            retval.proto_id = PROTO_TRUNK_2;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_LEAF_1 */
        case 0x19:
            retval.proto_id = PROTO_LEAF_1;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_LEAF_2 */
        case 0x1A:
            retval.proto_id = PROTO_LEAF_2;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IRTP */
        case 0x1C:
            retval.proto_id = PROTO_IRTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ISO_TP4 */
        case 0x1D:
            retval.proto_id = PROTO_ISO_TP4;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_NETBLT */
        case 0x1E:
            retval.proto_id = PROTO_NETBLT;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MFE_NSP */
        case 0x1F:
            retval.proto_id = PROTO_MFE_NSP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MERIT_INP */
        case 0x20:
            retval.proto_id = PROTO_MERIT_INP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_DCCP */
        case 0x21:
            retval.proto_id = PROTO_DCCP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_3PC */
        case 0x22:
            retval.proto_id = PROTO_3PC;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IDPR */
        case 0x23:
            retval.proto_id = PROTO_IDPR;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_XTP */
        case 0x24:
            retval.proto_id = PROTO_XTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_DDP */
        case 0x25:
            retval.proto_id = PROTO_DDP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IDPR_CMTP */
        case 0x26:
            retval.proto_id = PROTO_IDPR_CMTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_TP_PP */
        case 0x27:
            retval.proto_id = PROTO_TP_PP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IL */
        case 0x28:
            retval.proto_id = PROTO_IL;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SDRP */
        case 0x2A:
            retval.proto_id = PROTO_SDRP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IDRP */
        case 0x2D:
            retval.proto_id = PROTO_IDRP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_RSVP */
        case 0x2E:
            retval.proto_id = PROTO_RSVP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MHRP */
        case 0x30:
            retval.proto_id = PROTO_MHRP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_BNA */
        case 0x31:
            retval.proto_id = PROTO_BNA;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_I_NLSP */
        case 0x34:
            retval.proto_id = PROTO_I_NLSP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SWIPE */
        case 0x35:
            retval.proto_id = PROTO_SWIPE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_NARP */
        case 0x36:
            retval.proto_id = PROTO_NARP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MOBILE */
        case 0x37:
            retval.proto_id = PROTO_MOBILE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_TLSP */
        case 0x38:
            retval.proto_id = PROTO_TLSP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SKIP */
        case 0x39:
            retval.proto_id = PROTO_SKIP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ANY_HIP */
        case 0x3D:
            retval.proto_id = PROTO_ANY_HIP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_CFTP */
        case 0x3E:
            retval.proto_id = PROTO_CFTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ANY_LOCAL */
        case 0x3F:
            retval.proto_id = PROTO_ANY_LOCAL;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SAT_EXPAK */
        case 0x40:
            retval.proto_id = PROTO_SAT_EXPAK;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_KRYPTOLAN */
        case 0x41:
            retval.proto_id = PROTO_KRYPTOLAN;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_RVD */
        case 0x42:
            retval.proto_id = PROTO_RVD;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IPPC */
        case 0x43:
            retval.proto_id = PROTO_IPPC;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ANY_DFS */
        case 0x44:
            retval.proto_id = PROTO_ANY_DFS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SAT_MON */
        case 0x45:
            retval.proto_id = PROTO_SAT_MON;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_VISA */
        case 0x46:
            retval.proto_id = PROTO_VISA;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IPCV */
        case 0x47:
            retval.proto_id = PROTO_IPCV;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_CPNX */
        case 0x48:
            retval.proto_id = PROTO_CPNX;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_CPHB */
        case 0x49:
            retval.proto_id = PROTO_CPHB;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_WSN */
        case 0x4A:
            retval.proto_id = PROTO_WSN;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PVP */
        case 0x4B:
            retval.proto_id = PROTO_PVP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_BR_SAT_MON */
        case 0x4C:
            retval.proto_id = PROTO_BR_SAT_MON;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SUN_ND */
        case 0x4D:
            retval.proto_id = PROTO_SUN_ND;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_WB_MON */
        case 0x4E:
            retval.proto_id = PROTO_WB_MON;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_WB_EXPAK */
        case 0x4F:
            retval.proto_id = PROTO_WB_EXPAK;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ISO_IP */
        case 0x50:
            retval.proto_id = PROTO_ISO_IP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_VMTP */
        case 0x51:
            retval.proto_id = PROTO_VMTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SECURE_VMTP */
        case 0x52:
            retval.proto_id = PROTO_SECURE_VMTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_VINES */
        case 0x53:
            retval.proto_id = PROTO_VINES;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IPTM */
        case 0x54:
            retval.proto_id = PROTO_IPTM;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_NSFNET_IGP */
        case 0x55:
            retval.proto_id = PROTO_NSFNET_IGP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_DGP */
        case 0x56:
            retval.proto_id = PROTO_DGP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_TCF */
        case 0x57:
            retval.proto_id = PROTO_TCF;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_EIGRP */
        case 0x58:
            retval.proto_id = PROTO_EIGRP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SPRITE_RPC */
        case 0x5A:
            retval.proto_id = PROTO_SPRITE_RPC;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_LARP */
        case 0x5B:
            retval.proto_id = PROTO_LARP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MTP */
        case 0x5C:
            retval.proto_id = PROTO_MTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_AX_25 */
        case 0x5D:
            retval.proto_id = PROTO_AX_25;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MICP */
        case 0x5F:
            retval.proto_id = PROTO_MICP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SCC_SP */
        case 0x60:
            retval.proto_id = PROTO_SCC_SP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ETHERIP */
        case 0x61:
            retval.proto_id = PROTO_ETHERIP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ENCAP */
        case 0x62:
            retval.proto_id = PROTO_ENCAP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ANY_PES */
        case 0x63:
            retval.proto_id = PROTO_ANY_PES;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_GMTP */
        case 0x64:
            retval.proto_id = PROTO_GMTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IFMP */
        case 0x65:
            retval.proto_id = PROTO_IFMP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PNNI */
        case 0x66:
            retval.proto_id = PROTO_PNNI;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PIM */
        case 0x67:
            retval.proto_id = PROTO_PIM;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ARIS */
        case 0x68:
            retval.proto_id = PROTO_ARIS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SCPS */
        case 0x69:
            retval.proto_id = PROTO_SCPS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_QNX */
        case 0x6A:
            retval.proto_id = PROTO_QNX;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IPCOMP */
        case 0x6C:
            retval.proto_id = PROTO_IPCOMP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SNP */
        case 0x6D:
            retval.proto_id = PROTO_SNP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_COMPAQ_PEER */
        case 0x6E:
            retval.proto_id = PROTO_COMPAQ_PEER;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IPX_IN_IP */
        case 0x6F:
            retval.proto_id = PROTO_IPX_IN_IP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_VRRP */
        case 0x70:
            retval.proto_id = PROTO_VRRP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PGM */
        case 0x71:
            retval.proto_id = PROTO_PGM;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_ANY_0HOP */
        case 0x72:
            retval.proto_id = PROTO_ANY_0HOP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_DDX */
        case 0x74:
            retval.proto_id = PROTO_DDX;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IATP */
        case 0x75:
            retval.proto_id = PROTO_IATP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_STP */
        case 0x76:
            retval.proto_id = PROTO_STP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SRP */
        case 0x77:
            retval.proto_id = PROTO_SRP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_UTI */
        case 0x78:
            retval.proto_id = PROTO_UTI;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SMP */
        case 0x79:
            retval.proto_id = PROTO_SMP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SM */
        case 0x7A:
            retval.proto_id = PROTO_SM;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PTP */
        case 0x7B:
            retval.proto_id = PROTO_PTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IS_IS */
        case 0x7C:
            retval.proto_id = PROTO_IS_IS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_FIRE */
        case 0x7D:
            retval.proto_id = PROTO_FIRE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_CRTP */
        case 0x7E:
            retval.proto_id = PROTO_CRTP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_CRUDP */
        case 0x7F:
            retval.proto_id = PROTO_CRUDP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SSCOPMCE */
        case 0x80:
            retval.proto_id = PROTO_SSCOPMCE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_IPLT */
        case 0x81:
            retval.proto_id = PROTO_IPLT;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SPS */
        case 0x82:
            retval.proto_id = PROTO_SPS;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_PIPE */
        case 0x83:
            retval.proto_id = PROTO_PIPE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_FC */
        case 0x85:
            retval.proto_id = PROTO_FC;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_RSVP_E2E_IGNORE */
        case 0x86:
            retval.proto_id = PROTO_RSVP_E2E_IGNORE;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MOBILITY_HEADER */
        case 0x87:
            retval.proto_id = PROTO_MOBILITY_HEADER;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_MPLS_IN_IP */
        case 0x89:
            retval.proto_id = PROTO_MPLS_IN_IP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_HIP */
        case 0x8B:
            retval.proto_id = PROTO_HIP;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
            /* PROTO_SHIM6 */
        case 0x8C:
            retval.proto_id = PROTO_SHIM6;
            retval.offset = next_offset;
            retval.status = Classified;
            break;
        default:
            return 0;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

void ipv6_context_cleanup(void * proto_context, void * args) {
    close_session_id_lists(proto_context);
    cleanup_ipv6_internal_context(((protocol_instance_t *) proto_context)->args);
    close_ipv6_internal_context(proto_context);
}

void * setup_ipv6_context(void * proto_context, void * args) {
    return (void *) setup_ipv6_internal_context();
    //setup_application_detection();
    //setup_session_id_lists();
}

static attribute_metadata_t ip6_attributes_metadata[IP6_ATTRIBUTES_NB] = {
    {IP6_VERSION, IP6_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip6_version_extraction},
    {IP6_TRAFFIC_CLASS, IP6_TRAFFIC_CLASS_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip6_traffic_class_extraction},
    {IP6_FLOW_LABEL, IP6_FLOW_LABEL_ALIAS, MMT_U32_DATA, sizeof (int), 0, SCOPE_PACKET, ip6_flow_label_extraction},
    {IP6_PAYLOAD_LEN, IP6_PAYLOAD_LEN_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP6_NEXT_HEADER, IP6_NEXT_HEADER_ALIAS, MMT_U8_DATA, sizeof (char), 6, SCOPE_PACKET, general_char_extraction},
    {IP6_NEXT_PROTO, IP6_NEXT_PROTO_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_next_proto_extraction},
    {IP6_HOP_LIMIT, IP6_HOP_LIMIT_ALIAS, MMT_U8_DATA, sizeof (char), 7, SCOPE_PACKET, general_char_extraction},
    {IP6_SRC, IP6_SRC_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, 8, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP6_DST, IP6_DST_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, 24, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP6_CLIENT_ADDR, IP6_CLIENT_ADDR_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_client_addr_extraction},
    {IP6_SERVER_ADDR, IP6_SERVER_ADDR_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_server_addr_extraction},
    {IP6_CLIENT_PORT, IP6_CLIENT_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_client_port_extraction},
    {IP6_SERVER_PORT, IP6_SERVER_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_server_port_extraction},
};

int ipv6_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    /* IP is a flow based protocol. If at this level the flow associated to this packet is null
     * stop the classification procedure by returning zero. For IPv6 this should never happen
     * (fragmentation in IPv6 is different than IPv4).
     */
    if (ipacket->session == NULL) {
        return 0;
    }
    return 1;
}

int ipv6_post_classification_function(ipacket_t * ipacket, unsigned index) {
    if(ipacket->mmt_handler->has_reassembly){
        int s = sizeof(mmt_tcpip_internal_packet_t);
        ipacket->internal_packet = mmt_malloc (s);
        memset(ipacket->internal_packet, 0, s);
        ipacket->internal_packet->udp = NULL;
        ipacket->internal_packet->tcp = NULL;
        ipacket->internal_packet->packet_id = ipacket->packet_id;
    }else {
        ipacket->internal_packet = &((internal_ip_proto_context_t *) ((protocol_instance_t *) ipacket->session->protocol_container_context)->args)->packet;    
    }  
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;

    int ip_offset = get_packet_offset_at_index(ipacket, index);
    struct mmt_ipv6hdr *ip6h = (struct mmt_ipv6hdr *) & ipacket->data[ip_offset];

    uint32_t time = ((uint64_t) ipacket->p_hdr->ts.tv_sec) * MMT_MICRO_IN_SEC + ipacket->p_hdr->ts.tv_usec;
    packet->tick_timestamp = time;

    struct mmt_internal_tcpip_id_struct * src = NULL;
    struct mmt_internal_tcpip_id_struct * dst = NULL;

    packet->iph = NULL;
    packet->iphv6 = (struct mmt_ipv6hdr *) ip6h;
    packet->l3_packet_len = (ipacket->p_hdr->len - ip_offset);
    /* BW: add the length of the truncated packet as well */
    packet->l3_captured_packet_len = (ipacket->p_hdr->caplen - ip_offset);

    if (memcmp(&((mmt_ip6_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->higher_ip)->ip.s6_addr,
            &ip6h->saddr, IPv6_ALEN) == 0) {
        src = &((mmt_ip6_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->higher_ip)->id_internal_context;
        dst = &((mmt_ip6_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->lower_ip)->id_internal_context;
    } else {
        dst = &((mmt_ip6_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->higher_ip)->id_internal_context;
        src = &((mmt_ip6_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->lower_ip)->id_internal_context;
    }

    packet->flow = ipacket->session->internal_data;
    packet->src = src;
    packet->dst = dst;

    /* build selction packet bitmask */
    packet->mmt_selection_packet = MMT_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
    packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

    ipacket->session->packet_count_direction[ipacket->session->last_packet_direction]++;
    ipacket->session->packet_cap_count_direction[ipacket->session->last_packet_direction] += ipacket->nb_reassembled_packets;
    ipacket->session->data_volume_direction[ipacket->session->last_packet_direction] += ipacket->p_hdr->len;
    ipacket->session->data_cap_volume_direction[ipacket->session->last_packet_direction] += ipacket->total_caplen;
    return 1;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ipv6_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IPV6, PROTO_IPV6_ALIAS);

    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < IP6_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ip6_attributes_metadata[i]);
        }

        register_classification_function(protocol_struct, ip6_classify_next_proto);
        register_pre_post_classification_functions(protocol_struct, ipv6_pre_classification_function, ipv6_post_classification_function);

        register_sessionizer_function(protocol_struct, ip6_sessionizer, ip6_session_cleanup_on_timeout, ipv6_session_comp);

        register_proto_context_init_cleanup_function(protocol_struct, setup_ipv6_context, ipv6_context_cleanup, NULL);

        return register_protocol(protocol_struct, PROTO_IPV6);
    } else {
        return 0;
    }
}


