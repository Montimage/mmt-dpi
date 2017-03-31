
#include <string.h> // memcpy()

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "mmt_common_internal_include.h"

#include "ip.h"
#include "ip_session_id_management.h"
#include "proto_ip_dgram.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

bool ip_session_comp(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    if (l_session->ip_type != r_session->ip_type) return (l_session->ip_type < r_session->ip_type);

    // both flows of the same type
    int comp_val = memcmp(&l_session->next_proto, &r_session->next_proto, 5);
    if (comp_val == 0) {
        if (l_session->ip_type == 4) {
            comp_val = memcmp(l_session->lower_ip, r_session->lower_ip, IPv4_ALEN);
            if (comp_val == 0) {
                comp_val = memcmp(l_session->higher_ip, r_session->higher_ip, IPv4_ALEN);
            }
        } else {
            comp_val = memcmp(l_session->lower_ip, r_session->lower_ip, IPv6_ALEN);
            if (comp_val == 0) {
                comp_val = memcmp(l_session->higher_ip, r_session->higher_ip, IPv6_ALEN);
            }
        }
    }
    return comp_val < 0;
}


bool ipv4_session_comp(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    int comp_val;
    comp_val = l_session->next_proto - r_session->next_proto;

    if( comp_val == 0 )
   	 comp_val = l_session->lower_ip_port - r_session->lower_ip_port;

    if( comp_val == 0 )
   	 comp_val = l_session->higher_ip_port - r_session->higher_ip_port;

    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->higher_ip)[0] - ((char *)r_session->higher_ip)[0];
    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->higher_ip)[1] - ((char *)r_session->higher_ip)[1];
    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->higher_ip)[2] - ((char *)r_session->higher_ip)[2];
    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->higher_ip)[3] - ((char *)r_session->higher_ip)[3];

    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->lower_ip)[0] - ((char *)r_session->lower_ip)[0];
    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->lower_ip)[1] - ((char *)r_session->lower_ip)[1];
    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->lower_ip)[2] - ((char *)r_session->lower_ip)[2];
    if( comp_val == 0 )
   	 comp_val = ((char *)l_session->lower_ip)[3] - ((char *)r_session->lower_ip)[3];

    return comp_val < 0;
}
/*
 * IP data extraction routines
 */

int ip_version_extraction(const ipacket_t * packet, unsigned proto_index,
                          attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);

    struct iphdr * ip_hdr = (struct iphdr *) (& packet->data[proto_offset]);
    *((unsigned char *) extracted_data->data) = ip_hdr->version;
    return 1;
}

int ip_ihl_extraction(const ipacket_t * packet, unsigned proto_index,
                      attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);

    struct iphdr * ip_hdr = (struct iphdr *) (& packet->data[proto_offset]);
    *((unsigned char *) extracted_data->data) = ip_hdr->ihl * 4;
    return 1;
}

int ip_df_extraction(const ipacket_t * packet, unsigned proto_index,
                     attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);

    if (*((unsigned char *) & packet->data[proto_offset + attribute_offset]) & 0x40) {
        *((unsigned char *) extracted_data->data) = 1;
    } else {
        *((unsigned char *) extracted_data->data) = 0;
    }
    return 1;
}

int ip_mf_extraction(const ipacket_t * packet, unsigned proto_index,
                     attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);

    if (*((unsigned char *) & packet->data[proto_offset + attribute_offset]) & 0x20) {
        *((unsigned char *) extracted_data->data) = 1;
    } else {
        *((unsigned char *) extracted_data->data) = 0;
    }
    return 1;
}

int ip_frag_offset_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);

    *((unsigned short *) extracted_data->data) = (ntohs(*((unsigned short *) & packet->data[proto_offset + attribute_offset])) & 0x1fff)<<3;
    return 1;
}

int ip_client_port_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client) ? s_key->lower_ip_port : s_key->higher_ip_port;
        return 1;
    }
    return 0;
}

int ip_server_port_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client) ? s_key->higher_ip_port : s_key->lower_ip_port;
        return 1;
    }
    return 0;
}

int ip_client_addr_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned int *) extracted_data->data) = (s_key->is_lower_client) ? ((mmt_ip4_id_t *) s_key->lower_ip)->ip : ((mmt_ip4_id_t *) s_key->higher_ip)->ip;
        return 1;
    }
    return 0;
}

int ip_server_addr_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned int *) extracted_data->data) = (s_key->is_lower_client) ? ((mmt_ip4_id_t *) s_key->higher_ip)->ip : ((mmt_ip4_id_t *) s_key->lower_ip)->ip;
        return 1;
    }
    return 0;
}

/*
 * IP options extraction routines
 */

int ip_options_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //protocol_t * protocol_struct = get_protocol_struct_by_id(protocol_id);
    //int attribute_offset = protocol_struct->get_attribute_position(protocol_id, attribute_id);
    //int attr_data_len = protocol_struct->get_attribute_length(protocol_id, attribute_id);

    struct iphdr * ip_hdr = (struct iphdr *) (& packet->data[proto_offset]);
    int ihl = ip_hdr->ihl;
    extracted_data->data = NULL;
    if (ihl > 5) {
        ip_hdr = ip_hdr + 5 * 4;
        extracted_data->data = (unsigned char *) ip_hdr;
        return 1;
    }
    return 0;
}


/*
 * End of IP data extraction routines
 */


static inline uint8_t build_ipv4_session_key(u_char * ip_packet, mmt_session_key_t * ipv4_session) {
    uint8_t retval;
    uint16_t sport = 0, dport = 0;
    struct iphdr * iph = (struct iphdr *) ip_packet;
    ipv4_session->next_proto = iph->protocol;
    /* tcp / udp detection */
    if (ipv4_session->next_proto == 6) {
        const struct tcphdr *tcph = (struct tcphdr *) & ip_packet[iph->ihl * 4];
        sport = ntohs(tcph->source);
        dport = ntohs(tcph->dest);
    } else if (ipv4_session->next_proto == 17) {
        const struct udphdr *udph = (struct udphdr *) & ip_packet[iph->ihl * 4];
        sport = ntohs(udph->source);
        dport = ntohs(udph->dest);
    }
    // ipv4_session->lower_ip = (void*)mmt_malloc(sizeof(iph->saddr));
    // ipv4_session->higher_ip = (void*)mmt_malloc(sizeof(iph->daddr));
    if (iph->saddr < iph->daddr) {
        // memcpy(ipv4_session->lower_ip,&iph->saddr,sizeof(iph->saddr));
        // memcpy(ipv4_session->higher_ip,&iph->daddr,sizeof(iph->daddr));
        ipv4_session->lower_ip = &iph->saddr;
        ipv4_session->higher_ip = &iph->daddr;
        
        ipv4_session->lower_ip_port = sport;
        ipv4_session->higher_ip_port = dport;

        ipv4_session->is_lower_initiator = L2H_DIRECTION;
        ipv4_session->is_lower_client = L2H_DIRECTION;
        retval = L2H_DIRECTION;
    } else if (iph->saddr == iph->daddr) {
        if (sport < dport) {
            // memcpy(ipv4_session->lower_ip,&iph->saddr,sizeof(iph->saddr));
            // memcpy(ipv4_session->higher_ip,&iph->daddr,sizeof(iph->daddr));
            ipv4_session->lower_ip = &iph->saddr;
            ipv4_session->higher_ip = &iph->daddr;
            ipv4_session->lower_ip_port = sport;
            ipv4_session->higher_ip_port = dport;
            ipv4_session->is_lower_initiator = L2H_DIRECTION;
            ipv4_session->is_lower_client = L2H_DIRECTION;
            retval = L2H_DIRECTION;
        } else {
            // memcpy(ipv4_session->lower_ip,&iph->daddr,sizeof(iph->daddr));
            // memcpy(ipv4_session->higher_ip,&iph->saddr,sizeof(iph->saddr));
            ipv4_session->lower_ip = &iph->daddr;
            ipv4_session->higher_ip = &iph->saddr;
            ipv4_session->lower_ip_port = dport;
            ipv4_session->higher_ip_port = sport;
            ipv4_session->is_lower_initiator = H2L_DIRECTION;
            ipv4_session->is_lower_client = H2L_DIRECTION;
            retval = H2L_DIRECTION;
        }
    } else {
        // memcpy(ipv4_session->lower_ip,&iph->daddr,sizeof(iph->daddr));
        // memcpy(ipv4_session->higher_ip,&iph->saddr,sizeof(iph->saddr));
        ipv4_session->lower_ip = &iph->daddr;
        ipv4_session->higher_ip = &iph->saddr;
        ipv4_session->lower_ip_port = dport;
        ipv4_session->higher_ip_port = sport;
        ipv4_session->is_lower_initiator = H2L_DIRECTION;
        ipv4_session->is_lower_client = H2L_DIRECTION;
        retval = H2L_DIRECTION;
    }

    ipv4_session->ip_type = 4;

    return retval;
}

int ip_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    /* If we get here, then the packet is not fragmented. */
    int offset = get_packet_offset_at_index(ipacket, index);
    const struct iphdr * ip_hdr = (struct iphdr *) & ipacket->data[offset];

    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    switch (ip_hdr->protocol) // Layer 4 protocol identifier
    {
    /* ICMPv4 */
    case 1:
        retval.proto_id = PROTO_ICMP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* IGMP */
    case 2:
        retval.proto_id = PROTO_IGMP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    // IPv4
    case 4:
        retval.proto_id = PROTO_IP_IN_IP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* TCP */
    case 6:
        retval.proto_id = PROTO_TCP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* EGP */
    case 8:
        retval.proto_id = PROTO_EGP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* UDP */
    case 17:
        retval.proto_id = PROTO_UDP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    // IPv6
    case 41:
        retval.proto_id = PROTO_IPV6;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    // GRE
    case 47:
        retval.proto_id = PROTO_GRE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 50:
        retval.proto_id = PROTO_ESP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 51:
        retval.proto_id = PROTO_AH;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 58:
        retval.proto_id = PROTO_ICMPV6;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 89:
        retval.proto_id = PROTO_OSPF;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 94:
        retval.proto_id = PROTO_IP_IN_IP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 115:
        retval.proto_id = PROTO_L2TP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 132:
        retval.proto_id = PROTO_SCTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    case 136:
        retval.proto_id = PROTO_UDPLITE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_GGP */
    case 0x03:
        retval.proto_id = PROTO_GGP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ST */
    case 0x05:
        retval.proto_id = PROTO_ST;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_CBT */
    case 0x07:
        retval.proto_id = PROTO_CBT;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IGP */
    case 0x09:
        retval.proto_id = PROTO_IGP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_BBN_RCC_MON */
    case 0x0A:
        retval.proto_id = PROTO_BBN_RCC_MON;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_NVP_II */
    case 0x0B:
        retval.proto_id = PROTO_NVP_II;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PUP */
    case 0x0C:
        retval.proto_id = PROTO_PUP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ARGUS */
    case 0x0D:
        retval.proto_id = PROTO_ARGUS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_EMCON */
    case 0x0E:
        retval.proto_id = PROTO_EMCON;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_XNET */
    case 0x0F:
        retval.proto_id = PROTO_XNET;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_CHAOS */
    case 0x10:
        retval.proto_id = PROTO_CHAOS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MUX */
    case 0x12:
        retval.proto_id = PROTO_MUX;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_DCN_MEAS */
    case 0x13:
        retval.proto_id = PROTO_DCN_MEAS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_HMP */
    case 0x14:
        retval.proto_id = PROTO_HMP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PRM */
    case 0x15:
        retval.proto_id = PROTO_PRM;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_XNS_IDP */
    case 0x16:
        retval.proto_id = PROTO_XNS_IDP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_TRUNK_1 */
    case 0x17:
        retval.proto_id = PROTO_TRUNK_1;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_TRUNK_2 */
    case 0x18:
        retval.proto_id = PROTO_TRUNK_2;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_LEAF_1 */
    case 0x19:
        retval.proto_id = PROTO_LEAF_1;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_LEAF_2 */
    case 0x1A:
        retval.proto_id = PROTO_LEAF_2;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IRTP */
    case 0x1C:
        retval.proto_id = PROTO_IRTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ISO_TP4 */
    case 0x1D:
        retval.proto_id = PROTO_ISO_TP4;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_NETBLT */
    case 0x1E:
        retval.proto_id = PROTO_NETBLT;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MFE_NSP */
    case 0x1F:
        retval.proto_id = PROTO_MFE_NSP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MERIT_INP */
    case 0x20:
        retval.proto_id = PROTO_MERIT_INP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_DCCP */
    case 0x21:
        retval.proto_id = PROTO_DCCP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_3PC */
    case 0x22:
        retval.proto_id = PROTO_3PC;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IDPR */
    case 0x23:
        retval.proto_id = PROTO_IDPR;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_XTP */
    case 0x24:
        retval.proto_id = PROTO_XTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_DDP */
    case 0x25:
        retval.proto_id = PROTO_DDP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IDPR_CMTP */
    case 0x26:
        retval.proto_id = PROTO_IDPR_CMTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_TP_PP */
    case 0x27:
        retval.proto_id = PROTO_TP_PP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IL */
    case 0x28:
        retval.proto_id = PROTO_IL;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SDRP */
    case 0x2A:
        retval.proto_id = PROTO_SDRP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IDRP */
    case 0x2D:
        retval.proto_id = PROTO_IDRP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_RSVP */
    case 0x2E:
        retval.proto_id = PROTO_RSVP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MHRP */
    case 0x30:
        retval.proto_id = PROTO_MHRP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_BNA */
    case 0x31:
        retval.proto_id = PROTO_BNA;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_I_NLSP */
    case 0x34:
        retval.proto_id = PROTO_I_NLSP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SWIPE */
    case 0x35:
        retval.proto_id = PROTO_SWIPE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_NARP */
    case 0x36:
        retval.proto_id = PROTO_NARP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MOBILE */
    case 0x37:
        retval.proto_id = PROTO_MOBILE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_TLSP */
    case 0x38:
        retval.proto_id = PROTO_TLSP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SKIP */
    case 0x39:
        retval.proto_id = PROTO_SKIP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ANY_HIP */
    case 0x3D:
        retval.proto_id = PROTO_ANY_HIP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_CFTP */
    case 0x3E:
        retval.proto_id = PROTO_CFTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ANY_LOCAL */
    case 0x3F:
        retval.proto_id = PROTO_ANY_LOCAL;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SAT_EXPAK */
    case 0x40:
        retval.proto_id = PROTO_SAT_EXPAK;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_KRYPTOLAN */
    case 0x41:
        retval.proto_id = PROTO_KRYPTOLAN;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_RVD */
    case 0x42:
        retval.proto_id = PROTO_RVD;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IPPC */
    case 0x43:
        retval.proto_id = PROTO_IPPC;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ANY_DFS */
    case 0x44:
        retval.proto_id = PROTO_ANY_DFS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SAT_MON */
    case 0x45:
        retval.proto_id = PROTO_SAT_MON;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_VISA */
    case 0x46:
        retval.proto_id = PROTO_VISA;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IPCV */
    case 0x47:
        retval.proto_id = PROTO_IPCV;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_CPNX */
    case 0x48:
        retval.proto_id = PROTO_CPNX;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_CPHB */
    case 0x49:
        retval.proto_id = PROTO_CPHB;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_WSN */
    case 0x4A:
        retval.proto_id = PROTO_WSN;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PVP */
    case 0x4B:
        retval.proto_id = PROTO_PVP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_BR_SAT_MON */
    case 0x4C:
        retval.proto_id = PROTO_BR_SAT_MON;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SUN_ND */
    case 0x4D:
        retval.proto_id = PROTO_SUN_ND;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_WB_MON */
    case 0x4E:
        retval.proto_id = PROTO_WB_MON;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_WB_EXPAK */
    case 0x4F:
        retval.proto_id = PROTO_WB_EXPAK;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ISO_IP */
    case 0x50:
        retval.proto_id = PROTO_ISO_IP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_VMTP */
    case 0x51:
        retval.proto_id = PROTO_VMTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SECURE_VMTP */
    case 0x52:
        retval.proto_id = PROTO_SECURE_VMTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_VINES */
    case 0x53:
        retval.proto_id = PROTO_VINES;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IPTM */
    case 0x54:
        retval.proto_id = PROTO_IPTM;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_NSFNET_IGP */
    case 0x55:
        retval.proto_id = PROTO_NSFNET_IGP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_DGP */
    case 0x56:
        retval.proto_id = PROTO_DGP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_TCF */
    case 0x57:
        retval.proto_id = PROTO_TCF;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_EIGRP */
    case 0x58:
        retval.proto_id = PROTO_EIGRP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SPRITE_RPC */
    case 0x5A:
        retval.proto_id = PROTO_SPRITE_RPC;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_LARP */
    case 0x5B:
        retval.proto_id = PROTO_LARP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MTP */
    case 0x5C:
        retval.proto_id = PROTO_MTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_AX_25 */
    case 0x5D:
        retval.proto_id = PROTO_AX_25;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MICP */
    case 0x5F:
        retval.proto_id = PROTO_MICP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SCC_SP */
    case 0x60:
        retval.proto_id = PROTO_SCC_SP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ETHERIP */
    case 0x61:
        retval.proto_id = PROTO_ETHERIP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ENCAP */
    case 0x62:
        retval.proto_id = PROTO_ENCAP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ANY_PES */
    case 0x63:
        retval.proto_id = PROTO_ANY_PES;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_GMTP */
    case 0x64:
        retval.proto_id = PROTO_GMTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IFMP */
    case 0x65:
        retval.proto_id = PROTO_IFMP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PNNI */
    case 0x66:
        retval.proto_id = PROTO_PNNI;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PIM */
    case 0x67:
        retval.proto_id = PROTO_PIM;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ARIS */
    case 0x68:
        retval.proto_id = PROTO_ARIS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SCPS */
    case 0x69:
        retval.proto_id = PROTO_SCPS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_QNX */
    case 0x6A:
        retval.proto_id = PROTO_QNX;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IPCOMP */
    case 0x6C:
        retval.proto_id = PROTO_IPCOMP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SNP */
    case 0x6D:
        retval.proto_id = PROTO_SNP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_COMPAQ_PEER */
    case 0x6E:
        retval.proto_id = PROTO_COMPAQ_PEER;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IPX_IN_IP */
    case 0x6F:
        retval.proto_id = PROTO_IPX_IN_IP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_VRRP */
    case 0x70:
        retval.proto_id = PROTO_VRRP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PGM */
    case 0x71:
        retval.proto_id = PROTO_PGM;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_ANY_0HOP */
    case 0x72:
        retval.proto_id = PROTO_ANY_0HOP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_DDX */
    case 0x74:
        retval.proto_id = PROTO_DDX;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IATP */
    case 0x75:
        retval.proto_id = PROTO_IATP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_STP */
    case 0x76:
        retval.proto_id = PROTO_STP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SRP */
    case 0x77:
        retval.proto_id = PROTO_SRP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_UTI */
    case 0x78:
        retval.proto_id = PROTO_UTI;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SMP */
    case 0x79:
        retval.proto_id = PROTO_SMP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SM */
    case 0x7A:
        retval.proto_id = PROTO_SM;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PTP */
    case 0x7B:
        retval.proto_id = PROTO_PTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IS_IS */
    case 0x7C:
        retval.proto_id = PROTO_IS_IS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_FIRE */
    case 0x7D:
        retval.proto_id = PROTO_FIRE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_CRTP */
    case 0x7E:
        retval.proto_id = PROTO_CRTP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_CRUDP */
    case 0x7F:
        retval.proto_id = PROTO_CRUDP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SSCOPMCE */
    case 0x80:
        retval.proto_id = PROTO_SSCOPMCE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_IPLT */
    case 0x81:
        retval.proto_id = PROTO_IPLT;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SPS */
    case 0x82:
        retval.proto_id = PROTO_SPS;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_PIPE */
    case 0x83:
        retval.proto_id = PROTO_PIPE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_FC */
    case 0x85:
        retval.proto_id = PROTO_FC;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_RSVP_E2E_IGNORE */
    case 0x86:
        retval.proto_id = PROTO_RSVP_E2E_IGNORE;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MOBILITY_HEADER */
    case 0x87:
        retval.proto_id = PROTO_MOBILITY_HEADER;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_MPLS_IN_IP */
    case 0x89:
        retval.proto_id = PROTO_MPLS_IN_IP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_HIP */
    case 0x8B:
        retval.proto_id = PROTO_HIP;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    /* PROTO_SHIM6 */
    case 0x8C:
        retval.proto_id = PROTO_SHIM6;
        retval.offset = (ip_hdr->ihl * 4);
        retval.status = Classified;
        break;
    default:
        return 0;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

int ip_session_cleanup_on_timeout(void * protocol_context, mmt_session_t * timedout_session, void * args) {
    //Remove the session from the sessions hash
    delete_session_from_protocol_context(protocol_context, timedout_session->session_key); //TODO: we are not verifying the return of the delete

    // free session allocated memory. be careful about multiple free of the same data.
    // In the closup some session data are freed. These should not be the same as here.
    free_session_data(timedout_session->session_key, timedout_session, ((protocol_instance_t *) protocol_context)->args);
//printf("timeout\n");
    return 0;
}

static inline int ip_process_fragment( ipacket_t *ipacket, unsigned index )
{
    mmt_handler_t *mmt = ipacket->mmt_handler;
    mmt_hashmap_t *map = mmt->ip_streams;
    mmt_key_t     key;
    ip_dgram_t    *dg;

    unsigned off = get_packet_offset_at_index( ipacket, index );
    unsigned len = ipacket->p_hdr->caplen - off;

    if ( len < sizeof( struct iphdr )) {
        (void)fprintf( stderr, "*** Warning: malformed packet (not enough data): %lu\n",ipacket->packet_id );
        return 0;
    }

    const struct iphdr *ip = (struct iphdr *)(ipacket->data + off);

    key   = ip->saddr;
    key <<= 32;
    key  |= ip->daddr;
    key <<= 32;
    key  |= ip->id;
    if ( !hashmap_get( map, key, (void**)&dg )) {
        dg = ip_dgram_alloc();
        hashmap_insert_kv( map, key, dg );
    }
    ip_dgram_update( dg, ip, len , ipacket->p_hdr->caplen);
    // Check timed-out for all data gram
    if ( !ip_dgram_is_complete( dg )) {
        // debug("Fragmented packet is incompleted: %lu\n", ipacket->packet_id);
        return 0;
    }
    // At this point, dg is a fully reassembled datagram.
    // -> reconstruct ipacket from dg, and pass it along

    unsigned ioff = off + ( ip->ihl << 2 );
    uint8_t *x = (uint8_t*)mmt_malloc( ioff + dg->len );
    // copy the original ipacket data + IP header
    (void)memcpy( x,        ipacket->data, ioff );
    // copy the IP payload
    (void)memcpy( x + ioff, dg->x,         dg->len );
    ipacket->data = x;
    ipacket->p_hdr->len    = ioff + dg->len;
    ipacket->p_hdr->caplen = ioff + dg->len;
    ipacket->total_caplen  = dg->caplen;
    ipacket->nb_reassembled_packets = dg->nb_packets;
    // debug("Total captured packet: %d\n", dg->nb_packets);
    //hexdump( x, ioff + dg->len );
    hashmap_remove( map, key );
    ip_dgram_free( dg );
    return 1;
}

static inline int mmt_iph_is_fragmented(const struct iphdr *iph)
{
    //#ifdef REQUIRE_FULL_PACKETS
    unsigned ip_off = (ntohs( iph->frag_off ) & IP_OFFSET) << 3;
    unsigned ip_mf  =  ntohs( iph->frag_off ) & IP_MF;
    if (ip_mf != 0) return 1;
    if (ip_off > 0) return 1;
    //#endif
    return 0;
}

void * ip_sessionizer(void * protocol_context, ipacket_t * ipacket, unsigned index, int * is_new_session)
{
    int offset = get_packet_offset_at_index(ipacket, index);
    const struct iphdr * ip_hdr = (struct iphdr *) & ipacket->data[offset];
    mmt_session_key_t ipv4_session_key;
    // ipv4_session_key.lower_ip = NULL;
    // ipv4_session_key.higher_ip = NULL;
    uint8_t packet_direction;

    // uint16_t ip_offset = ntohs(ip_hdr->frag_off);
    // handle fragmented datagrams
    // Check if the packet is a fragment or not
    if (mmt_iph_is_fragmented(ip_hdr)) {
        ipacket->is_fragment = 1;
        // debug("Fragmented packet: %lu\n", ipacket->packet_id);
        if ( !ip_process_fragment( ipacket, index )) {
            *is_new_session = 0;
            return NULL;
        }
    }

    ipacket->is_completed = 1;

    // re-point to the reassempled IP header if reassembly took place
    // points to the same pointer if no fragmentation
    ip_hdr = (struct iphdr *) & ipacket->data[offset];

    // Get the session of this packet and set it to the packet's session
    packet_direction = build_ipv4_session_key((u_char *) ip_hdr, &ipv4_session_key);

    mmt_session_t * session = get_session(protocol_context, & ipv4_session_key, ipacket, is_new_session);
    if (session) {
        if (session->last_packet_direction != packet_direction && session->packet_count > 0) {
            ip_rtt_t ip_rtt;
            ip_rtt.direction = session->last_packet_direction;
            ip_rtt.session   = session;
            ip_rtt.rtt.tv_sec = ipacket->p_hdr->ts.tv_sec - session->s_last_activity_time.tv_sec;
            ip_rtt.rtt.tv_usec = ipacket->p_hdr->ts.tv_usec - session->s_last_activity_time.tv_usec;
            if ((int) ip_rtt.rtt.tv_usec < 0) {
                ip_rtt.rtt.tv_usec += 1000000;
                ip_rtt.rtt.tv_sec -= 1;
            }
            fire_attribute_event(ipacket, PROTO_IP, IP_RTT, index, (void *) & (ip_rtt));
        }


        // Fix proto_path , only fix til IP
        // TODO: May be need to fix for ipacket->proto_headers_offset = &session->proto_headers_offset and ipacket->proto_classif_status = &session->proto_classif_status;
        if (session->proto_path.proto_path[index] != PROTO_IP) {
            // debug("[IP] Fixing proto_path of session: %lu", session->session_id);
            // Get PROTO_IP index in current proto_path
            int j, ip_index = 0;
            for (j = 0; j < session->proto_path.len; j++) {
                if (session->proto_path.proto_path[j] == PROTO_IP) {
                    ip_index = j;
                    break;
                }
            }

            // debug("[IP] Current index of PROTO_IP: %d / (packet)%d", ip_index, index);
            if (ip_index != 0) {
                if (ip_index > index) {
                    // debug("[IP] Current protocol_path need to remove some protocol");
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
                    // debug("[IP] New protocol_path len %d", pre_path);
                } else {
                    // debug("[IP] Current protocol_path need to add some protocol from packet hierarchy");
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
                    // debug("[IP] New protocol_path len %d", new_len);
                }
            }

        }

        session->last_packet_direction = packet_direction;

    }
    return (void *) session;
}

void ip_context_cleanup(void * proto_context, void * args) {
    close_session_id_lists(proto_context);
    cleanup_ipv4_internal_context(((protocol_instance_t *) proto_context)->args);
    close_ipv4_internal_context(proto_context);
}

void * setup_ip_context(void * proto_context, void * args) {
    return (void *) setup_ipv4_internal_context();
    //setup_application_detection();
    //setup_session_id_lists();
}

static attribute_metadata_t ip_attributes_metadata[IP_ATTRIBUTES_NB] = {
    {IP_VERSION, IP_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip_version_extraction},
    {IP_HEADER_LEN, IP_HEADER_LEN_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip_ihl_extraction},
    {IP_PROTO_TOS, IP_PROTO_TOS_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP_TOT_LEN, IP_TOT_LEN_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP_IDENTIFICATION, IP_IDENTIFICATION_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP_DF_FLAG, IP_DF_FLAG_ALIAS, MMT_U8_DATA, sizeof (char), 6, SCOPE_PACKET, ip_df_extraction},
    {IP_MF_FLAG, IP_MF_FLAG_ALIAS, MMT_U8_DATA, sizeof (char), 6, SCOPE_PACKET, ip_mf_extraction},
    {IP_FRAG_OFFSET, IP_FRAG_OFFSET_ALIAS, MMT_U16_DATA, sizeof (short), 6, SCOPE_PACKET, ip_frag_offset_extraction},
    {IP_PROTO_TTL, IP_PROTO_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 8, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP_PROTO_ID, IP_PROTO_ID_ALIAS, MMT_U8_DATA, sizeof (char), 9, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP_CHECKSUM_MMT, IP_CHECKSUM_MMT_ALIAS, MMT_U16_DATA, sizeof (short), 10, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP_SRC, IP_SRC_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), 12, SCOPE_PACKET, general_int_extraction},
    {IP_DST, IP_DST_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), 16, SCOPE_PACKET, general_int_extraction},
    {IP_OPTS, IP_OPTS_ALIAS, MMT_DATA_POINTER,  sizeof (void *), -2, SCOPE_PACKET, ip_options_extraction},
    {IP_CLIENT_ADDR, IP_CLIENT_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_client_addr_extraction},
    {IP_SERVER_ADDR, IP_SERVER_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_server_addr_extraction},
    {IP_CLIENT_PORT, IP_CLIENT_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_client_port_extraction},
    {IP_SERVER_PORT, IP_SERVER_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_server_port_extraction},
};

int ip_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    /* IP is a flow based protocol. If at this level the flow associated to this packet is null
     * stop the classification procedure by returning zero. This can happen if the packet is fragmented.
     */
    if (ipacket->session == NULL) {
        return 0;
    }
    return 1;
}

int ip_post_classification_function(ipacket_t * ipacket, unsigned index) {
    if (ipacket->mmt_handler->has_reassembly == 1) {
        int s = sizeof(mmt_tcpip_internal_packet_t);
        ipacket->internal_packet = mmt_malloc (s);
        memset(ipacket->internal_packet, 0, s);
        ipacket->internal_packet->udp = NULL;
        ipacket->internal_packet->tcp = NULL;
        ipacket->internal_packet->packet_id = ipacket->packet_id;
    } else {
        ipacket->internal_packet = &((internal_ip_proto_context_t *) ((protocol_instance_t *) ipacket->session->protocol_container_context)->args)->packet;
    }
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;

    int ip_offset = get_packet_offset_at_index(ipacket, index);
    const struct iphdr * ip_hdr = (struct iphdr *) & ipacket->data[ip_offset];

    uint32_t time = ((uint64_t) ipacket->p_hdr->ts.tv_sec) * MMT_MICRO_IN_SEC + ipacket->p_hdr->ts.tv_usec;
    packet->tick_timestamp = time;

    struct mmt_internal_tcpip_id_struct * src = NULL;
    struct mmt_internal_tcpip_id_struct * dst = NULL;

    // only handle unfragmented packets
    // if (ip_hdr->version == 4 && (ntohs(ip_hdr->frag_off) & 0x1FFF) != 0) {
    //     return 0; //TODO
    // }
    // Frag_offset: (0x2000)
    // if(ipsize < iph->ihl * 4 || ipsize < ntohs(iph->tot_len) || ntohs(iph->tot_len) < iph->ihl * 4 || (iph->frag_off & htons(0x1FFF)) != 0) {
    //     return 0;
    // }
    if (mmt_iph_is_fragmented(ip_hdr) && !ipacket->is_completed) {
        return 0; //TODO
    }
    // printf("[IP] not fragmented: %lu\n", ipacket->packet_id);
    packet->iph = ip_hdr;
    packet->iphv6 = NULL;
    packet->l3_packet_len = ntohs(ip_hdr->tot_len);
    /* BW: add the length of the truncated packet as well */
    packet->l3_captured_packet_len = (ipacket->p_hdr->caplen - ip_offset);
    /* TODO: Check the padding -> allow only certain type of padding and inform other : if packet->l3_captured_packet_len != packet->l3_packet_len -> padding */
    //packet->l4_packet_len = packet->l3_packet_len - (ip_hdr->ihl * 4); //For IPv6 this is done in tcp and udp
    // packet->l4_packet_len = packet->l3_packet_len - (ip_hdr->ihl * 4); //For IPv6 this is done in tcp and udp
    if(ipacket->nb_reassembled_packets > 1){
        packet->l4_packet_len = packet->l3_captured_packet_len - (ip_hdr->ihl * 4); //For IPv6 this is done in tcp and udp
    }else{
        packet->l4_packet_len = packet->l3_packet_len - (ip_hdr->ihl * 4); //For IPv6 this is done in tcp and udp   
    }

    if (memcmp(&((mmt_ip4_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->higher_ip)->ip, &ip_hdr->saddr, IPv4_ALEN) == 0) {
        src = &((mmt_ip4_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->higher_ip)->id_internal_context;
        dst = &((mmt_ip4_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->lower_ip)->id_internal_context;
    } else {
        dst = &((mmt_ip4_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->higher_ip)->id_internal_context;
        src = &((mmt_ip4_id_t *) ((mmt_session_key_t *) ipacket->session->session_key)->lower_ip)->id_internal_context;
    }

    packet->flow = ipacket->session->internal_data;
    packet->src = src;
    packet->dst = dst;

    /* build selction packet bitmask */
    packet->mmt_selection_packet = MMT_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
    packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_IP | MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

    ipacket->session->packet_count_direction[ipacket->session->last_packet_direction]++;
    ipacket->session->packet_cap_count_direction[ipacket->session->last_packet_direction] += ipacket->nb_reassembled_packets;
    ipacket->session->data_volume_direction[ipacket->session->last_packet_direction] += ipacket->p_hdr->len;
    ipacket->session->data_cap_volume_direction[ipacket->session->last_packet_direction] += ipacket->total_caplen;

    return 1;
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ip_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IP, PROTO_IP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < IP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ip_attributes_metadata[i]);
        }

        register_classification_function(protocol_struct, ip_classify_next_proto);
        register_pre_post_classification_functions(protocol_struct, ip_pre_classification_function, ip_post_classification_function);

        register_sessionizer_function(protocol_struct, ip_sessionizer, ip_session_cleanup_on_timeout, ipv4_session_comp);

        register_proto_context_init_cleanup_function(protocol_struct, setup_ip_context, ip_context_cleanup, NULL);
        return register_protocol(protocol_struct, PROTO_IP);
    } else {
        return 0;
    }
}
