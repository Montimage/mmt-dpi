#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "ethernet.h"
#include "ip_session_id_management.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
int ethernet_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    const struct ethhdr *ethernet = (struct ethhdr *) & ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;
    switch (ntohs(ethernet->h_proto)) // Layer 3 protocol identifier
    {
            /* IPv4 */
        case ETH_P_IP:
            retval.proto_id = PROTO_IP;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
            /* IPv6 */
        case ETH_P_IPV6:
            retval.proto_id = PROTO_IPV6;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
            /* ARP */
            /* RARP: will be processed as ARP */
        case ETH_P_RARP:
        case ETH_P_ARP:
            retval.proto_id = PROTO_ARP;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
            /* 802.1Q */
        case ETH_P_8021Q:
            retval.proto_id = PROTO_8021Q;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
        case ETH_P_NDN:
            retval.proto_id = PROTO_NDN;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
        case 0x9100:
        case 0x9200:
        case 0x9300:
            retval.proto_id = PROTO_8021Q;
            retval.offset = sizeof (struct ethhdr) + 4;
            retval.status = Classified;
            break;
             /* PPPoE Discovery */
        case ETH_P_PPPoED:
            retval.proto_id = PROTO_PPPOE;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
            /* PPPoE Session */
        case ETH_P_PPPoES:
            retval.proto_id = PROTO_PPPOE;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
        // IEEE1588           
        case ETH_P_PTP:
            retval.proto_id = PROTO_PTP;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;            
        // IEEE1588           
        case ETH_P_PPP_IPCP:
        case ETH_P_PPP_LCP:
            retval.proto_id = PROTO_PPP;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break; 
        // FC           
        case ETH_P_FC:
            retval.proto_id = PROTO_FC;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break; 
            /* Batman */
        case ETH_P_BATMAN:
            retval.proto_id = PROTO_BATMAN;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
        case ETH_P_LOOP:
            retval.proto_id = PROTO_CTP;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;    
        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = sizeof (struct ethhdr);
            retval.status = Classified;
            break;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

classified_proto_t ethernet_stack_classification(ipacket_t * ipacket) {
    classified_proto_t retval;
    retval.offset = 0;
    retval.proto_id = PROTO_ETHERNET;
    retval.status = Classified;
    return retval;
}

static attribute_metadata_t ethernet_attributes_metadata[ETHERNET_ATTRIBUTES_NB] = {
    {ETH_DST, ETH_DST_ALIAS, MMT_DATA_MAC_ADDR, sizeof (mac_addr_t), 0, SCOPE_PACKET, general_byte_to_byte_extraction},
    {ETH_SRC, ETH_SRC_ALIAS, MMT_DATA_MAC_ADDR, sizeof (mac_addr_t), ETH_ALEN, SCOPE_PACKET, general_byte_to_byte_extraction},
    {ETH_PROTOCOL, ETH_PROTOCOL_ALIAS, MMT_U16_DATA, sizeof (short), 2 * ETH_ALEN, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};

/*
void ehternet_stack_internal_cleanup(void * stack_internal_packet, void * stack_internal_context) {
    cleanup_ipv4_internal_context((internal_ip_proto_context_t *) stack_internal_context);
    mmt_free(stack_internal_packet);
}
*/

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_ethernet_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ETHERNET, PROTO_ETHERNET_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for(; i < ETHERNET_ATTRIBUTES_NB; i ++) {
            register_attribute_with_protocol(protocol_struct, &ethernet_attributes_metadata[i]);
        }

        register_classification_function(protocol_struct, ethernet_classify_next_proto);

        // Ethernet is a major encapsulating protocol, register it as a stack
        register_protocol_stack(DLT_EN10MB, PROTO_ETHERNET_ALIAS, ethernet_stack_classification); //TODO: check the return value of this
        //register_protocol_stack_full(DLT_EN10MB, PROTO_ETHERNET_ALIAS, ethernet_stack_classification, ehternet_stack_internal_cleanup, (void *) setup_tcpip_internal_packet(), (void *) setup_tcpip_internal_context()); //TODO: check the return value of this

        return register_protocol(protocol_struct, PROTO_ETHERNET);
    } else {
        return 0;
    }
}
