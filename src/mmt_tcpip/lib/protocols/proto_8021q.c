#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
struct mmt_vlan_struct {
    uint16_t code;
    uint16_t h_proto;
};

int vlan_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    const struct mmt_vlan_struct *vl = (struct mmt_vlan_struct *) & ipacket->data[offset];
    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;
    switch (ntohs(vl->h_proto)) // Layer 3 protocol identifier
    {
            /* IPv4 */
        case ETH_P_IP:
            retval.proto_id = PROTO_IP;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
            /* IPv6 */
        case ETH_P_IPV6:
            retval.proto_id = PROTO_IPV6;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
            /*Double tagging*/
        case ETH_P_8021Q:
            retval.proto_id = PROTO_8021Q;
            retval.offset = sizeof (struct mmt_vlan_struct);
			retval.status = Classified;
			break;
            /* ARP */
            /* RARP: will be processed as ARP */
        case ETH_P_RARP:
        case ETH_P_ARP:
            retval.proto_id = PROTO_ARP;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
             /* PPPoE Discovery */
        case ETH_P_PPPoED:
            retval.proto_id = PROTO_PPPOE;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
            /* PPPoE Session */
        case ETH_P_PPPoES:
            retval.proto_id = PROTO_PPPOE;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
        default:
            retval.proto_id = PROTO_UNKNOWN;
            retval.offset = sizeof (struct mmt_vlan_struct);
            retval.status = Classified;
            break;
    }
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}


static int extract_attributes(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    const struct mmt_vlan_struct *vl = (struct mmt_vlan_struct *) & ipacket->data[offset];
	//two last bytes of 802.1Q tag format
	struct tag_format {
#if BYTE_ORDER == LITTLE_ENDIAN
		uint16_t vid : 12;
		uint8_t dei  :  1;
		uint8_t pcp  :  3;
#elif BYTE_ORDER == BIG_ENDIAN
		uint8_t pcp  :  3;
		uint8_t dei  :  1;
		uint16_t vid : 12;
#else
#error  "BYTE_ORDER must be defined"
#endif
	};

	uint16_t code =  ntohs(vl->code);
	struct tag_format *tag = (struct tag_format *) &code;

    switch( extracted_data->field_id ){
    case VLAN_TPID:
    	/*A 16-bit field set to a value of 0x8100 in order to
    	 * identify the frame as an IEEE 802.1Q-tagged frame*/
    	*((uint16_t *) extracted_data->data) = 0x8100;
    	break;

    case VLAN_PCP:
    	*((uint8_t *) extracted_data->data) = tag->pcp;
    	break;

    case VLAN_DEI:
    	*((uint8_t *) extracted_data->data) = tag->dei;
    	break;

    case VLAN_VID:
    	*((uint16_t *) extracted_data->data) = tag->vid;
    	break;

    default:
    	return 0; //< must not happen
    }
    return 1;
}

static attribute_metadata_t attributes_metadata[] = {
    {VLAN_TPID, VLAN_TPID_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 0, SCOPE_PACKET, extract_attributes},
    {VLAN_PCP,  VLAN_PCP_ALIAS,  MMT_U8_DATA,  sizeof (uint8_t),  2, SCOPE_PACKET, extract_attributes},
    {VLAN_DEI,  VLAN_DEI_ALIAS,  MMT_U8_DATA,  sizeof (uint8_t),  2, SCOPE_PACKET, extract_attributes},
    {VLAN_VID,  VLAN_VID_ALIAS,  MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, extract_attributes},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_8021q_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_8021Q, PROTO_8021Q_ALIAS);
    if (protocol_struct != NULL) {
    
    	//register attributes
    	int i,
		//number of attributes
		n = sizeof( attributes_metadata ) / sizeof( attributes_metadata[0] );
    	for( i=0; i<n; i++ )
    		register_attribute_with_protocol(protocol_struct, &attributes_metadata[i]);

        register_classification_function(protocol_struct, vlan_classify_next_proto);

        return register_protocol(protocol_struct, PROTO_8021Q);
    } else {
        return 0;
    }
}


