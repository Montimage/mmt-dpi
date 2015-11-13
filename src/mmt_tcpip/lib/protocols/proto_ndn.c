#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "ndn.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#include "ndn.h"
int ndn_TLV_check_type(int type){

    // 01 - ImplicitSha256DigestComponent
    if(type==1) return 1;
    
    if(type < 5 || type > 29 || type == 11) return 0;
    
    return 1;
}

ndn_tlv_t * ndn_TLV_init(){
    ndn_tlv_t *ndn_tlv;
    ndn_tlv = (ndn_tlv_t *)malloc(sizeof(ndn_tlv_t));
    ndn_tlv->type = 0;
    ndn_tlv->length = 0;
    ndn_tlv->nb_octets = 0;
    ndn_tlv->node_offset = 0;
    ndn_tlv->data_offset = 0;
    ndn_tlv->next = NULL;
    return ndn_tlv;
}

void ndn_TLV_free(ndn_tlv_t * ndn){
    
    if(ndn == NULL) return;

    // if(ndn->value != NULL) free(ndn->value);

    // if(ndn->remain_value != NULL) free(ndn->remain_value);

    if(ndn->next) ndn_TLV_free(ndn->next);

    free(ndn);
    // ndn = NULL;
}

int ndn_TLV_get_int(ndn_tlv_t *ndn, char *payload, int payload_len){
    
    if(ndn == NULL) return -1;

    if(payload == NULL) return -1;

    if(ndn->data_offset + ndn->length > payload_len){
        return -1;
    }

    int ret = str_hex2int(payload,ndn->data_offset, ndn->data_offset + ndn->length -1 );

    return ret;
}

char * ndn_TLV_get_string(ndn_tlv_t *ndn, char *payload, int payload_len){
    
    if(ndn == NULL) return NULL;

    if(payload == NULL) return NULL;

    if(ndn->data_offset + ndn->length > payload_len){
        return NULL;
    }

    char * ret = str_sub(payload,ndn->data_offset, ndn->data_offset + ndn->length -1 );

    return ret;
}

ndn_tlv_t * ndn_TLV_parser(char *payload, int offset, int total_length){

    if(payload == NULL) return NULL;

    int type = ndn_TLV_check_type(payload[offset]);

    if(type == 0) {
        debug("Wrong type : %d\n",payload[offset]);
        return NULL;
    }
    
    int first_octet = hex2int(payload[offset + 1]);

    ndn_tlv_t * ndn_new_node = NULL;
    
    if(first_octet == 0 ){
        if(offset + 2 == total_length){
            ndn_new_node = ndn_TLV_init();
            ndn_new_node->type = hex2int(payload[offset]);
            ndn_new_node->length = 0;
            ndn_new_node->node_offset = offset;
            ndn_new_node->data_offset = offset + 2;
            return ndn_new_node;
        }else{
            debug("First octet : %d\n",first_octet);
            // ndn_TLV_free(ndn_new_node);
            return NULL;
        }
    }
    
    ndn_new_node = ndn_TLV_init();
    ndn_new_node->type = hex2int(payload[offset]);
    ndn_new_node->node_offset = offset;
    switch(first_octet){
        // fd
        // 2 octets - 05 ab xx xx 07 yy yy:
        case 253:
            ndn_new_node->nb_octets = 2;
            break;
        // fe
        // 4 octets - 05 ab xx xx xx xx 07 yy yy
        case 254:
            ndn_new_node->nb_octets = 4;
            break;
        // ff
        // 8 octets - 05 ab xx xx xx xx xx xx xx xx 07 yy yy
        case 255:
            ndn_new_node->nb_octets = 8;
            break;
        // 1 octets - 05 xx 07
        default:
            ndn_new_node->nb_octets = 0;
            ndn_new_node->length = first_octet;
            break;
    }
    if(ndn_new_node->nb_octets>0){
        ndn_new_node->length = str_hex2int(payload,offset + 2, offset + 2 + ndn_new_node->nb_octets-1);    
    }
    ndn_new_node->data_offset = offset + 2 + ndn_new_node->nb_octets;

    if(total_length < ndn_new_node->data_offset + ndn_new_node->length){
        debug("Not correct length value : %d \n",total_length);
        ndn_TLV_free(ndn_new_node);
        return NULL;
    }

    // ndn_new_node->value = payload + 2 + ndn_new_node->nb_octets;
    // if(2 + ndn_new_node->nb_octets + ndn_new_node->length < total_length){
    //     char *new_str = payload + 2 + ndn_new_node->nb_octets + ndn_new_node->length;
    //     ndn_new_node->remain_value = str_copy(new_str);
    //     // if(new_str != NULL) free(new_str);
    //     // ndn_new_node->remain_value = payload + 2*(2 + ndn_new_node->nb_octets + ndn_new_node->length);
    // }
    return ndn_new_node;
}

ndn_tlv_t * ndn_find_node(char *payload, int total_length, ndn_tlv_t *root, int node_type){
    
    if( payload == NULL ) return NULL;

    if( root == NULL ) return NULL;
    
    if(root->data_offset == total_length) {
        // ndn_TLV_free(root);
        return NULL;
    }
    
    ndn_tlv_t * temp = ndn_TLV_parser(payload, root->data_offset,total_length);

    while(temp!=NULL){
        int offset = temp->data_offset + temp->length;
        if(temp->type == node_type){
            return temp;
        }
        if(offset == total_length) {
            ndn_TLV_free(temp);
            return NULL;
        }
        // Find depth - possible
        // ndn_tlv_t * temp_deeper = ndn_find_node(temp,node_type);

        // if(temp_deeper != NULL) return temp_deeper;

        // Find width
        // char *new_payload = str_copy(temp->remain_value);
        ndn_TLV_free(temp);
        temp = ndn_TLV_parser(payload, offset,total_length);
        // if(new_payload != NULL) free(new_payload);
    }
    return NULL;
}

int mmt_check_ndn_payload(char* payload, int packet_len){
    // Minimum packet: 050007
    if(packet_len < 3) return 0;

    // Check the first condition: 05 - interest packet, 06 - data packet
    if (payload[0] != 5 && payload[0] != 6) return 0;

    // Check the second condition: length
    ndn_tlv_t *root  = ndn_TLV_parser(payload, 0, packet_len);
    
    if(root == NULL)
        return 0;
    if( packet_len != root->data_offset + root->length){
        ndn_TLV_free(root);
        return 0;
    }

    // Check the condition of the common fields: name '07'
    if(payload[root->data_offset] != 7){
        ndn_TLV_free(root);
        return 0;
    }
    return 1;
}

ndn_tlv_t * ndn_TLV_parser_name_comp(char* payload, int total_length, int offset,int nc_length){
    // debug("\nRemain:\n %s\nLength: %d\n",payload,total_length);

    ndn_tlv_t *name_com = ndn_TLV_parser(payload,offset,total_length);

    if(name_com == NULL) return NULL;

    if(name_com->type != NDN_NAME_COMPONENTS) {
        return NULL;
    }

    int new_offset = name_com->data_offset + name_com->length;

    if(new_offset == total_length) return name_com;
    
    nc_length = nc_length - 2 - name_com->nb_octets - name_com->length;
    
    if(nc_length>0){
        // char *new_payload = str_copy();
        name_com->next = ndn_TLV_parser_name_comp(payload, total_length, new_offset, nc_length);
        // if(new_payload != NULL) free(new_payload);
    }
    return name_com;
}


////////////////////////////////////////////////////////////////////////////
///
///
///                      NDN EXTRACTING FUNCTIONS 
///
///
////////////////////////////////////////////////////////////////////////////


/////////////////////// COMMON FIELD ////////////////////////


uint8_t ndn_packet_type_extraction_payload(char* payload, int total_length){
    
    ndn_tlv_t *ndn = ndn_TLV_parser(payload,0,total_length);

    int ret = NDN_UNKNOWN_PACKET;
    if(ndn!=NULL){
        if(ndn->type == 5 || ndn->type==6) ret = ndn->type;
    }

    ndn_TLV_free(ndn);

    return ret;
}


int ndn_packet_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    uint8_t ret_v = ndn_packet_type_extraction_payload(payload,payload_len);
    if(ret_v != NDN_UNKNOWN_PACKET){
        *((uint8_t*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

uint32_t ndn_packet_length_extraction_payload(char* payload, int total_length){
    
    int ret = -1;

    ndn_tlv_t *ndn = ndn_TLV_parser(payload,0,total_length);

    if(ndn != NULL) {
        if(ndn->type == NDN_DATA_PACKET || ndn->type == NDN_INTEREST_PACKET){
            ret = ndn->length;
        }
    }

    ndn_TLV_free(ndn);
    
    return ret;
}

int ndn_packet_length_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    uint32_t ret_v = ndn_packet_length_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((uint32_t*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

char * ndn_TVL_get_name_components(ndn_tlv_t *name_com, char *payload, int total_length){
    char *ret = NULL;

    if(name_com != NULL) {

        ret = str_sub(payload,name_com->data_offset,name_com->data_offset + name_com->length - 1);

        ndn_tlv_t *temp = name_com->next;

        while(temp != NULL){

            char *str_temp = str_combine(ret,"/");
            if(ret != NULL) free(ret);
            ret = str_copy(str_temp);
            if(str_temp != NULL) free(str_temp);

            char *str_value = ndn_TLV_get_string(temp,payload,total_length);
            
            char *str_str = str_hex2str(str_value,0,temp->length-1);

            str_temp = str_combine(ret,str_str);
            if(ret != NULL) free(ret);
            ret = str_copy(str_temp);
            if(str_temp != NULL) free(str_temp);
            if(str_value != NULL) free(str_value);
            if(str_str != NULL) free(str_str);

            temp = temp->next;
        }
    }
    return ret;
}

char* ndn_name_components_extraction_payload(char *payload,int total_length){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,total_length);

    if(root==NULL){
        ndn_TLV_free(root);
        return NULL;
    }

    if(root->type == NDN_UNKNOWN_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    int offset = 2 + root->nb_octets;

    if(root->data_offset == total_length){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t * name_node = ndn_TLV_parser(payload, offset, total_length);

    char * ret;

    if(name_node != NULL ) {
        if(name_node->type == NDN_COMMON_NAME) {

                int new_offset = name_node->data_offset;
                if( new_offset < total_length) {
                
                    ndn_tlv_t * name_com = ndn_TLV_parser_name_comp(payload,total_length,new_offset,name_node->length);

                    ret = ndn_TVL_get_name_components(name_com, payload, total_length);

                    ndn_TLV_free(name_com);
            }

        }

    }

    ndn_TLV_free(name_node);

    ndn_TLV_free(root);

    return ret;
}

int ndn_name_components_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    char *ret_v = ndn_name_components_extraction_payload(payload,payload_len);
    if(ret_v != NULL){
        extracted_data->data = (void*)ret_v;
        return 1;
    }
    return 0;
}

// /////////////////////// INTEREST PACKET ////////////////////////

int ndn_interest_nonce_extraction_payload(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

    if(root == NULL) return -1;

    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_nonce = ndn_find_node(payload, payload_len, root, NDN_INTEREST_NONCE);

    int ret = ndn_TLV_get_int(ndn_nonce, payload, payload_len);

    ndn_TLV_free(ndn_nonce);

    ndn_TLV_free(root);
    
    return ret;
}

int ndn_interest_nonce_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    int ret_v = ndn_interest_nonce_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((int*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

int ndn_interest_lifetime_extraction_payload(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload, 0, payload_len);
    
    if(root == NULL) return -1;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_lifetime = ndn_find_node(payload, payload_len, root,NDN_INTEREST_LIFETIME);

    int ret = ndn_TLV_get_int(ndn_lifetime, payload, payload_len);

    ndn_TLV_free(ndn_lifetime);

    ndn_TLV_free(root);
    
    return ret;
}

int ndn_interest_lifetime_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    int ret_v = ndn_interest_lifetime_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((int*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

int ndn_interest_min_suffix_component_extraction_payload(char *payload,int payload_len){
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

    if(root == NULL) return -1;

    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(payload, payload_len, root, NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_min = ndn_find_node(payload, payload_len,ndn_selectors,NDN_INTEREST_MIN_SUFFIX_COMPONENT);

    int ret = ndn_TLV_get_int(ndn_min, payload, payload_len);

    ndn_TLV_free(ndn_min);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    return ret;
}

int ndn_interest_min_suffix_component_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    int ret_v = ndn_interest_min_suffix_component_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((int*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

int ndn_interest_max_suffix_component_extraction_payload(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);
    
    if(root == NULL) return -1;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(payload, payload_len,root,NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_max = ndn_find_node(payload, payload_len,ndn_selectors,NDN_INTEREST_MAX_SUFFIX_COMPONENT);

    int ret = ndn_TLV_get_int(ndn_max,payload,payload_len);

    ndn_TLV_free(ndn_max);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    return ret;
}

int ndn_interest_max_suffix_component_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    int ret_v = ndn_interest_min_suffix_component_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((int*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

int ndn_interest_publisher_publickey_locator_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }
    if(payload_len == 0) return 0;

    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

    if(root == NULL) return 0;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return 0;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(payload, payload_len,root,NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_publisher = ndn_find_node(payload, payload_len,ndn_selectors,NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR);

    char * ret_v = ndn_TLV_get_string(ndn_publisher,payload,payload_len);

    if( ndn_publisher == NULL) return 0;

    char *str_str = str_hex2str(ret_v,0,ndn_publisher->length-1);

    if(ret_v != NULL) free(ret_v);

    ndn_TLV_free(ndn_publisher);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    if(str_str != NULL){
        extracted_data->data = (void*)str_str;
        return 1;
    }
    return 0;
}

int ndn_interest_exclude_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }
    if(payload_len == 0) return 0;

    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

    if(root == NULL) return 0;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return 0;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(payload, payload_len,root,NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_exclude = ndn_find_node(payload, payload_len,ndn_selectors,NDN_INTEREST_EXCLUDE);

    if(ndn_exclude == NULL) {
        ndn_TLV_free(ndn_selectors);

        ndn_TLV_free(root);

        return 0;
    }
    ndn_tlv_t * name_com = ndn_TLV_parser_name_comp(payload,payload_len,ndn_exclude->data_offset,ndn_exclude->length);

    char * ret_v = ndn_TVL_get_name_components(name_com, payload, payload_len);

    if(name_com == NULL ) return 0;

    char *str_str = str_hex2str(ret_v,0,name_com->length-1);

    if(ret_v != NULL) free(ret_v);

    ndn_TLV_free(name_com);

    ndn_TLV_free(ndn_exclude);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    if(str_str != NULL){
        extracted_data->data = (void*)str_str;
        return 1;
    }
    return 0;
}


int ndn_interest_child_selector_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }
    if(payload_len == 0) return 0;

    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

    if(root == NULL) return 0;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return 0;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(payload, payload_len,root,NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_child = ndn_find_node(payload, payload_len,ndn_selectors,NDN_INTEREST_CHILD_SELECTOR);

    uint8_t ret_v = ndn_TLV_get_int(ndn_child,payload,payload_len);

    ndn_TLV_free(ndn_child);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    if(ret_v != -1){
        *((uint8_t*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}




int ndn_interest_must_be_fresh_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }
    if(payload_len == 0) return 0;

    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

    if(root == NULL) return 0;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return 0;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(payload, payload_len,root,NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_mustbe = ndn_find_node(payload, payload_len,ndn_selectors,NDN_INTEREST_MUST_BE_FRESH);
    int ret = 0;
    if(ndn_mustbe == NULL){
        ret = 0;
    }else{
        // This selector is encoded with Type and Length but no Value part
        if(ndn_mustbe->length > 0){
            ret = 0;
        }else{
            ret = 1;    
        }
    }
    
    *((uint8_t*)extracted_data->data) = ret;

    ndn_TLV_free(ndn_mustbe);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    return 1;
}

int ndn_interest_any_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }
    if(payload_len == 0) return 0;

    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

    if(root == NULL) return 0;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return 0;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(payload, payload_len,root,NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_any = ndn_find_node(payload, payload_len,ndn_selectors,NDN_INTEREST_ANY);
    int ret = 0;
    if(ndn_any == NULL){
        ret = 0;
    }else{
        // This selector is encoded with Type and Length but no Value part
        if(ndn_any->length > 0){
            ret = 0;
        }else{
            ret = 1;    
        }
    }
    
    *((uint8_t*)extracted_data->data) = ret;

    ndn_TLV_free(ndn_any);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    return 1;
}
// int ndn_implicit_sha256_digest_component_extraction(const ipacket_t * ipacket, unsigned proto_index,
//         attribute_t * extracted_data){
//     int offset = get_packet_offset_at_index(ipacket, proto_index);
//     char *payload = (char*)&ipacket->data[offset];
//     uint32_t payload_len = ipacket->internal_packet->payload_packet_len;
    
//     if(payload_len = 0) return 0;

//     ndn_tlv_t * root = ndn_TLV_parser(payload,0,total_length);

//     if(root == NULL) return 0;

//     if(root->type != NDN_INTEREST_PACKET){
//         ndn_TLV_free(root);
//         return 0;
//     }

//     ndn_tlv_t *ndn_data_content = ndn_find_node(payload, total_length, root, NDN_NAME_COMPONENTS);
    
//     char *ret = ndn_TLV_get_string(ndn_data_content,payload,total_length);

//     ndn_TLV_free(ndn_data_content);

//     ndn_TLV_free(root);

//     return ret;
// }
// /////////////////////// DATA PACKET ////////////////////////

char* ndn_data_content_extraction_payload(char *payload,int total_length){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,total_length);

    if(root == NULL) return NULL;

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t *ndn_data_content = ndn_find_node(payload, total_length, root, NDN_DATA_CONTENT);
    
    char *ret = ndn_TLV_get_string(ndn_data_content,payload,total_length);

    if( ndn_data_content == NULL ) return NULL;

    char * str_str = str_hex2str(ret,0,ndn_data_content->length-1);
    
    if(ret!=NULL) free(ret);

    ndn_TLV_free(ndn_data_content);

    ndn_TLV_free(root);

    return str_str;
}

int ndn_data_content_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    char *ret_v = ndn_data_content_extraction_payload(payload,payload_len);
    if(ret_v != NULL){
        extracted_data->data = (void*)ret_v;
        return 1;
    }
    return 0;
}


int ndn_data_content_type_extraction_payload(char *payload,int payload_len){
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);
    if(root == NULL) return -1;
    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_metainfo = ndn_find_node(payload, payload_len, root, NDN_DATA_METAINFO);

    if(ndn_metainfo == NULL){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_content_type = ndn_find_node(payload, payload_len, ndn_metainfo, NDN_DATA_CONTENT_TYPE);
    
    int ret = ndn_TLV_get_int(ndn_content_type,payload,payload_len);
    
    ndn_TLV_free(ndn_content_type);

    ndn_TLV_free(ndn_metainfo);

    ndn_TLV_free(root);

    return ret;
}

int ndn_data_content_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    int ret_v = ndn_data_content_type_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((uint8_t*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

int ndn_data_freshness_period_extraction_payload(char *payload,int payload_len){
    ndn_tlv_t * root = ndn_TLV_parser(payload, 0, payload_len);
    
    if(root == NULL) return -1;
    
    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    int ret = -1;

    ndn_tlv_t *ndn_metainfo = ndn_find_node(payload,payload_len,root, NDN_DATA_METAINFO);

    ndn_tlv_t *ndn_freshness_period = ndn_find_node(payload, payload_len, ndn_metainfo,NDN_DATA_FRESHNESS_PERIOD);
    
    ret = ndn_TLV_get_int(ndn_freshness_period, payload, payload_len);

    ndn_TLV_free(ndn_freshness_period);

    ndn_TLV_free(ndn_metainfo);

    ndn_TLV_free(root);

    return ret;
}

int ndn_data_freshness_period_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    int ret_v = ndn_data_freshness_period_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((int*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

int ndn_data_final_block_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }
    if(payload_len == 0) return 0;
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);
    
    if(root == NULL) return 0;
    
    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return 0;
    }

    ndn_tlv_t *ndn_metainfo = ndn_find_node(payload,payload_len,root, NDN_DATA_METAINFO);

    ndn_tlv_t *ndn_final_blockID = ndn_find_node(payload, payload_len, ndn_metainfo,NDN_DATA_FINAL_BLOCK_ID);

    if(ndn_final_blockID == NULL){
        ndn_TLV_free(ndn_metainfo);

        ndn_TLV_free(root);

        return 0;
    }
    ndn_tlv_t * name_com = ndn_TLV_parser_name_comp(payload,payload_len,ndn_final_blockID->data_offset,ndn_final_blockID->length);

    char * ret_v = ndn_TVL_get_name_components(name_com, payload, payload_len);

    ndn_TLV_free(name_com);

    ndn_TLV_free(ndn_final_blockID);

    ndn_TLV_free(ndn_metainfo);

    ndn_TLV_free(root);

    if(ret_v != NULL){
        extracted_data->data = (void*)ret_v;
        return 1;
    }
    return 0;
}

int ndn_data_signature_type_extraction_payload(char *payload,int payload_len){
    int ret = -1;
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);
    
    if(root == NULL) return -1;
    
    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return ret;
    }

    ndn_tlv_t *ndn_data_signature_info = ndn_find_node(payload, payload_len,root,NDN_DATA_SIGNATURE_INFO);

    ndn_tlv_t *ndn_data_signature_type = ndn_find_node(payload, payload_len,ndn_data_signature_info,NDN_DATA_SIGNATURE_TYPE);

    int st = ndn_TLV_get_int(ndn_data_signature_type,payload,payload_len);
    
    if(st == -1) ret = -1;

    if(st == 0) ret = DigestSha256;

    if(st == 1) ret = SignatureSha256WithRsa;   

    if(st == 2 || (st > 4 && st<=200) ) ret = ReservedForFutureAssignments; 

    if(st == 3) ret = SignatureSha256WithEcdsa; 

    if(st == 4) ret = SignatureHmacWithSha256;  

    if(st > 200 ) ret = Unassigned;     
    
    ndn_TLV_free(ndn_data_signature_type);
    
    ndn_TLV_free(ndn_data_signature_info);
    
    ndn_TLV_free(root);
    
    return ret;
}

int ndn_data_signature_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    int ret_v = ndn_data_signature_type_extraction_payload(payload,payload_len);
    if(ret_v != -1){
        *((uint8_t*)extracted_data->data) = ret_v;
        return 1;
    }
    return 0;
}

char* ndn_data_key_locator_extraction_payload(char *payload,int total_length){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,total_length);

    if(root == NULL) return NULL;

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t *ndn_data_signature_info = ndn_find_node(payload, total_length , root, NDN_DATA_SIGNATURE_INFO);

    ndn_tlv_t *ndn_data_key_locator =  ndn_find_node(payload, total_length , ndn_data_signature_info,NDN_DATA_KEY_LOCATOR);

    char *ret = ndn_TLV_get_string(ndn_data_key_locator,payload,total_length);

    if( ndn_data_key_locator == NULL ) return NULL;

    char *str_str = str_hex2str(ret,0,ndn_data_key_locator->length-1);

    if(ret != NULL) free(ret);

    ndn_TLV_free(ndn_data_key_locator);

    ndn_TLV_free(ndn_data_signature_info);

    ndn_TLV_free(root);

    return str_str;
}

int ndn_data_key_locator_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    char *ret_v = ndn_data_key_locator_extraction_payload(payload,payload_len);
    if(ret_v != NULL){
        extracted_data->data = (void*)ret_v;
        return 1;
    }
    return 0;
}

char* ndn_data_signature_value_extraction_payload(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);
    
    if(root == NULL) return NULL;

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t *ndn_data_signature_value = ndn_find_node(payload,payload_len,root,NDN_DATA_SIGNATURE_VALUE);
    
    char *ret = ndn_TLV_get_string(ndn_data_signature_value,payload,payload_len);

    if( ndn_data_signature_value == NULL ) return NULL;

    char *str_str = str_hex2str(ret,0,ndn_data_signature_value->length-1);

    if(ret != NULL) free(ret);

    ndn_TLV_free(ndn_data_signature_value);

    ndn_TLV_free(root);
    
    return str_str;
}

int ndn_data_signature_value_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(proto_index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    char *ret_v = ndn_data_signature_value_extraction_payload(payload,payload_len);
    if(ret_v != NULL){
        extracted_data->data = (void*)ret_v;
        return 1;
    }
    //             *((uint16_t*)extracted_data->data) = ftp_control->contrl_conn->c_port;
    return 0;
}




static void mmt_int_ndn_add_connection(ipacket_t * ipacket) {
    debug("NDN: mmt_int_ndn_add_connection");
    mmt_internal_add_connection(ipacket, PROTO_NDN, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_ndn(ipacket_t * ipacket, unsigned index) {
    debug("NDN: mmt_classify_me_ndn");
}

int mmt_check_ndn(ipacket_t * ipacket, unsigned index) {
    debug("NDN: mmt_check_ndn");
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
            
            debug("NDN: checking ndn payload %lu",ipacket->packet_id);
            int offset = get_packet_offset_at_index(ipacket, index + 1);
            char * payload = (char*)&ipacket->data[offset];
            uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

            if(payload_len==0){
                debug("NDN: payload_len == 0");
                return 0;
            }

            if(mmt_check_ndn_payload(payload,payload_len)!=0){
                debug("NDN: found ndn packet %lu",ipacket->packet_id);
                mmt_int_ndn_add_connection(ipacket);
                return 1;
            }
    }
    return 0;
}
//////////////////////////// EXTRACTION ///////////////////////////////////////


static attribute_metadata_t ndn_attributes_metadata[NDN_ATTRIBUTES_NB] = {
    // {NDN_IMPLICIT_SHA256_DIGEST_COMPONENT,NDN_IMPLICIT_SHA256_DIGEST_COMPONENT_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ndn_implicit_sha256_digest_component_extraction},
    {NDN_PACKET_TYPE,NDN_PACKET_TYPE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_packet_type_extraction},
    {NDN_PACKET_LENGTH,NDN_PACKET_LENGTH_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_packet_length_extraction},
    {NDN_NAME_COMPONENTS,NDN_NAME_COMPONENTS_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_name_components_extraction},
    {NDN_INTEREST_NONCE,NDN_INTEREST_NONCE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_nonce_extraction},
    {NDN_INTEREST_LIFETIME,NDN_INTEREST_LIFETIME_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_lifetime_extraction},
    {NDN_INTEREST_MIN_SUFFIX_COMPONENT,NDN_INTEREST_MIN_SUFFIX_COMPONENT_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_min_suffix_component_extraction},
    {NDN_INTEREST_MAX_SUFFIX_COMPONENT,NDN_INTEREST_MAX_SUFFIX_COMPONENT_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_max_suffix_component_extraction},
    {NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR,NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_publisher_publickey_locator_extraction},
    {NDN_INTEREST_EXCLUDE,NDN_INTEREST_EXCLUDE_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_exclude_extraction},
    {NDN_INTEREST_CHILD_SELECTOR,NDN_INTEREST_CHILD_SELECTOR_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_child_selector_extraction},
    {NDN_INTEREST_MUST_BE_FRESH,NDN_INTEREST_MUST_BE_FRESH_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_must_be_fresh_extraction},
    {NDN_INTEREST_ANY,NDN_INTEREST_ANY_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_any_extraction},
    {NDN_DATA_CONTENT,NDN_DATA_CONTENT_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_content_extraction},
    {NDN_DATA_SIGNATURE_VALUE,NDN_DATA_SIGNATURE_VALUE_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_signature_value_extraction},
    {NDN_DATA_CONTENT_TYPE,NDN_DATA_CONTENT_TYPE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_content_type_extraction},
    {NDN_DATA_FRESHNESS_PERIOD,NDN_DATA_FRESHNESS_PERIOD_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_freshness_period_extraction},
    {NDN_DATA_FINAL_BLOCK_ID,NDN_DATA_FINAL_BLOCK_ID_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_final_block_id_extraction},
    {NDN_DATA_SIGNATURE_TYPE,NDN_DATA_SIGNATURE_TYPE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_signature_type_extraction},
    {NDN_DATA_KEY_LOCATOR,NDN_DATA_KEY_LOCATOR_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_key_locator_extraction},
    // {NDN_DATA_KEY_DIGEST,NDN_DATA_KEY_DIGEST_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_key_digest_extraction},
};

//////////////////////////// END OF EXTRACTION /////////////////////////////////


///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////


/**
 * Analysis packet data
 * @param  ipacket packet to analysis
 * @param  index   protocol index
 * @return         MMT_CONTINUE
 *                 MMT_SKIP
 *                 MMT_DROP
 */
// int ndn_session_data_analysis(ipacket_t * ipacket, unsigned index) {
//     debug("NDN: ndn_session_data_analysis");
//     return MMT_CONTINUE;
// }

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////


// void * setup_ndn_context(void * proto_context, void * args) {
//     ftp_control_session_t * ftp_list_control_conns;
//     ftp_list_control_conns = (ftp_control_session_t*)malloc(sizeof(ftp_control_session_t));
//     ftp_list_control_conns->next = NULL;
//     return (void*)ftp_list_control_conns;
// }


void mmt_init_classify_me_ndn() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_NDN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_NDN);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ndn_struct() {
    
    debug("NDN: init_proto_ndn_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NDN, PROTO_NDN_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < NDN_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ndn_attributes_metadata[i]);
        }
        // register_proto_context_init_cleanup_function(protocol_struct, setup_ndn_context, NULL, NULL);
        // register_session_data_analysis_function(protocol_struct, ndn_session_data_analysis);
        mmt_init_classify_me_ndn();

        return register_protocol(protocol_struct, PROTO_NDN);
    } else {
        return 0;
    }
}


