#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "ndn.h"
#include <ctype.h>

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


int is_json_special_character(char c2){
    return (c2=='\"'||c2=='\\'||c2=='\b'||c2=='\f'||c2=='\n'||c2=='\r'||c2=='\t');
}


char * ndn_TLV_get_string(ndn_tlv_t *ndn, char *payload, int payload_len){
    
    if(ndn == NULL) return NULL;

    if(payload == NULL) return NULL;

    if(ndn->data_offset + ndn->length > payload_len){
        return NULL;
    }

    char * ret = str_sub(payload,ndn->data_offset, ndn->data_offset + ndn->length -1 );

    int i = 0;
    // Replace all character which is not printable
    for(i = 0 ;i < ndn->length;i++){
        if(is_json_special_character(ret[i])){
            // printf("Special character\n");
            ret[i]='_';
            // ret[i+1]='_';
            // i +=2;
        }

        if(ret[i]<32 || ret[i]>126){
            ret[i]='_';
        }
    }

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

ndn_proto_context_t * ndn_get_proto_context(ipacket_t *ipacket, unsigned index){
    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
            ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
    ndn_proto_context_t * ndn_proto_context = (ndn_proto_context_t*)configured_protocol->args;
    if(ndn_proto_context == NULL){
        log_err("Cannot get NDN protocol context");
        return NULL;
    }else{
        return ndn_proto_context;
    }
}

/**
 * Get list of control session from session context
 * @param  ipacket packet
 * @param  index   protocol index
 * @return         the pointer to the first control_session
 */
ndn_session_t * ndn_get_list_all_session(ipacket_t *ipacket, unsigned index){
    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
            ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
    ndn_proto_context_t * ndn_proto_context = (ndn_proto_context_t*)configured_protocol->args;
    if(ndn_proto_context == NULL){
        log_err("Cannot get NDN protocol context");
        return NULL;
    }else{
        return ndn_proto_context->dummy_session;
    }
}


// uint8_t ndn_packet_type_extraction_payload(char* payload, int total_length){
    


    // uint8_t ret = NDN_UNKNOWN_PACKET;
    // if(ndn!=NULL){
    //     if(ndn->type == 5) ret = NDN_INTEREST_PACKET;
    //     if(ndn->type == 6) ret = NDN_DATA_PACKET;
    // }

    // ndn_TLV_free(ndn);

    // return ret;
// }


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

    if(payload_len == 0){
        return 0;
    }

    uint8_t ret_v = NDN_UNKNOWN_PACKET;
    if(payload[0] == 5) ret_v = NDN_INTEREST_PACKET;
    else if(payload[0] == 6) ret_v = NDN_DATA_PACKET;
    *((uint8_t*)extracted_data->data) = ret_v;
    // uint8_t ret_v = ndn_packet_type_extraction_payload(payload,payload_len);
    // if(ret_v != NDN_UNKNOWN_PACKET){
        
        // 
    // }
    return 1;
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

    char * ret = NULL;

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

    if( ndn_publisher == NULL) {
        ndn_TLV_free(ndn_selectors);

        ndn_TLV_free(root);

        return 0;
    }

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
    
//     if(payload_len == 0) return 0;

//     ndn_tlv_t * root = ndn_TLV_parser(payload,0,payload_len);

//     if(root == NULL) return 0;

//     if(root->type != NDN_INTEREST_PACKET){
//         ndn_TLV_free(root);
//         return 0;
//     }

//     ndn_tlv_t *ndn_data_content = ndn_find_node(payload, payload_len, root, NDN_NAME_COMPONENTS);
    
//     char *ret = ndn_TLV_get_string(ndn_data_content,payload,payload_len);

//     if(ret != NULL){
//         extracted_data->data = (void*)ret;
//     }

//     ndn_TLV_free(ndn_data_content);

//     ndn_TLV_free(root);

//     return 1;
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

int ndn_list_sessions_extraction(const ipacket_t * ipacket, unsigned proto_index,
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

    if(payload_len == 0){
        return 0;
    }

    uint8_t ret_v = NDN_UNKNOWN_PACKET;
    if(payload[0] == 5) ret_v = NDN_INTEREST_PACKET;
    else if(payload[0] == 6) ret_v = NDN_DATA_PACKET;
    
    if(ret_v == NDN_UNKNOWN_PACKET) return 0;

    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)->configured_protocols[ipacket->proto_hierarchy->proto_path[proto_index]];

    ndn_proto_context_t * ret = (ndn_proto_context_t * )configured_protocol->args;

    if(ret == NULL) return 0;

    if(ret->dummy_session == NULL) return 0;

    if(ret->dummy_session->next == NULL) return 0;

    extracted_data->data = (void*)ret->dummy_session->next;
    return 1;
}


static void mmt_int_ndn_add_connection(ipacket_t * ipacket) {
    debug("NDN: mmt_int_ndn_add_connection");
    mmt_internal_add_connection(ipacket, PROTO_NDN, MMT_REAL_PROTOCOL);
}

// void mmt_classify_me_ndn(ipacket_t * ipacket, unsigned index) {
//     debug("NDN: mmt_classify_me_ndn");
// }

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

/// --- NDN SESSION ANALYSIS --- ///
ndn_tuple3_t * ndn_new_tuple3(){
    ndn_tuple3_t * t3 = mmt_malloc(sizeof(ndn_tuple3_t));
    t3->src_MAC = NULL;
    t3->dst_MAC = NULL;
    t3->name = NULL;
    t3->packet_type = 4;
    return t3;
}


void ndn_free_tuple3(ndn_tuple3_t * t3){
    if(t3 == NULL) return;
    if(t3->src_MAC !=NULL ){
        mmt_free(t3->src_MAC);
    }
    if(t3->dst_MAC !=NULL ){
        mmt_free(t3->dst_MAC);
    }
    if(t3->name !=NULL ){
        free(t3->name);
    }
    mmt_free(t3);
}


ndn_session_t * ndn_new_session(){
    ndn_session_t * ndn_session = mmt_malloc(sizeof(ndn_session_t));
    ndn_session->session_id = 0;
    ndn_session->tuple3 = NULL;
    ndn_session->s_init_time = NULL;
    // ndn_session->s_init_time->tv_usec = 0;
    ndn_session->s_last_activity_time = NULL;
    // ndn_session->s_last_activity_time->tv_usec = 0;
    ndn_session->interest_lifeTime[0] = 0;
    ndn_session->data_freshnessPeriod[0] = 0;
    ndn_session->nb_interest_packet[0] = 0;
    ndn_session->data_volume_interest_packet[0] = 0;
    ndn_session->ndn_volume_interest_packet[0] = 0;
    ndn_session->nb_data_packet[0] = 0;
    ndn_session->data_volume_data_packet[0] = 0;
    ndn_session->ndn_volume_data_packet[0] = 0;

    ndn_session->interest_lifeTime[1] = 0;
    ndn_session->data_freshnessPeriod[1] = 0;
    ndn_session->nb_interest_packet[1] = 0;
    ndn_session->data_volume_interest_packet[1] = 0;
    ndn_session->ndn_volume_interest_packet[1] = 0;
    ndn_session->nb_data_packet[1] = 0;
    ndn_session->data_volume_data_packet[1] = 0;
    ndn_session->ndn_volume_data_packet[1] = 0;

    ndn_session->next = NULL;
    ndn_session->user_arg = NULL;
    ndn_session->current_direction = 0;
    ndn_session->is_expired = 0;
    ndn_session->last_reported_time = NULL;
    return ndn_session;
}

uint8_t ndn_compare_tupe3(ndn_tuple3_t *t1 , ndn_tuple3_t *t2){
    
    if(t1 == NULL && t2 == NULL) return 3;

    if ((t1 == NULL && t2 != NULL)||(t1 != NULL && t2 == NULL)) return 0;

    if( str_compare(t1->name, t2->name) == 0) return 0;

    if( str_compare(t1->src_MAC, t2->src_MAC) == 1 && str_compare(t1->dst_MAC, t2->dst_MAC) == 1) return 1;

    if( str_compare(t1->src_MAC, t2->dst_MAC) == 1 && str_compare(t1->dst_MAC, t2->src_MAC) == 1) return 2; 

    return 0;   
}

void ndn_free_session(ndn_session_t *ndn_session){
    if(ndn_session == NULL) return;
    
    if(ndn_session->tuple3 != NULL){
        ndn_free_tuple3(ndn_session->tuple3);
    }

    if(ndn_session->s_init_time != NULL){
        mmt_free(ndn_session->s_init_time);
    }

    if(ndn_session->s_last_activity_time != NULL){
        mmt_free(ndn_session->s_last_activity_time);
    }
    // ndn_free_session(ndn_session->next);

    mmt_free(ndn_session);

}


ndn_session_t * ndn_find_session_by_tuple3(ndn_tuple3_t *t3, ndn_session_t * list_sessions){

    if(t3 == NULL) return NULL;

    if(list_sessions == NULL) return NULL;

    ndn_session_t *next_session = list_sessions;

    while(next_session != NULL){
        int res_com = ndn_compare_tupe3(t3, next_session->tuple3);
        debug("NDN: Compare tuple3... %d",res_com);
        if(res_com == 1 || res_com == 2 ) return next_session;
        next_session = next_session->next;
    }

    return NULL;
}

/// --- END OF NDN SESSION --- ///

//////////////////////////// EXTRACTION ///////////////////////////////////////


static attribute_metadata_t ndn_attributes_metadata[NDN_ATTRIBUTES_NB] = {
    // {NDN_IMPLICIT_SHA256_DIGEST_COMPONENT,NDN_IMPLICIT_SHA256_DIGEST_COMPONENT_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ndn_implicit_sha256_digest_component_extraction},
    {NDN_LIST_SESSIONS,NDN_LIST_SESSIONS_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ndn_list_sessions_extraction},
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
    
    // // {NDN_DATA_KEY_DIGEST,NDN_DATA_KEY_DIGEST_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_key_digest_extraction},
};

//////////////////////////// END OF EXTRACTION /////////////////////////////////


///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

void ndn_process_timed_out(ipacket_t *ipacket, unsigned index, ndn_session_t *current_session){
        
        debug("\nRemoving expired session: %lu",current_session->session_id);

        fire_attribute_event(ipacket, PROTO_NDN, NDN_LIST_SESSIONS, index, (void *) current_session);
        ndn_free_session(current_session);
}

uint64_t ndn_session_get_delay_time(ndn_session_t * current_session){
    uint64_t delay_time = current_session->interest_lifeTime[0];
    if(delay_time < current_session->interest_lifeTime[1]) delay_time = current_session->interest_lifeTime[1];
    if(delay_time < current_session->data_freshnessPeriod[0]) delay_time = current_session->data_freshnessPeriod[0];
    if(delay_time < current_session->data_freshnessPeriod[1]) delay_time = current_session->data_freshnessPeriod[1];
    delay_time = delay_time/1000;
    debug("\nNDN: Delay time of session %lu is: %lu",current_session->session_id,delay_time);
    return delay_time;
}


void ndn_process_timed_out_session(ipacket_t *ipacket, unsigned index, ndn_session_t * first_session, ndn_session_t *dummy_session){
    debug("\nNDN: ndn_process_timed_out_session ipacket: %lu",ipacket->packet_id);    
    long packet_seconds = ipacket->p_hdr->ts.tv_sec;
    ndn_session_t * current_session = first_session;
    ndn_session_t * previous_session = dummy_session;

    while(current_session != NULL){
        
        debug("\nNDN: regarding the session : %lu",current_session->session_id);    
        
        ndn_session_t *session_to_delete = current_session;
        current_session = session_to_delete->next; 
        
        uint64_t delay_time = ndn_session_get_delay_time(session_to_delete);
        int expired_session = 0;
        if(session_to_delete->s_last_activity_time != NULL){
            debug("\nNDN: Packet time: %lu - session_time: %lu = %lu",packet_seconds,session_to_delete->s_last_activity_time->tv_sec,(packet_seconds - session_to_delete->s_last_activity_time->tv_sec));
            if(packet_seconds - session_to_delete->s_last_activity_time->tv_sec > delay_time){
                expired_session = 1;
                previous_session->next = current_session;        
                // debug("\nNDN: Going to remove  : %lu",current_session->session_id);    
                // // Update dummy session if the session to be deleted is pointed by dummy session
                // if(list_sessions->next == session_to_delete){
                //     
                //     list_sessions->next = current_session;
                // }
                session_to_delete->is_expired = 1;
                ndn_process_timed_out(ipacket,index,session_to_delete);
            }
        }
        if(expired_session == 0){
            previous_session = session_to_delete;
        }
    }
    

    
}

/**
 * Analysis packet data
 * @param  ipacket packet to analysis
 * @param  index   protocol index
 * @return         MMT_CONTINUE
 *                 MMT_SKIP
 *                 MMT_DROP
 */
int ndn_session_data_analysis(ipacket_t * ipacket, unsigned index) {


    debug("NDN: ndn_session_data_analysis");
    int offset = get_packet_offset_at_index(ipacket, index);
    char *payload = (char*)&ipacket->data[offset];
    // NDN over Ethernet
    uint32_t payload_len = 0;
    if(index == 2){
        payload_len = ipacket->p_hdr->caplen - offset;
    }else{
        // NDN over TCP
        payload_len = ipacket->internal_packet->payload_packet_len;
    }

    if(payload_len == 0) {
        debug("NDN: payload_len == 0 of ipacket : %lu",ipacket->packet_id);
        return MMT_CONTINUE;
    }
    ndn_tlv_t * root = ndn_TLV_parser(payload, 0, payload_len);

    if (root == NULL) {
        debug("NDN: ndn root node is NULL of ipacket : %lu",ipacket->packet_id);
        return MMT_CONTINUE;
    }
    if(root->type != NDN_DATA_PACKET && root->type != NDN_INTEREST_PACKET){
        debug("NDN: Not NDN packet - ipacket : %lu",ipacket->packet_id);
        ndn_TLV_free(root);
        return MMT_CONTINUE;
    }

    // Create tuple3
    
    ndn_tuple3_t *t3 = ndn_new_tuple3();
    
    // Packet type of tuple3
    t3->packet_type = root->type;
    

    // Extract the MAC address
    t3->src_MAC = mmt_malloc(19);
    t3->dst_MAC = mmt_malloc(19);
    
    unsigned char * src_MAC_addr = mmt_malloc(7);
    memcpy(src_MAC_addr,&ipacket->data[0],ETH_ALEN);
    src_MAC_addr[ETH_ALEN] = '\0';
    unsigned  char * dst_MAC_addr = mmt_malloc(7);
    memcpy(dst_MAC_addr,&ipacket->data[ETH_ALEN],ETH_ALEN);
    dst_MAC_addr[ETH_ALEN] = '\0';
    snprintf(t3->dst_MAC , 18, "%02x:%02x:%02x:%02x:%02x:%02x", src_MAC_addr[0], src_MAC_addr[1], src_MAC_addr[2], src_MAC_addr[3], src_MAC_addr[4], src_MAC_addr[5] );
    t3->dst_MAC[18] = '\0';
    snprintf(t3->src_MAC , 18, "%02x:%02x:%02x:%02x:%02x:%02x", dst_MAC_addr[0], dst_MAC_addr[1], dst_MAC_addr[2], dst_MAC_addr[3], dst_MAC_addr[4], dst_MAC_addr[5] );
    t3->src_MAC[18] = '\0';
    mmt_free(src_MAC_addr);
    mmt_free(dst_MAC_addr);
    // Extract name component
    int name_offset = 2 + root->nb_octets;

    if(root->data_offset == payload_len){
        ndn_TLV_free(root);
        ndn_free_tuple3(t3);
        debug("NDN: Not NDN packet - ipacket : %lu",ipacket->packet_id);
        return MMT_CONTINUE;
    }

    ndn_tlv_t * name_node = ndn_TLV_parser(payload, name_offset, payload_len);

    char * name_component = NULL;

    if(name_node != NULL ) {
        if(name_node->type == NDN_COMMON_NAME) {

                int new_offset = name_node->data_offset;
                if( new_offset < payload_len) {
                
                    ndn_tlv_t * name_com = ndn_TLV_parser_name_comp(payload,payload_len,new_offset,name_node->length);

                    name_component = ndn_TVL_get_name_components(name_com, payload, payload_len);

                    ndn_TLV_free(name_com);
            }
        }

    }

    if(name_component == NULL){
        ndn_TLV_free(name_node);
        ndn_TLV_free(root);
        ndn_free_tuple3(t3);
        debug("NDN: Cannot parse name component - ipacket : %lu",ipacket->packet_id);
        return MMT_CONTINUE;
    }   
    
    ndn_TLV_free(name_node);

    t3->name = name_component;
    // free(name_component);
    debug("NDN: MAC (source): %s \n",t3->src_MAC);
    debug("NDN: MAC (destination): %s \n",t3->dst_MAC);
    debug("NDN: name: %s\n",t3->name);
    debug("NDN: Type: %d\n",t3->packet_type);
    // Created tuple3
    ndn_proto_context_t * ndn_proto_context = ndn_get_proto_context(ipacket,index);
    if(ndn_proto_context == NULL){
        debug("\nNDN: Cannot get NDN protocol context");
        return MMT_CONTINUE;
    }

    // Update last ndn packet
    if(ndn_proto_context->dummy_packet == NULL){
        ndn_proto_context->dummy_packet = mmt_malloc(sizeof(ipacket_t));
        ndn_proto_context->dummy_packet->mmt_handler = ipacket->mmt_handler;
        ndn_proto_context->dummy_packet->data = NULL;
    }
    ndn_proto_context->dummy_packet->packet_id = ipacket->packet_id;
    ndn_proto_context->dummy_packet->p_hdr = ipacket->p_hdr;

    // Update proto_index
    if(ndn_proto_context->proto_index == 0){
        ndn_proto_context->proto_index = index;
    }

    // Update list NDN session
    ndn_session_t *dummy_session = ndn_proto_context->dummy_session;

    if(dummy_session == NULL){
        debug("\nNDN: Cannot get ndn dummy_session");
        return MMT_CONTINUE;
    }

    if(dummy_session->next != NULL){
        ndn_process_timed_out_session(ipacket,index,dummy_session->next,dummy_session);    
    }else{
        debug("\nNDN: No session to process timed out");
    }
    

    ndn_session_t *ndn_session = ndn_find_session_by_tuple3(t3, dummy_session);
    int direction = 0;
    if(ndn_session == NULL){
        ndn_session = ndn_new_session();
        ndn_session->tuple3 = t3;
        ndn_session->s_init_time = mmt_malloc(sizeof(struct timeval));
        ndn_session->last_reported_time = mmt_malloc(sizeof(struct timeval));
        ndn_session->s_init_time->tv_sec = ipacket->p_hdr->ts.tv_sec;
        ndn_session->s_init_time->tv_usec = ipacket->p_hdr->ts.tv_usec;
        ndn_session->last_reported_time->tv_sec = ipacket->p_hdr->ts.tv_sec;
        ndn_session->last_reported_time->tv_usec = ipacket->p_hdr->ts.tv_usec;
        ndn_session->session_id = dummy_session->session_id;
        dummy_session->session_id += 1;
        debug("\nNDN: New session is created: %lu",ndn_session->session_id);
        if(dummy_session->next == NULL){
            debug("\nNDN: First session of the list");
            dummy_session->next = ndn_session;
        }else{
            debug("\nNDN: Added to the existing session of the list: %lu",dummy_session->next->session_id);
            ndn_session->next = dummy_session->next;    
            dummy_session->next = ndn_session;
        }
    }else{
        debug("\nNDN: Updating the session: %lu",ndn_session->session_id);
        if(str_compare(t3->src_MAC, ndn_session->tuple3->src_MAC) == 1){
            direction = 0;
        }else{
            direction = 1;
        }
        ndn_free_tuple3(t3);
    }
    
    // Update s_last_activity_time
    if(ndn_session->s_last_activity_time == NULL ){
        ndn_session->s_last_activity_time = mmt_malloc(sizeof(struct timeval));
    }

    ndn_session->s_last_activity_time->tv_sec = ipacket->p_hdr->ts.tv_sec;
    ndn_session->s_last_activity_time->tv_usec = ipacket->p_hdr->ts.tv_usec;   
    ///--- UPDATE SESSION DATA --- ///
    
    ndn_session->current_direction = direction;

    // Update Interest packet statistic
    if(root->type == NDN_INTEREST_PACKET){
        ndn_session->nb_interest_packet[direction]++;
        ndn_session->data_volume_interest_packet[direction] += ipacket->p_hdr->len;
        ndn_session->ndn_volume_interest_packet[direction] += root->length;

        ndn_tlv_t *ndn_lifetime = ndn_find_node(payload, payload_len, root,NDN_INTEREST_LIFETIME);
        if(ndn_lifetime != NULL){
            ndn_session->interest_lifeTime[direction] = ndn_TLV_get_int(ndn_lifetime, payload, payload_len);
            ndn_TLV_free(ndn_lifetime);
        }
        if(ndn_session->interest_lifeTime[direction] == 0){
            ndn_session->interest_lifeTime[direction] = NDN_MAX_EXPIRED_TIME;
        }
    }
    // Update Data packet statistic
    if(root->type == NDN_DATA_PACKET){
        ndn_session->nb_data_packet[direction]++;
        ndn_session->data_volume_data_packet[direction] += ipacket->p_hdr->len;
        ndn_session->ndn_volume_data_packet[direction] += root->length;

        ndn_tlv_t *ndn_metainfo = ndn_find_node(payload,payload_len,root, NDN_DATA_METAINFO);

        ndn_tlv_t *ndn_freshness_period = ndn_find_node(payload, payload_len, ndn_metainfo,NDN_DATA_FRESHNESS_PERIOD);
        
        ndn_session->data_freshnessPeriod[direction] = ndn_TLV_get_int(ndn_freshness_period, payload, payload_len);

        ndn_TLV_free(ndn_freshness_period);

        ndn_TLV_free(ndn_metainfo);
    }   
    
    ndn_TLV_free(root);

    debug("NDN: ndn_update_session_for_ipacket: %lu",ipacket->packet_id);
    // ndn_public_session_report(ndn_session);
    return MMT_CONTINUE;
}

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

void cleanup_ndn_context(void * proto_context, void * args){
    debug("NDN: cleanup_ndn_context");
    ndn_proto_context_t * ndn_proto_context = (ndn_proto_context_t*)((protocol_instance_t *) proto_context)->args;
    if(ndn_proto_context == NULL){
        log_err("\nNDN: Cannot get NDN protocol context");
        return;
    }
    ndn_session_t *dummy_session = ndn_proto_context->dummy_session;
    ipacket_t * dummy_packet = ndn_proto_context->dummy_packet;
    unsigned proto_index = ndn_proto_context->proto_index;

    ndn_session_t *current_session = dummy_session->next;
    
    while(current_session !=NULL){
        ndn_session_t *session_to_delete = current_session;
        current_session = session_to_delete->next;
        debug("\nNDN: Need to report this session: %lu",session_to_delete->session_id);
        ndn_process_timed_out(dummy_packet,proto_index,session_to_delete);

        // fire_attribute_event(dummy_packet, PROTO_NDN, NDN_LIST_SESSIONS, proto_index, (void *) session_to_delete);
        // ndn_free_session(session_to_delete);
    }
    ndn_free_session(dummy_session);
    mmt_free(ndn_proto_context->dummy_packet);
    mmt_free(ndn_proto_context);
}

/**
 * Setup ndn protocol context - create ndn_list_session
 * @param  proto_context 
 * @param  args          
 * @return               pointer points to the list_all_ndn_session
 */
void * setup_ndn_context(void * proto_context, void * args) {
    ndn_proto_context_t * ndn_proto_context;
    ndn_proto_context = mmt_malloc(sizeof(ndn_proto_context_t));
    // ndn_list_all_sessions = (ndn_session_t*)malloc(sizeof(ndn_session_t));
    ndn_proto_context->dummy_session = ndn_new_session();
    ndn_proto_context->dummy_packet = NULL;
    ndn_proto_context->proto_index = 0;
    // ndn_list_all_sessions->next = NULL;
    return (void*)ndn_proto_context;
}

void mmt_init_classify_me_ndn() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
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
        // register_pre_post_classification_functions(protocol_struct, NULL, NULL);
        register_proto_context_init_cleanup_function(protocol_struct, setup_ndn_context, cleanup_ndn_context, NULL);
        register_session_data_analysis_function(protocol_struct, ndn_session_data_analysis);
        mmt_init_classify_me_ndn();

        return register_protocol(protocol_struct, PROTO_NDN);
    } else {
        return 0;
    }
}


