#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "ndn.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#include "ndn.h"
int ndn_TLV_check_type(int type){

    // 01 - ImplicitSha256DigestComponent
    if(type==1) return 1;
    
    if(type < 5 || type > 29 || type == 11) return 0;
    
    return 1;
}

uint16_t ndn_TLV_get_type(char *type){
    if(type==NULL) return 0;
    if(strlen(type) != 2) return 0;
    unsigned long t_val = hex2dec(type);
    
    if(ndn_TLV_check_type(t_val)==0) return 0;
    
    return t_val;
}


ndn_tlv_t * ndn_TLV_init(){
    ndn_tlv_t *ndn_tlv;
    ndn_tlv = (ndn_tlv_t *)malloc(sizeof(ndn_tlv_t));
    ndn_tlv->type = 0;
    ndn_tlv->length = 0;
    ndn_tlv->nb_octets = 0;
    ndn_tlv->value = NULL;
    ndn_tlv->remain_value = NULL;
    ndn_tlv->next = NULL;
    return ndn_tlv;
}

void ndn_TLV_free(ndn_tlv_t * ndn){
    
    if(ndn == NULL) return;

    if(ndn->value != NULL) free(ndn->value);

    if(ndn->remain_value != NULL) free(ndn->remain_value);

    if(ndn->next) ndn_TLV_free(ndn->next);

    free(ndn);
    // ndn = NULL;
}

ndn_tlv_t * ndn_TLV_parser(char *payload, int total_length){

    if(payload == NULL) return NULL;

    char *str_type = str_sub(payload,0,1);

    int type = ndn_TLV_get_type(str_type);

    if(type == 0) {
        debug("Wrong type : %s\n",str_type);
        free(str_type);
        // ndn_TLV_free(ndn_new_node);
        return NULL;
    }
    free(str_type);

    char *first_octet = str_sub(payload,2,3);
    unsigned long val = hex2dec(first_octet);

    // Check the value of first octets
    if(val == -1 && val > 255 ) {
        debug("First octet : %s\n",first_octet);
        free(first_octet);
        // ndn_TLV_free(ndn_new_node);
        return NULL;
    }
    ndn_tlv_t * ndn_new_node = NULL;
    if(val == 0 ){
        if(total_length == 2){
            ndn_new_node = ndn_TLV_init();
            ndn_new_node->type = type;
            return ndn_new_node;
        }else{
            debug("First octet : %s\n",first_octet);
            free(first_octet);
            // ndn_TLV_free(ndn_new_node);
            return NULL;
        }
    }
    free(first_octet);
    
    ndn_new_node = ndn_TLV_init();
    ndn_new_node->type = type;
    // int nb_octets = 0;
    switch(val){
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
            // nb_octets = 0;
            break;
    }

    if(total_length < 2 + ndn_new_node->nb_octets){
        debug("Not correct length value : %lu \n",val);
        ndn_TLV_free(ndn_new_node);
        return NULL;
    }
    char *str_length;
    if(ndn_new_node->nb_octets != 0){
        str_length = str_sub(payload, 2*2, 2*(2 + ndn_new_node->nb_octets) - 1);
    }else{
        str_length = str_sub(payload, 2, 2*(2 + ndn_new_node->nb_octets) - 1);
    }
    ndn_new_node->length = hex2dec(str_length);

    if(str_length != NULL) free(str_length);
    
    ndn_new_node->value = str_sub(payload,(2 + ndn_new_node->nb_octets) * 2,(2 + ndn_new_node->nb_octets) * 2 + ndn_new_node->length*2-1);
    if(2 + ndn_new_node->nb_octets + ndn_new_node->length < total_length){
        char *new_str = payload + 2*(2 + ndn_new_node->nb_octets + ndn_new_node->length);
        ndn_new_node->remain_value = str_copy(new_str);
        // if(new_str != NULL) free(new_str);
        // ndn_new_node->remain_value = payload + 2*(2 + ndn_new_node->nb_octets + ndn_new_node->length);
    }
    return ndn_new_node;
}

ndn_tlv_t * ndn_find_node(ndn_tlv_t *root, int node_type){
    
    if(root==NULL) return NULL;

    if(root->value == NULL) {
        // ndn_TLV_free(root);
        return NULL;
    }
    if(ndn_TLV_check_type(node_type)==0) {
        // ndn_TLV_free(root);
        return NULL;
    }
    int remain_length = root->length;
    ndn_tlv_t * temp = ndn_TLV_parser(root->value,remain_length);

    while(temp!=NULL){
        remain_length = remain_length - 2 - temp->nb_octets - temp->length;
        if(temp->type == node_type){
            return temp;
        }
        if(temp->remain_value==NULL) return NULL;

        // Find depth - possible
        // ndn_tlv_t * temp_deeper = ndn_find_node(temp,node_type);

        // if(temp_deeper != NULL) return temp_deeper;

        // Find width
        char *new_payload = str_copy(temp->remain_value);
        ndn_TLV_free(temp);
        temp = ndn_TLV_parser(new_payload,remain_length);
        if(new_payload != NULL) free(new_payload);
    }
    ndn_TLV_free(temp);
    return NULL;
}

int mmt_check_ndn_payload(char* payload, int packet_len){
    // Minimum packet: 050007
    int ret = 0;
    if(packet_len < 3) return 0;

    // Check the first condition: 05 - interest packet, 06 - data packet
    if ( (payload[0] != '0') || (payload[1] != '5' && payload[1] != '6') ) return 0;

    // Check the second condition: length
    ndn_tlv_t *root  = ndn_TLV_parser(payload, packet_len);
    
    if(root == NULL)
        return 0;
    if( packet_len != root->length + 2 + root->nb_octets){
        ndn_TLV_free(root);
        return 0;
    }

    // Check the condition of the common fields: name '07'
    if(root->value[0]!='0' || root->value[1]!='7'){
        ndn_TLV_free(root);
        return 0;
    }

    if(root->type == 5){
        ndn_TLV_free(root);
        return 1;
    } 
        
    if(root->type == 6) {
        ndn_TLV_free(root);
        return 2;
    }

    return 0;
}

ndn_tlv_t * ndn_TLV_parser_name_comp(char* payload, int payload_len){
    // debug("\nRemain:\n %s\nLength: %d\n",payload,payload_len);
    ndn_tlv_t * name_com = ndn_TLV_parser(payload,payload_len);

    if(name_com == NULL) return NULL;

    if(name_com->type != NDN_NAME_COMPONENT) {
        ndn_TLV_free(name_com);
        return NULL;
    }
    if(name_com->value != NULL){
        name_com->value = str_sub(name_com->value,0,name_com->length*2-1);
    }
    int remain_length = payload_len - 2 - name_com->nb_octets - name_com->length;
    if(remain_length>0){
        // char *new_payload = str_copy();
        name_com->next = ndn_TLV_parser_name_comp(name_com->remain_value,remain_length);
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


uint8_t ndn_packet_type_extraction(char* payload, int packet_len){
    
    ndn_tlv_t *ndn = ndn_TLV_parser(payload,packet_len);

    int ret = NDN_UNKNOWN_PACKET;
    if(ndn!=NULL){
        if(ndn->type == 5 || ndn->type==6) ret = ndn->type;
    }

    ndn_TLV_free(ndn);

    return ret;
}


uint32_t ndn_packet_length_extraction(char* payload, int packet_len){
    
    int ret = 0;

    ndn_tlv_t *ndn = ndn_TLV_parser(payload,packet_len);

    if(ndn != NULL) {
        if(ndn->type == NDN_DATA_PACKET || ndn->type == NDN_INTEREST_PACKET){
            ret = ndn->length * 2;
        }
    }

    ndn_TLV_free(ndn);
    
    return ret;
}

char* ndn_name_components_extraction(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root==NULL){
        ndn_TLV_free(root);
        return NULL;
    }

    if(root->type == NDN_UNKNOWN_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    if(root->value == NULL){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t * name_node = ndn_TLV_parser(root->value,root->length);

    char * ret;

    if(name_node != NULL ) {
        if(name_node->type == NDN_COMMON_NAME) {

                if(name_node->value != NULL) {
                    // name_node->value = str_sub(name_node->value,0,name_node->length*2-1);
                char *new_payload = str_sub(name_node->value,0,name_node->length*2-1);

                ndn_tlv_t * name_com = ndn_TLV_parser_name_comp(new_payload,name_node->length);

                if(name_com != NULL) {
                    
                    ret = hex2str(name_com->value);

                    ndn_tlv_t *temp = name_com->next;
                    
                    while(temp != NULL){
                        
                        char *str_temp = str_combine(ret,"/");
                        if(ret != NULL) free(ret);
                        ret = str_copy(str_temp);
                        if(str_temp != NULL) free(str_temp);
                        
                        char *str_value = hex2str(temp->value);
                        
                        str_temp = str_combine(ret,str_value);
                        if(ret != NULL) free(ret);
                        ret = str_copy(str_temp);
                        if(str_temp != NULL) free(str_temp);
                        if(str_value != NULL) free(str_value);

                        temp = temp->next;
                    }

                    free(new_payload);
                    
                    ndn_TLV_free(name_com);
                }
            }

        }

    }

    ndn_TLV_free(name_node);

    ndn_TLV_free(root);

    return ret;
}

/////////////////////// INTEREST PACKET ////////////////////////

int ndn_interest_nonce_extraction(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_nonce = ndn_find_node(root,NDN_INTEREST_NONCE);

    int ret = -1;

    if(ndn_nonce != NULL) {
        if(ndn_nonce->value != NULL) {
            ret = hex2dec(ndn_nonce->value);
        }
    }

    ndn_TLV_free(ndn_nonce);

    ndn_TLV_free(root);
    
    return ret;
}


int ndn_interest_lifetime_extraction(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_lifetime = ndn_find_node(root,NDN_INTEREST_LIFETIME);

    int ret = -1; 
    if(ndn_lifetime != NULL) {
        if(ndn_lifetime->value != NULL) {
            ret = hex2dec(ndn_lifetime->value);
        }

    }

    ndn_TLV_free(ndn_lifetime);

    ndn_TLV_free(root);
    
    return ret;
}

int ndn_interest_min_suffix_component_extraction(char *payload,int payload_len){
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_INTEREST_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_selectors = ndn_find_node(root,NDN_INTEREST_SELECTORS);

    ndn_tlv_t *ndn_min = ndn_find_node(ndn_selectors,NDN_INTEREST_MIN_SUFFIX_COMPONENT);

    int ret = -1;

    if(ndn_min != NULL) {
        if(ndn_min->value != NULL){
            ret = hex2dec(ndn_min->value);
        }
    }
    ndn_TLV_free(ndn_min);

    ndn_TLV_free(ndn_selectors);

    ndn_TLV_free(root);

    return ret;
}


/////////////////////// DATA PACKET ////////////////////////

char* ndn_data_content_extraction(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t *ndn_data_content = ndn_find_node(root,NDN_DATA_CONTENT);

    if(ndn_data_content==NULL) return NULL;

    if(ndn_data_content->value==NULL) return NULL;

    char *ret = hex2str(ndn_data_content->value);

    ndn_TLV_free(ndn_data_content);

    ndn_TLV_free(root);

    return ret;
}

int ndn_data_content_type_extraction(char *payload,int payload_len){
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_metainfo = ndn_find_node(root,NDN_DATA_METAINFO);

    if(ndn_metainfo == NULL){
        ndn_TLV_free(root);
        return -1;
    }

    ndn_tlv_t *ndn_content_type = ndn_find_node(ndn_metainfo,NDN_DATA_CONTENT_TYPE);
    
    int ret = -1;
    if(ndn_content_type != NULL) {
        if(ndn_content_type->value != NULL) {
            ret = hex2dec(ndn_content_type->value);
        }
    }
    ndn_TLV_free(ndn_content_type);

    ndn_TLV_free(ndn_metainfo);

    ndn_TLV_free(root);

    return ret;
}

int ndn_data_freshness_period_extraction(char *payload,int payload_len){
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return -1;
    }

    int ret = -1;
    ndn_tlv_t *ndn_metainfo = ndn_find_node(root,NDN_DATA_METAINFO);

    ndn_tlv_t *ndn_freshness_period = ndn_find_node(ndn_metainfo,NDN_DATA_FRESHNESS_PERIOD);
    
    if(ndn_freshness_period != NULL) {

        if(ndn_freshness_period->value != NULL) {
            ret = hex2dec(ndn_freshness_period->value);
        }

    }
    ndn_TLV_free(ndn_freshness_period);

    ndn_TLV_free(ndn_metainfo);

    ndn_TLV_free(root);

    return ret;
}



int ndn_data_signature_type_extraction(char *payload,int payload_len){
    int ret = -1;
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return ret;
    }

    ndn_tlv_t *ndn_data_signature_info = ndn_find_node(root,NDN_DATA_SIGNATURE_INFO);

    ndn_tlv_t *ndn_data_signature_type = ndn_find_node(ndn_data_signature_info,NDN_DATA_SIGNATURE_TYPE);

    if(ndn_data_signature_type==NULL) {
        ndn_TLV_free(ndn_data_signature_info);
        ndn_TLV_free(root);
        return -1;
    }
    if(ndn_data_signature_type->value==NULL) {
        ndn_TLV_free(ndn_data_signature_type);
        ndn_TLV_free(ndn_data_signature_info);
        ndn_TLV_free(root);
        return -1;
    }
    unsigned long st = hex2dec(ndn_data_signature_type->value);
    
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

char* ndn_data_key_locator_extraction(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t *ndn_data_signature_info = ndn_find_node(root,NDN_DATA_SIGNATURE_INFO);

    ndn_tlv_t *ndn_data_key_locator =  ndn_find_node(ndn_data_signature_info,NDN_DATA_KEY_LOCATOR);

    char *ret = NULL;

    if(ndn_data_key_locator != NULL) {
        if(ndn_data_key_locator->value != NULL){
            ret = hex2str(ndn_data_key_locator->value);
        }
    }

    ndn_TLV_free(ndn_data_key_locator);

    ndn_TLV_free(ndn_data_signature_info);

    ndn_TLV_free(root);

    return ret;
}


char* ndn_data_signature_value_extraction(char *payload,int payload_len){
    
    ndn_tlv_t * root = ndn_TLV_parser(payload,payload_len);

    if(root->type != NDN_DATA_PACKET){
        ndn_TLV_free(root);
        return NULL;
    }

    ndn_tlv_t *ndn_data_signature_value = ndn_find_node(root,NDN_DATA_SIGNATURE_VALUE);
    
    char *ret = NULL;

    if(ndn_data_signature_value != NULL) {
        if(ndn_data_signature_value->value !=NULL) {
            ret = str_copy(ndn_data_signature_value->value);
        }
    }

    ndn_TLV_free(ndn_data_signature_value);

    ndn_TLV_free(root);
    
    return ret;
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
            int offset = get_packet_offset_at_index(ipacket, index);
            char *payload = (char*)&ipacket->data[offset];
            uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

            if(payload_len==0){
                debug("NDN: payload_len == 0");
                return 1;
            }

            if(mmt_check_ndn_payload(payload,payload_len)!=0){
                debug("NDN: found ndn packet %lu",ipacket->packet_id);
                mmt_int_ndn_add_connection(ipacket);
                return 1;
            }
    }
    return 1;
}
//////////////////////////// EXTRACTION ///////////////////////////////////////


static attribute_metadata_t ndn_attributes_metadata[NDN_ATTRIBUTES_NB] = {
    // {NDN_IMPLICIT_SHA256_DIGEST_COMPONENT,NDN_IMPLICIT_SHA256_DIGEST_COMPONENT_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ndn_implicit_sha256_digest_component_extraction},
    {NDN_PACKET_TYPE,NDN_PACKET_TYPE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_packet_type_extraction},
    {NDN_PACKET_LENGTH,NDN_PACKET_LENGTH_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_packet_length_extraction},
    {NDN_NAME_COMPONENT,NDN_NAME_COMPONENT_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_name_component_extraction},
    {NDN_INTEREST_NONCE,NDN_INTEREST_NONCE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_nonce_extraction},
    {NDN_INTEREST_LIFETIME,NDN_INTEREST_LIFETIME_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_lifetime_extraction},
    {NDN_INTEREST_MIN_SUFFIX_COMPONENT,NDN_INTEREST_MIN_SUFFIX_COMPONENT_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_min_suffix_component_extraction},
    {NDN_INTEREST_MAX_SUFFIX_COMPONENT,NDN_INTEREST_MAX_SUFFIX_COMPONENT_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_max_suffix_component_extraction},
    // {NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR,NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_publisher_publickey_locator_extraction},
    // {NDN_INTEREST_EXCLUDE,NDN_INTEREST_EXCLUDE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_exclude_extraction},
    // {NDN_INTEREST_CHILD_SELECTOR,NDN_INTEREST_CHILD_SELECTOR_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_child_selector_extraction},
    // {NDN_INTEREST_MUST_BE_FRESH,NDN_INTEREST_MUST_BE_FRESH_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_must_be_fresh_extraction},
    // {NDN_INTEREST_ANY,NDN_INTEREST_ANY_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_interest_any_extraction},
    {NDN_DATA_CONTENT,NDN_DATA_CONTENT_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_content_extraction},
    {NDN_DATA_SIGNATURE_VALUE,NDN_DATA_SIGNATURE_VALUE_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_signature_value_extraction},
    {NDN_DATA_CONTENT_TYPE,NDN_DATA_CONTENT_TYPE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_content_type_extraction},
    {NDN_DATA_FRESHNESS_PERIOD,NDN_DATA_FRESHNESS_PERIOD_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_freshness_period_extraction},
    // {NDN_DATA_FINAL_BLOCK_ID,NDN_DATA_FINAL_BLOCK_ID_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_final_block_id_extraction},
    {NDN_DATA_SIGNATURE_TYPE,NDN_DATA_SIGNATURE_TYPE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ndn_data_signature_type_extraction},
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
int ndn_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    debug("NDN: ndn_session_data_analysis");
    return MMT_CONTINUE;
}

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////


// void * setup_ndn_context(void * proto_context, void * args) {
//     ftp_control_session_t * ftp_list_control_conns;
//     ftp_list_control_conns = (ftp_control_session_t*)malloc(sizeof(ftp_control_session_t));
//     ftp_list_control_conns->next = NULL;
//     return (void*)ftp_list_control_conns;
// }


void mmt_init_classify_me_ftp() {
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


