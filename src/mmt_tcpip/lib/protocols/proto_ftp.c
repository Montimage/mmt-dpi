#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "ftp.h"

//////////// LUONG NGUYEN - END OF FUNCTION    /////////////////////////
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static void mmt_int_ftp_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_FTP, MMT_REAL_PROTOCOL);
}

/*
  return 0 if nothing has been detected
  return 1 if a pop packet
 */

static uint8_t search_ftp(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint8_t current_ftp_code = 0;

    /* initiate client direction flag */
    if (ipacket->session->data_packet_count == 1) {
        if (flow->l4.tcp.seen_syn) {
            flow->l4.tcp.ftp_client_direction = ipacket->session->setup_packet_direction;
        } else {
            /* no syn flag seen so guess */
            if (packet->payload_packet_len > 0) {
                if (packet->payload[0] >= '0' && packet->payload[0] <= '9') {
                    /* maybe server side */
                    flow->l4.tcp.ftp_client_direction = 1 - ipacket->session->last_packet_direction;
                } else {
                    flow->l4.tcp.ftp_client_direction = ipacket->session->last_packet_direction;
                }
            }
        }
    }

    if (ipacket->session->last_packet_direction == flow->l4.tcp.ftp_client_direction) {
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("USER ") &&
                (memcmp(packet->payload, "USER ", MMT_STATICSTRING_LEN("USER ")) == 0 ||
                memcmp(packet->payload, "user ", MMT_STATICSTRING_LEN("user ")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found USER command\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_USER_CMD;
            current_ftp_code = FTP_USER_CMD;
        } else if (packet->payload_packet_len >= MMT_STATICSTRING_LEN("FEAT") &&
                (memcmp(packet->payload, "FEAT", MMT_STATICSTRING_LEN("FEAT")) == 0 ||
                memcmp(packet->payload, "feat", MMT_STATICSTRING_LEN("feat")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found FEAT command\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_FEAT_CMD;
            current_ftp_code = FTP_FEAT_CMD;
        } else if (!mmt_int_check_possible_ftp_command((char*)packet->payload,packet->payload_packet_len)) {
            return 0;
        }
    } else {
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("220 ") &&
                (memcmp(packet->payload, "220 ", MMT_STATICSTRING_LEN("220 ")) == 0 ||
                memcmp(packet->payload, "220-", MMT_STATICSTRING_LEN("220-")) == 0)) {
            log_info("FTP: found 220 reply code\n");
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found 220 reply code\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("331 ") &&
                (memcmp(packet->payload, "331 ", MMT_STATICSTRING_LEN("331 ")) == 0 ||
                memcmp(packet->payload, "331-", MMT_STATICSTRING_LEN("331-")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found 331 reply code\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_331_CODE;
            current_ftp_code = FTP_331_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("211 ") &&
                (memcmp(packet->payload, "211 ", MMT_STATICSTRING_LEN("211 ")) == 0 ||
                memcmp(packet->payload, "211-", MMT_STATICSTRING_LEN("211-")) == 0)) {

            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP: found 211reply code\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_211_CODE;
            current_ftp_code = FTP_211_CODE;
        } else if (!mmt_int_check_possible_ftp_reply((char*)packet->payload,packet->payload_packet_len)) {
            if ((flow->l4.tcp.ftp_codes_seen & FTP_CODES) == 0 ||
                    (!mmt_int_check_possible_ftp_continuation_reply((char*)packet->payload,packet->payload_packet_len))) {
                return 0;
            }
        }
    }

    if ((flow->l4.tcp.ftp_codes_seen & FTP_COMMANDS) != 0 && (flow->l4.tcp.ftp_codes_seen & FTP_CODES) != 0) {

        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP detected\n");
        mmt_int_ftp_add_connection(ipacket);
        return 1;
    }

    /* if no valid code has been seen for the first packets reject */
    if (flow->l4.tcp.ftp_codes_seen == 0 && ipacket->session->data_packet_count > 3)
        return 0;

    /* otherwise wait more packets, wait more for traffic on known ftp port */
    if ((ipacket->session->last_packet_direction == ipacket->session->setup_packet_direction && packet->tcp && packet->tcp->dest == htons(21)) ||
            (ipacket->session->last_packet_direction != ipacket->session->setup_packet_direction && packet->tcp && packet->tcp->source == htons(21))) {
        /* flow to known ftp port */
        // return 1;
        /* wait much longer if this was a 220 code, initial messages might be long */
        if (current_ftp_code == FTP_220_CODE) {
            log_info("FTP: 220 code Waiting....(1/2)");
            if (ipacket->session->data_packet_count > 40)
                return 0;
        } else {
            if (ipacket->session->data_packet_count > 20)
                return 0;
        }
    } else {
        /* wait much longer if this was a 220 code, initial messages might be long */
        if (current_ftp_code == FTP_220_CODE) {
            log_info("FTP: 220 code Waiting....(2/2)");
            if (ipacket->session->data_packet_count > 20)
                return 0;
        } else {
            if (ipacket->session->data_packet_count > 10)
                return 0;
        }
    }

    return 2;
}

static void search_passive_ftp_mode(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    uint16_t plen;
    uint8_t i;
    uint32_t ftp_ip;


    // TODO check if normal passive mode also needs adaption for ipv6
    if (packet->payload_packet_len > 3 && mmt_mem_cmp(packet->payload, "227 ", 4) == 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP passive mode initial string\n");

        plen = 4; //=4 for "227 "
        while (1) {
            if (plen >= packet->payload_packet_len) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                        "plen >= packet->payload_packet_len, return\n");
                return;
            }
            if (packet->payload[plen] == '(') {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "found (. break.\n");
                break;
            }

            plen++;
        }
        plen++;

        if (plen >= packet->payload_packet_len)
            return;


        ftp_ip = 0;
        for (i = 0; i < 4; i++) {
            uint16_t oldplen = plen;
            ftp_ip =
                    (ftp_ip << 8) +
                    mmt_bytestream_to_number(&packet->payload[plen], packet->payload_packet_len - plen, &plen);
            if (oldplen == plen || plen >= packet->payload_packet_len) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP passive mode %u value parse failed\n",
                        i);
                return;
            }
            if (packet->payload[plen] != ',') {

                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                        "FTP passive mode %u value parse failed, char ',' is missing\n", i);
                return;
            }
            plen++;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                    "FTP passive mode %u value parsed, ip is now: %u\n", i, ftp_ip);

        }
        if (dst != NULL) {
            dst->ftp_ip.ipv4 = htonl(ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
        }
        if (src != NULL) {
            src->ftp_ip.ipv4 = packet->iph->daddr;
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to src");
        }
        return;
    }

    if (packet->payload_packet_len > 34 && mmt_mem_cmp(packet->payload, "229 Entering Extended Passive Mode", 34) == 0) {
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
        }
        if (src != NULL) {
            mmt_get_destination_ip_from_packet(packet, &src->ftp_ip);
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "saved ftp_ip, ftp_timer, ftp_timer_set to src");
        }
        return;
    }
}

static void search_active_ftp_mode(ipacket_t * ipacket) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (packet->payload_packet_len > 5
            && (mmt_mem_cmp(packet->payload, "PORT ", 5) == 0 || mmt_mem_cmp(packet->payload, "EPRT ", 5) == 0)) {

        //src->local_ftp_data_port = htons(data_port_number);
        if (src != NULL) {
            mmt_get_destination_ip_from_packet(packet, &src->ftp_ip);
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
                    packet->payload);
        }
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
                    packet->payload);
        }
    }
    return;
}

void mmt_classify_me_ftp(ipacket_t * ipacket, unsigned index) {
    

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (src != NULL && mmt_compare_packet_destination_ip_to_given_ip(packet, &src->ftp_ip)
            && packet->tcp->syn != 0 && packet->tcp->ack == 0
            && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask,
            PROTO_FTP) != 0 && src->ftp_timer_set != 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data, src!= 0.\n");

        if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - src->ftp_timer)) >= ftp_connection_timeout) {
            src->ftp_timer_set = 0;
        } else if (ntohs(packet->tcp->dest) > 1024
                && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
            mmt_int_ftp_add_connection(ipacket);
            return;
        }
    }

    if (dst != NULL && mmt_compare_packet_source_ip_to_given_ip(packet, &dst->ftp_ip)
            && packet->tcp->syn != 0 && packet->tcp->ack == 0
            && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
            PROTO_FTP) != 0 && dst->ftp_timer_set != 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data; dst!= 0.\n");

        if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - dst->ftp_timer)) >= ftp_connection_timeout) {
            dst->ftp_timer_set = 0;

        } else if (ntohs(packet->tcp->dest) > 1024
                && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
            mmt_int_ftp_add_connection(ipacket);
            return;
        }
    }
    // ftp data asymmetrically


    /* skip packets without payload */
    if (packet->payload_packet_len == 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                "FTP test skip because of data connection or zero byte packet_payload.\n");
        return;
    }
    /* skip excluded connections */

    // we test for FTP connection and search for passive mode
    if (packet->detected_protocol_stack[0] == PROTO_FTP) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                "detected ftp command mode. going to test data mode.\n");
        search_passive_ftp_mode(ipacket);

        search_active_ftp_mode(ipacket);
        return;
    }


    if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 0) {
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "unknown. need next packet.\n");

        return;
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP);
    MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "exclude ftp.\n");

}

int mmt_check_ftp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        if (src != NULL && mmt_compare_packet_destination_ip_to_given_ip(packet, &src->ftp_ip)
                && packet->tcp->syn != 0 && packet->tcp->ack == 0
                && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask,
                PROTO_FTP) != 0 && src->ftp_timer_set != 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data, src!= 0.\n");

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->ftp_timer)) >= ftp_connection_timeout) {
                src->ftp_timer_set = 0;
            } else if (ntohs(packet->tcp->dest) > 1024
                    && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }

        if (dst != NULL && mmt_compare_packet_source_ip_to_given_ip(packet, &dst->ftp_ip)
                && packet->tcp->syn != 0 && packet->tcp->ack == 0
                && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
                PROTO_FTP) != 0 && dst->ftp_timer_set != 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "possible ftp data; dst!= 0.\n");

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->ftp_timer)) >= ftp_connection_timeout) {
                dst->ftp_timer_set = 0;

            } else if (ntohs(packet->tcp->dest) > 1024
                    && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "detected FTP data stream.\n");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }
        // ftp data asymmetrically


        /* skip packets without payload */
        if (packet->payload_packet_len == 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                    "FTP test skip because of data connection or zero byte packet_payload.\n");
            return 1;
        }
        /* skip excluded connections */

        // we test for FTP connection and search for passive mode
        if (packet->detected_protocol_stack[0] == PROTO_FTP) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG,
                    "detected ftp command mode. going to test data mode.\n");
            search_passive_ftp_mode(ipacket);

            search_active_ftp_mode(ipacket);
            return 1;
        }


        if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 0) {
            MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "unknown. need next packet.\n");

            return 1;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP);
        MMT_LOG(PROTO_FTP, MMT_LOG_DEBUG, "exclude ftp.\n");

    }
    return 1;
}

//////////////////////////// EXTRACTION ///////////////////////////////////////


////////////////////// SESSION ATTRIBUTE EXTRACTION ///////////////////////
int ftp_session_conn_type_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_tuple6_t *t6;

    t6 = ftp_get_tuple6(packet);

    if(t6){
        extracted_data->data = (void*)t6->conn_type;
        return 1;   
    }
    
    return 0;
}


int ftp_server_contrl_addr_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){

    return 0;
}

int ftp_server_contrl_port_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}

int ftp_client_contrl_addr_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){

    return 0;
}

int ftp_client_contrl_port_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}

int ftp_username_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_password_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_features_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int ftp_status_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_syst_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_last_command_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_last_response_code_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_current_dir_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_server_data_addr_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){

    return 0;
}

int ftp_server_data_port_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}

int ftp_client_data_addr_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){

    return 0;
}

int ftp_client_data_port_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}

int ftp_data_type_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}

int ftp_data_transfer_type_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}

int ftp_data_mode_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}

int ftp_data_direction_extraction(onst ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data){
    return 0;
}



int ftp_file_name_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}


int ftp_file_size_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}

int ftp_file_last_modified_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    return 0;
}


////////////////////// PACKET ATTRIBUTE EXTRACTION ///////////////////////
int ftp_packet_type_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    int packet_type = ftp_get_packet_type_by_port_number((ipacket_t*)packet,proto_index);

    if(packet_type!=MMT_FTP_UNKNOWN_PACKET){
        extracted_data->data = (short*)&packet_type;
        log_info("FTP: packet_type %d in packet: %lu\n", *(short*)extracted_data->data,packet->packet_id);
        return 1;
    }
    return 0;
}

int ftp_packet_request_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number((ipacket_t*)packet,proto_index);
    if(packet_type==MMT_FTP_REQUEST_PACKET){
        int offset = get_packet_offset_at_index(packet, proto_index);
        char *payload = (char*)&packet->data[offset];
        int payload_len = packet->internal_packet->payload_packet_len;
        ftp_command_t * cmd = ftp_get_command(payload,payload_len);
        if(cmd->cmd!=MMT_FTP_UNKNOWN_CMD){
            log_info("FTP: packet_request %d in packet: %lu\n", cmd->cmd,packet->packet_id);
            extracted_data->data = (void*)cmd->str_cmd;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_request_parameter_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number((ipacket_t*)packet,proto_index);
    if(packet_type==MMT_FTP_REQUEST_PACKET){
        int offset = get_packet_offset_at_index(packet, proto_index);
        char *payload = (char*)&packet->data[offset];
        int payload_len = packet->internal_packet->payload_packet_len;
        ftp_command_t * cmd = ftp_get_command(payload,payload_len);
        if(cmd->cmd!=MMT_FTP_UNKNOWN_CMD && cmd->param!=NULL){
            log_info("FTP: packet_request_param %s in packet: %lu\n", cmd->param,packet->packet_id);
            extracted_data->data = (void*)cmd->param;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_response_code_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number((ipacket_t*)packet,proto_index);
    if(packet_type==MMT_FTP_RESPONSE_PACKET){
        int offset = get_packet_offset_at_index(packet, proto_index);
        char *payload = (char*)&packet->data[offset];
        int payload_len = packet->internal_packet->payload_packet_len;
        ftp_response_t * res = ftp_get_response(payload,payload_len);
        if(res->code!=MMT_FTP_UNKNOWN_CODE){
            log_info("FTP: packet_response %d in packet: %lu\n", res->code,packet->packet_id);
            extracted_data->data = (int*)&res->code;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_response_value_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number((ipacket_t*)packet,proto_index);
    if(packet_type==MMT_FTP_RESPONSE_PACKET){
        int offset = get_packet_offset_at_index(packet, proto_index);
        char *payload = (char*)&packet->data[offset];
        int payload_len = packet->internal_packet->payload_packet_len;
        ftp_response_t * res = ftp_get_response(payload,payload_len);
        if(res->code!=MMT_FTP_UNKNOWN_CODE&&res->value!=NULL){
            log_info("FTP: packet_response_value %s in packet: %lu\n", res->value,packet->packet_id);
            extracted_data->data = (void*)res->value;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_data_len_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number((ipacket_t*)packet,proto_index);
    if(packet_type==MMT_FTP_DATA_PACKET){
        extracted_data->data = (uint32_t*)&packet->internal_packet->payload_packet_len;
        log_info("FTP: extraction packet_payload_len: %d",*(int*)extracted_data);
        return 1;
    }
    return 0;
}

static attribute_metadata_t ftp_attributes_metadata[FTP_ATTRIBUTES_NB] = {
    ////////////// SESSION ATTRIBUTES //////////////////////////////
    /// FTP CONTROL CONNECTION SESSION ATTRIBUTES ///
    {FTP_SESSION_CONN_TYPE,FTP_SESSION_CONN_TYPE_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_session_conn_type_extraction},
    {FTP_SERVER_CONT_ADDR,FTP_SERVER_CONT_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_contrl_addr_extraction},
    {FTP_SERVER_CONT_PORT,FTP_SERVER_CONT_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_contrl_port_extraction},
    {FTP_CLIENT_CONT_PORT,FTP_CLIENT_CONT_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_contrl_port_extraction},
    {FTP_CLIENT_CONT_ADDR,FTP_CLIENT_CONT_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_contrl_addr_extraction},
    {FTP_SESSION_USERNAME,FTP_SESSION_USERNAME_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_username_extraction},
    {FTP_SESSION_PASSWORD,FTP_SESSION_PASSWORD_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_password_extraction},
    {FTP_SESSION_FEATURES,FTP_SESSION_FEATURES_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_features_extraction},
    {FTP_SYST,FTP_SYST_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_syst_extraction},
    {FTP_SESSION_STATUS,FTP_SESSION_STATUS_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_status_extraction},
    {FTP_LAST_COMMAND,FTP_LAST_COMMAND_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_last_command_extraction},
    {FTP_LAST_RESPONSE_CODE,FTP_LAST_RESPONSE_CODE_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_last_response_code_extraction},
    {FTP_CURRENT_DIR,FTP_CURRENT_DIR_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_current_dir_extraction},
    /// CURRENT FTP DATA CONNECTION SESSION ATTRIBUTES ///
    {FTP_SERVER_DATA_ADDR,FTP_SERVER_DATA_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_data_addr_extraction},
    {FTP_SERVER_DATA_PORT,FTP_SERVER_DATA_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_data_port_extraction},
    {FTP_CLIENT_DATA_ADDR,FTP_CLIENT_DATA_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_data_addr_extraction},
    {FTP_CLIENT_DATA_PORT,FTP_CLIENT_DATA_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_data_port_extraction},
    {FTP_DATA_TYPE,FTP_DATA_TYPE_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_type_extraction},
    {FTP_DATA_TRANSFER_TYPE,FTP_DATA_TRANSFER_TYPE_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_transfer_type_extraction},
    {FTP_DATA_MODE,FTP_DATA_MODE_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_mode_extraction},
    {FTP_DATA_DIRECTION,FTP_DATA_DIRECTION_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_direction_extraction},
    /// CURRENT FTP FILE ATTRIBUTES ///
    {FTP_FILE_NAME,FTP_FILE_NAME_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_name_extraction},
    {FTP_FILE_SIZE,FTP_FILE_SIZE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_size_extraction},
    {FTP_FILE_LAST_MODIFIED,FTP_FILE_LAST_MODIFIED_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_last_modified_extraction},
    ////////////// PACKET ATTRIBUTES //////////////////////////////
    {FTP_PACKET_TYPE,FTP_PACKET_TYPE_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_type_extraction},
    {FTP_PACKET_REQUEST,FTP_PACKET_REQUEST_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_request_extraction},
    {FTP_PACKET_REQUEST_PARAMETER,FTP_PACKET_REQUEST_PARAMETER_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_request_parameter_extraction},
    {FTP_PACKET_RESPONSE_CODE,FTP_PACKET_RESPONSE_CODE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_response_code_extraction},
    {FTP_PACKET_RESPONSE_VALUE,FTP_PACKET_RESPONSE_VALUE_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_response_value_extraction},
    {FTP_PACKET_DATA_LEN,FTP_PACKET_DATA_LEN_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_data_len_extraction},
};

//////////////////////////// END OF EXTRACTION /////////////////////////////////


///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

void ftp_data_packet(ipacket_t *ipacket,unsigned index){
    log_info("FTP: FTP_DATA PACKET: %lu",ipacket->packet_id);
    
    //printf("from http generic session data analysis\n");
    int offset = get_packet_offset_at_index(ipacket, index);

    char *payload = (char*)&ipacket->data[offset];

    // ftp_data_session_t *ftp_data = (ftp_data_session_t*)ipacket->session->session_data[index];
    
    // if(ftp_data != NULL){
    //     ipacket->session->session_data[index] =  ipacket->session->next->session_data[index];
    // }
    log_info("FTP: Payload: %s",payload);
}

/**
 * Analysis a request packet
 * @param ipacket     packet to analysis
 * @param index       protocol index
 * @param ftp_control FTP control connection session
 */
 void ftp_request_packet(ipacket_t *ipacket,unsigned index, ftp_control_session_t * ftp_control){
    log_info("FTP: FTP_REQUEST PACKET: %lu",ipacket->packet_id);
    
    int offset = get_packet_offset_at_index(ipacket, index);

    char *payload = (char*)&ipacket->data[offset];
    uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

    ftp_command_t * command = ftp_get_command(payload,payload_len);
    ftp_data_session_t *current_data_conn = ftp_control->current_data_conn;
    switch(command->cmd){
        case MMT_FTP_EPRT_CMD:
            current_data_conn->data_conn_mode = MMT_FTP_DATA_ACTIVE_MODE;
            current_data_conn->data_conn->c_addr = ftp_get_data_client_addr_from_EPRT(payload);
            current_data_conn->data_conn->c_port = ftp_get_data_client_port_from_EPRT(payload);
            break;
        case MMT_FTP_PORT_CMD:
            current_data_conn->data_conn_mode = MMT_FTP_DATA_ACTIVE_MODE;
            current_data_conn->data_conn->c_addr = ftp_get_addr_from_parameter(payload);
            current_data_conn->data_conn->c_port = ftp_get_port_from_parameter(payload);
        case MMT_FTP_USER_CMD:
            ftp_control->user->username = command->param;
            ftp_control->status = MMT_FTP_STATUS_OPENED;
            break;
        case MMT_FTP_PASS_CMD:
            ftp_control->user->password = command->param;
            break;
        case MMT_FTP_TYPE_CMD:
            current_data_conn->data_transfer_type=command->param;
            break;
        case MMT_FTP_LIST_CMD:
        case MMT_FTP_MLSD_CMD:
        case MMT_FTP_NLST_CMD:
            current_data_conn->data_type = MMT_FTP_DATA_TYPE_LIST;
            break;
        case MMT_FTP_MLST_CMD:
            current_data_conn->data_type = MMT_FTP_DATA_TYPE_UNKNOWN;
            break;
        case MMT_FTP_RETR_CMD:
            current_data_conn->file->file_name = command->param;
            current_data_conn->data_direction = MMT_FTP_DATA_DOWNLOAD;
            break;
        case MMT_FTP_STOR_CMD:
        case MMT_FTP_STOU_CMD:
            current_data_conn->file->file_name = command->param;
            current_data_conn->data_direction = MMT_FTP_DATA_UPLOAD;
            break;
        case MMT_FTP_SYST_CMD:
            ftp_control->session_syst = command->param;
            break;
        default:
            log_info("FTP: Client command: \n");
            log_info("Command: %s\n",command->str_cmd);
            if(command->param){
                log_info("Parameter: %s\n",command->param);
            }
            break;
    }
}


/**
 * Analyse response packet to get information of this ftp session
 * @param ipacket     ipacket to extract
 * @param index       index of protocol
 * @param ftp_control ftp control session of which this packet belongs to
 */
void ftp_response_packet(ipacket_t *ipacket,unsigned index,ftp_control_session_t *ftp_control){
    log_info("FTP: FTP_RESPONSE PACKET: %lu",ipacket->packet_id);
    
    int offset = get_packet_offset_at_index(ipacket, index);

    char *payload = (char*)&ipacket->data[offset];
    uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

    ftp_response_t * response = ftp_get_response(payload,payload_len);
    ftp_data_session_t *current_data_conn = ftp_control->current_data_conn;
    if(response->code!=MMT_FTP_UNKNOWN_CODE){
        log_info("FTP: %s",response->value);
        ftp_control->last_response = response;
        switch(response->code){
            case MMT_FTP_230_CODE:
                ftp_control->status = MMT_FTP_STATUS_CONTROLING;
                break;
            case MMT_FTP_CONTINUE_CODE:
                ftp_control->session_feats = str_append(ftp_control->session_feats,payload,payload_len);
                break;
            case MMT_FTP_257_CODE:
                ftp_control->current_dir=response->value;
                break;
            case MMT_FTP_213_CODE:
                if(ftp_control->last_command->cmd==MMT_FTP_MDTM_CMD){
                    current_data_conn->file->file_last_modified = response->value;
                }else if(ftp_control->last_command->cmd==MMT_FTP_SIZE_CMD){
                    current_data_conn->file->file_size = response->value;
                }
                break;
            case MMT_FTP_229_CODE:
                current_data_conn->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
                ftp_tuple6_t * t6 = ftp_new_tuple6();
                t6->s_port = ftp_get_data_server_port_code_229(response->value);
                t6->s_addr = ftp_control->contrl_conn->s_addr;
                t6->c_addr = ftp_control->contrl_conn->c_addr;
                t6->conn_type = MMT_FTP_DATA_CONNECTION;
                t6->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
                current_data_conn->data_conn = t6;
                break;
            case MMT_FTP_227_CODE:
                current_data_conn->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
                log_warn("FTP: 227 code, enter passive mode - not implemented yet");
                current_data_conn->data_conn->s_addr = ftp_get_data_server_addr_code_227(payload);
                current_data_conn->data_conn->s_port = ftp_get_data_server_port_code_227(payload);
                break;
            case MMT_FTP_228_CODE:
                current_data_conn->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
                t6->s_port = ftp_get_data_server_port_code_228(response->value);
                t6->s_addr = ftp_get_data_server_addr_code_228(response->value);
                t6->c_addr = ftp_control->contrl_conn->c_addr;
                t6->conn_type = MMT_FTP_DATA_CONNECTION;
                t6->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
                current_data_conn->data_conn = t6;
                break;
            case MMT_FTP_150_CODE:
                ftp_control->LAST_COMMAND = MMT_FTP_STATUS_DATA_OPENED;
                break;
            case MMT_FTP_226_CODE:
                ftp_control->session_status = MMT_FTP_STATUS_DATA_CLOSED;
                break;
            case MMT_FTP_221_CODE:
                ftp_control->session_status = MMT_FTP_STATUS_CLOSED;
                break;
            default:
                log_info("FTP: code : %d\n",response->code);
                log_info("FTP: value : %s\n",response->value);
                break;
        }
    }else{
        log_info("FTP: Received a response code:\n");
        log("Code: %d\n",response->code);
        log_info("Value : %s\n",response->value);
    }
}


int ftp_session_data_analysis(ipacket_t * ipacket, unsigned index) {

    log_info("FTP: START ANALYSING SESSION DATA OF PACKET: %lu",ipacket->packet_id);
    
    //printf("from http generic session data analysis\n");
    int offset = get_packet_offset_at_index(ipacket, index);
    
    char *payload = (char*)&ipacket->data[offset];

    // Make sure there is data to analayse
    if(strlen(payload)<=0){
        return MMT_CONTINUE;
    }
    
    ftp_tuple6_t *tuple6 = ftp_get_tuple6(ipacket,index);


    ftp_control_session_t *ftp_list_control = ftp_get_list_control_session(ipacket,index);
    ftp_control_session_t *ftp_control;
    ftp_data_session_t *ftp_data;
    if(tuple6->conn_type==MMT_FTP_CONTROL_CONNECTION){
        if(ipacket->session->session_data[index]){
            ftp_control = (ftp_control_session_t*)ipacket->session->session_data[index];
            int compare = ftp_compare_tuple6(tuple6,ftp_control->contrl_conn);
            if(compare == 0){
                fprintf(stderr, "FTP: Not correct control connection\n", );
                return MMT_CONTINUE;
            }else{
                ftp_control->contrl_conn->direction = tuple6->direction;
            }
        }else{
            ftp_control = ftp_new_control_session(tuple6);
            if(ftp_list_control->contrl_conn == NULL){
                ftp_list_control = ftp_control;
            }else{
                ftp_control_session_t * temp = ftp_list_control;
                while(temp->next){
                    temp = temp->next;
                }
                temp->next = ftp_control;
            }
        }
    }else{
        if(ipacket->session->session_data[index]){
            ftp_data = (ftp_data_session_t*)ipacket->session->session_data[index];
            int compare = ftp_compare_tuple6(tuple6,conn);
            ftp_set_tuple6_direction(tuple6,ftp_data->data_conn,compare);
        }else{
            // New not FTP control packet
            if(ftp_list_control->contrl_conn == NULL){
                fprintf(stderr, "FTP: Cannot find any control connection\n", );
                return MMT_CONTINUE;
            }else{
                ftp_control_session_t *temp = ftp_list_control;
                while(temp->next && temp->current_data_conn){
                    int compare = ftp_compare_tuple6(tuple6,temp->current_data_conn->data_conn);
                    if(compare!=0){
                        ftp_set_tuple6_direction(tuple6,temp->current_data_conn->data_conn,compare);
                        ipacket->session->session_data[index] = temp->current_data_conn;
                        break;
                    }
                    temp = temp->next;
                } 
            }
        }
    }

    if(tuple6->conn_type == MMT_FTP_CONTROL_CONNECTION && tuple6->direction == MMT_FTP_PACKET_SERVER && ftp_control){
        ftp_response_packet(ipacket,index,ftp_control);
    }else if(tuple6->conn_type == MMT_FTP_CONTROL_CONNECTION && tuple6->direction == MMT_FTP_PACKET_CLIENT && ftp_control){
        ftp_request_packet(ipacket,index,ftp_control);
    }else if(tuple6->conn_type == MMT_FTP_DATA_CONNECTION && ftp_data){
        ftp_data_packet(ipacket,index,ftp_data);
    }else{
        fprintf(stderr, "Cannot analysis data of packet: %lu\n",ipacket->packet_id);
        fprintf(stderr, "Connection type: %d\n",tuple6->conn_type);
        fprintf(stderr, "Connection direction: %d\n",tuple6->direction);
    }
    
    return MMT_CONTINUE;
}

// void ftp_session_data_init(ipacket_t * ipacket, unsigned index) {
//     log_info("FTP: INITIALING SESSION DATA");
//     ftp_session_data_t * ftp_session_data = (ftp_session_data_t *) mmt_malloc(sizeof (ftp_session_data_t));
//     memset(ftp_session_data, 0, sizeof (ftp_session_data_t));
//     ipacket->session->session_data[index] = ftp_session_data;

// }
///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

ftp_control_session_t ftp_get_list_control_session(ipacket_t *ipacket, unsigned index){
    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
            ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
    return (ftp_control_session_t)configured_protocol->args;
}


void * setup_ftp_context(void * proto_context, void * args) {
    ftp_control_session_t * ftp_list_control_conns;
    ftp_list_control_conns = (ftp_control_session_t*)malloc(sizeof(ftp_control_session_t));
    return ftp_list_control_conns;
}


void mmt_init_classify_me_ftp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FTP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ftp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FTP, PROTO_FTP_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < FTP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ftp_attributes_metadata[i]);
        }
        // register_session_data_initialization_function(protocol_struct, ftp_session_data_init);
        register_proto_context_init_cleanup_function(protocol_struct, setup_ftp_context, NULL, NULL);
        register_session_data_analysis_function(protocol_struct, ftp_session_data_analysis);
        mmt_init_classify_me_ftp();

        return register_protocol(protocol_struct, PROTO_FTP);
    } else {
        return 0;
    }
}


