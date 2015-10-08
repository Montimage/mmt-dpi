#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "ftp.h"


//////////// LUONG NGUYEN - FUNCTION    /////////////////////////

/**
 * Get FTP packet type by port number
 * @param  ipacket packet to analyse
 * @param  index   index of protocol
 * @return         MMT_FTP_RESPONSE_PACKET if this is the packet of server send to client on server control port 21
 *                 MMT_FTP_REQUEST_PACKET if this is the packet of client send to server on server control port 21
 *                 MMT_FTP_DATA_PACKET if this is the packet of server send to client on server data port
 *                 MMT_FTP_UNKNOWN_TYPE_PACKET don't know what is this
 */
int ftp_get_packet_type_by_port_number(ipacket_t *ipacket,unsigned index){
    if(ipacket->internal_packet->tcp){
        if(ipacket->internal_packet->tcp->source == htons(21)){
            return MMT_FTP_RESPONSE_PACKET;
        }else if(ipacket->internal_packet->tcp->dest == htons(21)){
            return MMT_FTP_REQUEST_PACKET;
        }else{
            ftp_session_data_t *ftp_session_data = (ftp_session_data_t*)ipacket->session->session_data[index];
            
            if(ftp_session_data==NULL){
                // Maybe first data packet
                ftp_session_data = (ftp_session_data_t*)ipacket->session->next->session_data[index];
            }

            if(ftp_session_data!=NULL&&ftp_session_data->data_server_port){
                if(ftp_session_data->data_server_port==ipacket->internal_packet->tcp->source||ftp_session_data->data_server_port==ipacket->internal_packet->tcp->dest){
                    return MMT_FTP_DATA_PACKET;
                }
            }
        }
    }
    return MMT_FTP_UNKNOWN_PACKET;
}
/**
 * Extract value from a string
 * @param  str         string to get value
 * @param  begin       begin substring
 * @param  payload_len payload len
 * @return             value
 */
char * str_subend(char *payload, char* begin,int payload_len){
    if(payload != NULL && begin !=NULL){
        // if(strstr(begin,(char*)str)==NULL) return NULL;
        int len;
        len = payload_len - strlen(begin)-2;
        char *ret;
        ret = (char * )malloc(len+1);
        memcpy(ret,payload+strlen(begin),len);
        ret[len]='\0';
        return ret;
    }
    return NULL;
}

char * str_add_features(char *array,char *payload,int payload_len){
    if(payload == NULL) return 0;
    char *new_feature;
    new_feature = (char*)malloc(payload_len-1);
    memcpy(new_feature,payload,payload_len-2);
    new_feature[payload_len-2] ='\0';
    if(array==NULL){
        array = new_feature;
    }else{
        int newLen = strlen(array)+strlen(new_feature)+2;
        array = realloc(array,newLen);
        strcat(array,":");
        strcat(array,new_feature);
        array[strlen(array)]='\0';
    }
    return array;
}

char * str_subvalue(char *str, char* begin, char * end){
    if(str != NULL && begin !=NULL && end != NULL){
        char *fromBegin;
        fromBegin = (char*)malloc(sizeof(str));

        fromBegin = strstr(str,begin);
        fromBegin = fromBegin + strlen(begin);

        if(fromBegin == NULL){
            return NULL;
        }else{
            char * endOfLine;
            endOfLine = (char*)malloc(sizeof(fromBegin));

            endOfLine = strstr(fromBegin,end);

            if(endOfLine == NULL){
                return NULL;
            }else{
                int len;
                len = strlen(fromBegin)-strlen(endOfLine);
                char *ret;
                ret = (char * )malloc((len+1)*sizeof(char));
                strncpy(ret,fromBegin,len);
                ret[len]='\0';
                return ret;
            }

        }
    }
    return NULL;
}
//////////// LUONG NGUYEN - END OF FUNCTION    /////////////////////////
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static void mmt_int_ftp_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_FTP, MMT_REAL_PROTOCOL);
}

/**
 * checks for possible FTP command
 * not all valid commands are tested, it just need to be 3 or 4 characters followed by a space if the
 * packet is longer
 *
 * this functions is not used to accept, just to not reject
 */
static uint8_t mmt_int_check_possible_ftp_command(char *payload , int payload_len) {
    if (payload_len < 3)
        return 0;

    if ((payload[0] < 'a' || payload[0] > 'z') &&
            (payload[0] < 'A' || payload[0] > 'Z'))
        return 0;
    if ((payload[1] < 'a' || payload[1] > 'z') &&
            (payload[1] < 'A' || payload[1] > 'Z'))
        return 0;
    if ((payload[2] < 'a' || payload[2] > 'z') &&
            (payload[2] < 'A' || payload[2] > 'Z'))
        return 0;

    if (payload_len > 3) {
        if ((payload[3] < 'a' || payload[3] > 'z') &&
                (payload[3] < 'A' || payload[3] > 'Z') && payload[3] != ' ')
            return 0;

        if (payload_len > 4) {
            if (payload[3] != ' ' && payload[4] != ' ')
                return 0;
        }
    }

    return 1;
}

/**
 * ftp replies are are 3-digit number followed by space or hyphen
 */
static uint8_t mmt_int_check_possible_ftp_reply(char *payload , int payload_len) {
    if (payload_len < 5)
        return 0;

    if (payload[3] != ' ' && payload[3] != '-')
        return 0;

    if (payload[0] < '0' || payload[0] > '9')
        return 0;
    if (payload[1] < '0' || payload[1] > '9')
        return 0;
    if (payload[2] < '0' || payload[2] > '9')
        return 0;

    return 1;
}

/**
 * check for continuation replies
 * there is no real indication whether it is a continuation message, we just
 * require that there are at least 5 ascii characters
 */
static uint8_t mmt_int_check_possible_ftp_continuation_reply(char *payload , int payload_len) {
    uint16_t i;

    if (payload_len< 5)
        return 0;

    for (i = 0; i < 5; i++) {
        if (payload[i] < ' ' || payload[i] > 127)
            return 0;
    }

    return 1;
}
/**
 * extract FTP command
 * @param  payload     payload contains the command
 * @param  payload_len payload len
 * @return             FTP command
 */
 ftp_command_t * ftp_get_command(char* payload,int payload_len){
    ftp_command_t *cmd;
    cmd = (ftp_command_t*)malloc(sizeof(ftp_command_t));
    if (payload_len > MMT_STATICSTRING_LEN("RETR ") &&
        (memcmp(payload, "RETR ", MMT_STATICSTRING_LEN("RETR ")) == 0 ||
            memcmp(payload, "retr ", MMT_STATICSTRING_LEN("retr ")) == 0)) {
        cmd->cmd_str="RETR";
        cmd->cmd = MMT_FTP_RETR_CMD;
        cmd->param = str_subend(payload,"RETR ",payload_len);
    }else if (payload_len > MMT_STATICSTRING_LEN("USER ") &&
        (memcmp(payload, "USER ", MMT_STATICSTRING_LEN("USER ")) == 0 ||
            memcmp(payload, "user ", MMT_STATICSTRING_LEN("user ")) == 0)) {
        cmd->cmd_str="USER";
        cmd->cmd = MMT_FTP_USER_CMD;
        cmd->param = str_subend(payload,"USER ",payload_len);
    }else if (payload_len > MMT_STATICSTRING_LEN("PASS ") &&
        (memcmp(payload, "PASS ", MMT_STATICSTRING_LEN("PASS ")) == 0 ||
            memcmp(payload, "pass ", MMT_STATICSTRING_LEN("pass ")) == 0)) {
        cmd->cmd_str="PASS";
        cmd->cmd = MMT_FTP_PASS_CMD;
        cmd->param = str_subend(payload,"PASS ",payload_len);
    } else if (payload_len > MMT_STATICSTRING_LEN("SYST ") &&
        (memcmp(payload, "SYST ", MMT_STATICSTRING_LEN("SYST ")) == 0 ||
            memcmp(payload, "syst ", MMT_STATICSTRING_LEN("syst ")) == 0)) {
        cmd->cmd_str="SYST";
        cmd->cmd = MMT_FTP_SYST_CMD;
        cmd->param=NULL;
        // cmd->param = str_subend(payload,"SYST ",payload_len);
    } else if (payload_len > MMT_STATICSTRING_LEN("PWD ") &&
        (memcmp(payload, "PWD ", MMT_STATICSTRING_LEN("PWD ")) == 0 ||
            memcmp(payload, "pwd ", MMT_STATICSTRING_LEN("pwd ")) == 0)) {
        cmd->cmd_str="PWD";
        cmd->cmd = MMT_FTP_PWD_CMD;
        cmd->param=NULL;
        // cmd->param = str_subend(payload,"PWD ",payload_len);
    }else if (payload_len > MMT_STATICSTRING_LEN("TYPE ") &&
        (memcmp(payload, "TYPE ", MMT_STATICSTRING_LEN("TYPE ")) == 0 ||
            memcmp(payload, "type ", MMT_STATICSTRING_LEN("type ")) == 0)) {
        cmd->cmd_str="TYPE";
        cmd->cmd = MMT_FTP_TYPE_CMD;
        cmd->param = str_subend(payload,"TYPE ",payload_len);
    }else if (payload_len > MMT_STATICSTRING_LEN("CWD ") &&
        (memcmp(payload, "CWD ", MMT_STATICSTRING_LEN("CWD ")) == 0 ||
            memcmp(payload, "cwd ", MMT_STATICSTRING_LEN("cwd ")) == 0)) {
        cmd->cmd_str="CWD";
        cmd->cmd = MMT_FTP_CWD_CMD;
        cmd->param=NULL;
        // cmd->param = str_subend(payload,"CWD ",payload_len);
    }else if (payload_len > MMT_STATICSTRING_LEN("SIZE ") &&
        (memcmp(payload, "SIZE ", MMT_STATICSTRING_LEN("SIZE ")) == 0 ||
            memcmp(payload, "size ", MMT_STATICSTRING_LEN("size ")) == 0)) {
        cmd->cmd_str="SIZE";
        cmd->cmd = MMT_FTP_SIZE_CMD;
        cmd->param = str_subend(payload,"SIZE ",payload_len);
    }else if (payload_len > MMT_STATICSTRING_LEN("EPSV ") &&
        (memcmp(payload, "EPSV ", MMT_STATICSTRING_LEN("EPSV ")) == 0 ||
            memcmp(payload, "epsv ", MMT_STATICSTRING_LEN("epsv ")) == 0)) {
        cmd->cmd_str="EPSV";
        cmd->cmd = MMT_FTP_EPSV_CMD;
        cmd->param=NULL;
        // cmd->param = str_subend(payload,"EPSV ",payload_len);
    }else if (payload_len >= MMT_STATICSTRING_LEN("FEAT") &&
        (memcmp(payload, "FEAT", MMT_STATICSTRING_LEN("FEAT")) == 0 ||
            memcmp(payload, "feat", MMT_STATICSTRING_LEN("feat")) == 0)) {
        cmd->cmd_str="FEAT";
        cmd->cmd = MMT_FTP_FEAT_CMD;
        cmd->param=NULL;
        // cmd->param = str_subend(payload,"FEAT",payload_len);
    }else if (payload_len >= MMT_STATICSTRING_LEN("MDTM ") &&
        (memcmp(payload, "MDTM ", MMT_STATICSTRING_LEN("MDTM ")) == 0 ||
            memcmp(payload, "mdtm ", MMT_STATICSTRING_LEN("mdtm ")) == 0)) {
        cmd->cmd_str="MDTM";
        cmd->cmd = MMT_FTP_MDTM_CMD;
        cmd->param = str_subend(payload,"MDTM ",payload_len);
    }else{
        cmd->cmd_str="UNKNOWN_CMD";
        cmd->cmd = MMT_FTP_UNKNOWN_CMD;
        cmd->param = payload;
    }
    return cmd;
}


/**
 * Get response code from a reponse packet
 * @param  payload     payload of packet
 * @param  payload_len payload len of packet
 * @return             a ftp response code: code + value
 */
 ftp_response_t * ftp_get_response(char* payload,int payload_len){
    ftp_response_t * res;
    res = (ftp_response_t*)malloc(sizeof(ftp_response_t));
    if (payload_len > MMT_STATICSTRING_LEN("150 ") &&
        (memcmp(payload, "150 ", MMT_STATICSTRING_LEN("150 ")) == 0 ||
            memcmp(payload, "150-", MMT_STATICSTRING_LEN("150-")) == 0)) {
        res->code = MMT_FTP_150_CODE;
        res->value = NULL;
    }else if (payload_len > MMT_STATICSTRING_LEN("220 ") &&
        (memcmp(payload, "220 ", MMT_STATICSTRING_LEN("220 ")) == 0 ||
            memcmp(payload, "220-", MMT_STATICSTRING_LEN("220-")) == 0)) {
        res->code = MMT_FTP_220_CODE;
        char *ver = str_subend(payload,"220 ",payload_len);
        if(ver == NULL){
            ver = str_subend(payload,"220-",payload_len);
        }
        res->value = ver;

    }else if (payload_len > MMT_STATICSTRING_LEN("230 ") &&
        (memcmp(payload, "230 ", MMT_STATICSTRING_LEN("230 ")) == 0 ||
            memcmp(payload, "230-", MMT_STATICSTRING_LEN("230-")) == 0)) {
        res->code = MMT_FTP_230_CODE;
        char *val = str_subend(payload,"230 ",payload_len);
        if(val == NULL){
            val = str_subend(payload,"230-",payload_len);
        }
        res->value =val;
    }else if (payload_len > MMT_STATICSTRING_LEN("215 ") &&
        (memcmp(payload, "215 ", MMT_STATICSTRING_LEN("215 ")) == 0 ||
            memcmp(payload, "215-", MMT_STATICSTRING_LEN("215-")) == 0)) {
        res->code = MMT_FTP_215_CODE;
        char *s = str_subend(payload,"215 ",payload_len);
        if(s == NULL){
            s = str_subend(payload,"215-",payload_len);
        }
        res->value =s;
    }else if (payload_len > MMT_STATICSTRING_LEN("229 ") &&
        (memcmp(payload, "229 ", MMT_STATICSTRING_LEN("229 ")) == 0 ||
            memcmp(payload, "229-", MMT_STATICSTRING_LEN("229-")) == 0)) {
        res->code = MMT_FTP_229_CODE;

        char *em = str_subend(payload,"229 ",payload_len);
        if(em == NULL){
            em = str_subend(payload,"229-",payload_len);
        }
        res->value = em;
    }else if (payload_len > MMT_STATICSTRING_LEN("213 ") &&
        (memcmp(payload, "213 ", MMT_STATICSTRING_LEN("213 ")) == 0 ||
            memcmp(payload, "213-", MMT_STATICSTRING_LEN("213-")) == 0)) {
        res->code = MMT_FTP_213_CODE;
        char *em = str_subend(payload,"213 ",payload_len);
        if(em == NULL){
            em = str_subend(payload,"213-",payload_len);
        }
        res->value = em;
    }else if (payload_len > MMT_STATICSTRING_LEN("257 ") &&
        (memcmp(payload, "257 ", MMT_STATICSTRING_LEN("257 ")) == 0 ||
            memcmp(payload, "257-", MMT_STATICSTRING_LEN("257-")) == 0)) {
        res->code = MMT_FTP_257_CODE;
        char *dir = str_subend(payload,"257 ",payload_len);
        if(dir == NULL){
            dir = str_subend(payload,"257-",payload_len);
        }
        res->value = dir;
    }else if (payload_len > MMT_STATICSTRING_LEN("250 ") &&
        (memcmp(payload, "250 ", MMT_STATICSTRING_LEN("250 ")) == 0 ||
            memcmp(payload, "250-", MMT_STATICSTRING_LEN("250-")) == 0)) {
        res->code = MMT_FTP_250_CODE;
        char *val = str_subend(payload,"250 ",payload_len);
        if(val == NULL){
            val = str_subend(payload,"250-",payload_len);
        }
        res->value =val;
    }else if (payload_len > MMT_STATICSTRING_LEN("200 ") &&
        (memcmp(payload, "200 ", MMT_STATICSTRING_LEN("200 ")) == 0 ||
            memcmp(payload, "200-", MMT_STATICSTRING_LEN("200-")) == 0)) {
        res->code = MMT_FTP_200_CODE;
        char *val = str_subend(payload,"200 ",payload_len);
        if(val == NULL){
            val = str_subend(payload,"200-",payload_len);
        }
        res->value =val;
    }else if (payload_len > MMT_STATICSTRING_LEN("331 ") &&
        (memcmp(payload, "331 ", MMT_STATICSTRING_LEN("331 ")) == 0 ||
            memcmp(payload, "331-", MMT_STATICSTRING_LEN("331-")) == 0)) {
        res->code = MMT_FTP_331_CODE;
        char *val = str_subend(payload,"331 ",payload_len);
        if(val == NULL){
            val = str_subend(payload,"331-",payload_len);
        }
        res->value =val;
    }else if (payload_len > MMT_STATICSTRING_LEN("226 ") &&
        (memcmp(payload, "226 ", MMT_STATICSTRING_LEN("226 ")) == 0 ||
            memcmp(payload, "226-", MMT_STATICSTRING_LEN("226-")) == 0)) {
        res->code = MMT_FTP_331_CODE;
        char *val = str_subend(payload,"226 ",payload_len);
        if(val == NULL){
            val = str_subend(payload,"226-",payload_len);
        }
        res->value =val;
    }else if (payload_len > MMT_STATICSTRING_LEN("211 ") &&
        (memcmp(payload, "211 ", MMT_STATICSTRING_LEN("211 ")) == 0 ||
            memcmp(payload, "211-", MMT_STATICSTRING_LEN("211-")) == 0)) {
        res->code = MMT_FTP_211_CODE;
        char *val = str_subend(payload,"211 ",payload_len);
        if(val == NULL){
            val = str_subend(payload,"211-",payload_len);
        }
        res->value =val;
    }else if (!mmt_int_check_possible_ftp_reply(payload, payload_len)) {
        if (mmt_int_check_possible_ftp_continuation_reply(payload, payload_len)) {
            res->code = MMT_FTP_CONTINUE_CODE;
            res->value = payload;
        }else{
            res->code = MMT_FTP_UNKNOWN_CODE;
            res->value = payload;
        }
    }else{
        res->code = MMT_FTP_UNKNOWN_CODE;
        res->value = payload;
    }
    return res;
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
int ftp_data_type_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_session_data_t* ftp_session_data = (ftp_session_data_t*)packet->session->session_data[proto_index];
    if(ftp_session_data!=NULL&&ftp_session_data->data_type!=NULL){
        extracted_data->data = (void*)ftp_session_data->data_type;
        log_info("FTP: ftp_data_type: %s",(char*)extracted_data->data);
        return 1;
    }
    return 0;
}

int ftp_session_mode_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_session_data_t* ftp_session_data = (ftp_session_data_t*)packet->session->session_data[proto_index];
    if(ftp_session_data!=NULL&&ftp_session_data->data_type!=NULL){
        extracted_data->data = (short*)&ftp_session_data->session_mode;
        log_info("FTP: ftp_session_mode: %d",*(short*)extracted_data->data);
        return 1;
    }
    return 0;
}


int ftp_file_name_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_session_data_t* ftp_session_data = (ftp_session_data_t*)packet->session->session_data[proto_index];
    if(ftp_session_data!=NULL&&ftp_session_data->data_type!=NULL){
        extracted_data->data = (void*)ftp_session_data->file_name;
        log_info("FTP: file_name: %s",(char*)extracted_data->data);
        return 1;
    }
    return 0;
}

int ftp_file_dir_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_session_data_t* ftp_session_data = (ftp_session_data_t*)packet->session->session_data[proto_index];
    if(ftp_session_data!=NULL&&ftp_session_data->data_type!=NULL){
        extracted_data->data = (void*)ftp_session_data->file_dir;
        log_info("FTP: file_dir: %s",(char*)extracted_data->data);
        return 1;
    }
    return 0;
}

int ftp_file_size_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_session_data_t* ftp_session_data = (ftp_session_data_t*)packet->session->session_data[proto_index];
    if(ftp_session_data!=NULL&&ftp_session_data->data_type!=NULL){
        extracted_data->data = (int*)ftp_session_data->file_size;
        log_info("FTP: file_size: %d",*(int*)extracted_data->data);
        return 1;
    }
    return 0;
}

int ftp_file_last_modified_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_session_data_t* ftp_session_data = (ftp_session_data_t*)packet->session->session_data[proto_index];
    if(ftp_session_data!=NULL&&ftp_session_data->data_type!=NULL){
        extracted_data->data = (void*)ftp_session_data->file_last_modified;
        log_info("FTP: file_last_modified: %s",(char*)extracted_data->data);
        return 1;
    }
    return 0;
}

////////////////////// PACKET ATTRIBUTE EXTRACTION ///////////////////////
int ftp_packet_type_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    int packet_type = ftp_get_packet_type_by_port_number(packet,proto_index);

    if(packet_type!=MMT_FTP_UNKNOWN_PACKET){
        extracted_data->data = (short*)&packet_type;
        log_info("FTP: packet_type %d in packet: %lu\n", *(short*)extracted_data->data,packet->packet_id);
        return 1;
    }
    return 0;
}

int ftp_packet_request_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number(packet,proto_index);
    if(packet_type==MMT_FTP_REQUEST_PACKET){
        int offset = get_packet_offset_at_index(packet, proto_index);
        char *payload = (char*)&packet->data[offset];
        int payload_len = packet->internal_packet->payload_packet_len;
        ftp_command_t * cmd = ftp_get_command(payload,payload_len);
        if(cmd->cmd!=MMT_FTP_UNKNOWN_CMD){
            log_info("FTP: packet_request %d in packet: %lu\n", cmd->cmd,packet->packet_id);
            extracted_data->data = (void*)cmd->cmd_str;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_request_parameter_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number(packet,proto_index);
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
    
    int packet_type = ftp_get_packet_type_by_port_number(packet,proto_index);
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
    
    int packet_type = ftp_get_packet_type_by_port_number(packet,proto_index);
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

int ftp_packet_data_offset_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number(packet,proto_index);
    if(packet_type==MMT_FTP_DATA_PACKET){
        int offset = get_packet_offset_at_index(packet, proto_index);
        extracted_data->data = (int*)&offset;
    }
    return 0;
}

int ftp_packet_data_len_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type_by_port_number(packet,proto_index);
    if(packet_type==MMT_FTP_DATA_PACKET){
        extracted_data->data = (int*)&packet->internal_packet->payload_packet_len;
        return 1;
    }
    return 0;
}


static attribute_metadata_t ftp_attributes_metadata[FTP_ATTRIBUTES_NB] = {
    // SCOPE_SESSION
    // {FTP_SERVER_VERSION,FTP_SERVER_VERSION_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_version_extraction},
    {FTP_DATA_TYPE,FTP_DATA_TYPE_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_type_extraction},
    {FTP_SESSION_MODE,FTP_SESSION_MODE_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_session_mode_extraction},
    // {FTP_SESSION_STATUS,FTP_SESSION_STATUS_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_status_extraction},
    // {FTP_SESSION_FEATURES,FTP_SESSION_FEATURES_ALIAS,MMT_STRING_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_features_extraction},
    // {FTP_EEMPM_229,FTP_EEMPM_229_ALIAS,MMT_STRING_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_eempm_229_extraction},
    // {FTP_SERVER_CONT_PORT,FTP_SERVER_CONT_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_contrl_port_extraction},
    // {FTP_CLIENT_CONT_PORT,FTP_CLIENT_CONT_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_contrl_port_extraction},
    // {FTP_SERVER_DATA_PORT,FTP_SERVER_DATA_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_data_port_extraction},
    // {FTP_CLIENT_DATA_PORT,FTP_CLIENT_DATA_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_data_port_extraction},
    // {FTP_SERVER_CONT_ADDR,FTP_SERVER_CONT_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_contrl_addr_extraction},
    // {FTP_CLIENT_CONT_ADDR,FTP_CLIENT_CONT_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_contrl_addr_extraction},
    // {FTP_SERVER_DATA_ADDR,FTP_SERVER_DATA_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_data_addr_extraction},
    // {FTP_CLIENT_DATA_ADDR,FTP_CLIENT_DATA_PORT_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_data_addr_extraction},
    {FTP_FILE_NAME,FTP_FILE_NAME_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_name_extraction},
    {FTP_FILE_DIR,FTP_FILE_DIR_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_dir_extraction},
    // {FTP_FILE_SIZE,FTP_FILE_SIZE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_size_extraction},
    {FTP_FILE_LAST_MODIFIED,FTP_FILE_LAST_MODIFIED_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_last_modified_extraction},

    // // SCOPE_PACKET
    {FTP_PACKET_TYPE,FTP_PACKET_TYPE_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_type_extraction},
    {FTP_PACKET_REQUEST,FTP_PACKET_REQUEST_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_request_extraction},
    {FTP_PACKET_REQUEST_PARAMETER,FTP_PACKET_REQUEST_PARAMETER_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_request_parameter_extraction},
    {FTP_PACKET_RESPONSE_CODE,FTP_PACKET_RESPONSE_CODE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_response_code_extraction},
    {FTP_PACKET_RESPONSE_VALUE,FTP_PACKET_RESPONSE_VALUE_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_response_value_extraction},
    {FTP_PACKET_DATA_OFFSET,FTP_PACKET_DATA_OFFSET_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_data_offset_extraction},
    {FTP_PACKET_DATA_LEN,FTP_PACKET_DATA_LEN_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_data_len_extraction},
    // {FTP_ATTRIBUTES_NB,FTP_ATTRIBUTES_NB_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_attributes_nb_extraction}
};

//////////////////////////// END OF EXTRACTION /////////////////////////////////










///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

void ftp_data_packet(ipacket_t *ipacket,unsigned index){
    log_info("FTP: FTP_DATA PACKET: %lu",ipacket->packet_id);
    
    //printf("from http generic session data analysis\n");
    int offset = get_packet_offset_at_index(ipacket, index);

    char *payload = (char*)&ipacket->data[offset];

    ftp_session_data_t *ftp_session_data = (ftp_session_data_t*)ipacket->session->session_data[index];
    
    if(ftp_session_data==NULL){
        ipacket->session->session_data[index] =  ipacket->session->next->session_data[index];
    }
    log_info("FTP: Payload: %s",payload);
}

/**
 * Extract request packets to get information about this ftp session
 * - user_name
 * - user_password
 * - file_name
 * - data_type
 * - session_mode
 * @param ipacket packet to analyse
 * @param index   index of protocol
 */
void ftp_request_packet(ipacket_t *ipacket,unsigned index){
    log_info("FTP: FTP_REQUEST PACKET: %lu",ipacket->packet_id);
    
    //printf("from http generic session data analysis\n");
    int offset = get_packet_offset_at_index(ipacket, index);

    char *payload = (char*)&ipacket->data[offset];
    uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

    log_info("FTP: Payload: %s",payload);
    ftp_session_data_t *ftp_session_data = (ftp_session_data_t*)ipacket->session->session_data[index];
    if(ftp_session_data==NULL){
        log_info("FTP: RE-INITIALING SESSION DATA");
        ftp_session_data = (ftp_session_data_t *) mmt_malloc(sizeof (ftp_session_data_t));
        memset(ftp_session_data, 0, sizeof (ftp_session_data_t));
        ipacket->session->session_data[index] = ftp_session_data;
    }

    // control_server_port
    if(ftp_session_data->control_server_port== 0){
        ftp_session_data->control_server_port=htons(21);
    }
        // control_client_port
    if(ftp_session_data->control_client_port== 0){
        if(ipacket->internal_packet->tcp->source == htons(21)){
            ftp_session_data->control_client_port = ipacket->internal_packet->tcp->dest;
        }else if(ipacket->internal_packet->tcp->dest == htons(21)){
            ftp_session_data->control_client_port = ipacket->internal_packet->tcp->source;
        }
    }else{
        if(ipacket->internal_packet->tcp->source == htons(21)){
            if(ftp_session_data->control_client_port != ipacket->internal_packet->tcp->dest){
                log_err("FTP: control_client_port is not matched!");
                return;
            }
        }else if(ipacket->internal_packet->tcp->dest == htons(21)){
            if(ftp_session_data->control_client_port != ipacket->internal_packet->tcp->source){
                log_err("FTP: control_client_port is not matched!");
                return;
            }
        }
    }

    ftp_command_t * command = ftp_get_command(payload,payload_len);

    if(command->cmd!=MMT_FTP_UNKNOWN_CMD){
        switch(command->cmd){
            case MMT_FTP_USER_CMD:
                ftp_session_data->user_name=command->param;
                break;
            case MMT_FTP_PASS_CMD:
                ftp_session_data->user_password=command->param;
                break;
            case MMT_FTP_RETR_CMD:
                ftp_session_data->file_name=command->param;
                break;
            case MMT_FTP_TYPE_CMD:
                ftp_session_data->data_type=command->param;
                break;
            case MMT_FTP_EPSV_CMD:
                ftp_session_data->session_mode = MMT_FTP_PASSIVE_MODE;
                break;
            default:
                break;
        }
    }else{
        log_err("FTP: Cannot get command");
    }
}

uint16_t ftp_get_data_server_port(char *payload){
    char *ret = str_subvalue(payload,"(|||","|)");
    return htons(atoi(ret));
}
/**
 * Analyse response packet to get information of this ftp session
 * - ftp_server_version
 * - status
 * - features
 * - file_dir
 * - file_size
 * - data_server_port
 * - file_last_modified
 * @param ipacket [description]
 * @param index   [description]
 */
void ftp_response_packet(ipacket_t *ipacket,unsigned index){
    log_info("FTP: FTP_RESPONSE PACKET: %lu",ipacket->packet_id);
    
    int offset = get_packet_offset_at_index(ipacket, index);

    char *payload = (char*)&ipacket->data[offset];
    uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

    log_info("FTP: Payload: %s",payload);
    ftp_session_data_t *ftp_session_data = (ftp_session_data_t*)ipacket->session->session_data[index];
    if(ftp_session_data==NULL){
        log_info("FTP: RE-INITIALING SESSION DATA");
        ftp_session_data = (ftp_session_data_t *) mmt_malloc(sizeof (ftp_session_data_t));
        memset(ftp_session_data, 0, sizeof (ftp_session_data_t));
        ipacket->session->session_data[index] = ftp_session_data;
    }

    // control_server_port
    if(ftp_session_data->control_server_port== 0){
        ftp_session_data->control_server_port=htons(21);
    }
        // control_client_port
    if(ftp_session_data->control_client_port== 0){
        if(ipacket->internal_packet->tcp->source == htons(21)){
            ftp_session_data->control_client_port = ipacket->internal_packet->tcp->dest;
        }else if(ipacket->internal_packet->tcp->dest == htons(21)){
            ftp_session_data->control_client_port = ipacket->internal_packet->tcp->source;
        }
    }else{
        if(ipacket->internal_packet->tcp->source == htons(21)){
            if(ftp_session_data->control_client_port != ipacket->internal_packet->tcp->dest){
                log_err("FTP: control_client_port is not matched!");
                return;
            }
        }else if(ipacket->internal_packet->tcp->dest == htons(21)){
            if(ftp_session_data->control_client_port != ipacket->internal_packet->tcp->source){
                log_err("FTP: control_client_port is not matched!");
                return;
            }
        }
    }

    ftp_response_t * response = ftp_get_response(payload,payload_len);

    if(response->code!=MMT_FTP_UNKNOWN_CODE){
        switch(response->code){
            // case MMT_FTP_220_CODE:
            //     ftp_session_data->server_version=response->value;
            //     ftp_session_data->session_status = MMT_FTP_STATUS_OPEN;
            //     break;
            case MMT_FTP_230_CODE:
                ftp_session_data->session_status = MMT_FTP_STATUS_CONTROLING;
                break;
            case MMT_FTP_CONTINUE_CODE:
                ftp_session_data->session_feats = str_add_features(ftp_session_data->session_feats,payload,payload_len);
                break;
            case MMT_FTP_257_CODE:
                if(ftp_session_data->file_dir==NULL){
                    ftp_session_data->file_dir=response->value;
                }else{
                    if(strlen(ftp_session_data->file_dir)<strlen(response->value)){
                        ftp_session_data->file_dir=response->value;
                    }
                }
                break;
            case MMT_FTP_213_CODE:
                if(ftp_session_data->session_status==MMT_FTP_STATUS_CONTROLING){
                    ftp_session_data->file_size=atoi(response->value);
                }else if(ftp_session_data->session_status==MMT_FTP_STATUS_TRANSFER_COMPLETED){
                    ftp_session_data->file_last_modified = response->value;
                }else{
                    log_warn("FTP: Code 203 need to update!");
                }
                break;
            case MMT_FTP_229_CODE:
                ftp_session_data->data_server_port = ftp_get_data_server_port(response->value);
                break;
            case MMT_FTP_150_CODE:
                ftp_session_data->session_status = MMT_FTP_STATUS_TRANSFERING;
                break;
            case MMT_FTP_226_CODE:
                ftp_session_data->session_status = MMT_FTP_STATUS_TRANSFER_COMPLETED;
                break;
            case MMT_FTP_221_CODE:
                ftp_session_data->session_status = MMT_FTP_STATUS_FINISHED;
                break;
            default:
                break;
        }
    }else{
        log_err("FTP: Cannot get response code");
    }
}

void ftp_unknown_type_packet(ipacket_t *ipacket,unsigned index){
    log_info("FTP: FTP_UNKNOWN_TYPE PACKET: %lu",ipacket->packet_id);
    
    //printf("from http generic session data analysis\n");
    int offset = get_packet_offset_at_index(ipacket, index);

    char *payload = (char*)&ipacket->data[offset];

    log_info("FTP: Payload: %s",payload);
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
    
    int packet_type = ftp_get_packet_type_by_port_number(ipacket,index);

    switch(packet_type){
        case MMT_FTP_DATA_PACKET:
            ftp_data_packet(ipacket,index);
            break;
        case MMT_FTP_REQUEST_PACKET:
            ftp_request_packet(ipacket,index);
            break;
        case MMT_FTP_RESPONSE_PACKET:
            ftp_response_packet(ipacket,index);
            break;
        case MMT_FTP_UNKNOWN_PACKET:
        default:
            ftp_unknown_type_packet(ipacket,index);
            break;
    }

    //First we check if the message starts with leading CRLF --- normally this should never be the case
    // offset += ignore_starting_crlf((const char*)&ipacket->data[offset], ipacket->p_hdr->len - offset);

    //Parse the first line line of the header (request or response line)
    return MMT_CONTINUE;
}

void ftp_session_data_init(ipacket_t * ipacket, unsigned index) {
    log_info("FTP: INITIALING SESSION DATA");
    ftp_session_data_t * ftp_session_data = (ftp_session_data_t *) mmt_malloc(sizeof (ftp_session_data_t));
    memset(ftp_session_data, 0, sizeof (ftp_session_data_t));
    ipacket->session->session_data[index] = ftp_session_data;

}
///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////
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
        register_session_data_initialization_function(protocol_struct, ftp_session_data_init);
        register_session_data_analysis_function(protocol_struct, ftp_session_data_analysis);
        mmt_init_classify_me_ftp();

        return register_protocol(protocol_struct, PROTO_FTP);
    } else {
        return 0;
    }
}


