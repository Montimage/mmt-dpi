#include "plugin_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ftp.h"
////////////////////////////////////// FTP FUNCTION //////////////////////////////////////

//////////////////////// STRING UTIL FUNCTIONS //////////////////////////////
/**
 * Replace a character by another character in all string
 * @param  str string
 * @param  c1  ascii code number of character will be replaced
 * @param  c2  ascii code number of replacing character
 * @return     new string after replacing
 */
char * str_replace_all_char(char *str,int c1, int c2){
    char *new_str;
    new_str = (char*)malloc(strlen(str)+1);
    memcpy(new_str,str,strlen(str));
    new_str[strlen(str)] = '\0';
    int i;
    for(i=0;i<strlen(str);i++){
        if((int)new_str[i]==c1){
            new_str[i]=(char)c2;
        }
    }
    return new_str;
}
/**
 * Get substring of a string between two index
 * @param  str   string to get substring from
 * @param  start start index
 *               To get sub string from start of string, the start index is -1
 * @param  end   end index
 *               To get sub string to the end of string, the end index of string is strlen(str)
 * @return       substring between @start and @end
 */
char * str_sub_index(char *str, int start, int end){
    
    int len = end - start-1;

    char *substr;
    substr = (char*)malloc(len);
    memcpy(substr,str + start + 1,len);
    substr[len]='\0';
    return substr;    
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

/**
 * Append a string into a string
 * @param  array       String to be appended
 * @param  payload     String to append
 * @param  payload_len len of added string
 * @return             new string after appending
 */
char * str_append(char *array,char *payload,int payload_len){
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

/**
 * Get sub string between two substrings
 * @param  str   string to get substring
 * @param  begin first substring
 * @param  end   second substring
 * @return       a string is between @begin and @end in @str
 */
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

/**
 * Get all indexes of a character in a string
 * @param  str string
 * @param  c   character
 * @return     an integer array which contains the list of indexes of character in string
 */
int * str_get_indexes(char *str, int c){
    int *indexes;
    indexes = (int*)malloc((strlen(str)+1)*sizeof(int));
    int i=0;
    int current_index = 0;
    for(i=0;i<strlen(str);i++){
        if((int)str[i]==c){
            indexes[current_index]=i;
            current_index++;
        }
    }
    indexes[current_index]=-1;
    return indexes;
}


//////////// FTP - FUNCTION    /////////////////////////

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
 * Get tuple 6 of packet: server_address: server_port - client_address: client_port, type of connection and direction of packet (send from server to client or other)
 * @param  ipacket packet
 * @return         a tuple6
 */
ftp_tuple6_t *ftp_get_tuple6(const ipacket_t * ipacket){
    ftp_tuple6_t *t6;
    t6 = (ftp_tuple6_t*)malloc(sizeof(ftp_tuple6_t));
    if(ipacket->internal_packet->tcp&&ipacket->internal_packet->iph){
        if(ipacket->internal_packet->tcp->source == htons(21)){
            t6->conn_type = MMT_FTP_CONTROL_CONNECTION;
            t6->direction = MMT_FTP_PACKET_SERVER;
            t6->s_addr = ipacket->internal_packet->iph->saddr;
            t6->s_port = ipacket->internal_packet->tcp->source;
            t6->c_addr = ipacket->internal_packet->iph->daddr;
            t6->c_port = ipacket->internal_packet->tcp->dest;
            return t6;
        }else if(ipacket->internal_packet->tcp->dest == htons(21)){
            t6->conn_type=MMT_FTP_CONTROL_CONNECTION;
            t6->direction = MMT_FTP_PACKET_CLIENT;
            t6->s_addr = ipacket->internal_packet->iph->daddr;
            t6->s_port = ipacket->internal_packet->tcp->dest;
            t6->c_addr = ipacket->internal_packet->iph->saddr;
            t6->c_port = ipacket->internal_packet->tcp->source;
            return t6;
        }else{
            t6->conn_type=MMT_FTP_DATA_CONNECTION;
            t6->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
            t6->s_addr = ipacket->internal_packet->iph->saddr;
            t6->s_port = ipacket->internal_packet->tcp->source;
            t6->c_addr = ipacket->internal_packet->iph->daddr;
            t6->c_port = ipacket->internal_packet->tcp->dest;
            return t6;
        }
    }
    return NULL;
}

/**
 * New FTP tuple6
 * @return new ftp tuple 6
 */
ftp_tuple6_t * ftp_new_tuple6(){
    ftp_tuple6_t * t = (ftp_tuple6_t*)malloc(sizeof(ftp_tuple6_t));
    t->conn_type = 0;
    t->direction = 0;
    t->s_addr = 0;
    t->s_port = 0;
    t->c_addr = 0;
    t->c_port = 0;
    return t;
}

/**
 * New FTP user
 * @return new ftp user
 */
ftp_user_t *ftp_new_user(){
    ftp_user_t *user = (ftp_user_t*)malloc(sizeof(ftp_user_t));
    user->username = NULL;
    user->password = NULL;
    return user;
}

/**
 * New ftp file transfering
 * @return file
 */
ftp_file_t * ftp_new_file(){
    ftp_file_t * file = (ftp_file_t*)malloc(sizeof(ftp_file_t));
    file->name = NULL;
    file->size = 0;
    file->last_modified = NULL;
    return file;
}

/**
 * New data connection
 * @return a new data connection 
 */
ftp_data_session_t * ftp_new_data_connection(){
    ftp_data_session_t * ftp_data;
    ftp_data = (ftp_data_session_t*)malloc(sizeof(ftp_data_session_t));
    ftp_data->data_conn = ftp_new_tuple6();
    ftp_data->data_conn->conn_type = MMT_FTP_DATA_CONNECTION;
    ftp_data->data_conn_mode = 0;
    ftp_data->data_transfer_type = NULL;
    ftp_data->data_type = 0;
    ftp_data->file = ftp_new_file();
    ftp_data->data_direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
    return ftp_data;
}

/**
 * Create new ftp control session
 * @param  tuple6 control connection tuple6
 * @return        a ftp control connection
 */
ftp_control_session_t * ftp_new_control_session(ftp_tuple6_t * tuple6){
    ftp_control_session_t * ftp_control; 
    ftp_control = (ftp_control_session_t*)malloc(sizeof(ftp_control_session_t));
    ftp_control->contrl_conn = tuple6;
    ftp_control->last_command = NULL;
    ftp_control->last_response = NULL;
    ftp_control->user = ftp_new_user();
    ftp_control->session_feats = NULL;
    ftp_control->session_syst = NULL;
    ftp_control->current_dir = NULL;
    ftp_control->current_data_session = ftp_new_data_connection();
    ftp_control->next = NULL;
    return ftp_control;
}


/**
* Compare 2 ftp tuple 6
* @param  t1 the first tuple
* @param  t2 The second tuple
* @return    1 if two tuples are MMT_FTP_CONTROL_CONNECTION and equal (do not care about the direction)
*            2 if two tuples are MMT_FTP_DATA_CONNECTION and equal and same direction
*            3 if two tuples are MMT_FTP_DATA_CONNECTION and equal and different direction - convert direction of t1
*            4 if the client_port of data connection is NULL and the other are equal (same direction)
*            5 if the client_port of data connection is NULL and the other are equal (different direction) - convert direction of t1
*            6 if the server_port of data connection is NULL and the other are equal (same direction)
*            7 if the server_port of data connection is NULL and the other are equal (different direction) - convert direction of t1
*            0 otherwise
*/
int ftp_compare_tuple6(ftp_tuple6_t *t1, ftp_tuple6_t * t2){

    if(t1->conn_type != t2->conn_type) return 0;

    if(t1->conn_type == MMT_FTP_CONTROL_CONNECTION){
        if(t1->c_addr != t2->c_addr) return 0;

        if(t1->s_addr != t2->s_addr) return 0;

        if(t1->c_port != t2->c_port) return 0;

        if(t1->s_port != t2->s_port) return 0;
        return 1;
    }else{
        if(t1->c_addr == t2->c_addr && t1->c_port == t2->c_port && t1->s_addr == t2->s_addr && t1->s_port== t2->s_port) return 2;
        if(t1->c_addr == t2->s_addr && t1->c_port == t2->s_port && t1->s_addr == t2->c_addr && t1->s_port== t2->c_port) return 3;
        // Extended passive mode - 229 and 227 code
        if(t1->c_addr == t2->c_addr && t2->c_port == 0 && t1->s_addr == t2->s_addr && t1->s_port== t2->s_port) return 4;
        if(t1->c_addr == t2->s_addr && t2->c_port == 0 && t1->s_addr == t2->c_addr && t1->c_port== t2->s_port) return 5;
        // Active mode - PORT and EPRT command
        if(t1->c_addr == t2->c_addr && t2->c_port == t2->c_port && t1->s_addr == t2->s_addr && t2->s_port == 0) return 6;
        if(t1->c_addr == t2->s_addr && t1->s_addr == t2->c_addr && t1->s_port == t2->c_port && t2->s_port == 0) return 7;
        return 0;
    }

    return 0;
}

/**
 * Set direction for a tuple6
 * @param tuple6 tuple6 to set direction
 * @param conn   tuple6 with correct direction
 */
void ftp_set_tuple6_direction(ftp_tuple6_t *tuple6,ftp_tuple6_t *conn, int compare){
    switch(compare){
        case 0:
            fprintf(stderr, "FTP: Not correct control connection\n");
            break;
        case 2:
            tuple6->direction = conn->direction;
            break;
        case 3:
            if(conn->direction == MMT_FTP_PACKET_SERVER){
                tuple6->direction = MMT_FTP_PACKET_CLIENT;
            }else if(conn->direction == MMT_FTP_PACKET_CLIENT){
                tuple6->direction = MMT_FTP_PACKET_SERVER;
            }
            break;
        case 4:
            tuple6->direction = conn->direction;
            conn->c_port = tuple6->c_port;
            break;
        case 5:
            conn->c_port = tuple6->s_port;
            if(conn->direction == MMT_FTP_PACKET_SERVER){
                tuple6->direction = MMT_FTP_PACKET_CLIENT;
            }else if(conn->direction == MMT_FTP_PACKET_CLIENT){
                tuple6->direction = MMT_FTP_PACKET_SERVER;
            }
            break;
        case 6:
            tuple6->direction = conn->direction;
            conn->s_port = tuple6->s_port;
            break;
        case 7:
            conn->s_port = tuple6->c_port;
            if(conn->direction == MMT_FTP_PACKET_SERVER){
                tuple6->direction = MMT_FTP_PACKET_CLIENT;
            }else if(conn->direction == MMT_FTP_PACKET_CLIENT){
                tuple6->direction = MMT_FTP_PACKET_SERVER;
            }
            break;
    }
}

/**
 * Check if a packet belongs to a control connection which is identified by server port number 21
 * @param  ipacket packet to check
 * @return         1 if the packet belongs to a control connection
 *                 2 if the packet doesn't belong to a control connection
 */
int ftp_check_control_packet(const ipacket_t *ipacket){
    if(ipacket->internal_packet->tcp){
        return (ipacket->internal_packet->tcp->source==htons(21)||ipacket->internal_packet->tcp->dest==htons(21));    
    }
    return 0;
}

/**
 * Set command ID for a command
 * @param cmd command to set id
 */
void ftp_set_command_id(ftp_command_t* cmd){
    if(strlen(cmd->str_cmd)==3){
        if(strcmp(cmd->str_cmd,"PWD") == 0 || strcmp(cmd->str_cmd,"pwd") == 0){
            cmd->cmd = MMT_FTP_PWD_CMD;
        }else if(strcmp(cmd->str_cmd,"CWD") == 0 || strcmp(cmd->str_cmd,"cwd") == 0){
            cmd->cmd = MMT_FTP_CWD_CMD;
        }else if(strcmp(cmd->str_cmd,"CCC") == 0 || strcmp(cmd->str_cmd,"ccc") == 0){
            cmd->cmd = MMT_FTP_CCC_CMD;
        }else if(strcmp(cmd->str_cmd,"ENC") == 0 || strcmp(cmd->str_cmd,"enc") == 0){
            cmd->cmd = MMT_FTP_ENC_CMD;
        }else if(strcmp(cmd->str_cmd,"MIC") == 0 || strcmp(cmd->str_cmd,"mic") == 0){
            cmd->cmd = MMT_FTP_MIC_CMD;
        }else if(strcmp(cmd->str_cmd,"MKD") == 0 || strcmp(cmd->str_cmd,"mkd") == 0){
            cmd->cmd = MMT_FTP_MKD_CMD;
        }else if(strcmp(cmd->str_cmd,"RMD") == 0 || strcmp(cmd->str_cmd,"rmd") == 0){
            cmd->cmd = MMT_FTP_RMD_CMD;
        }else if(strcmp(cmd->str_cmd,"MKD") == 0 || strcmp(cmd->str_cmd,"mkd") == 0){
            cmd->cmd = MMT_FTP_MKD_CMD;
        }else{
            cmd->cmd = MMT_FTP_UNKNOWN_CMD;
        }    
    }else{
        if(strcmp(cmd->str_cmd,"RETR") == 0 || strcmp(cmd->str_cmd,"retr") == 0){
            cmd->cmd = MMT_FTP_RETR_CMD;
        }else if(strcmp(cmd->str_cmd,"USER") == 0 || strcmp(cmd->str_cmd,"user") == 0){
            cmd->cmd = MMT_FTP_USER_CMD;
        }else if(strcmp(cmd->str_cmd,"PASS") == 0 || strcmp(cmd->str_cmd,"pass") == 0){
            cmd->cmd = MMT_FTP_PASS_CMD;
        }else if(strcmp(cmd->str_cmd,"SYST") == 0 || strcmp(cmd->str_cmd,"syst") == 0){
            cmd->cmd = MMT_FTP_SYST_CMD;
        }else if(strcmp(cmd->str_cmd,"TYPE") == 0 || strcmp(cmd->str_cmd,"type") == 0){
            cmd->cmd = MMT_FTP_TYPE_CMD;
        }else if(strcmp(cmd->str_cmd,"SIZE") == 0 || strcmp(cmd->str_cmd,"size") == 0){
            cmd->cmd = MMT_FTP_SIZE_CMD;
        }else if(strcmp(cmd->str_cmd,"EPSV") == 0 || strcmp(cmd->str_cmd,"epsv") == 0){
            cmd->cmd = MMT_FTP_EPSV_CMD;
        }else if(strcmp(cmd->str_cmd,"FEAT") == 0 || strcmp(cmd->str_cmd,"feat") == 0){
            cmd->cmd = MMT_FTP_FEAT_CMD;
        }else if(strcmp(cmd->str_cmd,"MDTM") == 0 || strcmp(cmd->str_cmd,"mdtm") == 0){
            cmd->cmd = MMT_FTP_MDTM_CMD;
        }else if(strcmp(cmd->str_cmd,"ABOR") == 0 || strcmp(cmd->str_cmd,"abor") == 0){
            cmd->cmd = MMT_FTP_ABOR_CMD;
        }else if(strcmp(cmd->str_cmd,"ACCT") == 0 || strcmp(cmd->str_cmd,"acct") == 0){
            cmd->cmd = MMT_FTP_ACCT_CMD;
        }else if(strcmp(cmd->str_cmd,"ALLO") == 0 || strcmp(cmd->str_cmd,"allo") == 0){
            cmd->cmd = MMT_FTP_ALLO_CMD;
        }else if(strcmp(cmd->str_cmd,"APPE") == 0 || strcmp(cmd->str_cmd,"appe") == 0){
            cmd->cmd = MMT_FTP_APPE_CMD;
        }else if(strcmp(cmd->str_cmd,"AUTH") == 0 || strcmp(cmd->str_cmd,"auth") == 0){
            cmd->cmd = MMT_FTP_AUTH_CMD;
        }else if(strcmp(cmd->str_cmd,"CDUP") == 0 || strcmp(cmd->str_cmd,"cdup") == 0){
            cmd->cmd = MMT_FTP_CDUP_CMD;
        }else if(strcmp(cmd->str_cmd,"CONF") == 0 || strcmp(cmd->str_cmd,"conf") == 0){
            cmd->cmd = MMT_FTP_CONF_CMD;
        }else if(strcmp(cmd->str_cmd,"DELE") == 0 || strcmp(cmd->str_cmd,"dele") == 0){
            cmd->cmd = MMT_FTP_DELE_CMD;
        }else if(strcmp(cmd->str_cmd,"EPRT") == 0 || strcmp(cmd->str_cmd,"eprt") == 0){
            cmd->cmd = MMT_FTP_EPRT_CMD;
        }else if(strcmp(cmd->str_cmd,"HELP") == 0 || strcmp(cmd->str_cmd,"help") == 0){
            cmd->cmd = MMT_FTP_HELP_CMD;
        }else if(strcmp(cmd->str_cmd,"LANG") == 0 || strcmp(cmd->str_cmd,"lang") == 0){
            cmd->cmd = MMT_FTP_LANG_CMD;
        }else if(strcmp(cmd->str_cmd,"LIST") == 0 || strcmp(cmd->str_cmd,"list") == 0){
            cmd->cmd = MMT_FTP_LIST_CMD;
        }else if(strcmp(cmd->str_cmd,"LPRT") == 0 || strcmp(cmd->str_cmd,"lprt") == 0){
            cmd->cmd = MMT_FTP_LPRT_CMD;
        }else if(strcmp(cmd->str_cmd,"LPSV") == 0 || strcmp(cmd->str_cmd,"lpsv") == 0){
            cmd->cmd = MMT_FTP_LPSV_CMD;
        }else if(strcmp(cmd->str_cmd,"MLSD") == 0 || strcmp(cmd->str_cmd,"mlsd") == 0){
            cmd->cmd = MMT_FTP_MLSD_CMD;
        }else if(strcmp(cmd->str_cmd,"MLST") == 0 || strcmp(cmd->str_cmd,"mlst") == 0){
            cmd->cmd = MMT_FTP_MLST_CMD;
        }else if(strcmp(cmd->str_cmd,"MODE") == 0 || strcmp(cmd->str_cmd,"mode") == 0){
            cmd->cmd = MMT_FTP_MODE_CMD;
        }else if(strcmp(cmd->str_cmd,"NLST") == 0 || strcmp(cmd->str_cmd,"nlst") == 0){
            cmd->cmd = MMT_FTP_NLST_CMD;
        }else if(strcmp(cmd->str_cmd,"NOOP") == 0 || strcmp(cmd->str_cmd,"noop") == 0){
            cmd->cmd = MMT_FTP_NOOP_CMD;
        }else if(strcmp(cmd->str_cmd,"OPTS") == 0 || strcmp(cmd->str_cmd,"opts") == 0){
            cmd->cmd = MMT_FTP_OPTS_CMD;
        }else if(strcmp(cmd->str_cmd,"PASV") == 0 || strcmp(cmd->str_cmd,"pasv") == 0){
            cmd->cmd = MMT_FTP_PASV_CMD;
        }else if(strcmp(cmd->str_cmd,"PBSZ") == 0 || strcmp(cmd->str_cmd,"pbsz") == 0){
            cmd->cmd = MMT_FTP_PBSZ_CMD;
        }else if(strcmp(cmd->str_cmd,"PORT") == 0 || strcmp(cmd->str_cmd,"port") == 0){
            cmd->cmd = MMT_FTP_PORT_CMD;
        }else if(strcmp(cmd->str_cmd,"QUIT") == 0 || strcmp(cmd->str_cmd,"quit") == 0){
            cmd->cmd = MMT_FTP_QUIT_CMD;
        }else if(strcmp(cmd->str_cmd,"REIN") == 0 || strcmp(cmd->str_cmd,"rein") == 0){
            cmd->cmd = MMT_FTP_REIN_CMD;
        }else if(strcmp(cmd->str_cmd,"REST") == 0 || strcmp(cmd->str_cmd,"rest") == 0){
            cmd->cmd = MMT_FTP_REST_CMD;
        }else if(strcmp(cmd->str_cmd,"RNFR") == 0 || strcmp(cmd->str_cmd,"rnfr") == 0){
            cmd->cmd = MMT_FTP_RNFR_CMD;
        }else if(strcmp(cmd->str_cmd,"RNTO") == 0 || strcmp(cmd->str_cmd,"rnto") == 0){
            cmd->cmd = MMT_FTP_RNTO_CMD;
        }else if(strcmp(cmd->str_cmd,"SITE") == 0 || strcmp(cmd->str_cmd,"site") == 0){
            cmd->cmd = MMT_FTP_SITE_CMD;
        }else if(strcmp(cmd->str_cmd,"SMNT") == 0 || strcmp(cmd->str_cmd,"smnt") == 0){
            cmd->cmd = MMT_FTP_SMNT_CMD;
        }else if(strcmp(cmd->str_cmd,"STAT") == 0 || strcmp(cmd->str_cmd,"stat") == 0){
            cmd->cmd = MMT_FTP_STAT_CMD;
        }else if(strcmp(cmd->str_cmd,"STOR") == 0 || strcmp(cmd->str_cmd,"stor") == 0){
            cmd->cmd = MMT_FTP_STOR_CMD;
        }else if(strcmp(cmd->str_cmd,"STOU") == 0 || strcmp(cmd->str_cmd,"stou") == 0){
            cmd->cmd = MMT_FTP_STOU_CMD;
        }else if(strcmp(cmd->str_cmd,"STRU") == 0 || strcmp(cmd->str_cmd,"stru") == 0){
            cmd->cmd = MMT_FTP_STRU_CMD;
        }else if(strcmp(cmd->str_cmd,"XCUP") == 0 || strcmp(cmd->str_cmd,"xcup") == 0){
            cmd->cmd = MMT_FTP_XCUP_CMD;
        }else if(strcmp(cmd->str_cmd,"XMKD") == 0 || strcmp(cmd->str_cmd,"xmkd") == 0){
            cmd->cmd = MMT_FTP_XMKD_CMD;
        }else if(strcmp(cmd->str_cmd,"XPWD") == 0 || strcmp(cmd->str_cmd,"xpwd") == 0){
            cmd->cmd = MMT_FTP_XPWD_CMD;
        }else if(strcmp(cmd->str_cmd,"XRCP") == 0 || strcmp(cmd->str_cmd,"xrcp") == 0){
            cmd->cmd = MMT_FTP_XRCP_CMD;
        }else if(strcmp(cmd->str_cmd,"XRMD") == 0 || strcmp(cmd->str_cmd,"xrmd") == 0){
            cmd->cmd = MMT_FTP_XRMD_CMD;
        }else if(strcmp(cmd->str_cmd,"XRSQ") == 0 || strcmp(cmd->str_cmd,"xrsq") == 0){
            cmd->cmd = MMT_FTP_XRSQ_CMD;
        }else if(strcmp(cmd->str_cmd,"XSEM") == 0 || strcmp(cmd->str_cmd,"xsem") == 0){
            cmd->cmd = MMT_FTP_XSEM_CMD;
        }else if(strcmp(cmd->str_cmd,"XSEN") == 0 || strcmp(cmd->str_cmd,"xsen") == 0){
            cmd->cmd = MMT_FTP_XSEN_CMD;
        }else{
            cmd->cmd = MMT_FTP_UNKNOWN_CMD;
        }
    }
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
    char * command;
    char * params;
    
    if(payload_len==6 && payload[3]!=' '){
        // FEAT\r\t command
        command = (char*)malloc(5);
        memcpy(command,payload,4);
        command[4]='\0';
        cmd->str_cmd = command;
        cmd->param = NULL;
    }else if(payload_len==5 && payload[2]!=' '){
        // PWD\r\t command
        command = (char*)malloc(4);
        memcpy(command,payload,3);
        command[3]='\0';
        cmd->str_cmd = command;
        cmd->param = NULL;
    }else{
        if(!mmt_int_check_possible_ftp_command(payload,payload_len)){
            cmd->cmd = MMT_FTP_UNKNOWN_CMD;
            cmd->str_cmd = "UNKNOWN_CMD";
            cmd->param = payload;
            return cmd;
        }
        
        if(payload[3]==' '){
            command = (char*)malloc(4);
            memcpy(command,payload,3);
            command[3]='\0';
            cmd->str_cmd = command;

            if(payload_len-6>0){
                params = (char*)malloc(payload_len-5);
                memcpy(params,payload+4,payload_len-6);
                params[payload_len-6]='\0';
                cmd->param = params;
            }else{
                cmd->param = NULL;
            }        
        }else if(payload[4]==' '){
            command = (char*)malloc(5);
            memcpy(command,payload,4);
            command[4]='\0';
            cmd->str_cmd = command;
            if(payload_len-7>0){
                params = (char*)malloc(payload_len-6);
                memcpy(params,payload+5,payload_len-7);
                params[payload_len-7]='\0';
                cmd->param = params;
            }else{
                cmd->param = NULL;
            } 
        }
    }

    ftp_set_command_id(cmd);

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
    int code;
    char *str_value;
    res = (ftp_response_t*)malloc(sizeof(ftp_response_t));
    
    if(mmt_int_check_possible_ftp_reply(payload,payload_len)){
        // Get response code
        char *str_code;
        str_code = (char*)malloc(4);
        memcpy(str_code,payload,3);
        str_code[3]='\0';
        code = atoi(str_code);
        res->str_code = str_code;
        res->code = code;

        // Get response value
        if(payload_len-6>0){
            str_value = (char*)malloc(payload_len-5);
            memcpy(str_value,payload+4,payload_len-6);
            str_value[payload_len-6]='\0';
            res->value = str_value;
        }else{
            res->value = NULL;
        }
        
    }else{
        if(mmt_int_check_possible_ftp_continuation_reply(payload,payload_len)){
            code = MMT_FTP_CONTINUE_CODE;
            str_value = (char*)malloc(payload_len-1);
            memcpy(str_value,payload,payload_len-2);
            str_value[payload_len-2]='\0';
            res->value = str_value;
            res->str_code = str_value;
        }else{
            code = MMT_FTP_UNKNOWN_CODE;
            str_value = (char*)malloc(payload_len-1);
            memcpy(str_value,payload,payload_len-2);
            str_value[payload_len-2]='\0';
            res->value = str_value;
            res->str_code = str_value;
        }
        res->code = code;
    }
    return res;
}


/**
 * Get client address from an EPRT command
 * @param  payload     Payload of command
 * Example: EPRT |1|132.235.1.2|6275|
 * @return             Client IP address
 */
uint32_t ftp_get_data_client_addr_from_EPRT(char * payload){
    // Get all the indexes of "|" in payload
    int asc_code = (int)'|';
    int * indexes = str_get_indexes(payload,asc_code);
    char * str_addr;
    int len = indexes[2]-indexes[1];
    str_addr = (char*)malloc(len);
    memcpy(str_addr,payload + indexes[1]+1,len-1);
    str_addr[len-1]='\0';
    return inet_addr(str_addr);
}

/**
 * Get client address from an EPRT command
 * @param  payload     Payload of command
 * Example: EPRT |1|132.235.1.2|6275|
 * @return             Client port number
 */
uint16_t ftp_get_data_client_port_from_EPRT(char *payload){
    // Get all the indexes of "|" in payload
    int asc_code = (int)'|';
    int * indexes = str_get_indexes(payload,asc_code);
    char * str_addr;
    int len = indexes[3]-indexes[2];
    str_addr = (char*)malloc(len);
    memcpy(str_addr,payload + indexes[2]+1,len-1);
    str_addr[len-1]='\0';
    return atoi(str_addr);
}

/**
 * Get an address from a string
 * @param  payload     string
 * Example: 192,168,1,2,7,138 -> addr = inet_addr("192.168.1.2")
 * @return             an address
 */
uint32_t ftp_get_addr_from_parameter(char * payload,uint32_t payload_len){
    // Get all the indexes of "|" in payload
    int asc_code = (int)',';
    int * indexes = str_get_indexes(payload,asc_code);
    char * str_addr;
    int len = indexes[3];
    str_addr = (char*)malloc(len+1);
    memcpy(str_addr,payload,len+1);
    str_addr[len]='\0';
    // printf("String before replacing: %s\n",str_addr);
    str_addr = str_replace_all_char(str_addr,(int)',', (int)'.');
    // printf("String after replacing: %s\n",str_addr);
    return inet_addr(str_addr);
}

/**
 * Get a port number from a string
 * @param  payload     string 
 * Example: 192,168,1,2,7,138 -> port_nb = 7*256 + 138
 * @return             port number
 */
uint16_t ftp_get_port_from_parameter(char *payload,uint32_t payload_len){
    // Get all the indexes of "|" in payload
    int asc_code = (int)',';
    int * indexes = str_get_indexes(payload,asc_code);
    
    char * nb1;
    nb1 = str_sub_index(payload,indexes[3],indexes[4]);
    printf("nb1 string: %s\n", nb1);

    char * nb2;
    nb2 = str_sub_index(payload,indexes[4],payload_len);
    printf("nb2 string: %s\n", nb2);
    uint16_t port = ntohs(atoi(nb1) * 256 + atoi(nb2));
    return port;
}

/**
 * Get data server port from response code 229
 * Example: Entering Extended Passive Mode (|||port|)
 * @param  payload payload to extract server port
 * @return         server port
 */
uint16_t ftp_get_data_server_port_code_229(char *payload){
    char *ret = str_subvalue(payload,"(|||","|)");
    return htons(atoi(ret));
}


/**
 * Get data server address from value of response code 227
 * @param  payload payload
 * @return         server address
 */
uint32_t ftp_get_data_server_addr_code_227(char * payload){
    char * str = str_subvalue(payload,"(",")");
    uint32_t len = strlen(str);
    return ftp_get_addr_from_parameter(str,len);
}
/**
 * Get data server port number from value of response code 227
 * @param  payload payload
 * @return         server address
 */
uint16_t ftp_get_data_server_port_code_227(char * payload){
    char * str = str_subvalue(payload,"(",")");
    uint32_t len = strlen(str);
    return ftp_get_port_from_parameter(str,len);
}

/**
 * Extract server port from response code 228
 * Example: Entering Long Passive Mode (long address, port).   
 * @param  payload Payload to extract
 * @return         port number
 */
uint16_t ftp_get_data_server_port_code_228(char *payload){
    char *ret = str_subvalue(payload,", ",")");
    return htons(atoi(ret));
}

/**
 * Extract serer address from response code 228
 * Example: Entering Long Passive Mode (long address, port).
 * @param  payload payload to extract
 * @return         server address
 */
uint16_t ftp_get_data_server_addr_code_228(char *payload){
    char *ret = str_subvalue(payload,"(",",");
    return htons(atoi(ret));
}
//////////// LUONG NGUYEN - END OF FUNCTION    /////////////////////////

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/**
 * Get list of control session from session context
 * @param  ipacket packet
 * @param  index   protocol index
 * @return         the pointer to the first control_session
 */
ftp_control_session_t * ftp_get_list_control_session(ipacket_t *ipacket, unsigned index){
    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
            ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
    return (ftp_control_session_t*)configured_protocol->args;
}

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


int ftp_get_packet_type(const ipacket_t *ipacket, unsigned index){
    
    if(ipacket->internal_packet->payload_packet_len==0){
        return MMT_FTP_PACKET_TYPE_UNKNOWN;
    }

    ftp_tuple6_t *tuple6 = ftp_get_tuple6(ipacket);
    if(tuple6->conn_type == MMT_FTP_CONTROL_CONNECTION){
        if(tuple6->direction == MMT_FTP_PACKET_SERVER){
            return MMT_FTP_PACKET_RESPONSE;
        }else{
            return MMT_FTP_PACKET_COMMAND;
        }
    }else if(tuple6->conn_type == MMT_FTP_DATA_CONNECTION){
        return MMT_FTP_PACKET_DATA;
    }
    return MMT_FTP_PACKET_TYPE_UNKNOWN;
}

////////////////////// SESSION ATTRIBUTE EXTRACTION ///////////////////////
/**
 * Extract connection type of which packet belongs to
 * @param  packet         packet
 * @param  proto_index    protocol index
 * @param  extracted_data extracted data
 * @return                1 if there is data 
 *                        0 there is no data
 */
int ftp_session_conn_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    ftp_tuple6_t *t6;

    t6 = ftp_get_tuple6(ipacket);

    if(t6){
        *((uint8_t*)extracted_data->data) = t6->conn_type;
        return 1;   
    }
    
    return 0;
}


int ftp_server_contrl_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->contrl_conn && ftp_control->contrl_conn->s_addr){
                *((uint32_t*)extracted_data->data) = ftp_control->contrl_conn->s_addr;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_server_contrl_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->contrl_conn && ftp_control->contrl_conn->s_port){
                *((uint16_t*)extracted_data->data) = ftp_control->contrl_conn->s_port;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_client_contrl_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->contrl_conn && ftp_control->contrl_conn->c_addr){
                *((uint32_t*)extracted_data->data) = ftp_control->contrl_conn->c_addr;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_client_contrl_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->contrl_conn && ftp_control->contrl_conn->c_port){
                *((uint16_t*)extracted_data->data) = ftp_control->contrl_conn->c_port;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_username_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->user && ftp_control->user->username){
                extracted_data->data = (void*)ftp_control->user->username;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_password_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->user && ftp_control->user->password){
                extracted_data->data = (void*)ftp_control->user->password;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_features_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->session_feats){
                extracted_data->data = (void*)ftp_control->session_feats;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_status_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->status){
                *((uint16_t*)extracted_data->data) = ftp_control->status;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_syst_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->session_syst){
                extracted_data->data = (void*)ftp_control->session_syst;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_last_command_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->last_command && ftp_control->last_command){
                extracted_data->data = (void*)ftp_control->last_command;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_last_response_code_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->last_response && ftp_control->last_response){
                extracted_data->data = (void*)ftp_control->last_response;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_current_dir_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_dir){
                extracted_data->data = (void*)ftp_control->current_dir;
                return 1;
            }
        }    
    }
    return 0;
}

int ftp_server_data_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session->data_conn && ftp_control->current_data_session->data_conn->s_addr){
                    *((uint32_t*)extracted_data->data) = ftp_control->current_data_session->data_conn->s_addr;
                    return 1;
                }
            }
        }    
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data){
            if(ftp_data->data_conn && ftp_data->data_conn->s_addr){
                *((uint32_t*)extracted_data->data) = ftp_data->data_conn->s_addr;
                return 1;
            }
        } 
    }
    return 0;
}

int ftp_server_data_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session->data_conn && ftp_control->current_data_session->data_conn->s_port){
                    *((uint16_t*)extracted_data->data) = ftp_control->current_data_session->data_conn->s_port;
                    return 1;
                }
            }
        }    
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data){
            if(ftp_data->data_conn && ftp_data->data_conn->s_port){
                *((uint16_t*)extracted_data->data) = ftp_data->data_conn->s_port;
                return 1;
            }
        } 
    }
    return 0;
}

int ftp_client_data_addr_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session->data_conn && ftp_control->current_data_session->data_conn->c_addr){
                    *((uint32_t*)extracted_data->data) = ftp_control->current_data_session->data_conn->c_addr;
                    return 1;
                }
            }
        }    
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data){
            if(ftp_data->data_conn && ftp_data->data_conn->c_addr){
                *((uint32_t*)extracted_data->data) = ftp_data->data_conn->c_addr;
                return 1;
            }
        } 
    }
    return 0;
}

int ftp_client_data_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session->data_conn && ftp_control->current_data_session->data_conn->c_port){
                    *((uint16_t*)extracted_data->data) = ftp_control->current_data_session->data_conn->c_port;
                    return 1;
                }
            }
        }    
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data){
            if(ftp_data->data_conn && ftp_data->data_conn->c_port){
                *((uint16_t*)extracted_data->data) = ftp_data->data_conn->c_port;
                return 1;
            }
        } 
    }
    return 0;
}

int ftp_data_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session && ftp_control->current_data_session->data_type){
                *((uint8_t*)extracted_data->data) = ftp_control->current_data_session->data_type;
                return 1;
            }
        }
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data && ftp_data->data_type){
            *((uint8_t*)extracted_data->data) = ftp_data->data_type;
            return 1;
        } 
    }
    return 0;
}

int ftp_data_transfer_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session && ftp_control->current_data_session->data_transfer_type){
                extracted_data->data = ftp_control->current_data_session->data_transfer_type;
                return 1;
            }
        }
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data && ftp_data->data_transfer_type){
            extracted_data->data = ftp_data->data_transfer_type;
            return 1;
        } 
    }
    return 0;
}

int ftp_data_mode_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session && ftp_control->current_data_session->data_conn_mode){
                *((uint8_t*)extracted_data->data) = ftp_control->current_data_session->data_conn_mode;
                return 1;
            }
        }
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data && ftp_data->data_conn_mode){
            *((uint8_t*)extracted_data->data) = ftp_data->data_conn_mode;
            return 1;
        } 
    }
    return 0;
}

int ftp_data_direction_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data){
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session){
                    *((uint8_t*)extracted_data->data) = ftp_control->current_data_session->data_direction;
                    return 1;
                }
            }
        }
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data && ftp_data->data_direction){
            *((uint8_t*)extracted_data->data) = ftp_data->data_direction;
            return 1;
        } 
    }
    return 0;
}



int ftp_file_name_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session->file && ftp_control->current_data_session->file->name){
                    extracted_data->data = (void*)ftp_control->current_data_session->file->name;
                    return 1;
                }
            }
        }    
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data){
            if(ftp_data->file && ftp_data->file->name){
                extracted_data->data = (void*)ftp_data->file->name;
                return 1;
            }
        } 
    }
    
    return 0;
}


int ftp_file_size_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session->file && ftp_control->current_data_session->file->size){
                    *((uint32_t*)extracted_data->data) = ftp_control->current_data_session->file->size;
                    return 1;
                }
            }
        }    
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data){
            if(ftp_data->file && ftp_data->file->size){
                *((uint32_t*)extracted_data->data) = ftp_data->file->size;
                return 1;
            }
        } 
    }
    return 0;
}

int ftp_file_last_modified_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if(ftp_check_control_packet(ipacket)){
        ftp_control_session_t * ftp_control = (ftp_control_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_control){
            if(ftp_control->current_data_session){
                if(ftp_control->current_data_session->file && ftp_control->current_data_session->file->last_modified){
                    extracted_data->data = (void*)ftp_control->current_data_session->file->last_modified;
                    return 1;
                }
            }
        }    
    }else{
        ftp_data_session_t * ftp_data = (ftp_data_session_t*)ipacket->session->session_data[proto_index];
        if(ftp_data){
            if(ftp_data->file && ftp_data->file->last_modified){
                extracted_data->data = (void*)ftp_data->file->last_modified;
                return 1;
            }
        } 
    }
    return 0;
}


////////////////////// PACKET ATTRIBUTE EXTRACTION ///////////////////////
int ftp_packet_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    uint8_t p_type = ftp_get_packet_type(ipacket,proto_index);
    *((uint8_t*)extracted_data->data) = p_type;
    return 1;
}

int ftp_packet_request_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type(ipacket,proto_index);
    if(packet_type==MMT_FTP_PACKET_COMMAND){
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        char *payload = (char*)&ipacket->data[offset];
        int payload_len = ipacket->internal_packet->payload_packet_len;
        ftp_command_t * cmd = ftp_get_command(payload,payload_len);
        if(cmd && cmd->str_cmd){
            log_info("FTP: packet_request %d in packet: %lu\n", cmd->cmd,ipacket->packet_id);
            extracted_data->data = (void*)cmd->str_cmd;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_request_parameter_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type(ipacket,proto_index);
    if(packet_type==MMT_FTP_PACKET_COMMAND){
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        char *payload = (char*)&ipacket->data[offset];
        int payload_len = ipacket->internal_packet->payload_packet_len;
        ftp_command_t * cmd = ftp_get_command(payload,payload_len);
        if(cmd && cmd->param){
            log_info("FTP: packet_request_param %s in packet: %lu\n", cmd->param,ipacket->packet_id);
            extracted_data->data = (void*)cmd->param;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_response_code_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type(ipacket,proto_index);
    if(packet_type==MMT_FTP_PACKET_RESPONSE){
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        char *payload = (char*)&ipacket->data[offset];
        int payload_len = ipacket->internal_packet->payload_packet_len;
        ftp_response_t * res = ftp_get_response(payload,payload_len);
        if(res && res->code){
            log_info("FTP: packet_response %d in packet: %lu\n", res->code,ipacket->packet_id);
            *((uint16_t*)extracted_data->data) = res->code;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_response_value_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type(ipacket,proto_index);
    if(packet_type==MMT_FTP_PACKET_RESPONSE){
        int offset = get_packet_offset_at_index(ipacket, proto_index);
        char *payload = (char*)&ipacket->data[offset];
        int payload_len = ipacket->internal_packet->payload_packet_len;
        ftp_response_t * res = ftp_get_response(payload,payload_len);
        if(res->code && res->value){
            log_info("FTP: packet_response_value %s in packet: %lu\n", res->value,ipacket->packet_id);
            extracted_data->data = (void*)res->value;
            return 1;      
        }
    }
    return 0;
}

int ftp_packet_data_len_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    
    int packet_type = ftp_get_packet_type(ipacket,proto_index);
    if(packet_type == MMT_FTP_PACKET_DATA){
        int len = ipacket->internal_packet->payload_packet_len;
        *((uint32_t*)extracted_data->data) = len;
        // log_info("FTP: extraction payload_packet_len: %d",*(uint32_t*)extracted_data->data);
        return 1;
    }
    return 0;
}

static attribute_metadata_t ftp_attributes_metadata[FTP_ATTRIBUTES_NB] = {
    ////////////// SESSION ATTRIBUTES //////////////////////////////
    /// FTP CONTROL CONNECTION SESSION ATTRIBUTES ///
    {FTP_SESSION_CONN_TYPE,FTP_SESSION_CONN_TYPE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_session_conn_type_extraction},
    {FTP_SERVER_CONT_ADDR,FTP_SERVER_CONT_ADDR_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_contrl_addr_extraction},
    {FTP_SERVER_CONT_PORT,FTP_SERVER_CONT_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_contrl_port_extraction},
    {FTP_CLIENT_CONT_PORT,FTP_CLIENT_CONT_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_contrl_port_extraction},    
    {FTP_CLIENT_CONT_ADDR,FTP_CLIENT_CONT_ADDR_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_contrl_addr_extraction},
    {FTP_USERNAME,FTP_USERNAME_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_username_extraction},
    {FTP_PASSWORD,FTP_PASSWORD_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_password_extraction},
    {FTP_SESSION_FEATURES,FTP_SESSION_FEATURES_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_features_extraction},
    {FTP_SYST,FTP_SYST_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_syst_extraction},
    {FTP_STATUS,FTP_STATUS_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_status_extraction},
    {FTP_LAST_COMMAND,FTP_LAST_COMMAND_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_last_command_extraction},
    {FTP_LAST_RESPONSE_CODE,FTP_LAST_RESPONSE_CODE_ALIAS,MMT_DATA_POINTER,sizeof(void*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_last_response_code_extraction},
    {FTP_CURRENT_DIR,FTP_CURRENT_DIR_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION_CHANGING,ftp_current_dir_extraction},
    /// CURRENT FTP DATA CONNECTION SESSION ATTRIBUTES ///
    {FTP_SERVER_DATA_ADDR,FTP_SERVER_DATA_ADDR_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_data_addr_extraction},
    {FTP_SERVER_DATA_PORT,FTP_SERVER_DATA_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_server_data_port_extraction},
    {FTP_CLIENT_DATA_ADDR,FTP_CLIENT_DATA_ADDR_ALIAS,MMT_DATA_IP_ADDR,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_data_addr_extraction},
    {FTP_CLIENT_DATA_PORT,FTP_CLIENT_DATA_PORT_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_client_data_port_extraction},
    {FTP_DATA_TYPE,FTP_DATA_TYPE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_type_extraction},
    {FTP_DATA_TRANSFER_TYPE,FTP_DATA_TRANSFER_TYPE_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_transfer_type_extraction},
    {FTP_DATA_MODE,FTP_DATA_MODE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_mode_extraction},
    {FTP_DATA_DIRECTION,FTP_DATA_DIRECTION_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_data_direction_extraction},
    /// CURRENT FTP FILE ATTRIBUTES ///
    {FTP_FILE_NAME,FTP_FILE_NAME_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_name_extraction},
    {FTP_FILE_SIZE,FTP_FILE_SIZE_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_size_extraction},
    {FTP_FILE_LAST_MODIFIED,FTP_FILE_LAST_MODIFIED_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_SESSION,ftp_file_last_modified_extraction},
    ////////////// PACKET ATTRIBUTES //////////////////////////////
    {FTP_PACKET_TYPE,FTP_PACKET_TYPE_ALIAS,MMT_U8_DATA,sizeof(char),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_type_extraction},
    {FTP_PACKET_REQUEST,FTP_PACKET_REQUEST_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_request_extraction},
    {FTP_PACKET_REQUEST_PARAMETER,FTP_PACKET_REQUEST_PARAMETER_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_request_parameter_extraction},
    {FTP_PACKET_RESPONSE_CODE,FTP_PACKET_RESPONSE_CODE_ALIAS,MMT_U16_DATA,sizeof(short),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_response_code_extraction},
    {FTP_PACKET_RESPONSE_VALUE,FTP_PACKET_RESPONSE_VALUE_ALIAS,MMT_STRING_DATA_POINTER,sizeof(char*),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_response_value_extraction},
    {FTP_PACKET_DATA_LEN,FTP_PACKET_DATA_LEN_ALIAS,MMT_U32_DATA,sizeof(int),POSITION_NOT_KNOWN,SCOPE_PACKET,ftp_packet_data_len_extraction}
};

//////////////////////////// END OF EXTRACTION /////////////////////////////////


///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////
/**
 * Analysis FTP data packet
 * @param ipacket  packet to analysis
 * @param index    protocol index
 * @param ftp_data ftp data session which this packet belongs to
 */
void ftp_data_packet(ipacket_t *ipacket,unsigned index,ftp_data_session_t * ftp_data){
    log_info("FTP: FTP_DATA PACKET: %lu",ipacket->packet_id);
    
    //printf("from http generic session data analysis\n");
    // int offset = get_packet_offset_at_index(ipacket, index);

    // char *payload = (char*)&ipacket->data[offset];

    // ftp_data_session_t *ftp_data = (ftp_data_session_t*)ipacket->session->session_data[index];
    
    // if(ftp_data != NULL){
    //     ipacket->session->session_data[index] =  ipacket->session->next->session_data[index];
    // }
    // log_info("FTP: Payload: %s",payload);
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
    ftp_control->last_command = command;
    ftp_data_session_t *current_data_session = ftp_control->current_data_session;
    switch(command->cmd){
        case MMT_FTP_EPRT_CMD:
            current_data_session->data_conn_mode = MMT_FTP_DATA_ACTIVE_MODE;
            current_data_session->data_conn->c_addr = ftp_get_data_client_addr_from_EPRT(payload);
            current_data_session->data_conn->c_port = ftp_get_data_client_port_from_EPRT(payload);
            break;
        case MMT_FTP_PORT_CMD:
            current_data_session->data_conn_mode = MMT_FTP_DATA_ACTIVE_MODE;
            current_data_session->data_conn->c_addr = ftp_get_addr_from_parameter(payload,payload_len);
            current_data_session->data_conn->c_port = ftp_get_port_from_parameter(payload,payload_len);
        case MMT_FTP_USER_CMD:
            ftp_control->user->username = command->param;
            ftp_control->status = MMT_FTP_STATUS_OPENED;
            break;
        case MMT_FTP_PASS_CMD:
            ftp_control->user->password = command->param;
            break;
        case MMT_FTP_TYPE_CMD:
            current_data_session->data_transfer_type=command->param;
            break;
        case MMT_FTP_LIST_CMD:
        case MMT_FTP_MLSD_CMD:
        case MMT_FTP_NLST_CMD:
            current_data_session->data_type = MMT_FTP_DATA_TYPE_LIST;
            break;
        case MMT_FTP_MLST_CMD:
            current_data_session->data_type = MMT_FTP_DATA_TYPE_UNKNOWN;
            break;
        case MMT_FTP_RETR_CMD:
            current_data_session->file->name = command->param;
            current_data_session->data_direction = MMT_FTP_DATA_DOWNLOAD;
            current_data_session->data_type  = MMT_FTP_DATA_TYPE_FILE;
            break;
        case MMT_FTP_STOR_CMD:
        case MMT_FTP_STOU_CMD:
            current_data_session->file->name = command->param;
            current_data_session->data_direction = MMT_FTP_DATA_UPLOAD;
            current_data_session->data_type  = MMT_FTP_DATA_TYPE_FILE;
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
    ftp_control->last_response = response;

    ftp_data_session_t *current_data_session = ftp_control->current_data_session;
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
                    current_data_session->file->last_modified = response->value;
                }else if(ftp_control->last_command->cmd==MMT_FTP_SIZE_CMD){
                    current_data_session->file->size = atoi(response->value);
                }
                break;
            case MMT_FTP_229_CODE:
                current_data_session->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
                ftp_tuple6_t * t6 = ftp_new_tuple6();
                t6->s_port = ftp_get_data_server_port_code_229(response->value);
                t6->s_addr = ftp_control->contrl_conn->s_addr;
                t6->c_addr = ftp_control->contrl_conn->c_addr;
                t6->conn_type = MMT_FTP_DATA_CONNECTION;
                t6->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
                current_data_session->data_conn = t6;
                break;
            case MMT_FTP_227_CODE:
                current_data_session->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
                current_data_session->data_conn->s_addr = ftp_get_data_server_addr_code_227(payload);
                current_data_session->data_conn->s_port = ftp_get_data_server_port_code_227(payload);
                current_data_session->data_conn->c_addr = ftp_control->contrl_conn->c_addr;
                break;
            case MMT_FTP_228_CODE:
                current_data_session->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
                ftp_tuple6_t * t62 = ftp_new_tuple6();
                t62->s_port = ftp_get_data_server_port_code_228(response->value);
                t62->s_addr = ftp_get_data_server_addr_code_228(response->value);
                t62->c_addr = ftp_control->contrl_conn->c_addr;
                t62->conn_type = MMT_FTP_DATA_CONNECTION;
                t62->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
                current_data_session->data_conn = t62;
                break;
            case MMT_FTP_150_CODE:
                ftp_control->status = MMT_FTP_STATUS_DATA_OPENED;
                break;
            case MMT_FTP_226_CODE:
                ftp_control->status = MMT_FTP_STATUS_DATA_CLOSED;
                break;
            case MMT_FTP_221_CODE:
                ftp_control->status = MMT_FTP_STATUS_CLOSED;
                break;
            case MMT_FTP_215_CODE:
                ftp_control->session_syst = response->value;
                break;
            default:
                log_info("FTP: code : %d\n",response->code);
                log_info("FTP: value : %s\n",response->value);
                break;
        }
    }else{
        log_info("FTP: Received a response code:\n");
        log_info("Code: %d\n",response->code);
        log_info("Value : %s\n",response->value);
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
int ftp_session_data_analysis(ipacket_t * ipacket, unsigned index) {

    log_info("FTP: START ANALYSING SESSION DATA OF PACKET: %lu",ipacket->packet_id);
    
    //printf("from http generic session data analysis\n");
    // int offset = get_packet_offset_at_index(ipacket, index);
    
    // char *payload = (char*)&ipacket->data[offset];

    // Make sure there is data to analayse
    if(ipacket->internal_packet->payload_packet_len==0){
        log_info("There is no FTP data to analysis: %lu\n",ipacket->packet_id);
        return MMT_CONTINUE;
    }
    
    ftp_tuple6_t *tuple6 = ftp_get_tuple6(ipacket);


    ftp_control_session_t *ftp_list_control = ftp_get_list_control_session(ipacket,index);
    ftp_control_session_t *ftp_control;
    ftp_data_session_t *ftp_data = NULL;
    if(tuple6->conn_type==MMT_FTP_CONTROL_CONNECTION){
        if(ipacket->session->session_data[index]){
            ftp_control = (ftp_control_session_t*)ipacket->session->session_data[index];
            int compare = ftp_compare_tuple6(tuple6,ftp_control->contrl_conn);
            if(compare == 0){
                fprintf(stderr, "FTP: Not correct control connection\n");
                return MMT_CONTINUE;
            }else{
                ftp_control->contrl_conn->direction = tuple6->direction;
            }
        }else{
            ftp_control = ftp_new_control_session(tuple6);
            if(ftp_list_control->next == NULL){
                ftp_list_control->next = ftp_control;
            }else{
                ftp_control_session_t * temp = ftp_list_control;
                while(temp->next){
                    temp = temp->next;
                }
                temp->next = ftp_control;
            }
            ipacket->session->session_data[index]=ftp_control;
        }
    }else{
        if(ipacket->session->session_data[index]){
            ftp_data = (ftp_data_session_t*)ipacket->session->session_data[index];
            int compare = ftp_compare_tuple6(tuple6,ftp_data->data_conn);
            if(compare!=0){
                ftp_set_tuple6_direction(tuple6,ftp_data->data_conn,compare);    
            }else{
                ftp_control_session_t *temp = ftp_list_control->next;
                while(temp && temp->current_data_session){
                    int compare = ftp_compare_tuple6(tuple6,temp->current_data_session->data_conn);
                    if(compare!=0){
                        ftp_set_tuple6_direction(tuple6,temp->current_data_session->data_conn,compare);
                        ipacket->session->session_data[index] = temp->current_data_session;
                        ftp_data = temp->current_data_session;
                        break;
                    }
                    temp = temp->next;
                } 
            }
        }else{
            // New not FTP control packet
            if(ftp_list_control->next == NULL){
                fprintf(stderr, "FTP: Cannot find any control connection\n");
                return MMT_CONTINUE;
            }else{
                ftp_control_session_t *temp = ftp_list_control->next;
                while(temp && temp->current_data_session){
                    int compare = ftp_compare_tuple6(tuple6,temp->current_data_session->data_conn);
                    if(compare!=0){
                        ftp_set_tuple6_direction(tuple6,temp->current_data_session->data_conn,compare);
                        ipacket->session->session_data[index] = temp->current_data_session;
                        ftp_data = temp->current_data_session;
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

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////


void * setup_ftp_context(void * proto_context, void * args) {
    ftp_control_session_t * ftp_list_control_conns;
    ftp_list_control_conns = (ftp_control_session_t*)malloc(sizeof(ftp_control_session_t));
    ftp_list_control_conns->next = NULL;
    return (void*)ftp_list_control_conns;
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
        register_proto_context_init_cleanup_function(protocol_struct, setup_ftp_context, NULL, NULL);
        register_session_data_analysis_function(protocol_struct, ftp_session_data_analysis);
        mmt_init_classify_me_ftp();

        return register_protocol(protocol_struct, PROTO_FTP);
    } else {
        return 0;
    }
}


