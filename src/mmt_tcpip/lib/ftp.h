/* 
 * File:   http.h
 * Author: montimage
 *
 * Created on 20 septembre 2011, 14:09
 */

#ifndef MMT_FTP_H
#define MMT_FTP_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

#define MMT_FTP_TIMEOUT                     10
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static uint32_t ftp_connection_timeout = MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;

// FTP control connection session status
#define MMT_FTP_STATUS_OPENED               1 // Open a session control
#define MMT_FTP_STATUS_CONTROLING           2 // Logged in successful and working on control connection
#define MMT_FTP_STATUS_DATA_OPENED          3 // A data connection is going to open to transfer data
#define MMT_FTP_STATUS_DATA_CLOSED          4 // A data connection closed
#define MMT_FTP_STATUS_CLOSED               5 // A control session closed

// TYPE OF CONNECTION 
#define MMT_FTP_CONTROL_CONNECTION          1 // Control connection on ftp server control port 21
#define MMT_FTP_DATA_CONNECTION             2 // Data connection on ftp server data port

//////// DATA TYPE /////
#define MMT_FTP_DATA_TYPE_FILE              1 // file transfering
#define MMT_FTP_DATA_TYPE_LIST              2 // Directory listing
#define MMT_FTP_DATA_TYPE_UNKNOWN           3 // Unknown, not yet classified

// DATA CONNECTION TYPE
#define MMT_FTP_DATA_PASSIVE_MODE           2 // Passive mode transfering
#define MMT_FTP_DATA_ACTIVE_MODE            1 // Active mode transfering

/////// PACKET TYPE //////
#define MMT_FTP_PACKET_DATA                 1 // FTP-DATA packet, contains only data
#define MMT_FTP_PACKET_COMMAND              2 // The packet on control connection, be sent from client to server (port 21)
#define MMT_FTP_PACKET_RESPONSE             3 // The packet on control connection, be sent from server (port 21) to client

#define MMT_FTP_PACKET_CLIENT               1 // Packet was sent from client to server
#define MMT_FTP_PACKET_SERVER               2 // Packet was sent from server to client
#define MMT_FTP_PACKET_UNKNOWN_DIRECTION    3 // Unknown direction


#define MMT_FTP_DATA_UPLOAD                 1 // The data connection is uploading data to server
#define MMT_FTP_DATA_DOWNLOAD               2 // The data connection is downloading data from server


/*
 * these are the commands we tracking and expecting to see to classify as FTP protocol
 */
enum {
    FTP_USER_CMD = 1 << 0,
    FTP_FEAT_CMD = 1 << 1,
    FTP_COMMANDS = ((1 << 2) - 1),
    FTP_220_CODE = 1 << 2,
    FTP_331_CODE = 1 << 3,
    FTP_211_CODE = 1 << 4,
    FTP_CODES = ((1 << 5) - 1 - FTP_COMMANDS)
};

////////////////////////////////////////// LIST OF FTP COMMAND //////////////////////////////////////////
/*
 * List of FTP commands - https://en.wikipedia.org/wiki/List_of_FTP_commands (6 October 2015 20h05)
 */
enum {
    MMT_FTP_UNKNOWN_CMD=0,
    MMT_FTP_ABOR_CMD, // Abort an active file transfer
    MMT_FTP_ACCT_CMD, // account information
    MMT_FTP_ALLO_CMD, // allocate sufficient disk space to receive a file
    MMT_FTP_APPE_CMD, // Append
    MMT_FTP_AUTH_CMD, // Authentication/ Security Mechanism
    MMT_FTP_CCC_CMD, // Clear command channel
    MMT_FTP_CDUP_CMD, // Change to parent directory
    MMT_FTP_CONF_CMD, // Confidentiality Protection Command
    MMT_FTP_CWD_CMD, // change working directory
    MMT_FTP_DELE_CMD, // Delete file
    MMT_FTP_ENC_CMD, // Privacy Protected Channel
    MMT_FTP_EPRT_CMD, // Specifies an extended address and port to which the server should connect,
    MMT_FTP_EPSV_CMD, // Enter extended passive mode
    MMT_FTP_FEAT_CMD, // Get the feature list implemented by the server
    MMT_FTP_HELP_CMD, // Returns usage documentation on a command if specified, else a general help documents is returned
    MMT_FTP_LANG_CMD, // Language Negotiation
    MMT_FTP_LIST_CMD, // Returns information of a file or directory if specified, else information of current working directory is returned. If the server supports the '-R' command, then a recursive directory listing will be returned
    MMT_FTP_LPRT_CMD, // Specifies a long address and port to which the server should connect.
    MMT_FTP_LPSV_CMD, // Enter long passive mode
    MMT_FTP_MDTM_CMD, // Return the last-modified time of a specified file
    MMT_FTP_MIC_CMD, // Integrity Protected Command
    MMT_FTP_MKD_CMD, // Make directory
    MMT_FTP_MLSD_CMD, // Lists the contents of a directory if a directory is named
    MMT_FTP_MLST_CMD, // Provides data about exactly the object named on its command line and no others
    MMT_FTP_MODE_CMD, // Sets the transfer mode(Stream, Block or compressed)
    MMT_FTP_NLST_CMD, // Return a list of file names in a specified directory 
    MMT_FTP_NOOP_CMD, // No operation (dummy packet, used mostly as keepalives)
    MMT_FTP_OPTS_CMD, // Select options for a feature 
    MMT_FTP_PASS_CMD, // Authentication password
    MMT_FTP_PASV_CMD, // Enter passive mode
    MMT_FTP_PBSZ_CMD, // RFC2228 Protection Buffer Size
    MMT_FTP_PORT_CMD, // Specifies an address and port to which the server should connect
    MMT_FTP_PROT_CMD, // RFC2228 Data channel protection level
    MMT_FTP_PWD_CMD, // Print working directory, Returns the current directory of the host
    MMT_FTP_QUIT_CMD, // Disconnect
    MMT_FTP_REIN_CMD, // Re-initialize the connection
    MMT_FTP_REST_CMD, // Restart transfer from the specified point
    MMT_FTP_RETR_CMD, // Retrive a copy of the file
    MMT_FTP_RMD_CMD, // Remove a directory
    MMT_FTP_RNFR_CMD, // Rename from
    MMT_FTP_RNTO_CMD, // Rename to
    MMT_FTP_SITE_CMD, // Sends site specific commands to remote server
    MMT_FTP_SIZE_CMD, // RFC3659 Return the size of a file
    MMT_FTP_SMNT_CMD, // Mount file structure
    MMT_FTP_STAT_CMD, // Returns the current status
    MMT_FTP_STOR_CMD, // Accept data and store data as a file at the server site
    MMT_FTP_STOU_CMD, // Store file uniquely
    MMT_FTP_STRU_CMD, // Set file transfer structure
    MMT_FTP_SYST_CMD, // Return system type
    MMT_FTP_TYPE_CMD, // Sets the transfer mode (ASCII/Binary)
    MMT_FTP_USER_CMD, // Authentication username
    MMT_FTP_XCUP_CMD, // RFC775 Change to the parent of the current working directory
    MMT_FTP_XMKD_CMD, // RFC775 Make directory
    MMT_FTP_XPWD_CMD, // RFC775 Print current working directory
    MMT_FTP_XRCP_CMD, // RFC743
    MMT_FTP_XRMD_CMD, // RFC775 Remove directory
    MMT_FTP_XRSQ_CMD, // RFC743
    MMT_FTP_XSEM_CMD, // RFC737 Send, mail if cannot
    MMT_FTP_XSEN_CMD, // RFC737 Send to terminal
};

///////////////////////////////// LIST OF FTP SERVER RETURN CODE ////////////////////////////////////
/*
 * List of FTP server response code - https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes (6 October 2015 20h05)
 */
enum{
    // Response possible from FTP response packet
    MMT_FTP_150_CODE = 150, // Open a data connection to transfer data
    MMT_FTP_211_CODE = 211, // Features
    MMT_FTP_213_CODE = 213, // Response file status: size, last_modified
    MMT_FTP_215_CODE = 215, // Response for SYST command
    MMT_FTP_220_CODE = 220, // Version of FTP server 
    MMT_FTP_226_CODE = 226, // Completed sending data and close data connection
    MMT_FTP_227_CODE = 227, // Enter active mode
    MMT_FTP_228_CODE = 228, // Enter long address passive mode
    MMT_FTP_229_CODE = 229, // Enter extended passive mode
    MMT_FTP_230_CODE = 230, // Directory changed susscessful
    MMT_FTP_250_CODE = 250, // Directory successful change
    MMT_FTP_257_CODE = 257, // Change directory
    MMT_FTP_331_CODE = 331, // Asking for the password
    MMT_FTP_CONTINUE_CODE = 999, // response for FEAT command
    MMT_FTP_UNKNOWN_CODE = 998 // All other response
}

/**
 * A Tuple 4: client_addr:client_port - server_addr:server_port
 */

typedef struct ftp_tuple6_struct{
    uint8_t conn_type; // MMT_FTP_CONTROL_CONNECTION or MMT_FTP_DATA_CONNECTION
    uint8_t direction;
    uint32_t client_addr;
    uint32_t client_port;
    uint32_t server_addr;
    uint32_t server_port;
} ftp_tuple6_t;

/**
 * FTP command structure: CMD PARAMETER
 */
typedef struct ftp_command_struct{
    int cmd;
    char *str_cmd;
    char *param;
}ftp_command_t;

/**
 * FTP response structure
 */
typedef struct ftp_response_struct{
    int code;
    char *value;
}ftp_response_t;

/**
 * FTP file - the file is going to be transfer
 */
typedef struct ftp_file_struct{
    char * name;
    char * last_modified;
    uint32_t size;
}ftp_file_t;

/**
 * FTP user account to access the data
 */
typedef struct ftp_user_struct{
    char * username;
    char * password;
}ftp_user_t;

/**
 * A FTP control session
 */
typedef struct ftp_control_session_struct{
    
    ftp_tuple6_t * contl_conn;

    ftp_command_t *last_command;

    ftp_response_t *last_response;

    ftp_user_t *user;

    char * session_syst;

    char *session_feats;

    char * current_dir;

    uint16_t status;
    
    ftp_data_session_t * current_data_session;

    ftp_control_session_struct *next;

}ftp_control_session_t;

/**
 * A FTP data session
 */
typedef struct ftp_data_session_struct{

    ftp_tuple6_t *data_conn;

    uint8_t data_conn_mode;// MMT_FTP_ACTIVE_MODE = 0, MMT_FTP_PASSIVE_MODE = 1

    char* data_transfer_type; // ASCII, IMAGE, EBCDIC, LOCAL

    uint8_t data_type; // MMT_FTP_DATA_TYPE_FILE, MMT_FTP_DATA_TYPE_LIST, MMT_FTP_DATA_TYPE_UNKNOWN

    uint8_t data_direction; // Upload or Download

    ftp_file_t *file;
}ftp_data_session_t;

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


ftp_tuple6_t *ftp_get_tuple6(ipacket_t * ipacket,unsigned int){
    ftp_tuple6_t *t6;
    t6 = (ftp_tuple6_t*)malloc(sizeof(ftp_tuple6_t));
    if(ipacket->internal_packet->tcp&&ipacket->internal_packet->iph){
        if(ipacket->internal_packet->tcp->source == htons(21)){
            t6->conn_type = MMT_FTP_CONTROL_CONNECTION;
            t6->direction = MMT_FTP_PACKET_SERVER;
            t6->s_addr = ipacket->internal_packet->iph->saddr;
            t6->s_port = ipacket->internal_packet->tcp->source;
            t6->c_addr = ipacket->internal_packet->tcp->daddr;
            t6->c_port = ipacket->internal_packet->tcp->dest;
            return t6;
        }else if(ipacket->internal_packet->tcp->dest == htons(21)){
            t6->connt_type=MMT_FTP_CONTROL_CONNECTION;
            t6->direction = MMT_FTP_PACKET_CLIENT;
            t6->s_addr = ipacket->internal_packet->iph->daddr;
            t6->s_port = ipacket->internal_packet->tcp->dest;
            t6->c_addr = ipacket->internal_packet->tcp->saddr;
            t6->c_port = ipacket->internal_packet->tcp->source;
            return t6;
        }else{
            t6->connt_type=MMT_FTP_DATA_CONNECTION;
            t6->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
            t6->s_addr = ipacket->internal_packet->iph->saddr;
            t6->s_port = ipacket->internal_packet->tcp->source;
            t6->c_addr = ipacket->internal_packet->tcp->daddr;
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
    file_user_t *user = (ftp_user_t*)malloc(sizeof(ftp_user_t));
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
    file->file_name = NULL;
    file->file_size = 0;
    file->file_last_modified = NULL;
    return file;
}

/**
 * New data connection
 * @return a new data connection 
 */
ftp_data_session_t * ftp_new_data_connection(){
    ftp_data_session_t * ftp_data;
    ftp_data = (ftp_data_session_t*)malloc(sizeof(ftp_data_session_t));
    ftp_data->data_conn = NULL;
    ftp_data->data_conn_mode = 0;
    ftp_data->data_transfer_type = NULL;
    ftp_data->data_type = 0;
    ftp_data->file = ftp_new_file();
    return ftp_data;
}

/**
 * Create new ftp control session
 * @param  tuple6 control connection tuple6
 * @return        a ftp control connection
 */
ftp_control_session_t * ftp_new_control_session(ftp_tuple6_t tuple6){
    ftp_control_session_t * ftp_control; 
    ftp_control = (ftp_control_session_t*)malloc(sizeof(ftp_control_session_t));
    ftp_control->contrl_conn = tuple6;
    ftp_control->last_command = NULL;
    ftp_control->last_response = NULL;
    ftp_control->user = NULL;
    ftp_control->session_feats = NULL;
    ftp_control->session_syst = NULL;
    ftp_control->current_dir = NULL;
    ftp_control->current_data_conn = ftp_new_data_connection();
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
        if(t1->client_addr != t2->client_addr) return 0;

        if(t1->server_addr != t2->server_addr) return 0;

        if(t1->client_port != t2->client_port) return 0;

        if(t1->server_port != t2->server_port) return 0;
        return 1;
    }else{
        if(t1->client_addr == t2->client_addr && t1->client_port == t2->client_port && t1->server_addr == t2->server_addr && t1->server_port== t2->server_port) return 2;
        if(t1->client_addr == t2->server_addr && t1->client_port == t2->server_port && t1->server_addr == t2->client_addr && t1->server_port== t2->client_port) return 3;
        // Extended passive mode - 229 and 227 code
        if(t1->client_addr == t2->client_addr && t2->client_port == NULL && t1->server_addr == t2->server_addr && t1->server_port== t2->server_port) return 4;
        if(t1->client_addr == t2->server_addr && t2->client_port == NULL && t1->server_addr == t2->client_addr && t1->server_port== t2->client_port) return 5;
        // Active mode - PORT and EPRT command
        if(t1->client_addr == t2->client_addr && t2->client_port == t2->client_port && t1->server_addr == t2->server_addr && t2->server_port = NULL) return 6;
        if(t1->client_addr == t2->server_addr && t1->server_addr == t2->client_addr && t1->server_port == t2->client_port && t2->server_port = NULL) return 7;
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
            fprintf(stderr, "FTP: Not correct control connection\n", );
            return MMT_CONTINUE;
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
int ftp_check_control_packet(ipacket_t *ipacket){
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
    if(!mmt_int_check_possible_ftp_command(payload,payload_len)){
        cmd->cmd = MMT_FTP_UNKNOWN_CMD;
        cmd->str_cmd = "UNKNOWN_CMD";
        cmd->param = payload;
        return cmd;
    }

    char * command;
    char * params;
    if(payload[3]==' '){
        command = (char*)malloc(4);
        memcpy(command,payload,3);
        command[3]='\0';
        params = (char*)malloc(payload_len-3);
        memcpy(params,payload+4,payload_len-3);
        params[payload_len-3]='\0';
    }else if(payload[4]==' '){
        command = (char*)malloc(5);
        memcpy(command,payload,4);
        command[4]='\0';
        params = (char*)malloc(payload_len-4);
        memcpy(params,payload+5,payload_len-4);
        params[payload_len-4]='\0';
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
        code = atoi(code);
        // Get response value
        str_value = (char*)malloc(payload_len-3);
        memcpy(str_value,payload+4,payload_len-4);
        str_value[payload_len-4]='\0';
    }else{
        if(mmt_int_check_possible_ftp_continuation_reply(payload,payload_len)){
            code = MMT_FTP_CONTINUE_CODE;
            str_value = payload;
        }else{
            code = MMT_FTP_UNKNOWN_CODE;
            str_value = payload;
        }
    }
       
    res->code = code;
    res->value = str_value;
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
    uint16_t port = atoi(nb1) * 256 + atoi(nb2);
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

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_FTP_H */