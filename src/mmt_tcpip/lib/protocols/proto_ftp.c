#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_FTP_TIMEOUT                     10
#define MMT_FTP_PASSIVE_MODE                1
#define MMT_FTP_ACTIVE_MODE                 0
#define MMT_FTP_CONTROL_CONNECTION          0
#define MMT_FTP_DATA_CONNECTION             1

//////// FTP SESSION STATUS //////
#define MMT_FTP_STATUS_OPEN                 0
#define MMT_FTP_STATUS_CONTROLING           1
#define MMT_FTP_STATUS_TRANSFERING          2
#define MMT_FTP_STATUS_TRANSFER_COMPLETE    3
#define MMT_FTP_STATUS_FINISHED             4
#define MMT_FTP_STATUS_ERROR                -1

static uint32_t ftp_connection_timeout = MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_ftp_add_connection(ipacket_t * ipacket) {
    log_info("mmt_int_ftp_add_connection : %lu",ipacket->packet_id);
    mmt_internal_add_connection(ipacket, PROTO_FTP, MMT_REAL_PROTOCOL);
}

// GET FROM C-easy library

char * str_subend(char *str, char* begin){
    if(str != NULL && begin !=NULL){
        char *fromBegin;
        fromBegin = (char*)malloc(sizeof(str));

        fromBegin = strstr(str,begin);
        fromBegin = fromBegin + strlen(begin);

        if(fromBegin == NULL){
            return NULL;
        }else{
            int len;
            len = strlen(fromBegin);
            char *ret;
            ret = (char * )malloc((len+1)*sizeof(char));
            strncpy(ret,fromBegin,len);
            ret[len]='\0';
            return ret;
        }
    }
    return NULL;
}

char ** str_add_new_string(char **array,char *str){
  if(str == NULL) return 0;
  int i=0;
  while(array[i] != NULL){
    i++;
  }

  array[i] = (char*)malloc(strlen(str)+1);
  strcpy(array[i],str);
  array[i][strlen(array[i])]='\0';
  return array;
}

// END OF C-easy library

/**
 * A Tuple 4: client_address:client_port - server_address:server_port
 */

typedef struct ftp_tuple4_struct{
    int conn_type; // MMT_FTP_CONTROL_CONNECTION or MMT_FTP_DATA_CONNECTION
    uint32_t client_addr;
    uint8_t client_port;
    uint32_t server_port;
    uint8_t server_port;
} ftp_tuple4_t;


/**
 * Get FTP tuple4 from packet
 * @param  ipacket packet to get
 * @return         a tuple 4 of packet
 */
ftp_tuple4_t * ftp_get_tupl4(ipacket_t * ipacket){

    ftp_tuple4_t *t;
    t = (ftp_tuple4_t*)malloc(sizeof(ftp_tuple4_t));
    if(ipacket->internal_packet->tcp->source == htons(21)){
        t.conn_type = 0;
        t.server_port = ipacket->internal_packet->tcp->source;
        t.server_address = ipacket->internal_packet->iph->saddr;
        t.client_port = ipacket->internal_packet->tcp->dest;
        t.client_address = ipacket->internal_packet->iph->daddr;
        return t; 
    }else if(ipacket->internal_packet->tcp->dest == htons(21)){
        t.conn_type = 0;
        t.server_port = ipacket->internal_packet->tcp->dest;
        t.server_address = ipacket->internal_packet->iph->daddr;
        t.client_port = ipacket->internal_packet->tcp->source;
        t.client_address = ipacket->internal_packet->iph->saddr; 
        return t;
    }else{
        t.conn_type = 1;
        t.server_port = ipacket->internal_packet->tcp->dest;
        t.server_address = ipacket->internal_packet->iph->daddr;
        t.client_port = ipacket->internal_packet->tcp->source;
        t.client_address = ipacket->internal_packet->iph->saddr; 
        return t;
    }

    return NULL;
};

/**
 * Compare 2 ftp tuple 4
 * @param  t1 the first tuple
 * @param  t2 The second tuple
 * @return    1 if two tuples are equal
 *            0 otherwise
 */
int ftp_compare_tuple4(ftp_tuple4_t *t1, ftp_tuple4_t t2){
    
    if(t1.conn_type != t2.conn_type) return 0;

    if(t1.conn_type == MMT_FTP_CONTROL_CONNECTION){
        if(t1->client_addr != t2->client_addr) return 0;

        if(t1->server_address != t2->server_address) return 0;

        if(t1->client_port != t2->client_port) return 0;

        if(t1->server_port != t2->server_port) return 0;
    }else{
        if(t1->client_addr == t2->client_addr && t1->client_port == t2->client_port && t1->server_address == t2->server_address && t1->server_port== t2->server_port) return 1;
        if(t1->client_addr == t2->server_addr && t1->client_port == t2->server_port && t1->server_address == t2->client_address && t1->server_port== t2->client_port) return 1;
        return 0;
    }
    
    return 0;
}

ftp_session_t list_ftp_session[10];

void ftp_add_new_session(ftp_session_t * fs){
    int i = 0;
    while(list_ftp_session[i] != NULL){
        i++;
    }
    list_ftp_session[i] = *fs;
};

ftp_session_t * ftp_get_session_by_tuple4(ftp_tuple4_t * t){
    int i = 0;
    while(list_ftp_session[i] != NULL){
        if(ftp_compare_tuple4(t,list_ftp_session[i]->ctrl_conn)) return list_ftp_session[i];
        if(ftp_compare_tuple4(t,list_ftp_session[i]->data_conn)) return list_ftp_session[i];
    }
    return NULL;
}

/**
 * FTP file - the file is going to be transfer
 */
typedef struct ftp_file_struct{
    char * name;
    char * dir;
    char * last_modified;
    uint32_t size;
    char * data;
}ftp_file_t;

typedef struct ftp_user_struct{
    char * username;
    char * password;
}ftp_user_t;

/**
 * A FTP session - for testing
 */
typedef struct ftp_session_struct{
    // Tuple 4 for control connection (server_port must be 21)
    ftp_tuple4_t * ctrl_conn;

    // Tuple 4 for data connection
    ftp_tuple4_t * data_conn;

    // File is going to be transfer
    ftp_file_t * file;

    char * data_type;

    // FTP version
    char * version;

    char * syst;

    uint8_t mode;// MMT_FTP_ACTIVE_MODE = 0, MMT_FTP_PASSIVE_MODE = 1

    ftp_user_t * user;

    char feats[10][6];

    int status;// MMT_FTP_STATUS_OPEN - MMT_FTP_STATUS_CONTROLING - MMT_FTP_STATUS_TRANSFERING - MMT_FTP_STATUS_TRANSFER_COMPLETE - MMT_FTP_STATUS_FINISHED

    char * EEPM_299;// Response from server: 299 entering extended passive mode (|||52275|)
}ftp_session_t;

/**
 * checks for possible FTP command: 
 * 
 * 
 * Service commands:  STOU RMD MKD PWD SYST RETR STOR APPE ALLO REST RNFR RNTO ABOR DELE LIST NLST SITE STAT HELP NOOP 
 * 
 * Acess control commands: USER PASS ACCT CWD CDUP SMNT REIN QUIT 
 * 
 *
 * Transfer parameter commands: PORT PASV TYPE(A E I L) STRU MODE
 *
 * RFC2389-> commands: FEAT
 * RFC2428-> commands: EPSV
 * not all valid commands are tested, it just need to be 3 or 4 characters followed by a space if the
 * packet is longer
 *
 * this functions is not used to accept, just to not reject
 */
static uint8_t mmt_int_check_possible_ftp_command(const struct mmt_tcpip_internal_packet_struct *packet) {
    log_info("mmt_int_check_possible_ftp_command ");
    if (packet->payload_packet_len < 3)
        return 0;

    if ((packet->payload[0] < 'a' || packet->payload[0] > 'z') &&
            (packet->payload[0] < 'A' || packet->payload[0] > 'Z'))
        return 0;
    if ((packet->payload[1] < 'a' || packet->payload[1] > 'z') &&
            (packet->payload[1] < 'A' || packet->payload[1] > 'Z'))
        return 0;
    if ((packet->payload[2] < 'a' || packet->payload[2] > 'z') &&
            (packet->payload[2] < 'A' || packet->payload[2] > 'Z'))
        return 0;

    if (packet->payload_packet_len > 3) {
        if ((packet->payload[3] < 'a' || packet->payload[3] > 'z') &&
                (packet->payload[3] < 'A' || packet->payload[3] > 'Z') && packet->payload[3] != ' ')
            return 0;

        if (packet->payload_packet_len > 4) {
            if (packet->payload[3] != ' ' && packet->payload[4] != ' ')
                return 0;
        }
    }

    return 1;
}

/**
 * ftp replies are are 3-digit number followed by space or hyphen
 * At least 5 ASCII characters
 * The forth character must be space or -
 * The 3 first character must be number
 */
static uint8_t mmt_int_check_possible_ftp_reply(const struct mmt_tcpip_internal_packet_struct *packet) {
    log_info("mmt_int_check_possible_ftp_reply : ");
    if (packet->payload_packet_len < 5)
        return 0;

    if (packet->payload[3] != ' ' && packet->payload[3] != '-')
        return 0;

    if (packet->payload[0] < '0' || packet->payload[0] > '9')
        return 0;
    if (packet->payload[1] < '0' || packet->payload[1] > '9')
        return 0;
    if (packet->payload[2] < '0' || packet->payload[2] > '9')
        return 0;

    return 1;
}

/**
 * check for continuation replies
 * there is no real indication whether it is a continuation message, we just
 * require that there are at least 5 ascii characters
 */
static uint8_t mmt_int_check_possible_ftp_continuation_reply(const struct mmt_tcpip_internal_packet_struct *packet) {
    log_info("mmt_int_check_possible_ftp_continuation_reply");
    uint16_t i;

    if (packet->payload_packet_len < 5)
        return 0;

    for (i = 0; i < 5; i++) {
        if (packet->payload[i] < ' ' || packet->payload[i] > 127)
            return 0;
    }
    log_info("mmt_int_check_possible_ftp_continuation_reply: %s",packet->payload);
    return 1;
}

/*
 * these are the commands we tracking and expecting to see
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

/**
 * Get FTP session by server port - for data connection
 * @param  port Server port
 * @return      a FTP session who has the EEPM_229 contains port
 */
ftp_session_t * ftp_get_session_by_server_port(uint8_t port){
    int i=0;
    char str_port[10];
    sprintf(str_port,"%d",port);
    while(list_ftp_session[i] != NULL){
        if(list_ftp_session[i]->EEPM_229 != NULL){
            if(strstr(list_ftp_session[i]->EEPM_229,port) != NULL){
                return list_ftp_session[i];
            }
        }
    }
    return NULL;
}

/*
  return 0 if nothing has been detected
  return 1 if a pop packet
  return 2 if 
 */

static uint8_t search_ftp(ipacket_t * ipacket) {
    ftp_tuple4_t *tuple4;
    tuple4 = ftp_get_tupl4(ipacket);

    ftp_session_t ftp_session = ftp_get_session_by_tuple4(tuple4);
    if(ftp_session == NULL){
        if(tuple4->conn_type == MMT_FTP_CONTROL_CONNECTION){
            // First packet of control connection
            ftp_session_t * ftp_new_session;
            ftp_new_session = (ftp_session_t*)malloc(sizeof(ftp_session_t));
            ftp_new_session->ctrl_conn = tupe4;
            ftp_add_new_session(ftp_new_session);
            ftp_session = ftp_new_session;
            ftp_session->status = MMT_FTP_STATUS_OPEN;
        }else{
            // First packet of data connection
            ftp_session = ftp_get_session_by_server_port(tuple4->server_port);
            if(ftp_session == NULL){
                ftp_session = ftp_get_session_by_server_port(tuple4->client_port);
                if(ftp_session != NULL){
                    ftp_tuple4_t * tuple4_2;
                    // revert tuple4
                    tuple4_2 = (ftp_tuple4_t*)malloc(sizeof(ftp_tuple4_t));
                    tuple4_2->client_addr = tuple4->server_address;
                    tuple4_2->client_port = tuple4->server_port;
                    tuple4_2->server_address = tuple4->client_addr;
                    tuple4_2->server_port = tuple4->client_port;
                    ftp_session->data_conn = tuple4_2;
                }else{
                    log_err("Could not find session of packet: %lu",ipacket->packet_id);
                }
            }else{
                ftp_session->data_conn = tuple4;
            } 
        }
    }

    // Check if this is a data packet in data connection
    if(tuple4->conn_type == MMT_FTP_DATA_CONNECTION){

    }

    log_info("FTP: search_ftp : %lu",ipacket->packet_id);


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
        if(ftp_session == NULL){
            log_info("FTP: Cannot find FTP session");
        }
        // Client request
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("USER ") &&
                (memcmp(packet->payload, "USER ", MMT_STATICSTRING_LEN("USER ")) == 0 ||
                memcmp(packet->payload, "user ", MMT_STATICSTRING_LEN("user ")) == 0)) {

            log_info( "FTP: found USER command\n");
            if(ftp_session != NULL){
                if(ftp_session->user==NULL){
                        ftp_user_t *ftp_user;
                        ftp_user = (ftp_user_t*)malloc(sizeof(ftp_user_t));
                        ftp_session->user = ftp_user;
                    }
                ftp_user->username = str_subend(packet->payload,"USER ");
            }
            flow->l4.tcp.ftp_codes_seen |= FTP_USER_CMD;
            current_ftp_code = FTP_USER_CMD;
        }else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("PASS ") &&
                (memcmp(packet->payload, "PASS ", MMT_STATICSTRING_LEN("PASS ")) == 0 ||
                memcmp(packet->payload, "pass ", MMT_STATICSTRING_LEN("pass ")) == 0)) {
                if(ftp_session != NULL){
                    if(ftp_session->user==NULL){
                        ftp_user_t *ftp_user;
                        ftp_user = (ftp_user_t*)malloc(sizeof(ftp_user_t));
                        ftp_session->user = ftp_user;
                    }
                    ftp_session->user->username = str_subend(packet->payload,"PASS ");
                }
            log_info( "FTP: found PASS command\n");
            // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
            // current_ftp_code = FTP_PASS_CMD;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("SYST ") &&
                (memcmp(packet->payload, "SYST ", MMT_STATICSTRING_LEN("SYST ")) == 0 ||
                memcmp(packet->payload, "syst ", MMT_STATICSTRING_LEN("syst ")) == 0)) {
                log_info( "FTP: found SYST command\n");
                // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
                // current_ftp_code = FTP_PASS_CMD;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("PWD ") &&
                (memcmp(packet->payload, "PWD ", MMT_STATICSTRING_LEN("PWD ")) == 0 ||
                memcmp(packet->payload, "pwd ", MMT_STATICSTRING_LEN("pwd ")) == 0)) {
                if(ftp_session !=NULL ){
                    if(ftp_session->file == NULL){
                        ftp_file_t *ftp_file;
                        ftp_file = (ftp_file_t*)malloc(sizeof(ftp_file_t));
                        ftp_session->file = ftp_file;
                    }
                    // ftp_session->syst = str_subend(packet->payload,"SYST ");
                }
                log_info( "FTP: found PWD command\n");
            // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
            // current_ftp_code = FTP_PASS_CMD;
        }
         else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("TYPE ") &&
                (memcmp(packet->payload, "TYPE ", MMT_STATICSTRING_LEN("TYPE ")) == 0 ||
                memcmp(packet->payload, "type ", MMT_STATICSTRING_LEN("type ")) == 0)) {

            log_info( "FTP: found TYPE command\n");
            if(ftp_session !=NULL ){
                ftp_session->data_type= str_subend(packet->payload,"TYPE ");
            }
            // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
            // current_ftp_code = FTP_PASS_CMD;
        }else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("CWD ") &&
                (memcmp(packet->payload, "CWD ", MMT_STATICSTRING_LEN("CWD ")) == 0 ||
                memcmp(packet->payload, "cwd ", MMT_STATICSTRING_LEN("cwd ")) == 0)) {

            log_info( "FTP: found CWD command\n");
            // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
            // current_ftp_code = FTP_PASS_CMD;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("SIZE ") &&
                (memcmp(packet->payload, "SIZE ", MMT_STATICSTRING_LEN("SIZE ")) == 0 ||
                memcmp(packet->payload, "size ", MMT_STATICSTRING_LEN("size ")) == 0)) {

            log_info( "FTP: found SIZE command\n");
            // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
            // current_ftp_code = FTP_PASS_CMD;
        }   else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("EPSV ") &&
                (memcmp(packet->payload, "EPSV ", MMT_STATICSTRING_LEN("EPSV ")) == 0 ||
                memcmp(packet->payload, "epsv ", MMT_STATICSTRING_LEN("epsv ")) == 0)) {
            if(ftp_session !=NULL ){
                ftp_session->mode = MMT_FTP_PASSIVE_MODE;
            }
            log_info( "FTP: found EPSV command\n");
            // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
            // current_ftp_code = FTP_PASS_CMD;
        }  else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("RETR ") &&
                (memcmp(packet->payload, "RETR ", MMT_STATICSTRING_LEN("RETR ")) == 0 ||
                memcmp(packet->payload, "retr ", MMT_STATICSTRING_LEN("retr ")) == 0)) {
                if(ftp_session->file == NULL){
                        ftp_file_t *ftp_file;
                        ftp_file = (ftp_file_t*)malloc(sizeof(ftp_file_t));
                        ftp_session->file = ftp_file;
                }

                ftp_session->file->name = str_subend(packet->payload,"RETR ");
            log_info( "FTP: found RETR command\n");
            // flow->l4.tcp.ftp_codes_seen |= FTP_PASS_CMD;
            // current_ftp_code = FTP_PASS_CMD;
        } else if (packet->payload_packet_len >= MMT_STATICSTRING_LEN("FEAT") &&
                (memcmp(packet->payload, "FEAT", MMT_STATICSTRING_LEN("FEAT")) == 0 ||
                memcmp(packet->payload, "feat", MMT_STATICSTRING_LEN("feat")) == 0)) {

            log_info( "FTP: found FEAT command\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_FEAT_CMD;
            current_ftp_code = FTP_FEAT_CMD;
        } else if (!mmt_int_check_possible_ftp_command(packet)) {
            return 0;
        }
    } else {
        // Server response
        if (packet->payload_packet_len > MMT_STATICSTRING_LEN("220 ") &&
                (memcmp(packet->payload, "220 ", MMT_STATICSTRING_LEN("220 ")) == 0 ||
                memcmp(packet->payload, "220-", MMT_STATICSTRING_LEN("220-")) == 0)) {

            // log_info( "FTP: found 220 reply code\n");
            log_info("FTP: found 220 reply code: %lu - version",ipacket->packet_id);
            log_info("FTP: Create new ftp session");
            
            if(ftp_session){
                ftp_new_session->version = str_subend(packet->payload,"220 ")||str_subend(packet->payload,"220-");
                ftp_session->status = MMT_FTP_STATUS_CONTROLING;
            }
            
            flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("230 ") &&
                (memcmp(packet->payload, "230 ", MMT_STATICSTRING_LEN("230 ")) == 0 ||
                memcmp(packet->payload, "230-", MMT_STATICSTRING_LEN("230-")) == 0)) {

            // log_info( "FTP: found 230 reply code\n");
            log_info("FTP: found 230 reply code: %lu",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("215 ") &&
                (memcmp(packet->payload, "215 ", MMT_STATICSTRING_LEN("215 ")) == 0 ||
                memcmp(packet->payload, "215-", MMT_STATICSTRING_LEN("215-")) == 0)) {
            if(ftp_session != NULL){
                ftp_session->syst = str_subend(packet->payload,"215 ")||str_subend(packet->payload,"215-");
            }
            // log_info( "FTP: found 215 reply code\n");
            log_info("FTP: found 215 reply code: %lu - system type",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("229 ") &&
                (memcmp(packet->payload, "229 ", MMT_STATICSTRING_LEN("229 ")) == 0 ||
                memcmp(packet->payload, "229-", MMT_STATICSTRING_LEN("229-")) == 0)) {
            if(ftp_session != NULL){
                ftp_session->EEPM_299 = str_subend(packet->payload,"229 ");
            }
            // log_info( "FTP: found 229 reply code\n");
            log_info("FTP: found 229 reply code: %lu - Passive mode information",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        }  else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("213 ") &&
                (memcmp(packet->payload, "213 ", MMT_STATICSTRING_LEN("213 ")) == 0 ||
                memcmp(packet->payload, "213-", MMT_STATICSTRING_LEN("213-")) == 0)) {
            if(ftp_session->file == NULL){
                        ftp_file_t *ftp_file;
                        ftp_file = (ftp_file_t*)malloc(sizeof(ftp_file_t));
                        ftp_session->file = ftp_file;
                }

                ftp_session->file->last_modified = str_subend(packet->payload,"213 ")||str_subend(packet->payload,"213-");
            // log_info( "FTP: found 213 reply code\n");
            log_info("FTP: found 213 reply code: %lu",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("257 ") &&
                (memcmp(packet->payload, "257 ", MMT_STATICSTRING_LEN("257 ")) == 0 ||
                memcmp(packet->payload, "257-", MMT_STATICSTRING_LEN("257-")) == 0)) {
            if(ftp_session->file == NULL){
                        ftp_file_t *ftp_file;
                        ftp_file = (ftp_file_t*)malloc(sizeof(ftp_file_t));
                        ftp_session->file = ftp_file;
                }
                char *dir;
                dir = str_subend(packet->payload,"213 ")||str_subend(packet->payload,"213-");
                if(strlen(dir) > strlen(ftp_session->file->dir)){
                    ftp_session->file->dir = dir;
                }

            // log_info( "FTP: found 257 reply code\n");
            log_info("FTP: found 257 reply code: %lu",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("250 ") &&
                (memcmp(packet->payload, "250 ", MMT_STATICSTRING_LEN("250 ")) == 0 ||
                memcmp(packet->payload, "250-", MMT_STATICSTRING_LEN("250-")) == 0)) {

            // log_info( "FTP: found 250 reply code\n");
            log_info("FTP: found 250 reply code: %lu",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("200 ") &&
                (memcmp(packet->payload, "200 ", MMT_STATICSTRING_LEN("200 ")) == 0 ||
                memcmp(packet->payload, "200-", MMT_STATICSTRING_LEN("200-")) == 0)) {

            // log_info( "FTP: found 200 reply code\n");
            log_info("FTP: found 200 reply code: %lu",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("150 ") &&
                (memcmp(packet->payload, "150 ", MMT_STATICSTRING_LEN("150 ")) == 0 ||
                memcmp(packet->payload, "150-", MMT_STATICSTRING_LEN("150-")) == 0)) {

            // log_info( "FTP: found 150 reply code\n");
            log_info("FTP: found 150 reply code: %lu",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            // current_ftp_code = FTP_220_CODE;
        }else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("331 ") &&
                (memcmp(packet->payload, "331 ", MMT_STATICSTRING_LEN("331 ")) == 0 ||
                memcmp(packet->payload, "331-", MMT_STATICSTRING_LEN("331-")) == 0)) {

            // log_info( "FTP: found 331 reply code\n");
            log_info("FTP: found 331 reply code: %lu",ipacket->packet_id);
            flow->l4.tcp.ftp_codes_seen |= FTP_331_CODE;
            current_ftp_code = FTP_331_CODE;
        }else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("226 ") &&
                (memcmp(packet->payload, "226 ", MMT_STATICSTRING_LEN("226 ")) == 0 ||
                memcmp(packet->payload, "226-", MMT_STATICSTRING_LEN("226-")) == 0)) {

            // log_info( "FTP: found 226 reply code\n");
            log_info("FTP: found 226 reply code: %lu - transfer completed",ipacket->packet_id);
            // flow->l4.tcp.ftp_codes_seen |= FTP_331_CODE;
            // current_ftp_code = FTP_331_CODE;
        } else if (packet->payload_packet_len > MMT_STATICSTRING_LEN("211 ") &&
                (memcmp(packet->payload, "211 ", MMT_STATICSTRING_LEN("211 ")) == 0 ||
                memcmp(packet->payload, "211-", MMT_STATICSTRING_LEN("211-")) == 0)) {

            // log_info( "FTP: found 211reply code\n");
            log_info("FTP: found 211 reply code %lu",ipacket->packet_id);
            flow->l4.tcp.ftp_codes_seen |= FTP_211_CODE;
            current_ftp_code = FTP_211_CODE;
        } else if (!mmt_int_check_possible_ftp_reply(packet)) {
            if ((flow->l4.tcp.ftp_codes_seen & FTP_CODES) == 0 ||
                    (!mmt_int_check_possible_ftp_continuation_reply(packet))) {
                return 0;
            }else{
                if(ftp_session !=NULL ){
                    str_add_new_string(ftp_session->feats,packet->payload));
                }
            }
        }
    }
    
    // if ((flow->l4.tcp.ftp_codes_seen & FTP_COMMANDS) != 0 && (flow->l4.tcp.ftp_codes_seen & FTP_CODES) != 0) {
    // I think the condition should be 'or' instead of 'and'
    if ((flow->l4.tcp.ftp_codes_seen & FTP_COMMANDS) != 0 || (flow->l4.tcp.ftp_codes_seen & FTP_CODES) != 0) {
        log_info("FTP detected: %lu",ipacket->packet_id);
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

        /* wait much longer if this was a 220 code, initial messages might be long */
        if (current_ftp_code == FTP_220_CODE) {
            if (ipacket->session->data_packet_count > 40)
                return 0;
        } else {
            if (ipacket->session->data_packet_count > 20)
                return 0;
        }
    } else {
        /* wait much longer if this was a 220 code, initial messages might be long */
        if (current_ftp_code == FTP_220_CODE) {
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
    log_info("FTP: search_passive_ftp_mode : %lu",ipacket->packet_id);

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    uint16_t plen;
    uint8_t i;
    uint32_t ftp_ip;


    // TODO check if normal passive mode also needs adaption for ipv6
    if (packet->payload_packet_len > 3 && mmt_mem_cmp(packet->payload, "227 ", 4) == 0) {
        log_info( "FTP passive mode initial string\n");

        plen = 4; //=4 for "227 "
        while (1) {
            if (plen >= packet->payload_packet_len) {
                log_info(
                        "plen >= packet->payload_packet_len, return\n");
                return;
            }
            if (packet->payload[plen] == '(') {
                log_info( "found (. break.\n");
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
                log_info( "FTP passive mode %u value parse failed\n",
                        i);
                return;
            }
            if (packet->payload[plen] != ',') {

                log_info(
                        "FTP passive mode %u value parse failed, char ',' is missing\n", i);
                return;
            }
            plen++;
            log_info(
                    "FTP passive mode %u value parsed, ip is now: %u\n", i, ftp_ip);

        }
        if (dst != NULL) {
            dst->ftp_ip.ipv4 = htonl(ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            log_info( "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
        }
        if (src != NULL) {
            src->ftp_ip.ipv4 = packet->iph->daddr;
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            log_info( "saved ftp_ip, ftp_timer, ftp_timer_set to src");
        }
        return;
    }

    if (packet->payload_packet_len > 34 && mmt_mem_cmp(packet->payload, "229 Entering Extended Passive Mode", 34) == 0) {
        log_info( "FTP PASSIVE MODE FOUND: payload %s: \n",packet->payload);
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            log_info( "saved ftp_ip, ftp_timer, ftp_timer_set to dst");
        }
        if (src != NULL) {
            mmt_get_destination_ip_from_packet(packet, &src->ftp_ip);
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
            log_info( "saved ftp_ip, ftp_timer, ftp_timer_set to src");
        }
        return;
    }
}

static void search_active_ftp_mode(ipacket_t * ipacket) {
    log_info("FTP: search_active_ftp_mode : %lu",ipacket->packet_id);

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
            log_info( "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
                    packet->payload);
        }
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
            log_info( "FTP ACTIVE MODE FOUND, command is %.*s\n", 4,
                    packet->payload);
        }
    }
    return;
}

void mmt_classify_me_ftp(ipacket_t * ipacket, unsigned index) {
    log_info("FTP: mmt_classify_me_ftp : %lu",ipacket->packet_id);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    if (src != NULL && mmt_compare_packet_destination_ip_to_given_ip(packet, &src->ftp_ip)
            && packet->tcp->syn != 0 && packet->tcp->ack == 0
            && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask,
            PROTO_FTP) != 0 && src->ftp_timer_set != 0) {
        log_info( "possible ftp data, src!= 0.\n");

        if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - src->ftp_timer)) >= ftp_connection_timeout) {
            src->ftp_timer_set = 0;
        } else if (ntohs(packet->tcp->dest) > 1024
                && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
            log_info( "detected FTP data stream.\n");
            mmt_int_ftp_add_connection(ipacket);
            return;
        }
    }

    if (dst != NULL && mmt_compare_packet_source_ip_to_given_ip(packet, &dst->ftp_ip)
            && packet->tcp->syn != 0 && packet->tcp->ack == 0
            && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
            && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
            PROTO_FTP) != 0 && dst->ftp_timer_set != 0) {
        log_info( "possible ftp data; dst!= 0.\n");

        if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                (packet->tick_timestamp - dst->ftp_timer)) >= ftp_connection_timeout) {
            dst->ftp_timer_set = 0;

        } else if (ntohs(packet->tcp->dest) > 1024
                && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
            log_info( "detected FTP data stream.\n");
            mmt_int_ftp_add_connection(ipacket);
            return;
        }
    }
    // ftp data asymmetrically


    /* skip packets without payload */
    if (packet->payload_packet_len == 0) {
        log_info(
                "FTP test skip because of data connection or zero byte packet_payload.\n");
        return;
    }
    /* skip excluded connections */

    // we test for FTP connection and search for passive mode
    if (packet->detected_protocol_stack[0] == PROTO_FTP) {
        log_info(
                "detected ftp command mode. going to test data mode.\n");
        search_passive_ftp_mode(ipacket);

        search_active_ftp_mode(ipacket);
        return;
    }


    if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 0) {
    // Why use search_ftp(ipacket) != 0? Should be !=1
    // if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 1) {
        log_info( "unknown. need next packet.\n");

        return;
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP);
    log_info( "exclude ftp.\n");

}

int mmt_check_ftp(ipacket_t * ipacket, unsigned index) {
    log_info("FTP: mmt_check_ftp : %lu",ipacket->packet_id);
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
            log_info( "possible ftp data, src!= 0.\n");

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->ftp_timer)) >= ftp_connection_timeout) {
                src->ftp_timer_set = 0;
            } else if (ntohs(packet->tcp->dest) > 1024
                    && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                log_info( "detected FTP data stream.\n");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }

        if (dst != NULL && mmt_compare_packet_source_ip_to_given_ip(packet, &dst->ftp_ip)
                && packet->tcp->syn != 0 && packet->tcp->ack == 0
                && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                && MMT_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask,
                PROTO_FTP) != 0 && dst->ftp_timer_set != 0) {
            log_info( "possible ftp data; dst!= 0.\n");

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->ftp_timer)) >= ftp_connection_timeout) {
                dst->ftp_timer_set = 0;

            } else if (ntohs(packet->tcp->dest) > 1024
                    && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                log_info( "detected FTP data stream.\n");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }
        // ftp data asymmetrically


        /* skip packets without payload */
        if (packet->payload_packet_len == 0) {
            log_info(
                    "FTP test skip because of data connection or zero byte packet_payload.\n");
            return 1;
        }
        /* skip excluded connections */

        // we test for FTP connection and search for passive mode
        if (packet->detected_protocol_stack[0] == PROTO_FTP) {
            log_info(
                    "detected ftp command mode. going to test data mode.\n");
            search_passive_ftp_mode(ipacket);

            search_active_ftp_mode(ipacket);

            search_ftp(ipacket);
            return 1;
        }


        if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 0) {
        // if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 1) {
            log_info( "unknown. need next packet.\n");

            return 1;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP);
        log_info( "exclude ftp.\n");

    }
    return 1;
}

void mmt_init_classify_me_ftp() {
    log_info("FTP: mmt_init_classify_me_ftp ");
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_FTP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_FTP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ftp_struct() {
    log_info("FTP: init_proto_ftp_struct ");
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FTP, PROTO_FTP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_ftp();

        return register_protocol(protocol_struct, PROTO_FTP);
    } else {
        return 0;
    }
}


