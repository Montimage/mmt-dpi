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
#define MMT_FTP_PASSIVE_MODE                1
#define MMT_FTP_ACTIVE_MODE                 0
#define MMT_FTP_MAX_SESSION                 1000

// TYPE OF CONNECTION 
#define MMT_FTP_CONTROL_CONNECTION          0
#define MMT_FTP_DATA_CONNECTION             1

//////// FTP SESSION STATUS //////
#define MMT_FTP_STATUS_OPEN                 0
#define MMT_FTP_STATUS_CONTROLING           1
#define MMT_FTP_STATUS_TRANSFERING          2
#define MMT_FTP_STATUS_TRANSFER_COMPLETED   3
#define MMT_FTP_STATUS_FINISHED             4
#define MMT_FTP_STATUS_ERROR               -1

/////// PACKET TYPE //////
#define MMT_FTP_DATA_PACKET                 0
#define MMT_FTP_REQUEST_PACKET              1
#define MMT_FTP_RESPONSE_PACKET             2
#define MMT_FTP_UNKNOWN_PACKET             -1    
//static uint32_t ftp_connection_timeout = MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static uint32_t ftp_connection_timeout = MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;

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

/*
 * these are the commands we tracking and expecting to see
 */
enum {
    MMT_FTP_UNKNOWN_CMD=0,
    MMT_FTP_USER_CMD = 12,
    MMT_FTP_PASS_CMD = 1,
    MMT_FTP_SYST_CMD = 2,
    MMT_FTP_FEAT_CMD = 3,
    MMT_FTP_PWD_CMD  = 4,
    MMT_FTP_TYPE_CMD = 5,
    MMT_FTP_CWD_CMD  = 6,
    MMT_FTP_SIZE_CMD = 7,
    MMT_FTP_EPSV_CMD = 8,
    MMT_FTP_RETR_CMD = 9,
    MMT_FTP_MDTM_CMD = 10,
    MMT_FTP_QUIT_CMD = 11,
    MMT_FTP_220_CODE = 220,
    MMT_FTP_331_CODE = 331,
    MMT_FTP_203_CODE = 203,
    MMT_FTP_215_CODE = 215,
    MMT_FTP_211_CODE = 211,
    MMT_FTP_200_CODE = 200,
    MMT_FTP_250_CODE = 250,
    MMT_FTP_257_CODE = 257,
    MMT_FTP_229_CODE = 229,
    MMT_FTP_150_CODE = 150,
    MMT_FTP_226_CODE = 226,
    MMT_FTP_221_CODE = 221,
    MMT_FTP_230_CODE = 230,
    MMT_FTP_213_CODE = 213,
    MMT_FTP_CONTINUE_CODE = 999,
    MMT_FTP_UNKNOWN_CODE = 998
};


/**
 * A Tuple 4: client_addr:client_port - server_addr:server_port
 */

typedef struct ftp_tuple4_struct{
    int conn_type; // MMT_FTP_CONTROL_CONNECTION or MMT_FTP_DATA_CONNECTION
    uint32_t client_addr;
    uint32_t client_port;
    uint32_t server_addr;
    uint32_t server_port;
} ftp_tuple4_t;

/**
 * FTP command structure: CMD PARAMETER
 */
typedef struct ftp_command_struct{
    int cmd;
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
// typedef struct ftp_file_struct{
//     char * name;
//     char * dir;
//     char * last_modified;
//     uint32_t size;
//     void * data;
// }ftp_file_t;

// typedef struct ftp_user_struct{
//     char * username;
//     char * password;
// }ftp_user_t;

/**
 * A FTP session - for testing
 */
typedef struct ftp_session_data_struct{
    // Tuple 4 for control connection (server_port must be 21)
    
    // control connection
    uint32_t control_client_addr;
    uint32_t control_server_addr;
    uint16_t control_client_port;
    uint16_t control_server_port;

    // data connection
    uint32_t data_client_addr;
    uint32_t data_server_addr;
    uint16_t data_client_port;
    uint16_t data_server_port;

    // file information
    char *file_dir;
    char *file_name;
    char *file_last_modified;
    uint32_t file_size;

    // user information
    char *user_name;
    char *user_password;

    // General information
    char * data_type;
    // FTP version
    char * server_version;
    char * session_syst;
    uint8_t session_mode;// MMT_FTP_ACTIVE_MODE = 0, MMT_FTP_PASSIVE_MODE = 1
    char *session_feats;
    int session_status;// MMT_FTP_STATUS_OPEN - MMT_FTP_STATUS_CONTROLING - MMT_FTP_STATUS_TRANSFERING - MMT_FTP_STATUS_TRANSFER_COMPLETE - MMT_FTP_STATUS_FINISHED
}ftp_session_data_t;

// struct http_session_data_struct {
//     int type; /**< indicates if this is a REQUEST or RESPONSE */
//     char * http_version;
//     char * requested_uri;
//     char * http_code_reason;
//     int http_code;
//     int http_method;
//     field_value_t session_field_values[HTTP_HEADERS_NB];
// };

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_FTP_H */