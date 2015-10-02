/**
 * FTP_H
 */
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_FTP_TIMEOUT                     10
#define MMT_FTP_PASSIVE_MODE                1
#define MMT_FTP_ACTIVE_MODE                 0

// TYPE OF CONNECTION 
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
 * FTP file - the file is going to be transfer
 */
typedef struct ftp_file_struct{
    char * name;
    char * dir;
    char * last_modified;
    uint32_t size;
    void * data;
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

    char *feats;

    int status;// MMT_FTP_STATUS_OPEN - MMT_FTP_STATUS_CONTROLING - MMT_FTP_STATUS_TRANSFERING - MMT_FTP_STATUS_TRANSFER_COMPLETE - MMT_FTP_STATUS_FINISHED

    char * EEPM_229;// Response from server: 299 entering extended passive mode (|||52275|)
}ftp_session_t;


