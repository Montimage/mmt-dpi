/**
 * FTP_H
 */
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
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
#define MMT_FTP_STATUS_TRANSFER_COMPLETED    3
#define MMT_FTP_STATUS_FINISHED             4
#define MMT_FTP_STATUS_ERROR                -1

//static uint32_t ftp_connection_timeout = MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/*
 * these are the commands we tracking and expecting to see
 */
enum {
    FTP_USER_CMD = 12,
    FTP_PASS_CMD = 1,
    FTP_SYST_CMD = 2,
    FTP_FEAT_CMD = 3,
    FTP_PWD_CMD  = 4,
    FTP_TYPE_CMD = 5,
    FTP_CWD_CMD  = 6,
    FTP_SIZE_CMD = 7,
    FTP_EPSV_CMD = 8,
    FTP_RETR_CMD = 9,
    FTP_MDTM_CMD = 10,
    FTP_QUIT_CMD = 11,
    FTP_220_CODE = 220,
    FTP_331_CODE = 331,
    FTP_203_CODE = 203,
    FTP_215_CODE = 215,
    FTP_211_CODE = 211,
    FTP_200_CODE = 200,
    FTP_250_CODE = 250,
    FTP_257_CODE = 257,
    FTP_229_CODE = 229,
    FTP_150_CODE = 150,
    FTP_226_CODE = 226,
    FTP_221_CODE = 221,
    FTP_230_CODE = 230,
    FTP_213_CODE = 213
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


