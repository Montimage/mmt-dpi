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
#define MMT_FTP_PACKET_TYPE_UNKNOWN         99 // ACK packet or packet not classified yet

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
    MMT_FTP_221_CODE = 221, // Close the control connection
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
};

/**
 * A Tuple 4: client_addr:client_port - server_addr:server_port
 */

typedef struct ftp_tuple6_struct{
    uint8_t conn_type; // MMT_FTP_CONTROL_CONNECTION or MMT_FTP_DATA_CONNECTION
    uint8_t direction;
    uint32_t c_addr;
    uint32_t c_port;
    uint32_t s_addr;
    uint32_t s_port;
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


/**
 * A FTP control session
 */
typedef struct ftp_control_session_struct{
    
    ftp_tuple6_t * contrl_conn;

    ftp_command_t *last_command;

    ftp_response_t *last_response;

    ftp_user_t *user;

    char * session_syst;

    char *session_feats;

    char * current_dir;

    uint16_t status;
    
    ftp_data_session_t * current_data_session;

    struct ftp_control_session_struct *next;

}ftp_control_session_t;

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_FTP_H */