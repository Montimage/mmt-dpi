# Data structures

## FTP tuple6

`ftp_tuple6_t` present a set of 6 parameters represents a FTP connection. If the connection is control connection then the `s_port` is 21.

```c
ftp_tuple6_struct{
    uint8_t conn_type; // Type of connection
    uint8_t direction; // 1 - client->server, 2 - server->client, 3 - unknown
    uint32_t s_addr; // Server address
    uint16_t s_port; // Server port number
    uint32_t c_addr; // Client address
    uint16_t c_port; // Client port
} ftp_tuple6_t;
```

## FTP control session

`ftp_control_session_struct` represents a FTP control connection session. At one time, a FTP control connection only handles a FTP data connection

```c
ftp_control_session_struct{
    ftp_tuple6_t * contrl_conn;
    ftp_command_t * last_command;
    ftp_request_t * last_response;
    ftp_user_t *user;
    char* session_syst;
    char* session_feats;
    char * current_dir;
    uint16_t status;
   ftp_data_session_t * current_data_conn;
}ftp_control_session_t;
```

## FTP data session

`ftp_data_session_struct` presents a FTP data connection session.

```sh
ftp_data_session_struct{
    ftp_tuple6_t * data_conn;
    uint8_t data_conn_mode;
    char * data_transfer_type;
    uint8_t data_type;
    uint8_t data_direction;
    ftp_file_t * file;
}ftp_data_session_t;
```

## FTP command

`ftp_command_struct` presents a command which is sent by client to server (server port number is 21)

```c
ftp_command_struct{
   uint_16 cmd;
   char *str_cmd;
   char *parameter;
}ftp_command_t;
```

## FTP response

`ftp_response_struct` presents a FTP response which is sent by server to client (server port number is 21)

```c
ftp_response_struct{
    uint_16 code;
    char *str_code;
    char *value;
}ftp_response_t;
```

## FTP file

`ftp_file_struct` presents a file which is transferred in a FTP data connection.

```c
ftp_file_struct{
   char *name;
   uint_32 size;
   int type;// classify by the file extension
   time_t last_modified;
}ftp_file_t;
```

## FTP user

`ftp_user_t` presents an user in a FTP session

```c
ftp_user_struct{
    char * username;
    char * password;
}ftp_user_t;
```

## FTP session attributes

| Attribute | MMT value | Value | Notes |
| ------------ | ------------ | --- | ---------------------- |
| FTP_SESSION_CONN_TYPE | MMT_FTP_CONTROL_CONNECTION | 1 | FTP Control connection |
|  | MMT_FTP_DATA_CONNECTION | 2 | FTP Data connection  |
| FTP_SERVER_CONT_ADDR |  |  | Server address of FTP control connection |
| FTP_SERVER_CONT_PORT |  | 21 | Server port number of FTP control connection |
| FTP_CLIENT_CONT_ADDR |  |  | Client address of FTP control connection |
| FTP_CLIENT_CONT_PORT |  |  | Client port number of FTP control connection |
| FTP_SESSION_USERNAME |  |  | FTP username of session |
| FTP_SESSION_PASSWORD |  |  | FTP password of session |
| FTP_SESSION_FEATURES |  |  | FTP features |
| FTP_SYST |  |  | FTP server system |
| FTP_STATUS | MMT_FTP_STATUS_OPENED | 1 | A FTP control session opened - detected by USER command |
|  | MMT_FTP_STATUS_CONTROLING | 2 | A FTP control session after user logged in successful and start controling - detected by response code 230 |
|  | MMT_FTP_STATUS_DATA_OPENED | 3 | A FTP data connection is going to open to transfer data - detected by response code 150 |
|  | MMT_FTP_STATUS_DATA_CLOSED | 4 | A FTP data connection is closed after completing transfer data - detected by response code 226 |
|  | MMT_FTP_STATUS_CLOSED | 5 | A FTP control session closed - detected by QUIT command |
| FTP_LAST_COMMAND | ftp_command_t |  | The last command has been seen |
| FTP_LAST_RESPONSE_CODE | ftp_response_t |  | The last response code has been seen |
| FTP_CURRENT_DIR |  |  | Current directory in FTP server |
| FTP_SERVER_DATA_ADDR |  |  | Server address of FTP data connection |
| FTP_SERVER_DATA_PORT |  |  | Server port number of FTP data connection |
| FTP_CLIENT_DATA_ADDR |  |  | Client address of FTP data connection |
| FTP_CLIENT_DATA_PORT |  |  | Client port number of FTP data connection |
| FTP_DATA_TYPE | MMT_FTP_DATA_TYPE_FILE | 1 | Current data connection transfers data a file |
|  | MMT_FTP_DATA_TYPE_LIST | 2 | Current data connection transfers data of an `ls` command |
|  | MMT_FTP_DATA_TYPE_UNKNOWN | 3 | Current data connection transfers data type is not classified yet |
| FTP_DATA_TRANSFER_TYPE |  | A | ASCII type |
|  |  | E | EBCDIC type |
|  |  | I | Binary type |
|  |  | L | Local type |
| FTP_DATA_MODE | MMT_FTP_DATA_PASSIVE_MODE | 1 | FTP data connection in passive mode detected by response code 227, 228 and 229|
|  | MMT_FTP_DATA_ACTIVE_MODE | 2 | FTP data connection in active mode - detected by command EPRT, PORT|
| FTP_DATA_DIRECTION | MMT_FTP_DATA_UPLOAD | 1 | Current data connection is transferring a file from client to server |
|  | MMT_FTP_DATA_DOWNLOAD | 2 | Current data connection is transferring a file from server to client |
|  |  | L | Local type |
| FTP_FILE_NAME |  |  | Name of the file which is going to be transferred |
| FTP_FILE_SIZE |  |  | Size of the file which is going to be transferred |
| FTP_FILE_LAST_MODIFIED |  |  | The last modified date of the file |

## FTP packet attributes

| Attribute | MMT value | Value | Notes |
| ------------ | ------------ | --- | ---------------------- |
| FTP_PACKET_TYPE | MMT_FTP_PACKET_DATA | 1 | The packet is a FTP data packet - only containing data and sent on FTP data connection |
|  | MMT_FTP_PACKET_COMMAND | 2 | The packet is sending from client to server on FTP control connection |
|  | MMT_FTP_PACKET_RESPONSE | 3 | The packet is sending from server to client on FTP control connection |
| FTP_PACKET_REQUEST | MMT_FTP_XXXX_CMD | | The FTP command sent from client to server |
| FTP_PACKET_REQUEST_PARAMETER |  |  | The parameter of FTP command |
| FTP_PACKET_RESPONSE_CODE | MMT_FTP_XXX_CODE |  | The FTP response code sent from server to client |
| FTP_PACKET_RESPONSE_VALUE |  |  | The value of response code |
| FTP_PACKET_DATA_LEN |  |  | The payload len of FTP packet |
| PROTO_PAYLOAD |  |  | The pointer to the data payload of FTP packet |
| PROTO_DATA_VOLUME |  |  | Data volume of protocol |
| PROTO_PAYLOAD_VOLUME |  |  | Payload volume of protocol |

### FTP commands value

```c
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

```

### FTP response code

```c
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

```
