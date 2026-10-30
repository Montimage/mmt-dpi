/*
 * proto_ftp_parse.c — FTP command and reply parsing: the shape checks the
 * classifier shares, the command id table, and the command/parameter and
 * reply-code/value extractors. Split out of proto_ftp.c by issue #544.
 */
#include "plugin_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ftp.h"

/**
 * checks for possible FTP command
 * not all valid commands are tested, it just need to be 3 or 4 characters followed by a space if the
 * packet is longer
 *
 * this functions is not used to accept, just to not reject
 */
uint8_t mmt_int_check_possible_ftp_command(char *payload , int payload_len) {
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
        // Check if this is a NOOP command
        if((payload[0]=='n'&&payload[1]=='o'&&payload[2]=='o'&&payload[3]=='p')
            ||(payload[0]=='N'&&payload[1]=='O'&&payload[2]=='O'&&payload[3]=='P')){
            return 2;
        }
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
uint8_t mmt_int_check_possible_ftp_reply(char *payload , int payload_len) {
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
uint8_t mmt_int_check_possible_ftp_continuation_reply(char *payload , int payload_len) {
    uint16_t i;

    if (payload_len < 5)
        return 0;

    for (i = 0; i < 5; i++) {
        if (payload[i] < ' ' || payload[i] > 127) // Can payload[i] > 127????  PVS-Studio says that the range is [-128,127] - A part of conditional expression is always false: payload[i] > 127. The value range of char type: [-128, 127].
            return 0;
    }

    return 1;
}

/**
 * Set command ID for a command
 * @param cmd command to set id
 */
inline static void ftp_set_command_id(ftp_command_t* cmd) {
    if (cmd->str_cmd == NULL) {
        cmd->cmd = MMT_FTP_UNKNOWN_CMD;
        return;
    }
    if (strlen(cmd->str_cmd) == 3) {
        if (strcmp(cmd->str_cmd, "PWD") == 0 || strcmp(cmd->str_cmd, "pwd") == 0) {
            cmd->cmd = MMT_FTP_PWD_CMD;
        } else if (strcmp(cmd->str_cmd, "CWD") == 0 || strcmp(cmd->str_cmd, "cwd") == 0) {
            cmd->cmd = MMT_FTP_CWD_CMD;
        } else if (strcmp(cmd->str_cmd, "CCC") == 0 || strcmp(cmd->str_cmd, "ccc") == 0) {
            cmd->cmd = MMT_FTP_CCC_CMD;
        } else if (strcmp(cmd->str_cmd, "ENC") == 0 || strcmp(cmd->str_cmd, "enc") == 0) {
            cmd->cmd = MMT_FTP_ENC_CMD;
        } else if (strcmp(cmd->str_cmd, "MIC") == 0 || strcmp(cmd->str_cmd, "mic") == 0) {
            cmd->cmd = MMT_FTP_MIC_CMD;
        } else if (strcmp(cmd->str_cmd, "MKD") == 0 || strcmp(cmd->str_cmd, "mkd") == 0) {
            cmd->cmd = MMT_FTP_MKD_CMD;
        } else if (strcmp(cmd->str_cmd, "RMD") == 0 || strcmp(cmd->str_cmd, "rmd") == 0) {
            cmd->cmd = MMT_FTP_RMD_CMD;
        }else {
            cmd->cmd = MMT_FTP_UNKNOWN_CMD;
        }
    } else {
        if (strcmp(cmd->str_cmd, "RETR") == 0 || strcmp(cmd->str_cmd, "retr") == 0) {
            cmd->cmd = MMT_FTP_RETR_CMD;
        } else if (strcmp(cmd->str_cmd, "USER") == 0 || strcmp(cmd->str_cmd, "user") == 0) {
            cmd->cmd = MMT_FTP_USER_CMD;
        } else if (strcmp(cmd->str_cmd, "PASS") == 0 || strcmp(cmd->str_cmd, "pass") == 0) {
            cmd->cmd = MMT_FTP_PASS_CMD;
        } else if (strcmp(cmd->str_cmd, "SYST") == 0 || strcmp(cmd->str_cmd, "syst") == 0) {
            cmd->cmd = MMT_FTP_SYST_CMD;
        } else if (strcmp(cmd->str_cmd, "TYPE") == 0 || strcmp(cmd->str_cmd, "type") == 0) {
            cmd->cmd = MMT_FTP_TYPE_CMD;
        } else if (strcmp(cmd->str_cmd, "SIZE") == 0 || strcmp(cmd->str_cmd, "size") == 0) {
            cmd->cmd = MMT_FTP_SIZE_CMD;
        } else if (strcmp(cmd->str_cmd, "EPSV") == 0 || strcmp(cmd->str_cmd, "epsv") == 0) {
            cmd->cmd = MMT_FTP_EPSV_CMD;
        } else if (strcmp(cmd->str_cmd, "FEAT") == 0 || strcmp(cmd->str_cmd, "feat") == 0) {
            cmd->cmd = MMT_FTP_FEAT_CMD;
        } else if (strcmp(cmd->str_cmd, "MDTM") == 0 || strcmp(cmd->str_cmd, "mdtm") == 0) {
            cmd->cmd = MMT_FTP_MDTM_CMD;
        } else if (strcmp(cmd->str_cmd, "ABOR") == 0 || strcmp(cmd->str_cmd, "abor") == 0) {
            cmd->cmd = MMT_FTP_ABOR_CMD;
        } else if (strcmp(cmd->str_cmd, "ACCT") == 0 || strcmp(cmd->str_cmd, "acct") == 0) {
            cmd->cmd = MMT_FTP_ACCT_CMD;
        } else if (strcmp(cmd->str_cmd, "ALLO") == 0 || strcmp(cmd->str_cmd, "allo") == 0) {
            cmd->cmd = MMT_FTP_ALLO_CMD;
        } else if (strcmp(cmd->str_cmd, "APPE") == 0 || strcmp(cmd->str_cmd, "appe") == 0) {
            cmd->cmd = MMT_FTP_APPE_CMD;
        } else if (strcmp(cmd->str_cmd, "AUTH") == 0 || strcmp(cmd->str_cmd, "auth") == 0) {
            cmd->cmd = MMT_FTP_AUTH_CMD;
        } else if (strcmp(cmd->str_cmd, "CDUP") == 0 || strcmp(cmd->str_cmd, "cdup") == 0) {
            cmd->cmd = MMT_FTP_CDUP_CMD;
        } else if (strcmp(cmd->str_cmd, "CONF") == 0 || strcmp(cmd->str_cmd, "conf") == 0) {
            cmd->cmd = MMT_FTP_CONF_CMD;
        } else if (strcmp(cmd->str_cmd, "DELE") == 0 || strcmp(cmd->str_cmd, "dele") == 0) {
            cmd->cmd = MMT_FTP_DELE_CMD;
        } else if (strcmp(cmd->str_cmd, "EPRT") == 0 || strcmp(cmd->str_cmd, "eprt") == 0) {
            cmd->cmd = MMT_FTP_EPRT_CMD;
        } else if (strcmp(cmd->str_cmd, "HELP") == 0 || strcmp(cmd->str_cmd, "help") == 0) {
            cmd->cmd = MMT_FTP_HELP_CMD;
        } else if (strcmp(cmd->str_cmd, "LANG") == 0 || strcmp(cmd->str_cmd, "lang") == 0) {
            cmd->cmd = MMT_FTP_LANG_CMD;
        } else if (strcmp(cmd->str_cmd, "LIST") == 0 || strcmp(cmd->str_cmd, "list") == 0) {
            cmd->cmd = MMT_FTP_LIST_CMD;
        } else if (strcmp(cmd->str_cmd, "LPRT") == 0 || strcmp(cmd->str_cmd, "lprt") == 0) {
            cmd->cmd = MMT_FTP_LPRT_CMD;
        } else if (strcmp(cmd->str_cmd, "LPSV") == 0 || strcmp(cmd->str_cmd, "lpsv") == 0) {
            cmd->cmd = MMT_FTP_LPSV_CMD;
        } else if (strcmp(cmd->str_cmd, "MLSD") == 0 || strcmp(cmd->str_cmd, "mlsd") == 0) {
            cmd->cmd = MMT_FTP_MLSD_CMD;
        } else if (strcmp(cmd->str_cmd, "MLST") == 0 || strcmp(cmd->str_cmd, "mlst") == 0) {
            cmd->cmd = MMT_FTP_MLST_CMD;
        } else if (strcmp(cmd->str_cmd, "MODE") == 0 || strcmp(cmd->str_cmd, "mode") == 0) {
            cmd->cmd = MMT_FTP_MODE_CMD;
        } else if (strcmp(cmd->str_cmd, "NLST") == 0 || strcmp(cmd->str_cmd, "nlst") == 0) {
            cmd->cmd = MMT_FTP_NLST_CMD;
        } else if (strcmp(cmd->str_cmd, "NOOP") == 0 || strcmp(cmd->str_cmd, "noop") == 0) {
            cmd->cmd = MMT_FTP_NOOP_CMD;
        } else if (strcmp(cmd->str_cmd, "OPTS") == 0 || strcmp(cmd->str_cmd, "opts") == 0) {
            cmd->cmd = MMT_FTP_OPTS_CMD;
        } else if (strcmp(cmd->str_cmd, "PASV") == 0 || strcmp(cmd->str_cmd, "pasv") == 0) {
            cmd->cmd = MMT_FTP_PASV_CMD;
        } else if (strcmp(cmd->str_cmd, "PBSZ") == 0 || strcmp(cmd->str_cmd, "pbsz") == 0) {
            cmd->cmd = MMT_FTP_PBSZ_CMD;
        } else if (strcmp(cmd->str_cmd, "PORT") == 0 || strcmp(cmd->str_cmd, "port") == 0) {
            cmd->cmd = MMT_FTP_PORT_CMD;
        } else if (strcmp(cmd->str_cmd, "QUIT") == 0 || strcmp(cmd->str_cmd, "quit") == 0) {
            cmd->cmd = MMT_FTP_QUIT_CMD;
        } else if (strcmp(cmd->str_cmd, "REIN") == 0 || strcmp(cmd->str_cmd, "rein") == 0) {
            cmd->cmd = MMT_FTP_REIN_CMD;
        } else if (strcmp(cmd->str_cmd, "REST") == 0 || strcmp(cmd->str_cmd, "rest") == 0) {
            cmd->cmd = MMT_FTP_REST_CMD;
        } else if (strcmp(cmd->str_cmd, "RNFR") == 0 || strcmp(cmd->str_cmd, "rnfr") == 0) {
            cmd->cmd = MMT_FTP_RNFR_CMD;
        } else if (strcmp(cmd->str_cmd, "RNTO") == 0 || strcmp(cmd->str_cmd, "rnto") == 0) {
            cmd->cmd = MMT_FTP_RNTO_CMD;
        } else if (strcmp(cmd->str_cmd, "SITE") == 0 || strcmp(cmd->str_cmd, "site") == 0) {
            cmd->cmd = MMT_FTP_SITE_CMD;
        } else if (strcmp(cmd->str_cmd, "SMNT") == 0 || strcmp(cmd->str_cmd, "smnt") == 0) {
            cmd->cmd = MMT_FTP_SMNT_CMD;
        } else if (strcmp(cmd->str_cmd, "STAT") == 0 || strcmp(cmd->str_cmd, "stat") == 0) {
            cmd->cmd = MMT_FTP_STAT_CMD;
        } else if (strcmp(cmd->str_cmd, "STOR") == 0 || strcmp(cmd->str_cmd, "stor") == 0) {
            cmd->cmd = MMT_FTP_STOR_CMD;
        } else if (strcmp(cmd->str_cmd, "STOU") == 0 || strcmp(cmd->str_cmd, "stou") == 0) {
            cmd->cmd = MMT_FTP_STOU_CMD;
        } else if (strcmp(cmd->str_cmd, "STRU") == 0 || strcmp(cmd->str_cmd, "stru") == 0) {
            cmd->cmd = MMT_FTP_STRU_CMD;
        } else if (strcmp(cmd->str_cmd, "XCUP") == 0 || strcmp(cmd->str_cmd, "xcup") == 0) {
            cmd->cmd = MMT_FTP_XCUP_CMD;
        } else if (strcmp(cmd->str_cmd, "XMKD") == 0 || strcmp(cmd->str_cmd, "xmkd") == 0) {
            cmd->cmd = MMT_FTP_XMKD_CMD;
        } else if (strcmp(cmd->str_cmd, "XPWD") == 0 || strcmp(cmd->str_cmd, "xpwd") == 0) {
            cmd->cmd = MMT_FTP_XPWD_CMD;
        } else if (strcmp(cmd->str_cmd, "XRCP") == 0 || strcmp(cmd->str_cmd, "xrcp") == 0) {
            cmd->cmd = MMT_FTP_XRCP_CMD;
        } else if (strcmp(cmd->str_cmd, "XRMD") == 0 || strcmp(cmd->str_cmd, "xrmd") == 0) {
            cmd->cmd = MMT_FTP_XRMD_CMD;
        } else if (strcmp(cmd->str_cmd, "XRSQ") == 0 || strcmp(cmd->str_cmd, "xrsq") == 0) {
            cmd->cmd = MMT_FTP_XRSQ_CMD;
        } else if (strcmp(cmd->str_cmd, "XSEM") == 0 || strcmp(cmd->str_cmd, "xsem") == 0) {
            cmd->cmd = MMT_FTP_XSEM_CMD;
        } else if (strcmp(cmd->str_cmd, "XSEN") == 0 || strcmp(cmd->str_cmd, "xsen") == 0) {
            cmd->cmd = MMT_FTP_XSEN_CMD;
        } else {
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
ftp_command_t * ftp_get_command(char* payload, int payload_len) {
    ftp_command_t *cmd = NULL;
    cmd = (ftp_command_t*)malloc(sizeof(ftp_command_t));
    if(cmd == NULL) return NULL;
    /* raw malloc — initialise all fields so a short/odd payload below can
     * never leave str_cmd or param uninitialised for free_ftp_command() or
     * ftp_set_command_id() (#195). */
    cmd->cmd = MMT_FTP_UNKNOWN_CMD;
    cmd->str_cmd = NULL;
    cmd->param = NULL;
    char * command = NULL;
    char * params = NULL;

    if (payload_len == 6 && payload[3] != ' ') {
        // FEAT\r\t command
        command = (char*)malloc(5);
        if(command == NULL) {
            free(cmd);
            return NULL;
        }
        memcpy(command, payload, 4);
        command[4] = '\0';
        cmd->str_cmd = command;
        cmd->param = NULL;
    } else if (payload_len == 5 && payload[2] != ' ') {
        // PWD\r\t command
        command = (char*)malloc(4);
        if (command == NULL)
        {
            free(cmd);
            return NULL;
        }
        memcpy(command, payload, 3);
        command[3] = '\0';
        cmd->str_cmd = command;
        cmd->param = NULL;
    } else {
        if (!mmt_int_check_possible_ftp_command(payload, payload_len)) {
            cmd->cmd = MMT_FTP_UNKNOWN_CMD;
            command = (char*)malloc(12);
            if (command == NULL)
            {
                free(cmd);
                return NULL;
            }
            memcpy(command, "UNKNOWN_CMD", 11);
            command[11]='\0';
            cmd->str_cmd = command;
            cmd->param = NULL;
            return cmd;
        }

        /* payload_len < 4 reaches here for inputs such as "ABC" that pass
         * mmt_int_check_possible_ftp_command(): bound each byte test (#195). */
        if (payload_len >= 4 && payload[3] == ' ') {
            command = (char*)malloc(4);
            if (command == NULL)
            {
                free(cmd);
                return NULL;
            }
            memcpy(command, payload, 3);
            command[3] = '\0';
            cmd->str_cmd = command;

            if (payload_len - 6 > 0) {
                params = (char*)malloc(payload_len - 5);
                if (params == NULL)
                {
                    free(command);
                    free(cmd);
                    return NULL;
                }
                memcpy(params, payload + 4, payload_len - 6);
                params[payload_len - 6] = '\0';
                cmd->param = params;
            } else {
                cmd->param = NULL;
            }
        } else if (payload_len >= 5 && payload[4] == ' ') {
            command = (char*)malloc(5);
            if (command == NULL)
            {
                free(cmd);
                return NULL;
            }
            memcpy(command, payload, 4);
            command[4] = '\0';
            cmd->str_cmd = command;
            if (payload_len - 7 > 0) {
                params = (char*)malloc(payload_len - 6);
                if (params == NULL)
                {
                    free(command);
                    free(cmd);
                    return NULL;
                }
                memcpy(params, payload + 5, payload_len - 7);
                params[payload_len - 7] = '\0';
                cmd->param = params;
            } else {
                cmd->param = NULL;
            }
        } else {
            /* A payload that passed the sanity check but carries no 3- or
             * 4-letter verb followed by a space (e.g. a bare 3- or 4-byte
             * input such as "ABC") is an unknown command — report it
             * explicitly instead of leaving str_cmd NULL (#206, F-BUG-068). */
            command = (char*)malloc(12);
            if (command == NULL)
            {
                free(cmd);
                return NULL;
            }
            memcpy(command, "UNKNOWN_CMD", 11);
            command[11]='\0';
            cmd->str_cmd = command;
            cmd->param = NULL;
        }
    }

    ftp_set_command_id(cmd);

    return cmd;
}

char * ftp_get_command_param(char* payload, int payload_len) {
    if (payload_len == 6 && payload[3] != ' ') {
        return NULL;
    } else if (payload_len == 5 && payload[2] != ' ') {
        return NULL;
    } else {
        if (!mmt_int_check_possible_ftp_command(payload, payload_len)) {
            char * params = NULL;
            params = (char*)malloc(payload_len + 1);
            if (params == NULL)
            {
                return NULL;
            }
            memcpy(params, payload, payload_len);
            params[payload_len] = '\0';
            return params;
        }else{
            if (payload_len >= 4 && payload[3] == ' ') {
                if (payload_len - 6 > 0) {
                    char * params = NULL;
                    params = (char*)malloc(payload_len - 5);
                    if (params == NULL)
                    {
                        return NULL;
                    }
                    memcpy(params, payload + 4, payload_len - 6);
                    params[payload_len - 6] = '\0';
                    return params;
                } else {
                    return NULL;
                }
            } else if (payload_len >= 5 && payload[4] == ' ') {
                if (payload_len - 7 > 0) {
                    char * params = NULL;
                    params = (char*)malloc(payload_len - 6);
                    if (params == NULL)
                    {
                        return NULL;
                    }
                    memcpy(params, payload + 5, payload_len - 7);
                    params[payload_len - 7] = '\0';
                    return params;
                } else {
                    return NULL;
                }
            }
        }
    }

    return NULL;
}

/* Issue #506: ftp_get_command_str() returns a heap string on every path so
 * its caller can free it (the extractor hands it to the handler). */
static char * ftp_unknown_command(void){
    char * command = (char*)malloc(sizeof("UNKNOWN_CMD"));
    if (command != NULL) {
        memcpy(command, "UNKNOWN_CMD", sizeof("UNKNOWN_CMD"));
    }
    return command;
}

char * ftp_get_command_str(char* payload, int payload_len){
    char * command = NULL;

    if (payload_len == 6 && payload[3] != ' ') {
        // FEAT\r\t command
        command = (char*)malloc(5);
        if (command == NULL)
        {
            return NULL;
        }
        memcpy(command, payload, 4);
        command[4] = '\0';
    } else if (payload_len == 5 && payload[2] != ' ') {
        // PWD\r\t command
        command = (char*)malloc(4);
        if (command == NULL)
        {
            return NULL;
        }
        memcpy(command, payload, 3);
        command[3] = '\0';
    } else {
        if (!mmt_int_check_possible_ftp_command(payload, payload_len)) {
            command = ftp_unknown_command();
        }else{
            if (payload_len >= 4 && payload[3] == ' ') {
                command = (char*)malloc(4);
                if (command == NULL)
                {
                    return NULL;
                }
                memcpy(command, payload, 3);
                command[3] = '\0';
            } else if (payload_len >= 5 && payload[4] == ' ') {
                command = (char*)malloc(5);
                if (command == NULL)
                {
                    return NULL;
                }
                memcpy(command, payload, 4);
                command[4] = '\0';
            } else {
                /* Possible command whose verb is not 3/4 letters + space
                 * (e.g. a bare "ABC") — report it, mirroring the
                 * not-a-command branch above (#206). */
                command = ftp_unknown_command();
            }
        }
    }
    return command;
}

/**
 * Get response code from a reponse packet
 * @param  payload     payload of packet
 * @param  payload_len payload len of packet
 * @return             a ftp response code: code + value
 */
ftp_response_t * ftp_get_response(char* payload, int payload_len) {
    ftp_response_t * res = NULL;
    int code = MMT_FTP_UNKNOWN_CODE;
    char *str_value = NULL;
    res = (ftp_response_t*)malloc(sizeof(ftp_response_t));
    if(res == NULL) return NULL;
    if (mmt_int_check_possible_ftp_reply(payload, payload_len)) {
        // Get response code
        char *str_code;
        str_code = (char*)malloc(4);
        if (str_code == NULL)
        {
            free(res);
            return NULL;
        }
        memcpy(str_code, payload, 3);
        str_code[3] = '\0';
        code = atoi(str_code);
        res->str_code = str_code;
        res->code = code;

        // Get response value
        if (payload_len - 6 > 0) {
            str_value = (char*)malloc(payload_len - 5);
            if (str_value == NULL)
            {
                free(str_code);
                free(res);
                return NULL;
            }
            memcpy(str_value, payload + 4, payload_len - 6);
            str_value[payload_len - 6] = '\0';
            res->value = str_value;
        } else {
            res->value = NULL;
        }

    } else {
        if (mmt_int_check_possible_ftp_continuation_reply(payload, payload_len)) {
            code = MMT_FTP_CONTINUE_CODE;
            str_value = (char*)malloc(payload_len - 1);
            if (str_value == NULL)
            {                
                free(res);
                return NULL;
            }
            memcpy(str_value, payload, payload_len - 2);
            str_value[payload_len - 2] = '\0';
            res->value = str_value;
            res->str_code = str_value;
        } else {
            code = MMT_FTP_UNKNOWN_CODE;
            /* This branch runs when payload_len < 5: a 0/1-byte payload makes
             * payload_len - 2 negative — a huge malloc/memcpy size (#195). */
            if (payload_len - 2 >= 0) {
                str_value = (char*)malloc(payload_len - 1);
                if (str_value == NULL)
                {
                    free(res);
                    return NULL;
                }
                memcpy(str_value, payload, payload_len - 2);
                str_value[payload_len - 2] = '\0';
                res->value = str_value;
                res->str_code = str_value;
            } else {
                res->value = NULL;
                res->str_code = NULL;
            }
        }
        res->code = code;
    }
    return res;
}

char * ftp_get_response_value(char* payload, int payload_len) {
    char *str_value = NULL;
    if (mmt_int_check_possible_ftp_reply(payload, payload_len)) {
        // Get response value
        if (payload_len - 6 > 0) {
            str_value = (char*)malloc(payload_len - 5);
            if (str_value == NULL)
            {
                return NULL;
            }
            memcpy(str_value, payload + 4, payload_len - 6);
            str_value[payload_len - 6] = '\0';
        }

    } else {
        if (mmt_int_check_possible_ftp_continuation_reply(payload, payload_len)) {
            str_value = (char*)malloc(payload_len - 1);
            if (str_value == NULL)
            {
                return NULL;
            }
            memcpy(str_value, payload, payload_len - 2);
            str_value[payload_len - 2] = '\0';
        }
    }
    return str_value;
}

/**
 * Get response code from a reponse packet
 * @param  payload     payload of packet
 * @param  payload_len payload len of packet
 * @return             a ftp response code: code + value
 */
int ftp_get_response_code(char* payload, int payload_len) {
    int code;
    if (mmt_int_check_possible_ftp_reply(payload, payload_len)) {
        // Get response code
        char *str_code = NULL;
        str_code = (char*)malloc(4);
        if (str_code == NULL)
        {
            return MMT_FTP_UNKNOWN_CODE;
        }
        memcpy(str_code, payload, 3);
        str_code[3] = '\0';
        code = atoi(str_code);
        free(str_code);
    } else {
        if (mmt_int_check_possible_ftp_continuation_reply(payload, payload_len)) {
            code = MMT_FTP_CONTINUE_CODE;
        } else {
            code = MMT_FTP_UNKNOWN_CODE;
        }
    }
    return code;
}
