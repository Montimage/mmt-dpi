/*
 * proto_ftp_session.c — FTP session state: the connection tuple (tuple6),
 * the lifecycles of the command, response, user, file, data-session and
 * control-session structures, and the per-handler control-session list.
 * Split out of proto_ftp.c by issue #544.
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
 * New FTP tuple6
 * @return new ftp tuple 6
 */
ftp_tuple6_t * ftp_new_tuple6() {
    ftp_tuple6_t * t = (ftp_tuple6_t*)malloc(sizeof(ftp_tuple6_t));
    if(t == NULL) return NULL;
    t->conn_type = 0;
    t->direction = 0;
    t->s_addr = 0;
    t->s_port = 0;
    t->c_addr = 0;
    t->c_port = 0;
    t->is_ipv6 = 0;
    t->c_addr_v6 = NULL;
    t->s_addr_v6 = NULL;
    t->ip_session_id = 0;
    return t;
}

ftp_tuple6_t *ftp_copy_tupl6(ftp_tuple6_t *tuple6) {
    ftp_tuple6_t * t = ftp_new_tuple6();
    if(t == NULL) return NULL;
    t->conn_type = tuple6->conn_type;
    t->direction = tuple6->direction;
    t->s_addr = tuple6->s_addr;
    t->s_port = tuple6->s_port;
    t->c_addr = tuple6->c_addr;
    t->c_port = tuple6->c_port;
    t->is_ipv6 = tuple6->is_ipv6;
    if(tuple6->is_ipv6){
        t->c_addr_v6 = (char*)malloc(33*sizeof(char));
        t->s_addr_v6 = (char*)malloc(33*sizeof(char));
        if (t->c_addr_v6 != NULL && t->s_addr_v6 !=NULL){
            memcpy(t->s_addr_v6, tuple6->s_addr_v6, 32);
            memcpy(t->c_addr_v6, tuple6->c_addr_v6, 32);
            t->c_addr_v6[32] = '\0';
            t->s_addr_v6[32] = '\0';
        } else {
            if(t->c_addr_v6 != NULL){ free(t->c_addr_v6); t->c_addr_v6 = NULL; }
            if(t->s_addr_v6 != NULL){ free(t->s_addr_v6); t->s_addr_v6 = NULL; }
        }
    }
    t->ip_session_id = tuple6->ip_session_id;
    return t;
}

void free_ftp_tuple6(ftp_tuple6_t *t6) {
    if(t6 == NULL) return;
    if(t6->c_addr_v6 != NULL) free(t6->c_addr_v6);
    if(t6->s_addr_v6 != NULL) free(t6->s_addr_v6);
    free(t6);
}

/**
 * Get tuple 6 of packet: server_address: server_port - client_address: client_port, type of connection and direction of packet (send from server to client or other)
 * @param  ipacket packet
 * @return         a tuple6
 */
ftp_tuple6_t *ftp_get_tuple6(const ipacket_t * ipacket) {
    /* The IPv6 address buffers hold the 16 raw address bytes but are sized
     * and zero-filled to 33 bytes: ftp_copy_tupl6() and ftp_compare_tuple6()
     * handle every c_addr_v6/s_addr_v6 as 32 bytes (the EPRT path stores the
     * address text there), which overran the former 17-byte buffers. */
    ftp_tuple6_t *t6;
    t6 = ftp_new_tuple6();
    if(t6 == NULL) return NULL;
    t6->ip_session_id = ipacket->session->session_id;
    if (ipacket->internal_packet->tcp && (ipacket->internal_packet->iph||ipacket->internal_packet->iphv6)) {
        if(ipacket->internal_packet->iphv6!=NULL){
            t6->is_ipv6 = 1;
        }else{
            t6->is_ipv6 = 0;
        }
        if (ipacket->internal_packet->tcp->source == htons(21)) {
            t6->conn_type = MMT_FTP_CONTROL_CONNECTION;
            t6->direction = MMT_FTP_PACKET_SERVER;
            if(t6->is_ipv6==0){
                t6->s_addr = ipacket->internal_packet->iph->saddr;
                t6->c_addr = ipacket->internal_packet->iph->daddr;    
            }else{
                t6->c_addr_v6 = (char*)calloc(33, sizeof(char));
                t6->s_addr_v6 = (char*)calloc(33, sizeof(char));
                if (t6->c_addr_v6 != NULL && t6->s_addr_v6 != NULL){
                    memcpy(t6->s_addr_v6, &ipacket->internal_packet->iphv6->saddr.mmt_v6_u.u6_addr8, 16);
                    memcpy(t6->c_addr_v6, &ipacket->internal_packet->iphv6->daddr.mmt_v6_u.u6_addr8, 16);
                    t6->s_addr_v6[16] = '\0';
                    t6->c_addr_v6[16] = '\0';
                }
            }            
            t6->s_port = ipacket->internal_packet->tcp->source;
            t6->c_port = ipacket->internal_packet->tcp->dest;
            return t6;
        } else if (ipacket->internal_packet->tcp->dest == htons(21)) {
            t6->conn_type = MMT_FTP_CONTROL_CONNECTION;
            t6->direction = MMT_FTP_PACKET_CLIENT;
            if(t6->is_ipv6==0){
                t6->s_addr = ipacket->internal_packet->iph->daddr;
                t6->c_addr = ipacket->internal_packet->iph->saddr;    
            }else{
                t6->c_addr_v6 = (char*)calloc(33, sizeof(char));
                t6->s_addr_v6 = (char*)calloc(33, sizeof(char));
                if (t6->c_addr_v6 != NULL && t6->s_addr_v6 != NULL)
                {
                    memcpy(t6->s_addr_v6, &ipacket->internal_packet->iphv6->daddr.mmt_v6_u.u6_addr8, 16);
                    memcpy(t6->c_addr_v6, &ipacket->internal_packet->iphv6->saddr.mmt_v6_u.u6_addr8, 16);
                    t6->s_addr_v6[16] = '\0';
                    t6->c_addr_v6[16] = '\0';
                }
            }
            t6->s_port = ipacket->internal_packet->tcp->dest;
            t6->c_port = ipacket->internal_packet->tcp->source;
            return t6;
        } else {
            t6->conn_type = MMT_FTP_DATA_CONNECTION;
            t6->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
            if(t6->is_ipv6==0){
                t6->s_addr = ipacket->internal_packet->iph->saddr;
                t6->c_addr = ipacket->internal_packet->iph->daddr;    
            }else{
                t6->c_addr_v6 = (char*)calloc(33, sizeof(char));
                t6->s_addr_v6 = (char*)calloc(33, sizeof(char));
                if (t6->c_addr_v6 != NULL && t6->s_addr_v6 != NULL)
                {
                    memcpy(t6->s_addr_v6, &ipacket->internal_packet->iphv6->saddr.mmt_v6_u.u6_addr8, 16);
                    memcpy(t6->c_addr_v6, &ipacket->internal_packet->iphv6->daddr.mmt_v6_u.u6_addr8, 16);
                    t6->s_addr_v6[16] = '\0';
                    t6->c_addr_v6[16] = '\0';
                }
            }
            t6->s_port = ipacket->internal_packet->tcp->source;
            t6->c_port = ipacket->internal_packet->tcp->dest;
            return t6;
        }
    }
    free_ftp_tuple6(t6);
    return NULL;
}

ftp_response_t * ftp_new_response() {
    ftp_response_t * res;
    res = (ftp_response_t*)malloc(sizeof(ftp_response_t));
    if(res == NULL) return NULL;
    res->code = MMT_FTP_UNKNOWN_CODE;
    res->value = NULL;
    res->str_code = NULL;
    return res;
}

void free_ftp_response(ftp_response_t *res) {
    debug("free_ftp_response is called \n");
    if (res == NULL) return;

    if (res->value != NULL) free(res->value);

    if (res->code == MMT_FTP_UNKNOWN_CODE || res->code == MMT_FTP_CONTINUE_CODE) {
        debug("No need to free");
    } else {
        if (res->str_code != NULL) free(res->str_code);
    }

    free(res);
}

ftp_command_t * ftp_new_command() {
    ftp_command_t * cmd;
    cmd = (ftp_command_t*)malloc(sizeof(ftp_command_t));
    if(cmd == NULL) return NULL;
    cmd->cmd = MMT_FTP_UNKNOWN_CMD;
    cmd->str_cmd = NULL;
    cmd->param = NULL;
    return cmd;
}

void free_ftp_command(ftp_command_t *cmd) {
    if (cmd == NULL) return;

    if (cmd->str_cmd != NULL) free(cmd->str_cmd);

    if (cmd->param != NULL) free(cmd->param);

    free(cmd);
}

/**
 * New FTP user
 * @return new ftp user
 */
ftp_user_t *ftp_new_user() {
    ftp_user_t *user = (ftp_user_t*)malloc(sizeof(ftp_user_t));
    if(user == NULL) return NULL;
    user->username = NULL;
    user->password = NULL;
    return user;
}

/**
 * Free a ftp user information
 * @param user [description]
 */
void free_ftp_user(ftp_user_t *user) {
    if (user == NULL) return;
    if (user->username != NULL) free(user->username);
    if (user->password != NULL) free(user->password);
    free(user);
}

/**
 * New ftp file transfering
 * @return file
 */
ftp_file_t * ftp_new_file() {
    ftp_file_t * file = (ftp_file_t*)malloc(sizeof(ftp_file_t));
    if(file == NULL) return NULL;
    file->name = NULL;
    file->size = 0;
    file->last_modified = NULL;
    return file;
}

/**
 * Free a file
 * @param file [description]
 */
void free_ftp_file(ftp_file_t *file) {
    if (file == NULL) return;
    if (file->name != NULL) free(file->name);
    if (file->last_modified != NULL) free(file->last_modified);
    free(file);
}

/**
 * New data connection
 * @return a new data connection
 */
ftp_data_session_t * ftp_new_data_connection() {
    ftp_data_session_t * ftp_data;
    ftp_data = (ftp_data_session_t*)malloc(sizeof(ftp_data_session_t));
    if(ftp_data == NULL) return NULL;
    ftp_data->data_conn = ftp_new_tuple6();
    if(ftp_data->data_conn == NULL){
        free(ftp_data);
        return NULL;
    }
    ftp_data->data_conn->conn_type = MMT_FTP_DATA_CONNECTION;
    ftp_data->data_conn_mode = 0;
    ftp_data->data_transfer_type = NULL;
    ftp_data->data_type = 0;
    ftp_data->file = ftp_new_file();
    if(ftp_data->file == NULL){
        free_ftp_tuple6(ftp_data->data_conn);
        free(ftp_data);
        return NULL;
    }
    ftp_data->data_direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
    ftp_data->control_session = NULL;
    return ftp_data;
}

/**
 * Free a ftp data session
 * @param ftp_data ftp data session
 */
void free_ftp_data_session(ftp_data_session_t *ftp_data) {
    if (ftp_data == NULL) return;
    free_ftp_tuple6(ftp_data->data_conn);
    if (ftp_data->data_transfer_type != NULL) free(ftp_data->data_transfer_type);
    free_ftp_file(ftp_data->file);
    free(ftp_data);
}

/**
 * Start the next transfer on the same data session object (issue #487).
 *
 * A data flow keeps its ftp_data_session_t in session_data[] without owning
 * it — the control session does. Freeing the object when a transfer ended
 * (226) left those aliases dangling, and the flow's next packet read freed
 * memory in ftp_session_data_analysis(). The object therefore lives as long
 * as its control session and is reset here to the state
 * ftp_new_data_connection() gives a fresh one; a flow of the finished
 * transfer no longer matches the new tuple and detaches itself on its next
 * packet (ftp_session_data_analysis()).
 * @return 0 on success, -1 when allocation failed (the session is unchanged)
 */
int ftp_reset_data_session(ftp_data_session_t *ftp_data) {
    ftp_tuple6_t *conn = ftp_new_tuple6();
    ftp_file_t *file = ftp_new_file();
    if (conn == NULL || file == NULL) {
        free_ftp_tuple6(conn);
        free_ftp_file(file);
        return -1;
    }
    conn->conn_type = MMT_FTP_DATA_CONNECTION;
    free_ftp_tuple6(ftp_data->data_conn);
    ftp_data->data_conn = conn;
    free_ftp_file(ftp_data->file);
    ftp_data->file = file;
    free(ftp_data->data_transfer_type);
    ftp_data->data_transfer_type = NULL;
    ftp_data->data_conn_mode = 0;
    ftp_data->data_type = 0;
    ftp_data->data_direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
    return 0;
}

/**
 * Create new ftp control session
 * @param  tuple6 control connection tuple6
 * @return        a ftp control connection
 */
ftp_control_session_t * ftp_new_control_session(ftp_tuple6_t * tuple6) {
    ftp_control_session_t * ftp_control;
    ftp_control = (ftp_control_session_t*)malloc(sizeof(ftp_control_session_t));
    if (ftp_control == NULL)
        return NULL;

    ftp_control->contrl_conn = ftp_copy_tupl6(tuple6);
    if(ftp_control->contrl_conn == NULL){
        free(ftp_control);
        return NULL;
    }
    ftp_control->last_command = NULL;
    ftp_control->last_response = NULL;
    ftp_control->user = ftp_new_user();
    if(ftp_control->user == NULL){
        free_ftp_tuple6(ftp_control->contrl_conn);
        free(ftp_control);
        return NULL;
    }
    ftp_control->session_feats = NULL;
    ftp_control->session_syst = NULL;
    ftp_control->current_dir = NULL;
    ftp_control->status = 0;
    ftp_control->current_data_session = ftp_new_data_connection();
    if(ftp_control->current_data_session == NULL){
        free_ftp_user(ftp_control->user);
        free_ftp_tuple6(ftp_control->contrl_conn);
        free(ftp_control);
        return NULL;
    }
    if(ftp_control->current_data_session->data_conn == NULL){
        free_ftp_data_session(ftp_control->current_data_session);
        free_ftp_user(ftp_control->user);
        free_ftp_tuple6(ftp_control->contrl_conn);
        free(ftp_control);
        return NULL;
    }
    ftp_control->current_data_session->data_conn->is_ipv6 = tuple6->is_ipv6;
    ftp_control->current_data_session->control_session = ftp_control;
    ftp_control->status = 0;
    ftp_control->next = NULL;
    return ftp_control;
}

/**
 * Free a ftp control session
 * @param ftp_control ftp control session is going to be free
 */
void free_ftp_control_session(ftp_control_session_t *ftp_control) {
    if (ftp_control == NULL) return;
    free_ftp_tuple6(ftp_control->contrl_conn);
    free_ftp_command(ftp_control->last_command);
    free_ftp_response(ftp_control->last_response);
    free_ftp_user(ftp_control->user);
    if (ftp_control->session_feats != NULL) free(ftp_control->session_feats);
    if (ftp_control->session_syst != NULL) free(ftp_control->session_syst);
    if (ftp_control->current_dir != NULL) free(ftp_control->current_dir);
    free_ftp_data_session(ftp_control->current_data_session);
    free_ftp_control_session(ftp_control->next);
    free(ftp_control);
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
*            8 if the server_port and server address of data connection is NULL and the other are equal (same direction)
*            7 if the client_port and client address of data connection is NULL and the other are equal (different direction) - convert direction of t1
*            0 otherwise
*/
int ftp_compare_tuple6(ftp_tuple6_t *t1, ftp_tuple6_t * t2) {

    if(t1 == NULL || t2==NULL) return 0;

    if (t1->conn_type != t2->conn_type) return 0;

    if(t1->is_ipv6!=t2->is_ipv6) return 0;

    if (t1->conn_type == MMT_FTP_CONTROL_CONNECTION) {
        if (t1->c_addr != t2->c_addr) return 0;

        if (t1->s_addr != t2->s_addr) return 0;

        if (t1->c_port != t2->c_port) return 0;

        if (t1->s_port != t2->s_port) return 0;

        if(t1->is_ipv6==1){
            if(mmt_memcmp(t1->c_addr_v6,t2->c_addr_v6,32)!=0) return 0;
            if(mmt_memcmp(t1->s_addr_v6,t2->s_addr_v6,32)!=0) return 0;
        }

        return 1;
    } else {
        if(t1->is_ipv6==1){
            if (mmt_memcmp(t1->c_addr_v6,t2->c_addr_v6,32)==0 && t1->c_port == t2->c_port && mmt_memcmp(t1->s_addr_v6,t2->s_addr_v6,32)==0 && t1->s_port == t2->s_port) return 2;
            if (mmt_memcmp(t1->c_addr_v6,t2->s_addr_v6,32)==0 && t1->c_port == t2->s_port && mmt_memcmp(t1->s_addr_v6,t2->c_addr_v6,32)==0 && t1->s_port == t2->c_port) return 3; 

            // Extended passive mode - 229 and 227 code
            if (mmt_memcmp(t1->c_addr_v6,t2->c_addr_v6,32)==0 && t2->c_port == 0 && mmt_memcmp(t1->s_addr_v6,t2->s_addr_v6,32)==0 && t1->s_port == t2->s_port) return 4;
            if (mmt_memcmp(t1->c_addr_v6,t2->s_addr_v6,32)==0 && t2->c_port == 0 && mmt_memcmp(t1->s_addr_v6,t2->c_addr_v6,32)==0 && t1->c_port == t2->s_port) return 5;
            // Active mode - PORT and EPRT command
            if (mmt_memcmp(t1->c_addr_v6,t2->c_addr_v6,32)==0 && t1->c_port == t2->c_port && mmt_memcmp(t1->s_addr_v6,t2->s_addr_v6,32)==0 && t2->s_port == 0) return 6;
            if (mmt_memcmp(t1->c_addr_v6,t2->s_addr_v6,32)==0 && mmt_memcmp(t1->s_addr_v6,t2->c_addr_v6,32)==0 && t1->s_port == t2->c_port && t2->s_port == 0) return 7;
        }
        if (t1->c_addr == t2->c_addr && t1->c_port == t2->c_port && t1->s_addr == t2->s_addr && t1->s_port == t2->s_port) return 2;
        if (t1->c_addr == t2->s_addr && t1->c_port == t2->s_port && t1->s_addr == t2->c_addr && t1->s_port == t2->c_port) return 3;
        // Extended passive mode - 229 and 227 code
        if (t1->c_addr == t2->c_addr && t2->c_port == 0 && t1->s_addr == t2->s_addr && t1->s_port == t2->s_port) return 4;
        if (t1->c_addr == t2->s_addr && t2->c_port == 0 && t1->s_addr == t2->c_addr && t1->c_port == t2->s_port) return 5;
        // Active mode - PORT and EPRT command
        if (t1->c_addr == t2->c_addr && t1->c_port == t2->c_port && t1->s_addr == t2->s_addr && t2->s_port == 0) return 6;
        if (t1->c_addr == t2->s_addr && t1->s_addr == t2->c_addr && t1->s_port == t2->c_port && t2->s_port == 0) return 7;
        if (t1->c_addr == t2->c_addr && t1->c_port == t2->c_port && t2->s_addr == 0 && t2->s_port == 0) return 8;
        if (t1->c_addr == t2->s_addr && t1->c_port == t2->s_port && t2->c_addr == 0 && t2->c_port == 0) return 9;
        return 0;
    }

    return 0;
}

/**
 * Set direction for a tuple6
 * @param tuple6 tuple6 to set direction
 * @param conn   tuple6 with correct direction
 */
void ftp_set_tuple6_direction(ftp_tuple6_t *tuple6, ftp_tuple6_t *conn, int compare) {
    switch (compare) {
    case 0:
        mmt_debug_log( "FTP: Not correct control connection\n");
        break;
    case 2:
        tuple6->direction = conn->direction;
        break;
    case 3:
        if (conn->direction == MMT_FTP_PACKET_SERVER) {
            tuple6->direction = MMT_FTP_PACKET_CLIENT;
        } else if (conn->direction == MMT_FTP_PACKET_CLIENT) {
            tuple6->direction = MMT_FTP_PACKET_SERVER;
        }
        break;
    case 4:
        tuple6->direction = conn->direction;
        conn->c_port = tuple6->c_port;
        break;
    case 5:
        conn->c_port = tuple6->s_port;
        if (conn->direction == MMT_FTP_PACKET_SERVER) {
            tuple6->direction = MMT_FTP_PACKET_CLIENT;
        } else if (conn->direction == MMT_FTP_PACKET_CLIENT) {
            tuple6->direction = MMT_FTP_PACKET_SERVER;
        }
        break;
    case 6:
        tuple6->direction = conn->direction;
        conn->s_port = tuple6->s_port;
        break;
    case 7:
        conn->s_port = tuple6->c_port;
        if (conn->direction == MMT_FTP_PACKET_SERVER) {
            tuple6->direction = MMT_FTP_PACKET_CLIENT;
        } else if (conn->direction == MMT_FTP_PACKET_CLIENT) {
            tuple6->direction = MMT_FTP_PACKET_SERVER;
        }
        break;
    case 8:
        tuple6->direction = conn->direction;
        conn->s_port = tuple6->s_port;
        conn->s_addr = tuple6->s_addr;
        break;
    case 9:
        conn->c_port = tuple6->s_port;
        if (conn->direction == MMT_FTP_PACKET_SERVER) {
            tuple6->direction = MMT_FTP_PACKET_CLIENT;
        } else if (conn->direction == MMT_FTP_PACKET_CLIENT) {
            tuple6->direction = MMT_FTP_PACKET_SERVER;
        }
        conn->s_port = tuple6->c_port;
        conn->s_addr = tuple6->c_addr;
        break;        
    }
}

/**
 * Get list of control session from session context
 * @param  ipacket packet
 * @param  index   protocol index
 * @return         the pointer to the first control_session
 */
ftp_control_session_t * ftp_get_list_control_session(ipacket_t *ipacket, unsigned index) {
    protocol_instance_t * configured_protocol = &(ipacket->mmt_handler)
            ->configured_protocols[ipacket->proto_hierarchy->proto_path[index]];
    return (ftp_control_session_t*)configured_protocol->args;
}
