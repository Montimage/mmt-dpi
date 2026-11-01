#include "plugin_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ftp.h"

/*
 * proto_ftp.c — the FTP dissector: classification, session-data analysis
 * and registration. Issue #544 split it by concern; ftp.h declares what
 * the units share:
 *   proto_ftp_session.c  connection tuple and session structure lifecycles
 *   proto_ftp_parse.c    command and reply parsing
 *   proto_ftp_addr.c     PORT/EPRT/LPRT and 227/228/229 address parameters
 *   proto_ftp_extract.c  attribute extractors and the attribute table
 */

/* Classification state of the FTP classifier (moved from ftp.h, issue #544:
 * ftp.h is shared by every proto_ftp*.c unit, these are proto_ftp.c's). */
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static uint32_t ftp_connection_timeout = MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;

/* Effective number of payload bytes that may be read at the protocol offset.
 * payload_packet_len derives from the IP total length and can exceed the
 * captured bytes on truncated pcaps, so it is clamped to caplen - offset
 * (F-BUG-069/F-BUG-107, #195). Returns 0 — and stores -1 in offset_out — when
 * the protocol offset is not inside the captured data. */
uint32_t ftp_effective_payload_len(const ipacket_t *ipacket, unsigned proto_index, int *offset_out){
    int offset = get_packet_offset_at_index(ipacket, proto_index);
    if( offset_out != NULL ) *offset_out = offset;
    uint32_t avail = 0;
    if( offset >= 0 && (size_t)offset < ipacket->p_hdr->caplen )
        avail = (uint32_t)(ipacket->p_hdr->caplen - (size_t)offset);
    uint32_t len = ipacket->internal_packet->payload_packet_len;
    return ( len > avail ) ? avail : len;
}

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

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
        if (packet->payload_packet_len > 5 &&
                (mmt_memcmp(packet->payload, "USER ", 5) == 0 ||
                 mmt_memcmp(packet->payload, "user ", 5) == 0)) {

            flow->l4.tcp.ftp_codes_seen |= FTP_USER_CMD;
            current_ftp_code = FTP_USER_CMD;
        } else if (packet->payload_packet_len >= 4 &&
                   (mmt_memcmp(packet->payload, "FEAT", 4) == 0 ||
                    mmt_memcmp(packet->payload, "feat", 4) == 0)) {

            flow->l4.tcp.ftp_codes_seen |= FTP_FEAT_CMD;
            current_ftp_code = FTP_FEAT_CMD;
        } else{
            int ret = mmt_int_check_possible_ftp_command((char*)packet->payload, packet->payload_packet_len);
            if (!ret) {
                return 0;
            }else{
                if(ret == 2){
                    flow->l4.tcp.ftp_codes_seen |= MMT_FTP_NOOP_CMD;
                    current_ftp_code = MMT_FTP_NOOP_CMD;
                }else{
                    flow->l4.tcp.ftp_codes_seen |= MMT_FTP_UNKNOWN_CMD;
                    current_ftp_code = MMT_FTP_UNKNOWN_CMD;
                }
            }  
        } 
    } else {
        if (packet->payload_packet_len > 4 &&
                (mmt_memcmp(packet->payload, "220 ", 4) == 0 ||
                 mmt_memcmp(packet->payload, "220-", 4) == 0)) {
            debug("FTP: found 220 reply code\n");
            flow->l4.tcp.ftp_codes_seen |= FTP_220_CODE;
            current_ftp_code = FTP_220_CODE;
        } else if (packet->payload_packet_len > 4 &&
                   (mmt_memcmp(packet->payload, "331 ", 4) == 0 ||
                    mmt_memcmp(packet->payload, "331-", 4) == 0)) {

            flow->l4.tcp.ftp_codes_seen |= FTP_331_CODE;
            current_ftp_code = FTP_331_CODE;
        } else if (packet->payload_packet_len > 4 &&
                   (mmt_memcmp(packet->payload, "211 ", 4) == 0 ||
                    mmt_memcmp(packet->payload, "211-", 4) == 0)) {

            flow->l4.tcp.ftp_codes_seen |= FTP_211_CODE;
            current_ftp_code = FTP_211_CODE;
        } else if (!mmt_int_check_possible_ftp_reply((char*)packet->payload, packet->payload_packet_len)) {
            if ((flow->l4.tcp.ftp_codes_seen & FTP_CODES) == 0 ||
                    (!mmt_int_check_possible_ftp_continuation_reply((char*)packet->payload, packet->payload_packet_len))) {
                return 0;
            }
        }
    }

    if (((flow->l4.tcp.ftp_codes_seen & FTP_COMMANDS) != 0 || (flow->l4.tcp.ftp_codes_seen & FTP_CODES) != 0)
        // Excluded SMTP command
        &&(packet->tcp && (packet->tcp->dest != htons(25) && packet->tcp->source != htons(25)))
        ) {

        debug("[PROTO_FTP] search_ftp: FTP detected");
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
            debug("FTP: 220 code Waiting....(1/2)");
            if (ipacket->session->data_packet_count > 40)
                return 0;
        } else {
            if (ipacket->session->data_packet_count > 20)
                return 0;
        }
    } else {
        /* wait much longer if this was a 220 code, initial messages might be long */
        if (current_ftp_code == FTP_220_CODE) {
            debug("FTP: 220 code Waiting....(2/2)");
            if (ipacket->session->data_packet_count > 20)
                return 0;
        } else {
            if (ipacket->session->data_packet_count > 10)
                return 0;
        }
    }

    return 4;
}

static void search_passive_ftp_mode(ipacket_t * ipacket) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    uint16_t plen;
    uint8_t i;
    uint32_t ftp_ip;

    /* PASV (227) carries an IPv4 address. On an IPv6 control connection
     * (packet->iph == NULL) the reply is handled like EPSV (229): the data
     * connection goes to the control connection's server address. */
    if (packet->payload_packet_len > 3 && mmt_mem_cmp(packet->payload, "227 ", 4) == 0) {

        plen = 4; //=4 for "227 "
        while (1) {
            if (plen >= packet->payload_packet_len) {
                return;
            }
            if (packet->payload[plen] == '(') {
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
                return;
            }
            if (packet->payload[plen] != ',') {

                return;
            }
            plen++;

        }
        if (dst != NULL) {
            if (packet->iph != NULL)
                dst->ftp_ip.ipv4 = htonl(ftp_ip);
            else
                mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
        }
        if (src != NULL) {
            mmt_get_destination_ip_from_packet(packet, &src->ftp_ip);
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
        }
        return;
    }

    if (packet->payload_packet_len > 34 && mmt_mem_cmp(packet->payload, "229 Entering Extended Passive Mode", 34) == 0) {
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
        }
        if (src != NULL) {
            mmt_get_destination_ip_from_packet(packet, &src->ftp_ip);
            src->ftp_timer = packet->tick_timestamp;
            src->ftp_timer_set = 1;
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
        }
        if (dst != NULL) {
            mmt_get_source_ip_from_packet(packet, &dst->ftp_ip);
            dst->ftp_timer = packet->tick_timestamp;
            dst->ftp_timer_set = 1;
        }
    }
    return;
}

int mmt_check_ftp(ipacket_t * ipacket, unsigned index) {
    // debug("[PROTO_FTP] mmt_check_ftp on packet: %lu, index: %d",ipacket->packet_id,index);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            ) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
        struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

        if (src != NULL && mmt_compare_packet_destination_ip_to_given_ip(packet, &src->ftp_ip)
                && packet->tcp->syn != 0 && packet->tcp->ack == 0
                && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                && MMT_HOST_HAS_PROTOCOL(src, PROTO_FTP) != 0 && src->ftp_timer_set != 0) {

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - src->ftp_timer)) >= ftp_connection_timeout) {
                src->ftp_timer_set = 0;
            } else if (ntohs(packet->tcp->dest) > 1024
                       && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                debug("[PROTO_FTP] mmt_check_ftp: detected FTP data stream (0)");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }

        if (dst != NULL && mmt_compare_packet_source_ip_to_given_ip(packet, &dst->ftp_ip)
                && packet->tcp->syn != 0 && packet->tcp->ack == 0
                && packet->detected_protocol_stack[0] == PROTO_UNKNOWN
                && MMT_HOST_HAS_PROTOCOL(dst, PROTO_FTP) != 0 && dst->ftp_timer_set != 0) {

            if (((MMT_INTERNAL_TIMESTAMP_TYPE)
                    (packet->tick_timestamp - dst->ftp_timer)) >= ftp_connection_timeout) {
                dst->ftp_timer_set = 0;

            } else if (ntohs(packet->tcp->dest) > 1024
                       && (ntohs(packet->tcp->source) > 1024 || ntohs(packet->tcp->source) == 20)) {
                debug("[PROTO_FTP] mmt_check_ftp: detected FTP data stream (1)");
                mmt_int_ftp_add_connection(ipacket);
                return 1;
            }
        }
        // ftp data asymmetrically

        /* skip packets without payload */
        if (packet->payload_packet_len == 0) {
            return 0;
        }
        /* skip excluded connections */

        // we test for FTP connection and search for passive mode
        if (packet->detected_protocol_stack[0] == PROTO_FTP) {
            search_passive_ftp_mode(ipacket);

            search_active_ftp_mode(ipacket);
            return 1;
        }

        if (packet->detected_protocol_stack[0] == PROTO_UNKNOWN && search_ftp(ipacket) != 0) {
            return 4;
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_FTP);

    }
    return 0;
}

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////
/**
 * Analysis a request packet
 * @param ipacket     packet to analysis
 * @param index       protocol index
 * @param ftp_control FTP control connection session
 */
void ftp_request_packet(ipacket_t *ipacket, unsigned index, ftp_control_session_t * ftp_control) {
    debug("FTP: FTP_REQUEST PACKET: %lu", ipacket->packet_id);

    int offset = get_packet_offset_at_index(ipacket, index);

    /* Clamp the IP-derived length to the captured bytes and validate the
     * offset before touching payload (F-BUG-069/F-BUG-107, #195). */
    uint32_t payload_len = ftp_effective_payload_len(ipacket, index, NULL);
    if (payload_len == 0) {
        return ;
    }
    char *payload = (char*)&ipacket->data[offset];
    if (payload[0] == '\0') {
        return ;
    }

    ftp_command_t * command = ftp_get_command(payload, payload_len);
    if (command == NULL) {
        return ;
    }

    if (ftp_control->last_command != NULL) {
        free_ftp_command(ftp_control->last_command);
    }

    ftp_control->last_command = command;
    ftp_data_session_t *current_data_session = ftp_control->current_data_session;
    /* A previous 226-reset under OOM can leave this NULL — the switch below
     * dereferences it unconditionally (#195). */
    if (current_data_session == NULL) {
        return ;
    }
    switch (command->cmd) {
    case MMT_FTP_EPRT_CMD:
        current_data_session->data_conn_mode = MMT_FTP_DATA_ACTIVE_MODE;
        if(current_data_session->data_conn->is_ipv6==1){
            char *ipv6_address_from_EPRT = ftp_get_data_client_addr_v6_from_EPRT(payload, payload_len);
            current_data_session->data_conn->c_addr_v6 = (char*)calloc(33, sizeof(char));
            if (current_data_session->data_conn->c_addr_v6!=NULL){
                /* Bounded copy into the fixed 33-byte buffer: an EPRT address
                 * field longer than 32 chars must not overflow it. Always leave
                 * a valid NUL-terminated string, even on malformed input. */
                snprintf(current_data_session->data_conn->c_addr_v6, 33, "%s",
                         ipv6_address_from_EPRT != NULL ? ipv6_address_from_EPRT : "");
            }
            free(ipv6_address_from_EPRT);
        }else{
            current_data_session->data_conn->c_addr = ftp_get_data_client_addr_from_EPRT(payload, payload_len);
        }
        current_data_session->data_conn->c_port = ftp_get_data_client_port_from_EPRT(payload, payload_len);    
        break;
    case MMT_FTP_PORT_CMD:
        current_data_session->data_conn_mode = MMT_FTP_DATA_ACTIVE_MODE;
        if(current_data_session->data_conn->is_ipv6==1){
            mmt_debug_log("[PROTO_FTP] ftp_request_packet: MMT_FTP_PORT_CMD for IPv6 is not implemented yet! %"PRIu64"\n",ipacket->packet_id);
            // strcpy(&current_data_session->data_conn->c_addr_v6,ftp_get_addr_v6_from_parameter(payload,payload_len));
        }else{
            /* payload + 5 skips the "PORT " prefix — the length must shrink
             * by the same amount or the bounded scan over-reads (#195). */
            current_data_session->data_conn->c_addr = ftp_get_addr_from_parameter(payload + 5,
                    (payload_len > 5) ? payload_len - 5 : 0);
        }
        current_data_session->data_conn->c_port = ftp_get_port_from_parameter(payload, payload_len);
        break;
    case MMT_FTP_LPRT_CMD:
        current_data_session->data_conn_mode = MMT_FTP_DATA_ACTIVE_MODE;
        if(current_data_session->data_conn->is_ipv6==1){
            char *ipv6_address_from_LPRT = ftp_get_data_client_addr_v6_from_LPRT(payload, payload_len);
            debug("[PROTO_FTP] %lu ipv6_address_from_LPRT: %s",ipacket->packet_id,ipv6_address_from_LPRT);
            current_data_session->data_conn->c_addr_v6 = (char*)calloc(33, sizeof(char));
            if (current_data_session->data_conn->c_addr_v6 !=NULL){
                /* Bounded copy into the fixed 33-byte buffer. Always leave a
                 * valid NUL-terminated string, even on malformed input. */
                snprintf(current_data_session->data_conn->c_addr_v6, 33, "%s",
                         ipv6_address_from_LPRT != NULL ? ipv6_address_from_LPRT : "");
            }
            free(ipv6_address_from_LPRT);
        }else{
            mmt_debug_log("[PROTO_FTP] ftp_request_packet: MMT_FTP_LPRT_CMD for IPv4 is not implemented yet! %"PRIu64"\n",ipacket->packet_id);
        }
        current_data_session->data_conn->c_port = ftp_get_data_client_port_from_LPRT(payload, payload_len);
        debug("[PROTO_FTP] %lu current_data_session->data_conn->c_port: %d",ipacket->packet_id,current_data_session->data_conn->c_port);
        break;
    case MMT_FTP_USER_CMD:
        if (ftp_control->user->username != NULL) {
            free(ftp_control->user->username);
        }

        ftp_control->user->username = str_copy(command->param);
        ftp_control->status = MMT_FTP_STATUS_OPENED;
        break;
    case MMT_FTP_PASS_CMD:

        if (ftp_control->user->password != NULL) {
            free(ftp_control->user->password);
        }
        ftp_control->user->password = str_copy(command->param);
        break;
    case MMT_FTP_TYPE_CMD:
        if (current_data_session->data_transfer_type != NULL) {
            free(current_data_session->data_transfer_type);
        }
        current_data_session->data_transfer_type = str_copy(command->param);
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
        if (current_data_session->file->name != NULL) {
            free(current_data_session->file->name);
        }
        current_data_session->file->name = str_copy(command->param);
        current_data_session->data_direction = MMT_FTP_DATA_DOWNLOAD;
        current_data_session->data_type  = MMT_FTP_DATA_TYPE_FILE;
        break;
    case MMT_FTP_STOR_CMD:
    case MMT_FTP_STOU_CMD:
        if (current_data_session->file->name != NULL) {
            free(current_data_session->file->name);
        }
        current_data_session->file->name = str_copy(command->param);
        current_data_session->data_direction = MMT_FTP_DATA_UPLOAD;
        current_data_session->data_type  = MMT_FTP_DATA_TYPE_FILE;
        break;
    case MMT_FTP_SYST_CMD:
        if (ftp_control->session_syst != NULL) {
            free(ftp_control->session_syst);
        }
        ftp_control->session_syst = str_copy(command->param);
        break;

    default:
        debug("FTP: Client command: \n");
        debug("Command: %s\n", command->str_cmd);
        if (command->param) {
            debug("Parameter: %s\n", command->param);
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
void ftp_response_packet(ipacket_t *ipacket, unsigned index, ftp_control_session_t *ftp_control) {
    debug("FTP: FTP_RESPONSE PACKET: %lu", ipacket->packet_id);

    int offset = get_packet_offset_at_index(ipacket, index);

    /* Clamp the IP-derived length to the captured bytes and validate the
     * offset before touching payload (F-BUG-069/F-BUG-107, #195). */
    uint32_t payload_len = ftp_effective_payload_len(ipacket, index, NULL);
    if (payload_len == 0) {
        return ;
    }
    char *payload = (char*)&ipacket->data[offset];
    if (payload[0] == '\0') {
        return ;
    }

    ftp_response_t * response = ftp_get_response(payload, payload_len);
    if (response == NULL) {
        return ;
    }

    if (ftp_control->last_response != NULL) {
        free_ftp_response(ftp_control->last_response);
    }

    ftp_control->last_response = response;
    ftp_data_session_t *current_data_session = ftp_control->current_data_session;
    /* A previous 226-reset under OOM can leave this NULL — the switch below
     * dereferences it unconditionally (#195). */
    if (current_data_session == NULL) {
        return ;
    }
    char *mstr = NULL;
    if (response->code != MMT_FTP_UNKNOWN_CODE) {
        debug("FTP: %s", response->value);
        switch (response->code) {
        case MMT_FTP_230_CODE:
            ftp_control->status = MMT_FTP_STATUS_CONTROLING;
            break;
        case MMT_FTP_CONTINUE_CODE:
            mstr = str_combine(ftp_control->session_feats, response->value);
            if (ftp_control->session_feats != NULL) {
                free(ftp_control->session_feats);
            }
            ftp_control->session_feats = mstr;
            break;
        case MMT_FTP_257_CODE:
            if (ftp_control->current_dir != NULL) {
                free(ftp_control->current_dir);
            }
            ftp_control->current_dir = str_copy(response->value);
            break;
        case MMT_FTP_213_CODE:
            if (ftp_control->last_command != NULL && ftp_control->last_command->cmd == MMT_FTP_MDTM_CMD) {
                if (current_data_session->file->last_modified != NULL) {
                    free(current_data_session->file->last_modified);
                }
                current_data_session->file->last_modified = str_copy(response->value);
            } else if (ftp_control->last_command != NULL && ftp_control->last_command->cmd == MMT_FTP_SIZE_CMD) {
                /* A short reply (e.g. "213 \r\n") leaves response->value NULL —
                 * atoi(NULL) would dereference it (#195). */
                current_data_session->file->size = (response->value != NULL) ? atoi(response->value) : 0;
            }
            break;
        case MMT_FTP_229_CODE:
            current_data_session->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
            ftp_tuple6_t * t6 = ftp_new_tuple6();
            if (t6 == NULL) break;
            t6->s_port = ftp_get_data_server_port_code_229(response->value,
                    (response->value != NULL) ? (uint32_t)strlen(response->value) : 0);
            t6->s_addr = ftp_control->contrl_conn->s_addr;
            t6->c_addr = ftp_control->contrl_conn->c_addr;
            t6->conn_type = MMT_FTP_DATA_CONNECTION;
            t6->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
            if (current_data_session->data_conn != NULL) {
                free_ftp_tuple6(current_data_session->data_conn);
            }
            current_data_session->data_conn = t6;
            break;
        case MMT_FTP_227_CODE:
            current_data_session->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
            current_data_session->data_conn->s_addr = ftp_get_data_server_addr_code_227(payload, payload_len);
            current_data_session->data_conn->s_port = ftp_get_data_server_port_code_227(payload, payload_len);
            current_data_session->data_conn->c_addr = ftp_control->contrl_conn->c_addr;
            break;
        case MMT_FTP_228_CODE:
            current_data_session->data_conn_mode = MMT_FTP_DATA_PASSIVE_MODE;
            ftp_tuple6_t * t62 = ftp_new_tuple6();
            if (t62 == NULL) break;
            t62->s_port = ftp_get_data_server_port_code_228(response->value,
                    (response->value != NULL) ? (uint32_t)strlen(response->value) : 0);
            t62->s_addr = ftp_get_data_server_addr_code_228(response->value,
                    (response->value != NULL) ? (uint32_t)strlen(response->value) : 0);
            t62->c_addr = ftp_control->contrl_conn->c_addr;
            t62->conn_type = MMT_FTP_DATA_CONNECTION;
            t62->direction = MMT_FTP_PACKET_UNKNOWN_DIRECTION;
            if (current_data_session->data_conn != NULL) {
                free_ftp_tuple6(current_data_session->data_conn);
            }
            current_data_session->data_conn = t62;
            break;
        case MMT_FTP_150_CODE:
            ftp_control->status = MMT_FTP_STATUS_DATA_OPENED;
            break;
        case MMT_FTP_226_CODE:
            ftp_control->status = MMT_FTP_STATUS_DATA_CLOSED;
            debug("FTP: Data has transferred completed -> Going to reset data connection");
            /* Reset in place, never free: data flows still point at this
             * object through their session_data[] (issue #487). */
            if (current_data_session->data_conn != NULL) {
                (void) ftp_reset_data_session(current_data_session);
            }
            break;
        case MMT_FTP_221_CODE:
            ftp_control->status = MMT_FTP_STATUS_CLOSED;
            break;
        case MMT_FTP_215_CODE:
            if (ftp_control->session_syst != NULL) {
                free(ftp_control->session_syst);
            }
            ftp_control->session_syst = str_copy(response->value);
            break;
        default:
            debug("FTP: code : %d\n", response->code);
            debug("FTP: value : %s\n", response->value);
            break;
        }
    } else {
        debug("FTP: Received a response code:\n");
        debug("Code: %d\n", response->code);
        debug("Value : %s\n", response->value);
    }
}

/* Issue #563: list nodes the data-connection lookups examine, counted only
 * in the resource_bounds build (-DMMT_FTP_LIST_STATS). */
#ifdef MMT_FTP_LIST_STATS
uint64_t mmt_ftp_list_visits;
#define FTP_LIST_VISIT() (mmt_ftp_list_visits++)
#else
#define FTP_LIST_VISIT() ((void) 0)
#endif

/**
 * Analysis packet data
 * @param  ipacket packet to analysis
 * @param  index   protocol index
 * @return         MMT_CONTINUE
 *                 MMT_SKIP
 *                 MMT_DROP
 */
int ftp_session_data_analysis(ipacket_t * ipacket, unsigned index) {

    debug("FTP: START ANALYSING SESSION DATA OF PACKET: %lu", ipacket->packet_id);

    // Make sure there is data to analayse
    if (ipacket->internal_packet->payload_packet_len == 0) {
        debug("There is no FTP data to analysis: %lu\n", ipacket->packet_id);
        return MMT_CONTINUE;
    }

    /* Issue #563: every return below releases the tuple with
     * free_ftp_tuple6() — free() alone leaked an IPv6 tuple's two address
     * buffers on every packet. */
    ftp_tuple6_t *tuple6 = ftp_get_tuple6(ipacket);

    if(tuple6==NULL){
        debug("[PROTO_FTP] ftp_session_data_analysis: cannot get tuple6 of packet: %lu\n", ipacket->packet_id);
        return MMT_CONTINUE;
    }

    ftp_context_t *ctx = ftp_get_context(ipacket, index);
    if (ctx == NULL) {
        free_ftp_tuple6(tuple6);
        return MMT_CONTINUE;
    }
    ftp_control_session_t *live = &ctx->live;   // sentinel of the live list
    ftp_control_session_t *ftp_control = NULL;
    ftp_data_session_t *ftp_data = NULL;
    if (tuple6->conn_type == MMT_FTP_CONTROL_CONNECTION) {
        if (ipacket->session->session_data[index]) {
            ftp_control = (ftp_control_session_t*)ipacket->session->session_data[index];
            int compare = 0;
            if(ftp_control->contrl_conn == NULL){
                free_ftp_tuple6(tuple6);
                return MMT_CONTINUE;
            }
            compare = ftp_compare_tuple6(tuple6, ftp_control->contrl_conn);
            if (compare == 0) {
                // mmt_debug_log( "FTP: Not correct control connection\n");
                free_ftp_tuple6(tuple6);
                return MMT_CONTINUE;
            } else {
                ftp_control->contrl_conn->direction = tuple6->direction;
            }
        } else {
            ftp_control = ftp_new_control_session(tuple6);
            /* Issue #563 (F-PERF-106): O(1) tail append; the session leaves
             * the list when its flow expires (ftp_session_data_cleanup). */
            ftp_context_link(ctx, ftp_control);
            ipacket->session->session_data[index] = ftp_control;
        }
    } else {
        if (ipacket->session->session_data[index]) {
            ftp_data = (ftp_data_session_t*)ipacket->session->session_data[index];
            int compare = ftp_compare_tuple6(tuple6, ftp_data->data_conn);
            if (compare != 0) {
                ftp_set_tuple6_direction(tuple6, ftp_data->data_conn, compare);
            } else {
                ftp_control_session_t *temp = live->next;
                while (temp != live && temp->current_data_session) {
                    FTP_LIST_VISIT();
                    int compare = ftp_compare_tuple6(tuple6, temp->current_data_session->data_conn);
                    if (compare != 0) {
                        ftp_set_tuple6_direction(tuple6, temp->current_data_session->data_conn, compare);
                        ftp_data_attach(ipacket->session, index, temp->current_data_session);
                        ftp_data = temp->current_data_session;
                        break;
                    }
                    temp = temp->next;
                }
                if (temp == live || temp->current_data_session == NULL) {
                    /* The transfer this flow belonged to has ended — its data
                     * session was reset for the next one (226): detach rather
                     * than attribute this flow to that next transfer. */
                    ftp_data_attach(ipacket->session, index, NULL);
                    ftp_data = NULL;
                }
            }
        } else {
            // New not FTP control packet
            if (live->next == live) {
                // mmt_debug_log( "FTP: Cannot find any control connection\n");
                free_ftp_tuple6(tuple6);   // issue #563: was leaked on this return
                return MMT_CONTINUE;
            } else {
                ftp_control_session_t *temp = live->next;
                while (temp != live && temp->current_data_session) {
                    FTP_LIST_VISIT();
                    int compare = ftp_compare_tuple6(tuple6, temp->current_data_session->data_conn);
                    if (compare != 0) {
                        ftp_set_tuple6_direction(tuple6, temp->current_data_session->data_conn, compare);
                        ftp_data_attach(ipacket->session, index, temp->current_data_session);
                        ftp_data = temp->current_data_session;
                        break;
                    }
                    temp = temp->next;
                }
            }
        }
    }

    if (tuple6->conn_type == MMT_FTP_CONTROL_CONNECTION && tuple6->direction == MMT_FTP_PACKET_SERVER && ftp_control) {
        ftp_response_packet(ipacket, index, ftp_control);
    } else if (tuple6->conn_type == MMT_FTP_CONTROL_CONNECTION && tuple6->direction == MMT_FTP_PACKET_CLIENT && ftp_control) {
        ftp_request_packet(ipacket, index, ftp_control);
    } else if (tuple6->conn_type == MMT_FTP_DATA_CONNECTION && ftp_data) {
        debug("Reconstruct data packet of packet: %lu\n", ipacket->packet_id);
        ftp_data->data_conn->ip_session_id = tuple6->ip_session_id;
        // ftp_data_packet(ipacket,index,ftp_data);
    } else {
        debug("Cannot analysis data of packet: %lu\n", ipacket->packet_id);
        debug("Connection type: %d\n", tuple6->conn_type);
        debug("Connection direction: %d\n", tuple6->direction);
    }

    // Finished working with tuple6
    free_ftp_tuple6(tuple6);

    return MMT_CONTINUE;
}

///////////////////////////////// SESSION DATA ANALYSE ////////////////////////////////////////

void * setup_ftp_context(void * proto_context, void * args) {
    /* Issue #563: the live and retired control-session lists (ftp.h). */
    return (void*)ftp_new_context();
}

/**
 * Release the per-handler FTP protocol context allocated by setup_ftp_context().
 *
 * The context holds the control-session lists stored in the protocol
 * instance's "args" field (see ftp_get_context()). The lists and everything
 * they own (per-session str_copy/str_combine strings, user
 * credentials, file metadata, connection tuples, ...) are released here on
 * handler teardown. Without this, mmt_close_handler() left the whole tree
 * leaked (Valgrind: 80B definitely + 933B indirectly lost). The signature
 * matches generic_proto_context_cleanup_function: proto_context is the
 * protocol_instance_t* and the allocated context lives at its ->args field.
 */
void cleanup_ftp_context(void * proto_context, void * args) {
    if (proto_context == NULL) return;
    protocol_instance_t * configured_protocol = (protocol_instance_t *) proto_context;
    ftp_context_t * ctx = (ftp_context_t *) configured_protocol->args;
    if (ctx != NULL) {
        ftp_free_context(ctx);
        configured_protocol->args = NULL;
    }
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ftp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_FTP, PROTO_FTP_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < FTP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ftp_attributes_metadata[i]);
        }
        register_proto_context_init_cleanup_function(protocol_struct, setup_ftp_context, cleanup_ftp_context, NULL);
        register_session_data_analysis_function(protocol_struct, ftp_session_data_analysis);
        /* Issue #563: unlink a control session when its flow expires. */
        register_session_data_cleanup_function(protocol_struct, ftp_session_data_cleanup);
        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION,
                PROTO_FTP, PROTO_FTP);

        return register_protocol(protocol_struct, PROTO_FTP);
    } else {
        return 0;
    }
}
