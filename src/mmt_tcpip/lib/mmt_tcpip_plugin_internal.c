#include "mmt_common_internal_include.h"

void mmt_add_content_type(ipacket_t * ipacket, uint16_t content_class, uint16_t content_type) {
    if (ipacket->session) {
        ipacket->session->content_info.content_class = content_class;
        ipacket->session->content_info.content_type = content_type;
    }

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (packet) {
        packet->content_info.content_class = content_class;
        packet->content_info.content_type = content_type;
    }
}

void mmt_internal_add_connection(ipacket_t * ipacket, uint16_t detected_protocol, mmt_protocol_type_t protocol_type) {
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;

    mmt_change_internal_flow_packet_protocol(ipacket, detected_protocol, protocol_type);

    if (src != NULL) {
        MMT_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, detected_protocol);
    }
    if (dst != NULL) {
        MMT_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, detected_protocol);
    }
}

void mmt_change_internal_flow_protocol(ipacket_t * ipacket, uint16_t detected_protocol, mmt_protocol_type_t protocol_type) {
    struct mmt_internal_tcpip_session_struct *flow = ipacket->internal_packet->flow;
#if PROTOCOL_HISTORY_SIZE > 1
    uint8_t a;
    uint8_t stack_size;
    uint16_t new_is_real = 0;
    uint16_t preserve_bitmask;
#endif

    if (!flow)
        return;

#if PROTOCOL_HISTORY_SIZE > 1
    stack_size = flow->protocol_stack_info.current_stack_size_minus_one + 1;

    /* here are the rules for stack manipulations:
     * 1.if the new protocol is a real protocol, insert it at the position
     *   of the top-most real protocol or below the last non-unknown correlated
     *   protocol.
     * 2.if the new protocol is not real, put it on top of stack but if there is
     *   a real protocol in the stack, make sure at least one real protocol remains
     *   in the stack
     */

    if (protocol_type == MMT_CORRELATED_PROTOCOL) {
        uint16_t saved_real_protocol = PROTO_UNKNOWN;

        if (stack_size == PROTOCOL_HISTORY_SIZE) {
            /* check whether we will lost real protocol information due to shifting */
            uint16_t real_protocol = flow->protocol_stack_info.entry_is_real_protocol;

            for (a = 0; a < stack_size; a++) {
                if (real_protocol & 1)
                    break;
                real_protocol >>= 1;
            }

            if (a == (stack_size - 1)) {
                /* oh, only one real protocol at the end, store it and insert it later */
                saved_real_protocol = flow->detected_protocol_stack[stack_size - 1];
            }
        } else {
            flow->protocol_stack_info.current_stack_size_minus_one++;
            stack_size++;
        }

        /* now shift and insert */
        for (a = stack_size - 1; a > 0; a--) {
            flow->detected_protocol_stack[a] = flow->detected_protocol_stack[a - 1];
        }

        flow->protocol_stack_info.entry_is_real_protocol <<= 1;

        /* now set the new protocol */

        flow->detected_protocol_stack[0] = detected_protocol;

        /* restore real protocol */
        if (saved_real_protocol != PROTO_UNKNOWN) {
            flow->detected_protocol_stack[stack_size - 1] = saved_real_protocol;
            flow->protocol_stack_info.entry_is_real_protocol |= 1 << (stack_size - 1);
        }
        /* done */
    } else {
        uint8_t insert_at = 0;

        if (!(flow->protocol_stack_info.entry_is_real_protocol & 1)) {
            uint16_t real_protocol = flow->protocol_stack_info.entry_is_real_protocol;

            for (a = 0; a < stack_size; a++) {
                if (real_protocol & 1)
                    break;
                real_protocol >>= 1;
            }

            insert_at = a;
        }

        if (insert_at >= stack_size) {
            /* no real protocol found, insert it at the bottom */

            insert_at = stack_size - 1;
        }

        if (stack_size < PROTOCOL_HISTORY_SIZE) {
            flow->protocol_stack_info.current_stack_size_minus_one++;
            stack_size++;
        }

        /* first shift all stacks */
        for (a = stack_size - 1; a > insert_at; a--) {
            flow->detected_protocol_stack[a] = flow->detected_protocol_stack[a - 1];
        }

        preserve_bitmask = (1 << insert_at) - 1;

        new_is_real = (flow->protocol_stack_info.entry_is_real_protocol & (~preserve_bitmask)) << 1;
        new_is_real |= flow->protocol_stack_info.entry_is_real_protocol & preserve_bitmask;

        flow->protocol_stack_info.entry_is_real_protocol = new_is_real;

        /* now set the new protocol */

        flow->detected_protocol_stack[insert_at] = detected_protocol;

        /* and finally update the additional stack information */

        flow->protocol_stack_info.entry_is_real_protocol |= 1 << insert_at;
    }
#else
    flow->detected_protocol_stack[0] = detected_protocol;
    flow->detected_subprotocol_stack[0] = detected_subprotocol;
#endif
}

void mmt_change_internal_packet_protocol(ipacket_t * ipacket, uint16_t detected_protocol, mmt_protocol_type_t protocol_type) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    /* NOTE: everything below is identically to change_flow_protocol
     *        except flow->packet If you want to change something here,
     *        don't! Change it for the flow function and apply it here
     *        as well */
#if PROTOCOL_HISTORY_SIZE > 1
    uint8_t a;
    uint8_t stack_size;
    uint16_t new_is_real = 0;
    uint16_t preserve_bitmask;
#endif

    if (!packet)
        return;

#if PROTOCOL_HISTORY_SIZE > 1
    stack_size = packet->protocol_stack_info.current_stack_size_minus_one + 1;

    /* here are the rules for stack manipulations:
     * 1.if the new protocol is a real protocol, insert it at the position
     *   of the top-most real protocol or below the last non-unknown correlated
     *   protocol.
     * 2.if the new protocol is not real, put it on top of stack but if there is
     *   a real protocol in the stack, make sure at least one real protocol remains
     *   in the stack
     */

    if (protocol_type == MMT_CORRELATED_PROTOCOL) {
        uint16_t saved_real_protocol = PROTO_UNKNOWN;

        if (stack_size == PROTOCOL_HISTORY_SIZE) {
            /* check whether we will lost real protocol information due to shifting */
            uint16_t real_protocol = packet->protocol_stack_info.entry_is_real_protocol;

            for (a = 0; a < stack_size; a++) {
                if (real_protocol & 1)
                    break;
                real_protocol >>= 1;
            }

            if (a == (stack_size - 1)) {
                /* oh, only one real protocol at the end, store it and insert it later */
                saved_real_protocol = packet->detected_protocol_stack[stack_size - 1];
            }
        } else {
            packet->protocol_stack_info.current_stack_size_minus_one++;
            stack_size++;
        }

        /* now shift and insert */
        for (a = stack_size - 1; a > 0; a--) {
            packet->detected_protocol_stack[a] = packet->detected_protocol_stack[a - 1];
        }

        packet->protocol_stack_info.entry_is_real_protocol <<= 1;

        /* now set the new protocol */

        packet->detected_protocol_stack[0] = detected_protocol;

        /* restore real protocol */
        if (saved_real_protocol != PROTO_UNKNOWN) {
            packet->detected_protocol_stack[stack_size - 1] = saved_real_protocol;
            packet->protocol_stack_info.entry_is_real_protocol |= 1 << (stack_size - 1);
        }
        /* done */
    } else {
        uint8_t insert_at = 0;

        if (!(packet->protocol_stack_info.entry_is_real_protocol & 1)) {
            uint16_t real_protocol = packet->protocol_stack_info.entry_is_real_protocol;

            for (a = 0; a < stack_size; a++) {
                if (real_protocol & 1)
                    break;
                real_protocol >>= 1;
            }

            insert_at = a;
        }

        if (insert_at >= stack_size) {
            /* no real protocol found, insert it at the first unknown protocol */

            insert_at = stack_size - 1;
        }

        if (stack_size < PROTOCOL_HISTORY_SIZE) {
            packet->protocol_stack_info.current_stack_size_minus_one++;
            stack_size++;
        }

        /* first shift all stacks */
        for (a = stack_size - 1; a > insert_at; a--) {
            packet->detected_protocol_stack[a] = packet->detected_protocol_stack[a - 1];
        }

        preserve_bitmask = (1 << insert_at) - 1;

        new_is_real = (packet->protocol_stack_info.entry_is_real_protocol & (~preserve_bitmask)) << 1;
        new_is_real |= packet->protocol_stack_info.entry_is_real_protocol & preserve_bitmask;

        packet->protocol_stack_info.entry_is_real_protocol = new_is_real;

        /* now set the new protocol */

        packet->detected_protocol_stack[insert_at] = detected_protocol;

        /* and finally update the additional stack information */

        packet->protocol_stack_info.entry_is_real_protocol |= 1 << insert_at;
    }
#else
    packet->detected_protocol_stack[0] = detected_protocol;
    packet->detected_subprotocol_stack[0] = detected_subprotocol;
#endif
}

unsigned int mmt_get_protocol_by_port_number(uint8_t proto,
        uint32_t shost, uint16_t sport,
        uint32_t dhost, uint16_t dport) {
    if (proto == IPPROTO_UDP) {
        if (MMT_PORT_MATCH(sport, dport, 67) || MMT_PORT_MATCH(sport, dport, 68)) return (PROTO_DHCP);
        else if (MMT_PORT_MATCH(sport, dport, 137) || MMT_PORT_MATCH(sport, dport, 138)) return (PROTO_NETBIOS);
        else if (MMT_PORT_MATCH(sport, dport, 161) || MMT_PORT_MATCH(sport, dport, 162)) return (PROTO_SNMP);
        else if (MMT_PORT_MATCH(sport, dport, 5353) || MMT_PORT_MATCH(sport, dport, 5354)) return (PROTO_MDNS);
        else if (MMT_PORT_MATCH(sport, dport, 53)) return (PROTO_DNS);
        // else if (MMT_PORT_MATCH(sport, dport, 270)) return (PROTO_GIST); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 271)) return (PROTO_PT_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 323)) return (PROTO_RPKI_RTR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 324)) return (PROTO_RPKI_RTR_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 456)) return (PROTO_MACON_UDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 465)) return (PROTO_IGMPV3LITE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 474)) return (PROTO_TN_TL_W2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 512)) return (PROTO_COMSAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 512)) return (PROTO_BIFF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 513)) return (PROTO_WHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 520)) return (PROTO_ROUTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 623)) return (PROTO_ASF_RMCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 664)) return (PROTO_ASF_SECURE_RMCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 716)) return (PROTO_PANA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 750)) return (PROTO_LOADAV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 750)) return (PROTO_KERBEROS_IV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 773)) return (PROTO_NOTIFY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 774)) return (PROTO_ACMAINT_DBD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 775)) return (PROTO_ACMAINT_TRANSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 998)) return (PROTO_PUPARP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 999)) return (PROTO_APPLIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 514)) return (PROTO_SYSLOG);//-was generated automatically by MMTCrawler - @luongnv89 -
        else if (MMT_PORT_MATCH(sport, dport, 88)) return (PROTO_KERBEROS);
    } else if (proto == IPPROTO_TCP) {
        if (MMT_PORT_MATCH(sport, dport, 443)) return (PROTO_SSL);
        else if (MMT_PORT_MATCH(sport, dport, 22)) return (PROTO_SSH);
        else if (MMT_PORT_MATCH(sport, dport, 23)) return (PROTO_TELNET);
        else if (MMT_PORT_MATCH(sport, dport, 445)) return (PROTO_SMB);
        else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_HTTP);
        else if (MMT_PORT_MATCH(sport, dport, 3000)) return (PROTO_HTTP);
        else if (MMT_PORT_MATCH(sport, dport, 3001)) return (PROTO_SSL);
        else if (MMT_PORT_MATCH(sport, dport, 8080) || MMT_PORT_MATCH(sport, dport, 3128)) return (PROTO_HTTP_PROXY);
        else if (MMT_PORT_MATCH(sport, dport, 389)) return (PROTO_LDAP);
        else if (MMT_PORT_MATCH(sport, dport, 143) || MMT_PORT_MATCH(sport, dport, 993)) return (PROTO_IMAP);
        else if (MMT_PORT_MATCH(sport, dport, 25) || MMT_PORT_MATCH(sport, dport, 465)) return (PROTO_SMTP);
        else if (MMT_PORT_MATCH(sport, dport, 135)) return (PROTO_DCERPC);
        else if (MMT_PORT_MATCH(sport, dport, 1494) || MMT_PORT_MATCH(sport, dport, 2598)) return (PROTO_CITRIX); /* http://support.citrix.com/article/CTX104147 */
        else if (MMT_PORT_MATCH(sport, dport, 389)) return (PROTO_LDAP);
        else if (MMT_PORT_MATCH(sport, dport, 88)) return (PROTO_KERBEROS);
        else if (MMT_PORT_MATCH(sport, dport, 554)) return (PROTO_RTSP); 
        // else if (MMT_PORT_MATCH(sport, dport, 1)) return (PROTO_TCPMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 2)) return (PROTO_COMPRESSNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 5)) return (PROTO_RJE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 7)) return (PROTO_ECHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 9)) return (PROTO_DISCARD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 11)) return (PROTO_SYSTAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 13)) return (PROTO_DAYTIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 17)) return (PROTO_QOTD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 18)) return (PROTO_MSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 19)) return (PROTO_CHARGEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 20)) return (PROTO_FTP_DATA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 27)) return (PROTO_NSW_FE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 29)) return (PROTO_MSG_ICP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 31)) return (PROTO_MSG_AUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 33)) return (PROTO_DSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 37)) return (PROTO_TIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 38)) return (PROTO_RAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 39)) return (PROTO_RLP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 41)) return (PROTO_GRAPHICS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 42)) return (PROTO_NAME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 42)) return (PROTO_NAMESERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 43)) return (PROTO_NICNAME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 44)) return (PROTO_MPM_FLAGS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 45)) return (PROTO_MPM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 46)) return (PROTO_MPM_SND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 47)) return (PROTO_NI_FTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 48)) return (PROTO_AUDITD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 49)) return (PROTO_TACACS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 50)) return (PROTO_RE_MAIL_CK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 52)) return (PROTO_XNS_TIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 53)) return (PROTO_DOMAIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 54)) return (PROTO_XNS_CH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 55)) return (PROTO_ISI_GL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 56)) return (PROTO_XNS_AUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 58)) return (PROTO_XNS_MAIL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 61)) return (PROTO_NI_MAIL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 62)) return (PROTO_ACAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 63)) return (PROTO_WHOISPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 63)) return (PROTO_WHOIS__); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 64)) return (PROTO_COVIA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 65)) return (PROTO_TACACS_DS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 66)) return (PROTO_SQL_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 66)) return (PROTO_SQLNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 67)) return (PROTO_BOOTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 68)) return (PROTO_BOOTPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 70)) return (PROTO_GOPHER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 71)) return (PROTO_NETRJS_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 72)) return (PROTO_NETRJS_2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 73)) return (PROTO_NETRJS_3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 74)) return (PROTO_NETRJS_4); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 76)) return (PROTO_DEOS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 78)) return (PROTO_VETTCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 79)) return (PROTO_FINGER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_WWW); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_WWW_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 82)) return (PROTO_XFER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 83)) return (PROTO_MIT_ML_DEV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 84)) return (PROTO_CTF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 86)) return (PROTO_MFCOBOL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 89)) return (PROTO_SU_MIT_TG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 90)) return (PROTO_DNSIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 91)) return (PROTO_MIT_DOV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 92)) return (PROTO_NPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 93)) return (PROTO_DCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 94)) return (PROTO_OBJCALL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 95)) return (PROTO_SUPDUP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 96)) return (PROTO_DIXIE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 97)) return (PROTO_SWIFT_RVF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 98)) return (PROTO_TACNEWS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 99)) return (PROTO_METAGRAM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 101)) return (PROTO_HOSTNAME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 102)) return (PROTO_ISO_TSAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 103)) return (PROTO_GPPITNP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 104)) return (PROTO_ACR_NEMA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 105)) return (PROTO_CSO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 105)) return (PROTO_CSNET_NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 106)) return (PROTO_3COM_TSMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 107)) return (PROTO_RTELNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 108)) return (PROTO_SNAGAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 109)) return (PROTO_POP2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 110)) return (PROTO_POP3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 111)) return (PROTO_SUNRPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 112)) return (PROTO_MCIDAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 113)) return (PROTO_IDENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 113)) return (PROTO_AUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 115)) return (PROTO_SFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 116)) return (PROTO_ANSANOTIFY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 117)) return (PROTO_UUCP_PATH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 118)) return (PROTO_SQLSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 119)) return (PROTO_NNTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 120)) return (PROTO_CFDPTKT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 121)) return (PROTO_ERPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 122)) return (PROTO_SMAKYNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 124)) return (PROTO_ANSATRADER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 125)) return (PROTO_LOCUS_MAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 126)) return (PROTO_NXEDIT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 127)) return (PROTO_LOCUS_CON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 128)) return (PROTO_GSS_XLICEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 129)) return (PROTO_PWDGEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 130)) return (PROTO_CISCO_FNA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 131)) return (PROTO_CISCO_TNA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 132)) return (PROTO_CISCO_SYS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 133)) return (PROTO_STATSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 134)) return (PROTO_INGRES_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 135)) return (PROTO_EPMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 136)) return (PROTO_PROFILE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 137)) return (PROTO_NETBIOS_NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 138)) return (PROTO_NETBIOS_DGM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 139)) return (PROTO_NETBIOS_SSN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 140)) return (PROTO_EMFIS_DATA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 141)) return (PROTO_EMFIS_CNTL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 142)) return (PROTO_BL_IDM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 144)) return (PROTO_UMA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 145)) return (PROTO_UAAC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 146)) return (PROTO_ISO_TP0); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 148)) return (PROTO_JARGON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 149)) return (PROTO_AED_512); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 151)) return (PROTO_HEMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 152)) return (PROTO_BFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 153)) return (PROTO_SGMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 154)) return (PROTO_NETSC_PROD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 155)) return (PROTO_NETSC_DEV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 156)) return (PROTO_SQLSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 157)) return (PROTO_KNET_CMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 158)) return (PROTO_PCMAIL_SRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 159)) return (PROTO_NSS_ROUTING); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 160)) return (PROTO_SGMP_TRAPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 162)) return (PROTO_SNMPTRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 163)) return (PROTO_CMIP_MAN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 164)) return (PROTO_CMIP_AGENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 165)) return (PROTO_XNS_COURIER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 166)) return (PROTO_S_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 167)) return (PROTO_NAMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 168)) return (PROTO_RSVD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 169)) return (PROTO_SEND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 170)) return (PROTO_PRINT_SRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 171)) return (PROTO_MULTIPLEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 172)) return (PROTO_CL_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 172)) return (PROTO_CL1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 173)) return (PROTO_XYPLEX_MUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 174)) return (PROTO_MAILQ); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 175)) return (PROTO_VMNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 176)) return (PROTO_GENRAD_MUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 178)) return (PROTO_NEXTSTEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 180)) return (PROTO_RIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 181)) return (PROTO_UNIFY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 182)) return (PROTO_AUDIT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 183)) return (PROTO_OCBINDER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 184)) return (PROTO_OCSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 185)) return (PROTO_REMOTE_KIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 186)) return (PROTO_KIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 187)) return (PROTO_ACI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 188)) return (PROTO_MUMPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 189)) return (PROTO_QFT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 190)) return (PROTO_GACP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 191)) return (PROTO_PROSPERO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 192)) return (PROTO_OSU_NMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 193)) return (PROTO_SRMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 195)) return (PROTO_DN6_NLM_AUD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 196)) return (PROTO_DN6_SMM_RED); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 197)) return (PROTO_DLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 198)) return (PROTO_DLS_MON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 199)) return (PROTO_SMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 200)) return (PROTO_SRC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 201)) return (PROTO_AT_RTMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 202)) return (PROTO_AT_NBP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 203)) return (PROTO_AT_3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 204)) return (PROTO_AT_ECHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 205)) return (PROTO_AT_5); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 206)) return (PROTO_AT_ZIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 207)) return (PROTO_AT_7); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 208)) return (PROTO_AT_8); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 209)) return (PROTO_QMTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 210)) return (PROTO_Z39_50); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 211)) return (PROTO_914C_G); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 211)) return (PROTO_914CG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 212)) return (PROTO_ANET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 213)) return (PROTO_IPX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 214)) return (PROTO_VMPWSCS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 215)) return (PROTO_SOFTPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 216)) return (PROTO_CAILIC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 217)) return (PROTO_DBASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 218)) return (PROTO_MPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 219)) return (PROTO_UARPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 220)) return (PROTO_IMAP3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 221)) return (PROTO_FLN_SPX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 222)) return (PROTO_RSH_SPX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 223)) return (PROTO_CDC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 224)) return (PROTO_MASQDIALER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 242)) return (PROTO_DIRECT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 243)) return (PROTO_SUR_MEAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 244)) return (PROTO_INBUSINESS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 245)) return (PROTO_LINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 246)) return (PROTO_DSP3270); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 247)) return (PROTO_SUBNTBCST_TFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 248)) return (PROTO_BHFHS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 257)) return (PROTO_SET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 259)) return (PROTO_ESRO_GEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 260)) return (PROTO_OPENPORT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 261)) return (PROTO_NSIIOPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 262)) return (PROTO_ARCISDMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 263)) return (PROTO_HDAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 264)) return (PROTO_BGMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 265)) return (PROTO_X_BONE_CTL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 266)) return (PROTO_SST); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 267)) return (PROTO_TD_SERVICE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 268)) return (PROTO_TD_REPLICA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 271)) return (PROTO_PT_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 280)) return (PROTO_HTTP_MGMT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 281)) return (PROTO_PERSONAL_LINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 282)) return (PROTO_CABLEPORT_AX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 283)) return (PROTO_RESCAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 284)) return (PROTO_CORERJD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 286)) return (PROTO_FXP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 287)) return (PROTO_K_BLOCK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 308)) return (PROTO_NOVASTORBAKCUP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 309)) return (PROTO_ENTRUSTTIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 310)) return (PROTO_BHMDS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 311)) return (PROTO_ASIP_WEBADMIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 312)) return (PROTO_VSLMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 313)) return (PROTO_MAGENTA_LOGIC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 314)) return (PROTO_OPALIS_ROBOT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 315)) return (PROTO_DPSI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 316)) return (PROTO_DECAUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 317)) return (PROTO_ZANNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 318)) return (PROTO_PKIX_TIMESTAMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 319)) return (PROTO_PTP_EVENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 320)) return (PROTO_PTP_GENERAL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 321)) return (PROTO_PIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 322)) return (PROTO_RTSPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 323)) return (PROTO_RPKI_RTR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 324)) return (PROTO_RPKI_RTR_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 333)) return (PROTO_TEXAR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 344)) return (PROTO_PDAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 345)) return (PROTO_PAWSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 346)) return (PROTO_ZSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 347)) return (PROTO_FATSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 348)) return (PROTO_CSI_SGWP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 349)) return (PROTO_MFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 350)) return (PROTO_MATIP_TYPE_A); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 351)) return (PROTO_MATIP_TYPE_B); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 351)) return (PROTO_BHOETTY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 352)) return (PROTO_DTAG_STE_SB); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 352)) return (PROTO_BHOEDAP4); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 353)) return (PROTO_NDSAUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 354)) return (PROTO_BH611); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 355)) return (PROTO_DATEX_ASN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 356)) return (PROTO_CLOANTO_NET_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 357)) return (PROTO_BHEVENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 358)) return (PROTO_SHRINKWRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 359)) return (PROTO_NSRMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 360)) return (PROTO_SCOI2ODIALOG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 361)) return (PROTO_SEMANTIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 362)) return (PROTO_SRSSEND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 363)) return (PROTO_RSVP_TUNNEL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 364)) return (PROTO_AURORA_CMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 365)) return (PROTO_DTK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 366)) return (PROTO_ODMR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 367)) return (PROTO_MORTGAGEWARE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 368)) return (PROTO_QBIKGDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 369)) return (PROTO_RPC2PORTMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 370)) return (PROTO_CODAAUTH2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 371)) return (PROTO_CLEARCASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 372)) return (PROTO_ULISTPROC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 373)) return (PROTO_LEGENT_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 374)) return (PROTO_LEGENT_2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 375)) return (PROTO_HASSLE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 376)) return (PROTO_NIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 377)) return (PROTO_TNETOS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 378)) return (PROTO_DSETOS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 379)) return (PROTO_IS99C); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 380)) return (PROTO_IS99S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 381)) return (PROTO_HP_COLLECTOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 382)) return (PROTO_HP_MANAGED_NODE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 383)) return (PROTO_HP_ALARM_MGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 384)) return (PROTO_ARNS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 385)) return (PROTO_IBM_APP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 386)) return (PROTO_ASA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 387)) return (PROTO_AURP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 388)) return (PROTO_UNIDATA_LDM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 390)) return (PROTO_UIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 391)) return (PROTO_SYNOTICS_RELAY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 392)) return (PROTO_SYNOTICS_BROKER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 393)) return (PROTO_META5); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 394)) return (PROTO_EMBL_NDT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 395)) return (PROTO_NETCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 396)) return (PROTO_NETWARE_IP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 397)) return (PROTO_MPTN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 399)) return (PROTO_ISO_TSAP_C2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 400)) return (PROTO_OSB_SD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 401)) return (PROTO_UPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 402)) return (PROTO_GENIE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 403)) return (PROTO_DECAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 404)) return (PROTO_NCED); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 405)) return (PROTO_NCLD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 406)) return (PROTO_IMSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 407)) return (PROTO_TIMBUKTU); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 408)) return (PROTO_PRM_SM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 409)) return (PROTO_PRM_NM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 410)) return (PROTO_DECLADEBUG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 411)) return (PROTO_RMT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 412)) return (PROTO_SYNOPTICS_TRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 413)) return (PROTO_SMSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 414)) return (PROTO_INFOSEEK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 415)) return (PROTO_BNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 416)) return (PROTO_SILVERPLATTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 417)) return (PROTO_ONMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 418)) return (PROTO_HYPER_G); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 419)) return (PROTO_ARIEL1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 420)) return (PROTO_SMPTE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 421)) return (PROTO_ARIEL2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 422)) return (PROTO_ARIEL3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 423)) return (PROTO_OPC_JOB_START); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 424)) return (PROTO_OPC_JOB_TRACK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 425)) return (PROTO_ICAD_EL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 426)) return (PROTO_SMARTSDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 427)) return (PROTO_SVRLOC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 428)) return (PROTO_OCS_CMU); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 429)) return (PROTO_OCS_AMU); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 430)) return (PROTO_UTMPSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 431)) return (PROTO_UTMPCD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 432)) return (PROTO_IASD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 433)) return (PROTO_NNSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 434)) return (PROTO_MOBILEIP_AGENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 435)) return (PROTO_MOBILIP_MN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 436)) return (PROTO_DNA_CML); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 437)) return (PROTO_COMSCM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 438)) return (PROTO_DSFGW); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 439)) return (PROTO_DASP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 440)) return (PROTO_SGCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 441)) return (PROTO_DECVMS_SYSMGT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 442)) return (PROTO_CVC_HOSTD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 443)) return (PROTO_HTTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 444)) return (PROTO_SNPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 445)) return (PROTO_MICROSOFT_DS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 446)) return (PROTO_DDM_RDB); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 447)) return (PROTO_DDM_DFM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 448)) return (PROTO_DDM_SSL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 449)) return (PROTO_AS_SERVERMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 450)) return (PROTO_TSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 451)) return (PROTO_SFS_SMP_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 452)) return (PROTO_SFS_CONFIG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 453)) return (PROTO_CREATIVESERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 454)) return (PROTO_CONTENTSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 455)) return (PROTO_CREATIVEPARTNR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 456)) return (PROTO_MACON_TCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 457)) return (PROTO_SCOHELP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 458)) return (PROTO_APPLEQTC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 459)) return (PROTO_AMPR_RCMD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 460)) return (PROTO_SKRONK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 461)) return (PROTO_DATASURFSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 462)) return (PROTO_DATASURFSRVSEC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 463)) return (PROTO_ALPES); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 464)) return (PROTO_KPASSWD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 465)) return (PROTO_URD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 466)) return (PROTO_DIGITAL_VRC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 467)) return (PROTO_MYLEX_MAPD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 468)) return (PROTO_PHOTURIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 469)) return (PROTO_RCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 470)) return (PROTO_SCX_PROXY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 471)) return (PROTO_MONDEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 472)) return (PROTO_LJK_LOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 473)) return (PROTO_HYBRID_POP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 474)) return (PROTO_TN_TL_W1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 475)) return (PROTO_TCPNETHASPSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 476)) return (PROTO_TN_TL_FD1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 477)) return (PROTO_SS7NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 478)) return (PROTO_SPSC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 479)) return (PROTO_IAFSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 480)) return (PROTO_IAFDBASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 481)) return (PROTO_PH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 482)) return (PROTO_BGS_NSI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 483)) return (PROTO_ULPNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 484)) return (PROTO_INTEGRA_SME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 485)) return (PROTO_POWERBURST); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 486)) return (PROTO_AVIAN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 487)) return (PROTO_SAFT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 488)) return (PROTO_GSS_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 489)) return (PROTO_NEST_PROTOCOL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 490)) return (PROTO_MICOM_PFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 491)) return (PROTO_GO_LOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 492)) return (PROTO_TICF_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 493)) return (PROTO_TICF_2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 494)) return (PROTO_POV_RAY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 495)) return (PROTO_INTECOURIER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 496)) return (PROTO_PIM_RP_DISC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 497)) return (PROTO_RETROSPECT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 498)) return (PROTO_SIAM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 499)) return (PROTO_ISO_ILL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 500)) return (PROTO_ISAKMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 501)) return (PROTO_STMF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 502)) return (PROTO_MBAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 503)) return (PROTO_INTRINSA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 504)) return (PROTO_CITADEL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 505)) return (PROTO_MAILBOX_LM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 506)) return (PROTO_OHIMSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 507)) return (PROTO_CRS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 508)) return (PROTO_XVTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 509)) return (PROTO_SNARE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 510)) return (PROTO_FCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 511)) return (PROTO_PASSGO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 512)) return (PROTO_EXEC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 513)) return (PROTO_LOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 514)) return (PROTO_SHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 515)) return (PROTO_PRINTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 516)) return (PROTO_VIDEOTEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 517)) return (PROTO_TALK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 518)) return (PROTO_NTALK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 519)) return (PROTO_UTIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 520)) return (PROTO_EFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 521)) return (PROTO_RIPNG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 522)) return (PROTO_ULP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 523)) return (PROTO_IBM_DB2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 524)) return (PROTO_NCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 525)) return (PROTO_TIMED); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 526)) return (PROTO_TEMPO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 527)) return (PROTO_STX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 528)) return (PROTO_CUSTIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 529)) return (PROTO_IRC_SERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 530)) return (PROTO_COURIER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 531)) return (PROTO_CONFERENCE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 532)) return (PROTO_NETNEWS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 533)) return (PROTO_NETWALL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 534)) return (PROTO_WINDREAM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 535)) return (PROTO_IIOP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 536)) return (PROTO_OPALIS_RDV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 537)) return (PROTO_NMSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 538)) return (PROTO_GDOMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 539)) return (PROTO_APERTUS_LDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 540)) return (PROTO_UUCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 541)) return (PROTO_UUCP_RLOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 542)) return (PROTO_COMMERCE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 543)) return (PROTO_KLOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 544)) return (PROTO_KSHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 545)) return (PROTO_APPLEQTCSRVR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 546)) return (PROTO_DHCPV6_CLIENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 547)) return (PROTO_DHCPV6_SERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 548)) return (PROTO_AFPOVERTCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 549)) return (PROTO_IDFP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 550)) return (PROTO_NEW_RWHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 551)) return (PROTO_CYBERCASH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 552)) return (PROTO_DEVSHR_NTS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 553)) return (PROTO_PIRP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 555)) return (PROTO_DSF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 556)) return (PROTO_REMOTEFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 557)) return (PROTO_OPENVMS_SYSIPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 558)) return (PROTO_SDNSKMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 559)) return (PROTO_TEEDTAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 560)) return (PROTO_RMONITOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 561)) return (PROTO_MONITOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 562)) return (PROTO_CHSHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 563)) return (PROTO_NNTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 564)) return (PROTO_9PFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 565)) return (PROTO_WHOAMI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 566)) return (PROTO_STREETTALK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 567)) return (PROTO_BANYAN_RPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 568)) return (PROTO_MS_SHUTTLE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 569)) return (PROTO_MS_ROME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 570)) return (PROTO_METER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 572)) return (PROTO_SONAR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 573)) return (PROTO_BANYAN_VIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 574)) return (PROTO_FTP_AGENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 575)) return (PROTO_VEMMI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 576)) return (PROTO_IPCD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 577)) return (PROTO_VNAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 578)) return (PROTO_IPDD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 579)) return (PROTO_DECBSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 580)) return (PROTO_SNTP_HEARTBEAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 581)) return (PROTO_BDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 582)) return (PROTO_SCC_SECURITY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 583)) return (PROTO_PHILIPS_VC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 584)) return (PROTO_KEYSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 586)) return (PROTO_PASSWORD_CHG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 587)) return (PROTO_SUBMISSION); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 588)) return (PROTO_CAL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 589)) return (PROTO_EYELINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 590)) return (PROTO_TNS_CML); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 591)) return (PROTO_HTTP_ALT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 592)) return (PROTO_EUDORA_SET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 593)) return (PROTO_HTTP_RPC_EPMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 594)) return (PROTO_TPIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 595)) return (PROTO_CAB_PROTOCOL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 596)) return (PROTO_SMSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 597)) return (PROTO_PTCNAMESERVICE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 598)) return (PROTO_SCO_WEBSRVRMG3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 599)) return (PROTO_ACP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 600)) return (PROTO_IPCSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 601)) return (PROTO_SYSLOG_CONN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 602)) return (PROTO_XMLRPC_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 603)) return (PROTO_IDXP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 604)) return (PROTO_TUNNEL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 605)) return (PROTO_SOAP_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 606)) return (PROTO_URM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 607)) return (PROTO_NQS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 608)) return (PROTO_SIFT_UFT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 609)) return (PROTO_NPMP_TRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 610)) return (PROTO_NPMP_LOCAL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 611)) return (PROTO_NPMP_GUI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 612)) return (PROTO_HMMP_IND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 613)) return (PROTO_HMMP_OP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 614)) return (PROTO_SSHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 615)) return (PROTO_SCO_INETMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 616)) return (PROTO_SCO_SYSMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 617)) return (PROTO_SCO_DTMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 618)) return (PROTO_DEI_ICDA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 619)) return (PROTO_COMPAQ_EVM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 620)) return (PROTO_SCO_WEBSRVRMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 621)) return (PROTO_ESCP_IP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 622)) return (PROTO_COLLABORATOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 623)) return (PROTO_OOB_WS_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 624)) return (PROTO_CRYPTOADMIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 625)) return (PROTO_DEC_DLM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 626)) return (PROTO_ASIA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 627)) return (PROTO_PASSGO_TIVOLI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 628)) return (PROTO_QMQP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 629)) return (PROTO_3COM_AMP3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 630)) return (PROTO_RDA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 632)) return (PROTO_BMPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 633)) return (PROTO_SERVSTAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 634)) return (PROTO_GINAD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 635)) return (PROTO_RLZDBASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 636)) return (PROTO_LDAPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 637)) return (PROTO_LANSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 638)) return (PROTO_MCNS_SEC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 639)) return (PROTO_MSDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 640)) return (PROTO_ENTRUST_SPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 641)) return (PROTO_REPCMD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 642)) return (PROTO_ESRO_EMSDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 643)) return (PROTO_SANITY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 644)) return (PROTO_DWR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 645)) return (PROTO_PSSC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 646)) return (PROTO_LDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 647)) return (PROTO_DHCP_FAILOVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 648)) return (PROTO_RRP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 649)) return (PROTO_CADVIEW_3D); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 650)) return (PROTO_OBEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 651)) return (PROTO_IEEE_MMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 652)) return (PROTO_HELLO_PORT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 653)) return (PROTO_REPSCMD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 654)) return (PROTO_AODV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 655)) return (PROTO_TINC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 656)) return (PROTO_SPMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 657)) return (PROTO_RMC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 658)) return (PROTO_TENFOLD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 660)) return (PROTO_MAC_SRVR_ADMIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 661)) return (PROTO_HAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 662)) return (PROTO_PFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 663)) return (PROTO_PURENOISE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 664)) return (PROTO_OOB_WS_HTTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 665)) return (PROTO_SUN_DR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 666)) return (PROTO_MDQS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 666)) return (PROTO_DOOM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 667)) return (PROTO_DISCLOSE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 668)) return (PROTO_MECOMM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 669)) return (PROTO_MEREGISTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 670)) return (PROTO_VACDSM_SWS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 671)) return (PROTO_VACDSM_APP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 672)) return (PROTO_VPPS_QUA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 673)) return (PROTO_CIMPLEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 674)) return (PROTO_ACAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 675)) return (PROTO_DCTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 676)) return (PROTO_VPPS_VIA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 677)) return (PROTO_VPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 678)) return (PROTO_GGF_NCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 679)) return (PROTO_MRM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 680)) return (PROTO_ENTRUST_AAAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 681)) return (PROTO_ENTRUST_AAMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 682)) return (PROTO_XFR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 683)) return (PROTO_CORBA_IIOP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 684)) return (PROTO_CORBA_IIOP_SSL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 685)) return (PROTO_MDC_PORTMAPPER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 686)) return (PROTO_HCP_WISMAR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 687)) return (PROTO_ASIPREGISTRY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 688)) return (PROTO_REALM_RUSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 689)) return (PROTO_NMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 690)) return (PROTO_VATP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 691)) return (PROTO_MSEXCH_ROUTING); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 692)) return (PROTO_HYPERWAVE_ISP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 693)) return (PROTO_CONNENDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 694)) return (PROTO_HA_CLUSTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 695)) return (PROTO_IEEE_MMS_SSL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 696)) return (PROTO_RUSHD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 697)) return (PROTO_UUIDGEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 698)) return (PROTO_OLSR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 699)) return (PROTO_ACCESSNETWORK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 700)) return (PROTO_EPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 701)) return (PROTO_LMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 702)) return (PROTO_IRIS_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 704)) return (PROTO_ELCSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 705)) return (PROTO_AGENTX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 706)) return (PROTO_SILC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 707)) return (PROTO_BORLAND_DSJ); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 709)) return (PROTO_ENTRUST_KMSH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 710)) return (PROTO_ENTRUST_ASH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 711)) return (PROTO_CISCO_TDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 712)) return (PROTO_TBRPF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 713)) return (PROTO_IRIS_XPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 714)) return (PROTO_IRIS_XPCS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 715)) return (PROTO_IRIS_LWZ); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 729)) return (PROTO_NETVIEWDM1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 730)) return (PROTO_NETVIEWDM2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 731)) return (PROTO_NETVIEWDM3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 741)) return (PROTO_NETGW); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 742)) return (PROTO_NETRCS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 744)) return (PROTO_FLEXLM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 747)) return (PROTO_FUJITSU_DEV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 748)) return (PROTO_RIS_CM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 749)) return (PROTO_KERBEROS_ADM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 750)) return (PROTO_RFILE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 751)) return (PROTO_PUMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 752)) return (PROTO_QRH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 753)) return (PROTO_RRH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 754)) return (PROTO_TELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 758)) return (PROTO_NLOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 759)) return (PROTO_CON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 760)) return (PROTO_NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 761)) return (PROTO_RXE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 762)) return (PROTO_QUOTAD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 763)) return (PROTO_CYCLESERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 764)) return (PROTO_OMSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 765)) return (PROTO_WEBSTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 767)) return (PROTO_PHONEBOOK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 769)) return (PROTO_VID); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 770)) return (PROTO_CADLOCK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 771)) return (PROTO_RTIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 772)) return (PROTO_CYCLESERV2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 773)) return (PROTO_SUBMIT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 774)) return (PROTO_RPASSWD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 775)) return (PROTO_ENTOMB); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 776)) return (PROTO_WPAGES); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 777)) return (PROTO_MULTILING_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 780)) return (PROTO_WPGS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 800)) return (PROTO_MDBS_DAEMON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 801)) return (PROTO_DEVICE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 802)) return (PROTO_MBAP_S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 810)) return (PROTO_FCP_UDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 828)) return (PROTO_ITM_MCELL_S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 829)) return (PROTO_PKIX_3_CA_RA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 830)) return (PROTO_NETCONF_SSH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 831)) return (PROTO_NETCONF_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 832)) return (PROTO_NETCONFSOAPHTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 833)) return (PROTO_NETCONFSOAPBEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 847)) return (PROTO_DHCP_FAILOVER2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 848)) return (PROTO_GDOI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 853)) return (PROTO_DOMAIN_S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 860)) return (PROTO_ISCSI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 861)) return (PROTO_OWAMP_CONTROL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 862)) return (PROTO_TWAMP_CONTROL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 873)) return (PROTO_RSYNC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 886)) return (PROTO_ICLCNET_LOCATE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 887)) return (PROTO_ICLCNET_SVINFO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 888)) return (PROTO_ACCESSBUILDER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 888)) return (PROTO_CDDBP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 900)) return (PROTO_OMGINITIALREFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 901)) return (PROTO_SMPNAMERES); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 902)) return (PROTO_IDEAFARM_DOOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 903)) return (PROTO_IDEAFARM_PANIC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 910)) return (PROTO_KINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 911)) return (PROTO_XACT_BACKUP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 912)) return (PROTO_APEX_MESH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 913)) return (PROTO_APEX_EDGE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 989)) return (PROTO_FTPS_DATA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 990)) return (PROTO_FTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 991)) return (PROTO_NAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 992)) return (PROTO_TELNETS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 995)) return (PROTO_POP3S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 996)) return (PROTO_VSINET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 997)) return (PROTO_MAITRD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 998)) return (PROTO_BUSBOY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 999)) return (PROTO_GARCON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 999)) return (PROTO_PUPROUTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1000)) return (PROTO_CADLOCK2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1010)) return (PROTO_SURF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1021)) return (PROTO_EXP1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1022)) return (PROTO_EXP2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1025)) return (PROTO_BLACKJACK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 21)) return (PROTO_FTP);//File Transfer Protocol . FTP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 22)) return (PROTO_SSH);//The Secure Shell (SSH) . SSH -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 23)) return (PROTO_TELNET);//Telnet -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 25)) return (PROTO_SMTP);//Simple Mail Transfer -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 69)) return (PROTO_TFTP);//Trivial File Transfer -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_HTTP);//World Wide Web HTTP Defined TXT keys: u=<username> p=<password> path=<path to . HTTP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 88)) return (PROTO_KERBEROS);//Kerberos -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 123)) return (PROTO_NTP);//Network Time Protocol -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 143)) return (PROTO_IMAP);//Internet Message Access -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 147)) return (PROTO_ISO_IP);//ISO-IP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 161)) return (PROTO_SNMP);//SNMP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 177)) return (PROTO_XDMCP);//X Display Manager Control -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 179)) return (PROTO_BGP);//Border Gateway Protocol . BGP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 194)) return (PROTO_IRC);//Internet Relay Chat Protocol -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 269)) return (PROTO_MANET);//MANET Protocols -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 389)) return (PROTO_LDAP);//Lightweight Directory Access -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 398)) return (PROTO_KRYPTOLAN);//Kryptolan -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 554)) return (PROTO_RTSP);//Real Time Streaming Protocol -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 631)) return (PROTO_IPP);//IPP (Internet Printing -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 993)) return (PROTO_IMAPS);//imap4 protocol over TLS/SSL -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 1214)) return (PROTO_KAZAA);//KAZAA -was generated automatically by MMTCrawler - @luongnv89 - 


    }

    return (PROTO_UNKNOWN);
}

unsigned int mmt_guess_protocol_by_port_number(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint16_t sport, dport;
    if (packet->tcp) {
        sport = htons(packet->tcp->source);
        dport = htons(packet->tcp->dest);
        if (MMT_PORT_MATCH(sport, dport, 443)) return (PROTO_SSL);
        else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_HTTP);
        else if (MMT_PORT_MATCH(sport, dport, 8080)) return (PROTO_HTTP);
        else if (MMT_PORT_MATCH(sport, dport, 5222)) return (PROTO_UNENCRYPED_JABBER);
        else if (MMT_PORT_MATCH(sport, dport, 1935)) return (PROTO_FLASH);
        else if (MMT_PORT_MATCH(sport, dport, 143)) return (PROTO_IMAP);
        else if (MMT_PORT_MATCH(sport, dport, 993)) return (PROTO_IMAPS);
        else if (MMT_PORT_MATCH(sport, dport, 25)) return (PROTO_SMTP);
        else if (MMT_PORT_MATCH(sport, dport, 465)) return (PROTO_SMTPS);
        else if (MMT_PORT_MATCH(sport, dport, 110)) return (PROTO_POP);
        else if (MMT_PORT_MATCH(sport, dport, 995)) return (PROTO_POPS);
        else if (MMT_PORT_MATCH(sport, dport, 135)) return (PROTO_DCERPC);
        else if (MMT_PORT_MATCH(sport, dport, 389)) return (PROTO_LDAP);
        else if (MMT_PORT_MATCH(sport, dport, 22)) return (PROTO_SSH);
        else if (MMT_PORT_MATCH(sport, dport, 23)) return (PROTO_TELNET);
        else if (MMT_PORT_MATCH(sport, dport, 445)) return (PROTO_SMB);
        else if (MMT_PORT_MATCH(sport, dport, 389)) return (PROTO_LDAP);
        else if (MMT_PORT_MATCH(sport, dport, 88)) return (PROTO_KERBEROS);
        else if (MMT_PORT_MATCH(sport, dport, 554)) return (PROTO_RTSP); 
        // else if (MMT_PORT_MATCH(sport, dport, 1)) return (PROTO_TCPMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 2)) return (PROTO_COMPRESSNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 5)) return (PROTO_RJE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 7)) return (PROTO_ECHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 9)) return (PROTO_DISCARD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 11)) return (PROTO_SYSTAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 13)) return (PROTO_DAYTIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 17)) return (PROTO_QOTD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 18)) return (PROTO_MSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 19)) return (PROTO_CHARGEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 20)) return (PROTO_FTP_DATA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 27)) return (PROTO_NSW_FE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 29)) return (PROTO_MSG_ICP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 31)) return (PROTO_MSG_AUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 33)) return (PROTO_DSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 37)) return (PROTO_TIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 38)) return (PROTO_RAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 39)) return (PROTO_RLP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 41)) return (PROTO_GRAPHICS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 42)) return (PROTO_NAME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 42)) return (PROTO_NAMESERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 43)) return (PROTO_NICNAME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 44)) return (PROTO_MPM_FLAGS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 45)) return (PROTO_MPM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 46)) return (PROTO_MPM_SND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 47)) return (PROTO_NI_FTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 48)) return (PROTO_AUDITD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 49)) return (PROTO_TACACS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 50)) return (PROTO_RE_MAIL_CK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 52)) return (PROTO_XNS_TIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 53)) return (PROTO_DOMAIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 54)) return (PROTO_XNS_CH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 55)) return (PROTO_ISI_GL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 56)) return (PROTO_XNS_AUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 58)) return (PROTO_XNS_MAIL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 61)) return (PROTO_NI_MAIL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 62)) return (PROTO_ACAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 63)) return (PROTO_WHOISPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 63)) return (PROTO_WHOIS__); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 64)) return (PROTO_COVIA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 65)) return (PROTO_TACACS_DS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 66)) return (PROTO_SQL_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 66)) return (PROTO_SQLNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 67)) return (PROTO_BOOTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 68)) return (PROTO_BOOTPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 70)) return (PROTO_GOPHER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 71)) return (PROTO_NETRJS_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 72)) return (PROTO_NETRJS_2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 73)) return (PROTO_NETRJS_3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 74)) return (PROTO_NETRJS_4); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 76)) return (PROTO_DEOS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 78)) return (PROTO_VETTCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 79)) return (PROTO_FINGER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_WWW); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_WWW_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 82)) return (PROTO_XFER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 83)) return (PROTO_MIT_ML_DEV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 84)) return (PROTO_CTF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 86)) return (PROTO_MFCOBOL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 89)) return (PROTO_SU_MIT_TG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 90)) return (PROTO_DNSIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 91)) return (PROTO_MIT_DOV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 92)) return (PROTO_NPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 93)) return (PROTO_DCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 94)) return (PROTO_OBJCALL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 95)) return (PROTO_SUPDUP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 96)) return (PROTO_DIXIE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 97)) return (PROTO_SWIFT_RVF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 98)) return (PROTO_TACNEWS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 99)) return (PROTO_METAGRAM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 101)) return (PROTO_HOSTNAME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 102)) return (PROTO_ISO_TSAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 103)) return (PROTO_GPPITNP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 104)) return (PROTO_ACR_NEMA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 105)) return (PROTO_CSO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 105)) return (PROTO_CSNET_NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 106)) return (PROTO_3COM_TSMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 107)) return (PROTO_RTELNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 108)) return (PROTO_SNAGAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 109)) return (PROTO_POP2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 110)) return (PROTO_POP3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 111)) return (PROTO_SUNRPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 112)) return (PROTO_MCIDAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 113)) return (PROTO_IDENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 113)) return (PROTO_AUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 115)) return (PROTO_SFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 116)) return (PROTO_ANSANOTIFY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 117)) return (PROTO_UUCP_PATH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 118)) return (PROTO_SQLSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 119)) return (PROTO_NNTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 120)) return (PROTO_CFDPTKT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 121)) return (PROTO_ERPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 122)) return (PROTO_SMAKYNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 124)) return (PROTO_ANSATRADER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 125)) return (PROTO_LOCUS_MAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 126)) return (PROTO_NXEDIT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 127)) return (PROTO_LOCUS_CON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 128)) return (PROTO_GSS_XLICEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 129)) return (PROTO_PWDGEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 130)) return (PROTO_CISCO_FNA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 131)) return (PROTO_CISCO_TNA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 132)) return (PROTO_CISCO_SYS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 133)) return (PROTO_STATSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 134)) return (PROTO_INGRES_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 135)) return (PROTO_EPMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 136)) return (PROTO_PROFILE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 137)) return (PROTO_NETBIOS_NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 138)) return (PROTO_NETBIOS_DGM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 139)) return (PROTO_NETBIOS_SSN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 140)) return (PROTO_EMFIS_DATA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 141)) return (PROTO_EMFIS_CNTL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 142)) return (PROTO_BL_IDM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 144)) return (PROTO_UMA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 145)) return (PROTO_UAAC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 146)) return (PROTO_ISO_TP0); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 148)) return (PROTO_JARGON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 149)) return (PROTO_AED_512); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 151)) return (PROTO_HEMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 152)) return (PROTO_BFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 153)) return (PROTO_SGMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 154)) return (PROTO_NETSC_PROD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 155)) return (PROTO_NETSC_DEV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 156)) return (PROTO_SQLSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 157)) return (PROTO_KNET_CMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 158)) return (PROTO_PCMAIL_SRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 159)) return (PROTO_NSS_ROUTING); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 160)) return (PROTO_SGMP_TRAPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 162)) return (PROTO_SNMPTRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 163)) return (PROTO_CMIP_MAN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 164)) return (PROTO_CMIP_AGENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 165)) return (PROTO_XNS_COURIER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 166)) return (PROTO_S_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 167)) return (PROTO_NAMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 168)) return (PROTO_RSVD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 169)) return (PROTO_SEND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 170)) return (PROTO_PRINT_SRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 171)) return (PROTO_MULTIPLEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 172)) return (PROTO_CL_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 172)) return (PROTO_CL1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 173)) return (PROTO_XYPLEX_MUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 174)) return (PROTO_MAILQ); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 175)) return (PROTO_VMNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 176)) return (PROTO_GENRAD_MUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 178)) return (PROTO_NEXTSTEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 180)) return (PROTO_RIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 181)) return (PROTO_UNIFY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 182)) return (PROTO_AUDIT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 183)) return (PROTO_OCBINDER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 184)) return (PROTO_OCSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 185)) return (PROTO_REMOTE_KIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 186)) return (PROTO_KIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 187)) return (PROTO_ACI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 188)) return (PROTO_MUMPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 189)) return (PROTO_QFT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 190)) return (PROTO_GACP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 191)) return (PROTO_PROSPERO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 192)) return (PROTO_OSU_NMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 193)) return (PROTO_SRMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 195)) return (PROTO_DN6_NLM_AUD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 196)) return (PROTO_DN6_SMM_RED); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 197)) return (PROTO_DLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 198)) return (PROTO_DLS_MON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 199)) return (PROTO_SMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 200)) return (PROTO_SRC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 201)) return (PROTO_AT_RTMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 202)) return (PROTO_AT_NBP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 203)) return (PROTO_AT_3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 204)) return (PROTO_AT_ECHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 205)) return (PROTO_AT_5); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 206)) return (PROTO_AT_ZIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 207)) return (PROTO_AT_7); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 208)) return (PROTO_AT_8); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 209)) return (PROTO_QMTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 210)) return (PROTO_Z39_50); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 211)) return (PROTO_914C_G); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 211)) return (PROTO_914CG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 212)) return (PROTO_ANET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 213)) return (PROTO_IPX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 214)) return (PROTO_VMPWSCS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 215)) return (PROTO_SOFTPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 216)) return (PROTO_CAILIC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 217)) return (PROTO_DBASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 218)) return (PROTO_MPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 219)) return (PROTO_UARPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 220)) return (PROTO_IMAP3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 221)) return (PROTO_FLN_SPX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 222)) return (PROTO_RSH_SPX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 223)) return (PROTO_CDC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 224)) return (PROTO_MASQDIALER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 242)) return (PROTO_DIRECT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 243)) return (PROTO_SUR_MEAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 244)) return (PROTO_INBUSINESS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 245)) return (PROTO_LINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 246)) return (PROTO_DSP3270); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 247)) return (PROTO_SUBNTBCST_TFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 248)) return (PROTO_BHFHS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 257)) return (PROTO_SET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 259)) return (PROTO_ESRO_GEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 260)) return (PROTO_OPENPORT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 261)) return (PROTO_NSIIOPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 262)) return (PROTO_ARCISDMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 263)) return (PROTO_HDAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 264)) return (PROTO_BGMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 265)) return (PROTO_X_BONE_CTL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 266)) return (PROTO_SST); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 267)) return (PROTO_TD_SERVICE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 268)) return (PROTO_TD_REPLICA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 271)) return (PROTO_PT_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 280)) return (PROTO_HTTP_MGMT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 281)) return (PROTO_PERSONAL_LINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 282)) return (PROTO_CABLEPORT_AX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 283)) return (PROTO_RESCAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 284)) return (PROTO_CORERJD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 286)) return (PROTO_FXP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 287)) return (PROTO_K_BLOCK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 308)) return (PROTO_NOVASTORBAKCUP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 309)) return (PROTO_ENTRUSTTIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 310)) return (PROTO_BHMDS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 311)) return (PROTO_ASIP_WEBADMIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 312)) return (PROTO_VSLMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 313)) return (PROTO_MAGENTA_LOGIC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 314)) return (PROTO_OPALIS_ROBOT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 315)) return (PROTO_DPSI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 316)) return (PROTO_DECAUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 317)) return (PROTO_ZANNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 318)) return (PROTO_PKIX_TIMESTAMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 319)) return (PROTO_PTP_EVENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 320)) return (PROTO_PTP_GENERAL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 321)) return (PROTO_PIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 322)) return (PROTO_RTSPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 323)) return (PROTO_RPKI_RTR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 324)) return (PROTO_RPKI_RTR_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 333)) return (PROTO_TEXAR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 344)) return (PROTO_PDAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 345)) return (PROTO_PAWSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 346)) return (PROTO_ZSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 347)) return (PROTO_FATSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 348)) return (PROTO_CSI_SGWP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 349)) return (PROTO_MFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 350)) return (PROTO_MATIP_TYPE_A); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 351)) return (PROTO_MATIP_TYPE_B); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 351)) return (PROTO_BHOETTY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 352)) return (PROTO_DTAG_STE_SB); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 352)) return (PROTO_BHOEDAP4); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 353)) return (PROTO_NDSAUTH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 354)) return (PROTO_BH611); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 355)) return (PROTO_DATEX_ASN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 356)) return (PROTO_CLOANTO_NET_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 357)) return (PROTO_BHEVENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 358)) return (PROTO_SHRINKWRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 359)) return (PROTO_NSRMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 360)) return (PROTO_SCOI2ODIALOG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 361)) return (PROTO_SEMANTIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 362)) return (PROTO_SRSSEND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 363)) return (PROTO_RSVP_TUNNEL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 364)) return (PROTO_AURORA_CMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 365)) return (PROTO_DTK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 366)) return (PROTO_ODMR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 367)) return (PROTO_MORTGAGEWARE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 368)) return (PROTO_QBIKGDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 369)) return (PROTO_RPC2PORTMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 370)) return (PROTO_CODAAUTH2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 371)) return (PROTO_CLEARCASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 372)) return (PROTO_ULISTPROC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 373)) return (PROTO_LEGENT_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 374)) return (PROTO_LEGENT_2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 375)) return (PROTO_HASSLE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 376)) return (PROTO_NIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 377)) return (PROTO_TNETOS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 378)) return (PROTO_DSETOS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 379)) return (PROTO_IS99C); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 380)) return (PROTO_IS99S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 381)) return (PROTO_HP_COLLECTOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 382)) return (PROTO_HP_MANAGED_NODE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 383)) return (PROTO_HP_ALARM_MGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 384)) return (PROTO_ARNS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 385)) return (PROTO_IBM_APP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 386)) return (PROTO_ASA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 387)) return (PROTO_AURP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 388)) return (PROTO_UNIDATA_LDM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 390)) return (PROTO_UIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 391)) return (PROTO_SYNOTICS_RELAY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 392)) return (PROTO_SYNOTICS_BROKER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 393)) return (PROTO_META5); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 394)) return (PROTO_EMBL_NDT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 395)) return (PROTO_NETCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 396)) return (PROTO_NETWARE_IP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 397)) return (PROTO_MPTN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 399)) return (PROTO_ISO_TSAP_C2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 400)) return (PROTO_OSB_SD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 401)) return (PROTO_UPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 402)) return (PROTO_GENIE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 403)) return (PROTO_DECAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 404)) return (PROTO_NCED); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 405)) return (PROTO_NCLD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 406)) return (PROTO_IMSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 407)) return (PROTO_TIMBUKTU); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 408)) return (PROTO_PRM_SM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 409)) return (PROTO_PRM_NM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 410)) return (PROTO_DECLADEBUG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 411)) return (PROTO_RMT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 412)) return (PROTO_SYNOPTICS_TRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 413)) return (PROTO_SMSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 414)) return (PROTO_INFOSEEK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 415)) return (PROTO_BNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 416)) return (PROTO_SILVERPLATTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 417)) return (PROTO_ONMUX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 418)) return (PROTO_HYPER_G); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 419)) return (PROTO_ARIEL1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 420)) return (PROTO_SMPTE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 421)) return (PROTO_ARIEL2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 422)) return (PROTO_ARIEL3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 423)) return (PROTO_OPC_JOB_START); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 424)) return (PROTO_OPC_JOB_TRACK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 425)) return (PROTO_ICAD_EL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 426)) return (PROTO_SMARTSDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 427)) return (PROTO_SVRLOC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 428)) return (PROTO_OCS_CMU); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 429)) return (PROTO_OCS_AMU); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 430)) return (PROTO_UTMPSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 431)) return (PROTO_UTMPCD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 432)) return (PROTO_IASD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 433)) return (PROTO_NNSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 434)) return (PROTO_MOBILEIP_AGENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 435)) return (PROTO_MOBILIP_MN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 436)) return (PROTO_DNA_CML); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 437)) return (PROTO_COMSCM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 438)) return (PROTO_DSFGW); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 439)) return (PROTO_DASP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 440)) return (PROTO_SGCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 441)) return (PROTO_DECVMS_SYSMGT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 442)) return (PROTO_CVC_HOSTD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 443)) return (PROTO_HTTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 444)) return (PROTO_SNPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 445)) return (PROTO_MICROSOFT_DS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 446)) return (PROTO_DDM_RDB); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 447)) return (PROTO_DDM_DFM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 448)) return (PROTO_DDM_SSL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 449)) return (PROTO_AS_SERVERMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 450)) return (PROTO_TSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 451)) return (PROTO_SFS_SMP_NET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 452)) return (PROTO_SFS_CONFIG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 453)) return (PROTO_CREATIVESERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 454)) return (PROTO_CONTENTSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 455)) return (PROTO_CREATIVEPARTNR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 456)) return (PROTO_MACON_TCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 457)) return (PROTO_SCOHELP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 458)) return (PROTO_APPLEQTC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 459)) return (PROTO_AMPR_RCMD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 460)) return (PROTO_SKRONK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 461)) return (PROTO_DATASURFSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 462)) return (PROTO_DATASURFSRVSEC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 463)) return (PROTO_ALPES); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 464)) return (PROTO_KPASSWD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 465)) return (PROTO_URD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 466)) return (PROTO_DIGITAL_VRC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 467)) return (PROTO_MYLEX_MAPD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 468)) return (PROTO_PHOTURIS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 469)) return (PROTO_RCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 470)) return (PROTO_SCX_PROXY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 471)) return (PROTO_MONDEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 472)) return (PROTO_LJK_LOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 473)) return (PROTO_HYBRID_POP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 474)) return (PROTO_TN_TL_W1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 475)) return (PROTO_TCPNETHASPSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 476)) return (PROTO_TN_TL_FD1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 477)) return (PROTO_SS7NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 478)) return (PROTO_SPSC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 479)) return (PROTO_IAFSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 480)) return (PROTO_IAFDBASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 481)) return (PROTO_PH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 482)) return (PROTO_BGS_NSI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 483)) return (PROTO_ULPNET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 484)) return (PROTO_INTEGRA_SME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 485)) return (PROTO_POWERBURST); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 486)) return (PROTO_AVIAN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 487)) return (PROTO_SAFT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 488)) return (PROTO_GSS_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 489)) return (PROTO_NEST_PROTOCOL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 490)) return (PROTO_MICOM_PFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 491)) return (PROTO_GO_LOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 492)) return (PROTO_TICF_1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 493)) return (PROTO_TICF_2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 494)) return (PROTO_POV_RAY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 495)) return (PROTO_INTECOURIER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 496)) return (PROTO_PIM_RP_DISC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 497)) return (PROTO_RETROSPECT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 498)) return (PROTO_SIAM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 499)) return (PROTO_ISO_ILL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 500)) return (PROTO_ISAKMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 501)) return (PROTO_STMF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 502)) return (PROTO_MBAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 503)) return (PROTO_INTRINSA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 504)) return (PROTO_CITADEL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 505)) return (PROTO_MAILBOX_LM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 506)) return (PROTO_OHIMSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 507)) return (PROTO_CRS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 508)) return (PROTO_XVTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 509)) return (PROTO_SNARE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 510)) return (PROTO_FCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 511)) return (PROTO_PASSGO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 512)) return (PROTO_EXEC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 513)) return (PROTO_LOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 514)) return (PROTO_SHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 515)) return (PROTO_PRINTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 516)) return (PROTO_VIDEOTEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 517)) return (PROTO_TALK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 518)) return (PROTO_NTALK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 519)) return (PROTO_UTIME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 520)) return (PROTO_EFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 521)) return (PROTO_RIPNG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 522)) return (PROTO_ULP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 523)) return (PROTO_IBM_DB2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 524)) return (PROTO_NCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 525)) return (PROTO_TIMED); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 526)) return (PROTO_TEMPO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 527)) return (PROTO_STX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 528)) return (PROTO_CUSTIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 529)) return (PROTO_IRC_SERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 530)) return (PROTO_COURIER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 531)) return (PROTO_CONFERENCE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 532)) return (PROTO_NETNEWS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 533)) return (PROTO_NETWALL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 534)) return (PROTO_WINDREAM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 535)) return (PROTO_IIOP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 536)) return (PROTO_OPALIS_RDV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 537)) return (PROTO_NMSP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 538)) return (PROTO_GDOMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 539)) return (PROTO_APERTUS_LDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 540)) return (PROTO_UUCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 541)) return (PROTO_UUCP_RLOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 542)) return (PROTO_COMMERCE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 543)) return (PROTO_KLOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 544)) return (PROTO_KSHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 545)) return (PROTO_APPLEQTCSRVR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 546)) return (PROTO_DHCPV6_CLIENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 547)) return (PROTO_DHCPV6_SERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 548)) return (PROTO_AFPOVERTCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 549)) return (PROTO_IDFP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 550)) return (PROTO_NEW_RWHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 551)) return (PROTO_CYBERCASH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 552)) return (PROTO_DEVSHR_NTS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 553)) return (PROTO_PIRP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 555)) return (PROTO_DSF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 556)) return (PROTO_REMOTEFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 557)) return (PROTO_OPENVMS_SYSIPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 558)) return (PROTO_SDNSKMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 559)) return (PROTO_TEEDTAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 560)) return (PROTO_RMONITOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 561)) return (PROTO_MONITOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 562)) return (PROTO_CHSHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 563)) return (PROTO_NNTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 564)) return (PROTO_9PFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 565)) return (PROTO_WHOAMI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 566)) return (PROTO_STREETTALK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 567)) return (PROTO_BANYAN_RPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 568)) return (PROTO_MS_SHUTTLE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 569)) return (PROTO_MS_ROME); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 570)) return (PROTO_METER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 572)) return (PROTO_SONAR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 573)) return (PROTO_BANYAN_VIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 574)) return (PROTO_FTP_AGENT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 575)) return (PROTO_VEMMI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 576)) return (PROTO_IPCD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 577)) return (PROTO_VNAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 578)) return (PROTO_IPDD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 579)) return (PROTO_DECBSRV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 580)) return (PROTO_SNTP_HEARTBEAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 581)) return (PROTO_BDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 582)) return (PROTO_SCC_SECURITY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 583)) return (PROTO_PHILIPS_VC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 584)) return (PROTO_KEYSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 586)) return (PROTO_PASSWORD_CHG); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 587)) return (PROTO_SUBMISSION); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 588)) return (PROTO_CAL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 589)) return (PROTO_EYELINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 590)) return (PROTO_TNS_CML); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 591)) return (PROTO_HTTP_ALT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 592)) return (PROTO_EUDORA_SET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 593)) return (PROTO_HTTP_RPC_EPMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 594)) return (PROTO_TPIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 595)) return (PROTO_CAB_PROTOCOL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 596)) return (PROTO_SMSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 597)) return (PROTO_PTCNAMESERVICE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 598)) return (PROTO_SCO_WEBSRVRMG3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 599)) return (PROTO_ACP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 600)) return (PROTO_IPCSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 601)) return (PROTO_SYSLOG_CONN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 602)) return (PROTO_XMLRPC_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 603)) return (PROTO_IDXP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 604)) return (PROTO_TUNNEL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 605)) return (PROTO_SOAP_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 606)) return (PROTO_URM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 607)) return (PROTO_NQS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 608)) return (PROTO_SIFT_UFT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 609)) return (PROTO_NPMP_TRAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 610)) return (PROTO_NPMP_LOCAL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 611)) return (PROTO_NPMP_GUI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 612)) return (PROTO_HMMP_IND); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 613)) return (PROTO_HMMP_OP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 614)) return (PROTO_SSHELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 615)) return (PROTO_SCO_INETMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 616)) return (PROTO_SCO_SYSMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 617)) return (PROTO_SCO_DTMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 618)) return (PROTO_DEI_ICDA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 619)) return (PROTO_COMPAQ_EVM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 620)) return (PROTO_SCO_WEBSRVRMGR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 621)) return (PROTO_ESCP_IP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 622)) return (PROTO_COLLABORATOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 623)) return (PROTO_OOB_WS_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 624)) return (PROTO_CRYPTOADMIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 625)) return (PROTO_DEC_DLM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 626)) return (PROTO_ASIA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 627)) return (PROTO_PASSGO_TIVOLI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 628)) return (PROTO_QMQP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 629)) return (PROTO_3COM_AMP3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 630)) return (PROTO_RDA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 632)) return (PROTO_BMPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 633)) return (PROTO_SERVSTAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 634)) return (PROTO_GINAD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 635)) return (PROTO_RLZDBASE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 636)) return (PROTO_LDAPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 637)) return (PROTO_LANSERVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 638)) return (PROTO_MCNS_SEC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 639)) return (PROTO_MSDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 640)) return (PROTO_ENTRUST_SPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 641)) return (PROTO_REPCMD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 642)) return (PROTO_ESRO_EMSDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 643)) return (PROTO_SANITY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 644)) return (PROTO_DWR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 645)) return (PROTO_PSSC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 646)) return (PROTO_LDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 647)) return (PROTO_DHCP_FAILOVER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 648)) return (PROTO_RRP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 649)) return (PROTO_CADVIEW_3D); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 650)) return (PROTO_OBEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 651)) return (PROTO_IEEE_MMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 652)) return (PROTO_HELLO_PORT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 653)) return (PROTO_REPSCMD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 654)) return (PROTO_AODV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 655)) return (PROTO_TINC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 656)) return (PROTO_SPMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 657)) return (PROTO_RMC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 658)) return (PROTO_TENFOLD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 660)) return (PROTO_MAC_SRVR_ADMIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 661)) return (PROTO_HAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 662)) return (PROTO_PFTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 663)) return (PROTO_PURENOISE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 664)) return (PROTO_OOB_WS_HTTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 665)) return (PROTO_SUN_DR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 666)) return (PROTO_MDQS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 666)) return (PROTO_DOOM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 667)) return (PROTO_DISCLOSE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 668)) return (PROTO_MECOMM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 669)) return (PROTO_MEREGISTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 670)) return (PROTO_VACDSM_SWS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 671)) return (PROTO_VACDSM_APP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 672)) return (PROTO_VPPS_QUA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 673)) return (PROTO_CIMPLEX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 674)) return (PROTO_ACAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 675)) return (PROTO_DCTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 676)) return (PROTO_VPPS_VIA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 677)) return (PROTO_VPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 678)) return (PROTO_GGF_NCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 679)) return (PROTO_MRM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 680)) return (PROTO_ENTRUST_AAAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 681)) return (PROTO_ENTRUST_AAMS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 682)) return (PROTO_XFR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 683)) return (PROTO_CORBA_IIOP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 684)) return (PROTO_CORBA_IIOP_SSL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 685)) return (PROTO_MDC_PORTMAPPER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 686)) return (PROTO_HCP_WISMAR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 687)) return (PROTO_ASIPREGISTRY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 688)) return (PROTO_REALM_RUSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 689)) return (PROTO_NMAP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 690)) return (PROTO_VATP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 691)) return (PROTO_MSEXCH_ROUTING); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 692)) return (PROTO_HYPERWAVE_ISP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 693)) return (PROTO_CONNENDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 694)) return (PROTO_HA_CLUSTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 695)) return (PROTO_IEEE_MMS_SSL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 696)) return (PROTO_RUSHD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 697)) return (PROTO_UUIDGEN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 698)) return (PROTO_OLSR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 699)) return (PROTO_ACCESSNETWORK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 700)) return (PROTO_EPP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 701)) return (PROTO_LMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 702)) return (PROTO_IRIS_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 704)) return (PROTO_ELCSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 705)) return (PROTO_AGENTX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 706)) return (PROTO_SILC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 707)) return (PROTO_BORLAND_DSJ); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 709)) return (PROTO_ENTRUST_KMSH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 710)) return (PROTO_ENTRUST_ASH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 711)) return (PROTO_CISCO_TDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 712)) return (PROTO_TBRPF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 713)) return (PROTO_IRIS_XPC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 714)) return (PROTO_IRIS_XPCS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 715)) return (PROTO_IRIS_LWZ); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 729)) return (PROTO_NETVIEWDM1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 730)) return (PROTO_NETVIEWDM2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 731)) return (PROTO_NETVIEWDM3); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 741)) return (PROTO_NETGW); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 742)) return (PROTO_NETRCS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 744)) return (PROTO_FLEXLM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 747)) return (PROTO_FUJITSU_DEV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 748)) return (PROTO_RIS_CM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 749)) return (PROTO_KERBEROS_ADM); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 750)) return (PROTO_RFILE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 751)) return (PROTO_PUMP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 752)) return (PROTO_QRH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 753)) return (PROTO_RRH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 754)) return (PROTO_TELL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 758)) return (PROTO_NLOGIN); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 759)) return (PROTO_CON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 760)) return (PROTO_NS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 761)) return (PROTO_RXE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 762)) return (PROTO_QUOTAD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 763)) return (PROTO_CYCLESERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 764)) return (PROTO_OMSERV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 765)) return (PROTO_WEBSTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 767)) return (PROTO_PHONEBOOK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 769)) return (PROTO_VID); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 770)) return (PROTO_CADLOCK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 771)) return (PROTO_RTIP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 772)) return (PROTO_CYCLESERV2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 773)) return (PROTO_SUBMIT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 774)) return (PROTO_RPASSWD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 775)) return (PROTO_ENTOMB); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 776)) return (PROTO_WPAGES); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 777)) return (PROTO_MULTILING_HTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 780)) return (PROTO_WPGS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 800)) return (PROTO_MDBS_DAEMON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 801)) return (PROTO_DEVICE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 802)) return (PROTO_MBAP_S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 810)) return (PROTO_FCP_UDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 828)) return (PROTO_ITM_MCELL_S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 829)) return (PROTO_PKIX_3_CA_RA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 830)) return (PROTO_NETCONF_SSH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 831)) return (PROTO_NETCONF_BEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 832)) return (PROTO_NETCONFSOAPHTTP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 833)) return (PROTO_NETCONFSOAPBEEP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 847)) return (PROTO_DHCP_FAILOVER2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 848)) return (PROTO_GDOI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 853)) return (PROTO_DOMAIN_S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 860)) return (PROTO_ISCSI); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 861)) return (PROTO_OWAMP_CONTROL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 862)) return (PROTO_TWAMP_CONTROL); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 873)) return (PROTO_RSYNC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 886)) return (PROTO_ICLCNET_LOCATE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 887)) return (PROTO_ICLCNET_SVINFO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 888)) return (PROTO_ACCESSBUILDER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 888)) return (PROTO_CDDBP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 900)) return (PROTO_OMGINITIALREFS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 901)) return (PROTO_SMPNAMERES); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 902)) return (PROTO_IDEAFARM_DOOR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 903)) return (PROTO_IDEAFARM_PANIC); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 910)) return (PROTO_KINK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 911)) return (PROTO_XACT_BACKUP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 912)) return (PROTO_APEX_MESH); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 913)) return (PROTO_APEX_EDGE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 989)) return (PROTO_FTPS_DATA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 990)) return (PROTO_FTPS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 991)) return (PROTO_NAS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 992)) return (PROTO_TELNETS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 995)) return (PROTO_POP3S); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 996)) return (PROTO_VSINET); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 997)) return (PROTO_MAITRD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 998)) return (PROTO_BUSBOY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 999)) return (PROTO_GARCON); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 999)) return (PROTO_PUPROUTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1000)) return (PROTO_CADLOCK2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1010)) return (PROTO_SURF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1021)) return (PROTO_EXP1); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1022)) return (PROTO_EXP2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 1025)) return (PROTO_BLACKJACK); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 21)) return (PROTO_FTP);//File Transfer Protocol . FTP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 22)) return (PROTO_SSH);//The Secure Shell (SSH) . SSH -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 23)) return (PROTO_TELNET);//Telnet -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 25)) return (PROTO_SMTP);//Simple Mail Transfer -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 69)) return (PROTO_TFTP);//Trivial File Transfer -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 80)) return (PROTO_HTTP);//World Wide Web HTTP Defined TXT keys: u=<username> p=<password> path=<path to . HTTP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 88)) return (PROTO_KERBEROS);//Kerberos -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 123)) return (PROTO_NTP);//Network Time Protocol -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 143)) return (PROTO_IMAP);//Internet Message Access -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 147)) return (PROTO_ISO_IP);//ISO-IP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 161)) return (PROTO_SNMP);//SNMP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 177)) return (PROTO_XDMCP);//X Display Manager Control -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 179)) return (PROTO_BGP);//Border Gateway Protocol . BGP -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 194)) return (PROTO_IRC);//Internet Relay Chat Protocol -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 269)) return (PROTO_MANET);//MANET Protocols -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 389)) return (PROTO_LDAP);//Lightweight Directory Access -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 398)) return (PROTO_KRYPTOLAN);//Kryptolan -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 554)) return (PROTO_RTSP);//Real Time Streaming Protocol -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 631)) return (PROTO_IPP);//IPP (Internet Printing -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 993)) return (PROTO_IMAPS);//imap4 protocol over TLS/SSL -was generated automatically by MMTCrawler - @luongnv89 - 
        // else if (MMT_PORT_MATCH(sport, dport, 1214)) return (PROTO_KAZAA);//KAZAA -was generated automatically by MMTCrawler - @luongnv89 - 


    } else if(packet->udp) {
        sport = htons(packet->udp->source);
        dport = htons(packet->udp->dest);
        if (MMT_PORT_MATCH(sport, dport, 67) || MMT_PORT_MATCH(sport, dport, 68)) return (PROTO_DHCP);
        else if (MMT_PORT_MATCH(sport, dport, 137) || MMT_PORT_MATCH(sport, dport, 138)) return (PROTO_NETBIOS);
        else if (MMT_PORT_MATCH(sport, dport, 161) || MMT_PORT_MATCH(sport, dport, 162)) return (PROTO_SNMP);
        else if (MMT_PORT_MATCH(sport, dport, 5353) || MMT_PORT_MATCH(sport, dport, 5354)) return (PROTO_MDNS);
        else if (MMT_PORT_MATCH(sport, dport, 53)) return (PROTO_DNS);
        else if (MMT_PORT_MATCH(sport, dport, 88)) return (PROTO_KERBEROS);
        // else if (MMT_PORT_MATCH(sport, dport, 270)) return (PROTO_GIST); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 271)) return (PROTO_PT_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 323)) return (PROTO_RPKI_RTR); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 324)) return (PROTO_RPKI_RTR_TLS); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 456)) return (PROTO_MACON_UDP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 465)) return (PROTO_IGMPV3LITE); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 474)) return (PROTO_TN_TL_W2); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 512)) return (PROTO_COMSAT); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 512)) return (PROTO_BIFF); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 513)) return (PROTO_WHO); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 520)) return (PROTO_ROUTER); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 623)) return (PROTO_ASF_RMCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 664)) return (PROTO_ASF_SECURE_RMCP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 716)) return (PROTO_PANA); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 750)) return (PROTO_LOADAV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 750)) return (PROTO_KERBEROS_IV); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 773)) return (PROTO_NOTIFY); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 774)) return (PROTO_ACMAINT_DBD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 775)) return (PROTO_ACMAINT_TRANSD); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 998)) return (PROTO_PUPARP); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 999)) return (PROTO_APPLIX); // was generated automatically by MMTCrawler - @luongnv89
        // else if (MMT_PORT_MATCH(sport, dport, 514)) return (PROTO_SYSLOG);//-was generated automatically by MMTCrawler - @luongnv89 -

    }
    return (PROTO_UNKNOWN);
}

