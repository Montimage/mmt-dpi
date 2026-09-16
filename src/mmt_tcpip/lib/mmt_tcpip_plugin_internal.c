#include "mmt_common_internal_include.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ------------------------------------------------------------------------
 * M9 (issue #26): externally-updatable, port -> protocol *hint* table.
 *
 * The built-in switches in _get_proto_by_{tcp,udp}_port_number() below remain
 * the bundled default. Operators may additionally provide a data file (path in
 * MMT_DPI_PORT_MAP_FILE) with extra "<tcp|udp> <port> <protocol>" rules. These
 * are consulted ONLY AFTER the built-in switch returns PROTO_UNKNOWN, so they
 * never override a compiled-in mapping and add nothing when the variable is
 * unset (the default / CI path) -> classification stays byte-identical.
 *
 * Port-based attribution is, by design, the weakest signal in the pipeline: it
 * is a *hint* of last resort (callers only consult it after payload-signature
 * and IP-range classification have already failed, and only when the handler
 * opts in via enable_port_classify(), which is OFF by default). Sourcing the
 * extra ports from an updatable file keeps that weak signal out of the
 * compiled-in tables and lets it be refreshed without a rebuild.
 *
 * The arrays are populated once at init time (init_tcpip_plugin(), single
 * threaded) and only read afterwards on the hot path -> threading-contract safe.
 * ------------------------------------------------------------------------ */
typedef struct {
    uint16_t port;
    uint32_t proto_id;
} ext_port_entry_t;

static ext_port_entry_t *ext_tcp_ports = NULL;
static size_t            ext_tcp_ports_n = 0;
static ext_port_entry_t *ext_udp_ports = NULL;
static size_t            ext_udp_ports_n = 0;

/* M9 (issue #74): override port hints. A rule tagged "override" in the data
 * file lands here and is consulted *before* the compiled-in switch, so it can
 * replace a built-in port->protocol mapping (extend rules above can only fill
 * gaps). Empty unless an external file supplies override rules -> default path
 * byte-identical. */
static ext_port_entry_t *ext_tcp_ports_override = NULL;
static size_t            ext_tcp_ports_override_n = 0;
static ext_port_entry_t *ext_udp_ports_override = NULL;
static size_t            ext_udp_ports_override_n = 0;

static inline uint64_t _ext_port_lookup(const ext_port_entry_t *table, size_t n,
                                        uint16_t port_number) {
    for (size_t i = 0; i < n; i++) {
        if (table[i].port == port_number) {
            return table[i].proto_id;
        }
    }
    return PROTO_UNKNOWN;
}

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

inline static uint64_t _get_proto_by_tcp_port_number(uint16_t port_number,const u_char * payload, int payload_packet_len){
    // M9 (issue #74): override hints win over the compiled-in switch.
    uint64_t override_id = _ext_port_lookup(ext_tcp_ports_override,
                                            ext_tcp_ports_override_n, port_number);
    if (override_id != PROTO_UNKNOWN) {
        return override_id;
    }
    switch(port_number){
        case 443:
        return PROTO_SSL;

        case 80:
        case 8080:
        return PROTO_HTTP;

        case 22:
        return PROTO_SSH;

        case 23:
        return PROTO_TELNET;

        case 25:
        return PROTO_SMTP;

        case 465:
        return PROTO_SMTPS;

        case 110:
        return PROTO_POP;

        case 995:
        return PROTO_POPS;

        case 143:
        return PROTO_IMAP;

        case 993:
        return PROTO_IMAPS;

        case 445:
        return PROTO_SMB;

        case 88:
        return PROTO_KERBEROS;

        case 135:
        return PROTO_DCERPC;

        case 389:
        return PROTO_LDAP;

        case 554:
        return PROTO_RTSP;

        case 500:
        return PROTO_IPSEC;

        case 5800:
        case 5900:
        case 5901:
        return PROTO_VNC;

        case 5222:
        return PROTO_UNENCRYPED_JABBER;

        case 1935:
        return PROTO_FLASH;

        case 3128:
        return PROTO_HTTP_PROXY;

        case 2598:
        case 1494:
        return PROTO_CITRIX;/* http://support.citrix.com/article/CTX104147 */

    }
    // M9 (issue #26): fall back to externally-loaded port hints (extend-only).
    return _ext_port_lookup(ext_tcp_ports, ext_tcp_ports_n, port_number);
}

inline static uint64_t _get_proto_by_udp_port_number(uint16_t port_number,const u_char * payload, int payload_packet_len){
    // M9 (issue #74): override hints win over the compiled-in switch.
    uint64_t override_id = _ext_port_lookup(ext_udp_ports_override,
                                            ext_udp_ports_override_n, port_number);
    if (override_id != PROTO_UNKNOWN) {
        return override_id;
    }
    switch(port_number){
        case 67:
        case 68:
        return PROTO_DHCP;

        case 137:
        case 138:
        return PROTO_NETBIOS;

        case 161:
        case 162:
        return PROTO_SNMP;

        case 5353:
        case 5354:
        return PROTO_MDNS;

        case 53:
        return PROTO_DNS;

        case 88:
        return PROTO_KERBEROS;

        case 500:
        return PROTO_IPSEC;

        case 5355:
        return PROTO_LLMNR;
        case 1883:
        case 8883:
        return PROTO_MQTT;
    }
    // M9 (issue #26): fall back to externally-loaded port hints (extend-only).
    return _ext_port_lookup(ext_udp_ports, ext_udp_ports_n, port_number);
}
// unsigned int mmt_get_protocol_by_port_number(uint8_t proto, uint16_t sport, uint16_t dport) {
//     uint64_t proto_id = PROTO_UNKNOWN;
//     if (proto == IPPROTO_UDP) {
//         proto_id = _get_proto_by_udp_port_number(sport);
//         if(proto_id == PROTO_UNKNOWN){
//              proto_id = _get_proto_by_udp_port_number(dport);
//         }
//     } else if (proto == IPPROTO_TCP) {
//         proto_id = _get_proto_by_tcp_port_number(sport);
//         if(proto_id == PROTO_UNKNOWN){
//              proto_id = _get_proto_by_tcp_port_number(dport);
//         }
//     }

//     return (proto_id);
// }

/*
 * M9 (issue #75): payload-confirmed port-only demotion.
 *
 * Minimal, allocation-free leading-byte signatures for the protocols the port
 * switches above can attribute. Deliberately conservative: a protocol with no
 * signature below returns 0, so when payload confirmation is required an
 * unconfirmed port-only guess is demoted rather than trusted. Kept independent
 * of the full per-protocol classifiers (which carry side effects) so it is safe
 * to call cheaply on the classification path.
 */
int mmt_payload_confirms_proto(uint32_t proto_id,
                               const unsigned char *payload,
                               int payload_packet_len) {
    if (payload == NULL || payload_packet_len <= 0) {
        return 0;
    }
    switch (proto_id) {
        case PROTO_HTTP: {
            /* request methods or a response status line */
            static const struct { const char *s; int n; } sigs[] = {
                {"GET ", 4}, {"POST ", 5}, {"HEAD ", 5}, {"PUT ", 4},
                {"DELETE ", 7}, {"OPTIONS ", 8}, {"PATCH ", 6}, {"TRACE ", 6},
                {"CONNECT ", 8}, {"HTTP/", 5}
            };
            int i;
            for (i = 0; i < (int)(sizeof(sigs) / sizeof(sigs[0])); i++) {
                if (payload_packet_len >= sigs[i].n &&
                    memcmp(payload, sigs[i].s, sigs[i].n) == 0) {
                    return 1;
                }
            }
            return 0;
        }
        case PROTO_SSL:
            /* TLS/SSLv3 record: content type 0x14-0x17, version major 0x03 */
            return (payload_packet_len >= 3 &&
                    payload[0] >= 0x14 && payload[0] <= 0x17 &&
                    payload[1] == 0x03 && payload[2] <= 0x04);
        case PROTO_SSH:
            return (payload_packet_len >= 4 && memcmp(payload, "SSH-", 4) == 0);
        case PROTO_SMTP:
            /* server greeting "220" or client EHLO/HELO */
            return (payload_packet_len >= 4 &&
                    ((payload[0] == '2' && payload[1] == '2' && payload[2] == '0') ||
                     memcmp(payload, "EHLO", 4) == 0 ||
                     memcmp(payload, "HELO", 4) == 0));
        case PROTO_POP:
            return (payload_packet_len >= 3 && memcmp(payload, "+OK", 3) == 0);
        case PROTO_IMAP:
            return (payload_packet_len >= 4 && memcmp(payload, "* OK", 4) == 0);
        case PROTO_FTP:
            /* control-channel greeting "220 " or multiline "220-" */
            return (payload_packet_len >= 4 &&
                    payload[0] == '2' && payload[1] == '2' && payload[2] == '0' &&
                    (payload[3] == ' ' || payload[3] == '-'));
        default:
            return 0;
    }
}

unsigned int mmt_guess_protocol_by_port_number(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint64_t proto_id = PROTO_UNKNOWN;
    uint16_t sport, dport;
    if (packet->tcp) {
        /* Issue #212 (F-BUG-031): packet->tcp->source/dest are network byte
         * order — converting FROM wire to host order is ntohs(), not the
         * host-to-network direction. (Identical bit-swap on common platforms,
         * but the wrong name.) */
        sport = ntohs(packet->tcp->source);
        dport = ntohs(packet->tcp->dest);
        proto_id = _get_proto_by_tcp_port_number(sport,packet->payload,packet->payload_packet_len);
        if(proto_id == PROTO_UNKNOWN){
             proto_id = _get_proto_by_tcp_port_number(dport,packet->payload,packet->payload_packet_len);
        }
    } else if(packet->udp) {
        sport = ntohs(packet->udp->source);
        dport = ntohs(packet->udp->dest);
        proto_id = _get_proto_by_udp_port_number(sport,packet->payload,packet->payload_packet_len);
        if(proto_id == PROTO_UNKNOWN){
             proto_id = _get_proto_by_udp_port_number(dport,packet->payload,packet->payload_packet_len);
        }
    }
    /* M9 (issue #75): demote a port-only guess unless the payload confirms it.
     * Default-off (port_classify_payload_confirm == 0) keeps the bundled
     * behaviour byte-identical to the baseline. */
    if (proto_id != PROTO_UNKNOWN &&
        ipacket->mmt_handler->port_classify_payload_confirm != 0 &&
        !mmt_payload_confirms_proto((uint32_t) proto_id,
                                    packet->payload, packet->payload_packet_len)) {
        return PROTO_UNKNOWN;
    }
    return (proto_id);
}

/* Grow `*table` by one and append a {port, proto_id} hint. Returns 1/0. */
static int _ext_port_append(ext_port_entry_t **table, size_t *count,
                            uint16_t port, uint32_t proto_id) {
    ext_port_entry_t *grown =
        (ext_port_entry_t *) mmt_realloc(*table, (*count + 1) * sizeof(**table));
    if (grown == NULL) {
        return 0;
    }
    grown[*count].port     = port;
    grown[*count].proto_id = proto_id;
    *table = grown;
    (*count)++;
    return 1;
}

int mmt_tcpip_load_port_map_file(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        mmt_stderr_log( "[mmt-dpi][M9] could not open port-map file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    char line[512];
    int loaded = 0, lineno = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash != NULL) {
            *hash = '\0';
        }
        // Format: "<tcp|udp> <port> <PROTO> [override]". The optional fourth
        // token (issue #74) routes the hint to the override table (consulted
        // before the built-in switch); anything else is flagged but the rule
        // still loads as an extend hint.
        char l4[16], proto_tok[128], flag_tok[32];
        int port = 0;
        int nf = sscanf(line, "%15s %d %127s %31s", l4, &port, proto_tok, flag_tok);
        if (nf < 3) {
            continue; // blank / malformed line -> skip silently
        }
        int is_override = 0;
        if (nf >= 4) {
            if (strcasecmp(flag_tok, "override") == 0) {
                is_override = 1;
            } else {
                mmt_stderr_log( "[mmt-dpi][M9] %s:%d unknown flag '%s' (expected "
                        "'override') - treating hint as extend\n",
                        path, lineno, flag_tok);
            }
        }
        if (port <= 0 || port > 65535) {
            mmt_stderr_log( "[mmt-dpi][M9] %s:%d port %d out of range - skipped\n",
                    path, lineno, port);
            continue;
        }
        uint32_t proto_id = get_protocol_id_by_name(proto_tok);
        if (proto_id == PROTO_UNKNOWN) {
            char *end = NULL;
            long val = strtol(proto_tok, &end, 10);
            if (end != proto_tok && *end == '\0' && val > 0 && val < PROTO_MAX_IDENTIFIER) {
                proto_id = (uint32_t) val;
            }
        }
        if (proto_id == PROTO_UNKNOWN) {
            mmt_stderr_log( "[mmt-dpi][M9] %s:%d unknown protocol '%s' - skipped\n",
                    path, lineno, proto_tok);
            continue;
        }
        int ok = 0;
        if (strcasecmp(l4, "tcp") == 0) {
            ok = is_override
                ? _ext_port_append(&ext_tcp_ports_override, &ext_tcp_ports_override_n,
                                   (uint16_t) port, proto_id)
                : _ext_port_append(&ext_tcp_ports, &ext_tcp_ports_n,
                                   (uint16_t) port, proto_id);
        } else if (strcasecmp(l4, "udp") == 0) {
            ok = is_override
                ? _ext_port_append(&ext_udp_ports_override, &ext_udp_ports_override_n,
                                   (uint16_t) port, proto_id)
                : _ext_port_append(&ext_udp_ports, &ext_udp_ports_n,
                                   (uint16_t) port, proto_id);
        } else {
            mmt_stderr_log( "[mmt-dpi][M9] %s:%d expected 'tcp'/'udp', got '%s' - skipped\n",
                    path, lineno, l4);
            continue;
        }
        if (ok) {
            loaded++;
        }
    }
    fclose(fp);
    return loaded;
}

void mmt_tcpip_load_external_port_map(void) {
    const char *path = getenv("MMT_DPI_PORT_MAP_FILE");
    if (path == NULL || path[0] == '\0') {
        return; // default: byte-identical to the compiled-in baseline
    }
    int n = mmt_tcpip_load_port_map_file(path);
    if (n > 0) {
        mmt_stderr_log( "[mmt-dpi][M9] loaded %d external port hint(s) from %s\n",
                n, path);
    }
}

void mmt_tcpip_free_external_port_map(void) {
    mmt_free(ext_tcp_ports);
    ext_tcp_ports = NULL;
    ext_tcp_ports_n = 0;
    mmt_free(ext_udp_ports);
    ext_udp_ports = NULL;
    ext_udp_ports_n = 0;
    // M9 (#74): override tables.
    mmt_free(ext_tcp_ports_override);
    ext_tcp_ports_override = NULL;
    ext_tcp_ports_override_n = 0;
    mmt_free(ext_udp_ports_override);
    ext_udp_ports_override = NULL;
    ext_udp_ports_override_n = 0;
}

