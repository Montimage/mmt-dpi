#include "mmt_common_internal_include.h"
#include "avltree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>

/*
 */
static inline int _mmt_case_sensitive_reverse_hostname_matching(const char *hostname, const char *url, size_t hostname_len, size_t url_len) {
    /* Issue #212 (F-BUG-026): guard the zero-length cases first —
     * `url_len - 1` underflows size_t when url_len == 0, and `hostname_len - 1`
     * would place hnr one byte BEFORE the buffer, dereferenced by the loop.
     * The hostname is packet-derived and may not be NUL-terminated, so the
     * counters must be tested BEFORE dereferencing the cursors (the old order
     * `*hnr && *hnr == *urlr && url_len && hostname_len` read one byte before
     * both buffers once a counter reached 0). */
    if (hostname_len == 0 || url_len == 0 || hostname == NULL || url == NULL) {
        return 0; //No match
    }
    if (hostname_len < url_len - 1) {
        return 0; //No match
    }

    const char * hnr  = &hostname[hostname_len - 1];
    const char * urlr = &url[url_len - 1];

    while (url_len && hostname_len && *hnr && *hnr == *urlr) {
        url_len--;
        hostname_len--;
        hnr--;
        urlr--;
    }
    if (0 == url_len || hostname_len == 0)
        return 1; /* they are equal this far */

    return 0;
}

int mmt_case_sensitive_reverse_hostname_matching(const char *hostname, const char *url, size_t hostname_len, size_t url_len) {
    return _mmt_case_sensitive_reverse_hostname_matching( hostname, url, hostname_len, url_len);
}

/* Generated protocol-match data: hostname-suffix table (issue #250).
 * Included as a data unit so this file holds only classification logic.
 */
#include "mmt_tcpip_classif_doted_host_names.inc"

static protocol_match ak_cdn_url_start_with_names[] = {
    {"fbcdn-sphotos", PROTO_FACEBOOK, 13, MMT_CONTENT_CDN | MMT_CONTENT_IMAGE},
    {"fbstatic", PROTO_FACEBOOK, 8, MMT_CONTENT_CDN},
    {"fbcdn-profile", PROTO_FACEBOOK, 13, MMT_CONTENT_CDN},
    {"fbcdn-video", PROTO_FACEBOOK, 11, MMT_CONTENT_CDN | MMT_CONTENT_VIDEO},
    {"fbexternal", PROTO_FACEBOOK, 10, MMT_CONTENT_CDN},
    {"fbcdn-photos", PROTO_FACEBOOK, 12, MMT_CONTENT_CDN | MMT_CONTENT_IMAGE},
    {"fbcdn", PROTO_FACEBOOK, 5, MMT_CONTENT_CDN},
    { NULL, 0, 0}
};

static inline uint32_t get_proto_id_from_ak_cdn(ipacket_t * ipacket, char *hostname, u_int hostname_len) {
    int i = 0;
    while (ak_cdn_url_start_with_names[i].string_to_match != NULL) {
        if (hostname_len > ak_cdn_url_start_with_names[i].str_len && strncmp(hostname, ak_cdn_url_start_with_names[i].string_to_match, ak_cdn_url_start_with_names[i].str_len) == 0) {
            ipacket->session->content_flags = ipacket->session->content_flags | ak_cdn_url_start_with_names[i].content_flags;
            return ak_cdn_url_start_with_names[i].proto_id;
        }
        i++;
    }

    return PROTO_AKAMAI; //This is akamai anyway
}

/* Generated protocol-match data: IPv4 prefix table, ~10k ranges (issue #250).
 * Included as a data unit so this file holds only classification logic.
 */
#include "mmt_tcpip_classif_proto_ip_address.inc"

// ~10.000 IP ranges
static avltree_t * proto_avltrees[NETMASK_MAX_NB];

/* ------------------------------------------------------------------------
 * M9 (issue #26 / #74): externally-updatable IP-range attribution.
 *
 * Extra CIDR->protocol rules loaded from MMT_DPI_IP_RANGES_FILE are merged ON
 * TOP of the compiled-in proto_ip_address[] table. Two precedence classes are
 * supported (issue #74):
 *
 *   - "extend" rules (the default, and the only mode in #26) are appended to the
 *     same per-prefix AVL trees as the built-in table. Longest-prefix-first
 *     lookup means a more-specific external rule already wins over a broader
 *     built-in one, but an extend rule can never displace a built-in entry at
 *     the *same* prefix+network.
 *   - "override" rules (issue #74) are kept in a SEPARATE per-prefix tree set
 *     that is consulted *before* the built-in/extend trees, so they take
 *     precedence over a compiled-in mapping (replace, not just extend).
 *
 * Externally-loaded entry structs are heap-allocated (the built-in ones point
 * into the static const table) so we track them in a single-linked list and
 * release them in _free_proto_avltrees(). The lists/trees are only mutated at
 * init time, single threaded, before any worker thread runs. When the env var
 * is unset (the default / CI path) nothing extra is loaded and classification
 * stays byte-identical to the compiled-in baseline.
 * ------------------------------------------------------------------------ */
static avltree_t * proto_avltrees_override[NETMASK_MAX_NB];

typedef struct _dyn_ip_range_node {
    proto_based_ip_t            entry;
    struct _dyn_ip_range_node * next;
} _dyn_ip_range_node_t;

static _dyn_ip_range_node_t * _dyn_ip_ranges = NULL;

/* Insert one IPv4 CIDR->protocol rule (host-byte-order network + mask) into the
 * AVL trees. `is_override` routes it to the override tree set (consulted first)
 * instead of the extend trees. Returns 1 on success, 0 if the prefix length is
 * out of the supported range or the allocation/insert failed. Used only for
 * externally-loaded rules; the built-in table keeps its zero-allocation fast
 * path below. */
static int _insert_dynamic_ip_range(int netmask_nb, uint32_t netmask_address,
                                    uint32_t ip_address, int proto_id,
                                    int is_override) {
    // The AVL trees are indexed by prefix length; the array has NETMASK_MAX_NB
    // slots (0 .. NETMASK_MAX_NB-1). Reject anything that would index OOB or a
    // /0 catch-all (which the built-in table never uses either).
    if (netmask_nb <= 0 || netmask_nb >= NETMASK_MAX_NB) {
        return 0;
    }
    _dyn_ip_range_node_t * dyn = (_dyn_ip_range_node_t *) mmt_malloc(sizeof(*dyn));
    if (dyn == NULL) {
        return 0;
    }
    dyn->entry.netmask_nb      = netmask_nb;
    dyn->entry.netmask_address = netmask_address;
    dyn->entry.ip_address      = ip_address & netmask_address;
    dyn->entry.proto_id        = proto_id;

    avltree_t ** trees = is_override ? proto_avltrees_override : proto_avltrees;

    // A second rule for the same prefix+network in the same class would hit
    // avltree_insert()'s duplicate-key branch. Detect the duplicate and update
    // the existing node in place instead (last rule wins); the superseded entry
    // stays tracked in the cleanup list. avltree_find() is NULL-safe for an
    // empty tree. (Issue #212 (F-BUG-027): the duplicate branch used to return
    // the unlinked node, orphaning the whole subtree — avltree_insert() now
    // returns the existing root, but the explicit in-place update is still
    // required for the last-rule-wins semantics.)
    avltree_t * existing = avltree_find(trees[netmask_nb], dyn->entry.ip_address);
    if (existing != NULL) {
        // Per the extend/override contract (docs/External-Attribution.md): an
        // *extend* rule must never displace a compiled-in entry at the same
        // prefix+network — only an `override` rule may. The extend tree set
        // (proto_avltrees) is seeded with the static proto_ip_address[] nodes,
        // so a same-CIDR extend collision can land on a built-in node. Detect
        // that (data pointer inside the static built-in table) and drop the
        // extend rule rather than overwriting the built-in attribution. The
        // override tree set holds no built-ins, so override collisions never
        // match here and fall through to the last-rule-wins update below.
        uintptr_t hit = (uintptr_t) existing->data;
        uintptr_t lo  = (uintptr_t) proto_ip_address;
        uintptr_t hi  = (uintptr_t) (proto_ip_address +
                            sizeof(proto_ip_address) / sizeof(proto_ip_address[0]));
        if (hit >= lo && hit < hi) {
            // Built-in stays authoritative; the extend rule is a no-op. Treated
            // as an accepted (valid) line so the loader's rule count is unchanged.
            mmt_free(dyn);
            return 1;
        }
        // Collision with an earlier dynamic rule of the same class: last rule
        // wins. The superseded entry stays tracked in the cleanup list.
        existing->data = (void *) &dyn->entry;
        dyn->next = _dyn_ip_ranges;
        _dyn_ip_ranges = dyn;
        return 1;
    }

    avltree_t * node = avltree_create(dyn->entry.ip_address, (void*)&dyn->entry);
    if (node == NULL) {
        mmt_free(dyn);
        return 0;
    }
    trees[netmask_nb] = avltree_insert(trees[netmask_nb], node);

    // Keep the heap entry alive and tracked for cleanup.
    dyn->next = _dyn_ip_ranges;
    _dyn_ip_ranges = dyn;
    return 1;
}

/* ------------------------------------------------------------------------
 * M9 (issue #74): externally-loaded IPv6 CIDR->protocol attribution.
 *
 * The compiled-in table and the AVL trees above are IPv4-only (a uint32_t key).
 * IPv6 ranges have no compiled-in baseline, so they live entirely in this
 * heap-allocated, init-time-only linked list and are matched by a 128-bit
 * longest-prefix scan. The list is empty unless an external file supplies IPv6
 * rules, so the default IPv6 classification path is unchanged.
 * ------------------------------------------------------------------------ */
typedef struct _ipv6_range_node {
    uint8_t                   addr[16];   // network address, already masked
    int                       prefix;     // 1 .. 128
    int                       proto_id;
    int                       is_override; // override rules win over extend rules
    struct _ipv6_range_node * next;
} _ipv6_range_node_t;

static _ipv6_range_node_t * _ipv6_ranges = NULL;

/* Mask `src` in place to keep only the leading `prefix` bits (rest zeroed). */
static void _ipv6_apply_mask(uint8_t addr[16], int prefix) {
    int full = prefix / 8;
    int rem  = prefix % 8;
    int i;
    if (rem) {
        addr[full] = (uint8_t) (addr[full] & (uint8_t) (0xFFu << (8 - rem)));
        full++;
    }
    for (i = full; i < 16; i++) {
        addr[i] = 0;
    }
}

/* Return 1 if `addr` falls inside the `net`/`prefix` IPv6 network. `net` must
 * already be masked to `prefix` bits. */
static int _ipv6_match(const uint8_t addr[16], const uint8_t net[16], int prefix) {
    int full = prefix / 8;
    int rem  = prefix % 8;
    if (full && memcmp(addr, net, full) != 0) {
        return 0;
    }
    if (rem) {
        uint8_t mask = (uint8_t) (0xFFu << (8 - rem));
        if ((uint8_t) (addr[full] & mask) != (uint8_t) (net[full] & mask)) {
            return 0;
        }
    }
    return 1;
}

/* Insert one IPv6 CIDR->protocol rule. The address is masked to `prefix` bits
 * on the way in. Returns 1 on success, 0 on bad prefix / allocation failure. */
static int _insert_ipv6_range(const uint8_t addr[16], int prefix, int proto_id,
                              int is_override) {
    if (prefix <= 0 || prefix > 128) {
        return 0;
    }
    _ipv6_range_node_t * node = (_ipv6_range_node_t *) mmt_malloc(sizeof(*node));
    if (node == NULL) {
        return 0;
    }
    memcpy(node->addr, addr, 16);
    _ipv6_apply_mask(node->addr, prefix);
    node->prefix      = prefix;
    node->proto_id    = proto_id;
    node->is_override  = is_override;
    node->next        = _ipv6_ranges;
    _ipv6_ranges      = node;
    return 1;
}

/* Longest-prefix-match lookup over the externally-loaded IPv6 ranges, applied to
 * the source then the destination address. Override rules win over extend rules
 * regardless of prefix length; within a class the longest prefix wins. Returns
 * the matched protocol id, or -1 when nothing matches. */
int _find_proto_id_by_address6(const uint8_t ip_src[16], const uint8_t ip_dest[16]) {
    int best_override = -1, best_override_prefix = -1;
    int best_extend   = -1, best_extend_prefix   = -1;
    _ipv6_range_node_t * n = _ipv6_ranges;
    while (n != NULL) {
        if (_ipv6_match(ip_src, n->addr, n->prefix) ||
            _ipv6_match(ip_dest, n->addr, n->prefix)) {
            if (n->is_override) {
                if (n->prefix > best_override_prefix) {
                    best_override_prefix = n->prefix;
                    best_override        = n->proto_id;
                }
            } else if (n->prefix > best_extend_prefix) {
                best_extend_prefix = n->prefix;
                best_extend        = n->proto_id;
            }
        }
        n = n->next;
    }
    return (best_override != -1) ? best_override : best_extend;
}

/**
 * Initialize protocol AVL Trees
 */
void _init_proto_avltrees() {
    // mmt_debug_log("[debug] _init_proto_avltrees ... \n");
    int i = 0 , nb_nodes = 0;
    for (i = NETMASK_MAX_NB - 1 ; i >= 0; i--) {
        proto_avltrees[i] = 0x0;
        proto_avltrees_override[i] = 0x0; // M9 (#74): external override tree set
    }

    i = 0;

    while (proto_ip_address[i].netmask_nb != 0) {
        uint32_t key = proto_ip_address[i].ip_address;
        int tree_index = proto_ip_address[i].netmask_nb;
        /* Issue #212 (F-BUG-028): the index came straight from the generated
         * table — a malformed entry would index proto_avltrees[] out of bounds.
         * Range-check it like the external-rule loader does. */
        if (tree_index <= 0 || tree_index >= NETMASK_MAX_NB) {
            mmt_stderr_log( "[mmt-dpi] proto_ip_address[%d]: prefix length %d out of range [1,%d] - entry skipped\n",
                    i, tree_index, NETMASK_MAX_NB - 1);
            i++;
            continue;
        }
        // mmt_debug_log("[debug] %d new node key = %u, tree_index = %d\n", i, key, tree_index);
        avltree_t * node = avltree_create(key, (void*)&proto_ip_address[i]);
        if (node != NULL) {
            int is_duplicate = 0;
            proto_avltrees[tree_index] = avltree_insert_ex(proto_avltrees[tree_index], node, &is_duplicate);
            if (is_duplicate) {
                /* A duplicate table key must not silently orphan the subtree
                 * (F-BUG-027); the unlinked node stays ours — free it. */
                mmt_stderr_log( "[mmt-dpi] proto_ip_address[%d]: duplicate key %u - entry skipped\n",
                        i, key);
                avltree_free_node(node);
            } else {
                nb_nodes++;
            }
            // mmt_debug_log("[debug] new node has been added into tree: %d\n", tree_index);
            // avltree_show_node(node);
        }
        i++;
    }
#ifdef DEBUG
    mmt_debug_log("AVLTrees - total number of nodes: %d\n",nb_nodes);
    mmt_debug_log("Index\t Height \t Size\n");
    for (i = 0; i < NETMASK_MAX_NB; i ++) {
        if(proto_avltrees[i] != NULL){
            mmt_debug_log("%d\t %d \t %d\n",i,avltree_get_height(proto_avltrees[i],1),avltree_size(proto_avltrees[i]));
        }
    }
#endif    
}

/* Longest-prefix-first lookup over one IPv4 per-prefix AVL tree set, applied to
 * the source then the destination address. Returns the matched protocol id or
 * -1 when nothing matches. */
static int _find_proto_id_in_trees(avltree_t * const trees[], uint32_t ip_src,
                                   uint32_t ip_dest) {
    int i;
    for (i = NETMASK_MAX_NB - 1 ; i >= 0; i--) {
        if (trees[i] != NULL) {
            proto_based_ip_t * proto = (proto_based_ip_t * ) avltree_get_data(trees[i]);
            // Check the source address
            uint32_t key_src = ip_src & proto->netmask_address;
            avltree_t * node_src = avltree_find(trees[i],key_src);
            if(node_src != NULL){
                proto_based_ip_t * found_proto = (proto_based_ip_t * ) avltree_get_data(node_src);
                return found_proto->proto_id;
            }
            // Check the destination address
            uint32_t key_dest = ip_dest & proto->netmask_address;
            avltree_t * node_dest = avltree_find(trees[i],key_dest);
            if(node_dest != NULL){
                proto_based_ip_t * found_proto = (proto_based_ip_t * ) avltree_get_data(node_dest);
                return found_proto->proto_id;
            }
        }
    }
    return -1;
}

int _find_proto_id_by_address(uint32_t ip_src,uint32_t ip_dest){
    // M9 (#74): operator-supplied override rules win over the compiled-in table.
    int proto_id = _find_proto_id_in_trees(proto_avltrees_override, ip_src, ip_dest);
    if (proto_id != -1) {
        return proto_id;
    }
    return _find_proto_id_in_trees(proto_avltrees, ip_src, ip_dest);
}

void _free_proto_avltrees(){
    // mmt_debug_log("[debug] _free_proto_avltrees ... \n");
    int i = 0;
    for (i = NETMASK_MAX_NB - 1 ; i >= 0; i--) {
        avltree_free_tree(proto_avltrees[i]);
        proto_avltrees[i] = NULL;
        avltree_free_tree(proto_avltrees_override[i]); // M9 (#74) override set
        proto_avltrees_override[i] = NULL;
    }
    // Release the heap-allocated externally-loaded IPv4 IP-range entries
    // (issue #26 extend rules + issue #74 override rules — both tracked here).
    _dyn_ip_range_node_t * dyn = _dyn_ip_ranges;
    while (dyn != NULL) {
        _dyn_ip_range_node_t * next = dyn->next;
        mmt_free(dyn);
        dyn = next;
    }
    _dyn_ip_ranges = NULL;
    // Release the externally-loaded IPv6 ranges (issue #74).
    _ipv6_range_node_t * v6 = _ipv6_ranges;
    while (v6 != NULL) {
        _ipv6_range_node_t * next = v6->next;
        mmt_free(v6);
        v6 = next;
    }
    _ipv6_ranges = NULL;
}

/* Resolve a protocol token to an id: first by registered name, then (to keep
 * the data files robust against future protocol renames) as a raw numeric id. */
static int _resolve_proto_token(const char *token) {
    uint32_t proto_id = get_protocol_id_by_name(token);
    if (proto_id != PROTO_UNKNOWN) {
        return (int) proto_id;
    }
    // Accept a bare positive integer id as a fallback.
    char *end = NULL;
    long val = strtol(token, &end, 10);
    if (end != token && *end == '\0' && val > 0 && val < PROTO_MAX_IDENTIFIER) {
        return (int) val;
    }
    return PROTO_UNKNOWN;
}

int mmt_tcpip_load_ip_ranges_file(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        mmt_stderr_log( "[mmt-dpi][M9] could not open IP-range file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    char line[512];
    int loaded = 0, lineno = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;
        // Strip comments (everything after '#') and surrounding whitespace.
        char *hash = strchr(line, '#');
        if (hash != NULL) {
            *hash = '\0';
        }
        // Format: "<addr>/<prefixlen> <PROTO> [override]". The optional third
        // token (issue #74) routes the rule to the override set; anything else
        // there is flagged but the rule still loads as an extend rule.
        char cidr[128], proto_tok[128], flag_tok[32];
        int nf = sscanf(line, "%127s %127s %31s", cidr, proto_tok, flag_tok);
        if (nf < 2) {
            continue; // blank / malformed line -> skip silently
        }
        int is_override = 0;
        if (nf >= 3) {
            if (strcasecmp(flag_tok, "override") == 0) {
                is_override = 1;
            } else {
                mmt_stderr_log( "[mmt-dpi][M9] %s:%d unknown flag '%s' (expected "
                        "'override') - treating rule as extend\n",
                        path, lineno, flag_tok);
            }
        }
        // Split "<addr>/<prefixlen>".
        char *slash = strchr(cidr, '/');
        if (slash == NULL) {
            mmt_stderr_log( "[mmt-dpi][M9] %s:%d missing '/prefix' in '%s' - skipped\n",
                    path, lineno, cidr);
            continue;
        }
        *slash = '\0';
        int prefix = atoi(slash + 1);

        // An ':' in the address selects the IPv6 path (issue #74); otherwise the
        // address is parsed as IPv4 (issue #26), keeping byte-identical
        // behaviour for existing IPv4-only data files.
        int is_ipv6 = (strchr(cidr, ':') != NULL);
        int proto_id;
        if (is_ipv6) {
            struct in6_addr addr6;
            if (inet_pton(AF_INET6, cidr, &addr6) != 1) {
                mmt_stderr_log( "[mmt-dpi][M9] %s:%d invalid IPv6 address '%s' - skipped\n",
                        path, lineno, cidr);
                continue;
            }
            if (prefix <= 0 || prefix > 128) {
                mmt_stderr_log( "[mmt-dpi][M9] %s:%d IPv6 prefix /%d out of range [1,128] - skipped\n",
                        path, lineno, prefix);
                continue;
            }
            proto_id = _resolve_proto_token(proto_tok);
            if (proto_id == PROTO_UNKNOWN) {
                mmt_stderr_log( "[mmt-dpi][M9] %s:%d unknown protocol '%s' - skipped\n",
                        path, lineno, proto_tok);
                continue;
            }
            if (_insert_ipv6_range(addr6.s6_addr, prefix, proto_id, is_override)) {
                loaded++;
            }
            continue;
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, cidr, &addr) != 1) {
            mmt_stderr_log( "[mmt-dpi][M9] %s:%d invalid IPv4 address '%s' - skipped\n",
                    path, lineno, cidr);
            continue;
        }
        if (prefix <= 0 || prefix >= NETMASK_MAX_NB) {
            mmt_stderr_log( "[mmt-dpi][M9] %s:%d prefix /%d out of range [1,%d] - skipped\n",
                    path, lineno, prefix, NETMASK_MAX_NB - 1);
            continue;
        }
        proto_id = _resolve_proto_token(proto_tok);
        if (proto_id == PROTO_UNKNOWN) {
            mmt_stderr_log( "[mmt-dpi][M9] %s:%d unknown protocol '%s' - skipped\n",
                    path, lineno, proto_tok);
            continue;
        }
        // Work in host byte order to match _find_proto_id_by_address().
        uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
        uint32_t ip   = ntohl(addr.s_addr);
        if (_insert_dynamic_ip_range(prefix, mask, ip, proto_id, is_override)) {
            loaded++;
        }
    }
    fclose(fp);
    return loaded;
}

void mmt_tcpip_load_external_ip_ranges(void) {
    const char *path = getenv("MMT_DPI_IP_RANGES_FILE");
    if (path == NULL || path[0] == '\0') {
        return; // default: byte-identical to the compiled-in baseline
    }
    int n = mmt_tcpip_load_ip_ranges_file(path);
    if (n > 0) {
        mmt_stderr_log( "[mmt-dpi][M9] loaded %d external IP-range rule(s) from %s\n",
                n, path);
    }
}

uint32_t get_proto_id_from_address(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->iph /* IPv4 */) {
        int proto_id = _find_proto_id_by_address(ntohl(packet->iph->saddr),ntohl(packet->iph->daddr));

        if( likely(proto_id != -1)){
            return proto_id;
        }
    }
#ifdef MMT_SUPPORT_IPV6
    // M9 (#74): IPv6 attribution comes entirely from externally-loaded ranges
    // (there is no compiled-in IPv6 table). The list is empty by default, so the
    // default IPv6 classification path is unchanged.
    else if (packet->iphv6 != NULL) {
        int proto_id = _find_proto_id_by_address6(packet->iphv6->saddr.mmt_v6_addr,
                                                  packet->iphv6->daddr.mmt_v6_addr);
        if( likely(proto_id != -1)){
            return proto_id;
        }
    }
#endif
    return PROTO_UNKNOWN;
}

uint32_t _get_proto_id_by_hostname(ipacket_t * ipacket, char *hostname, u_int hostname_len) {
    int i = 0;
    //struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    while ( likely( doted_host_names[i].string_to_match != NULL )) {
        if (_mmt_case_sensitive_reverse_hostname_matching(hostname, doted_host_names[i].string_to_match, hostname_len, doted_host_names[i].str_len)) {
            ipacket->session->content_flags = ipacket->session->content_flags | doted_host_names[i].content_flags;
            if (doted_host_names[i].proto_id == PROTO_AKAMAI) {
                return get_proto_id_from_ak_cdn(ipacket, hostname, hostname_len);
            }
            return doted_host_names[i].proto_id;
        }
        i++;
    }

    return PROTO_UNKNOWN;
}

#define NO_PROTO 0

/* ------------------------------------------------------------------------
 * Issue #253 (F-PERF-007): sparse, lazily-built reversed-hostname trie.
 *
 * The old node was a dense 256-way branch table plus a protocol pointer —
 * 2,056 bytes per node — and the ~9,091 nodes the 1,167 suffixes expand to
 * (~17.9 MB resident) were built in the library constructor whether or not
 * hostname classification ever ran.
 *
 * A node now carries a sorted array of (char -> child) edges: a child lookup
 * is a short linear scan (most nodes have one or two children; the root has
 * the most, bounded by the alphabet of suffix-final characters). Resident
 * cost is 24 bytes per node plus 16 bytes per edge — about 0.4 MB for the
 * compiled-in table — and the whole structure materialises only on the first
 * get_proto_id_by_hostname() call, so a deployment that never classifies by
 * hostname pays nothing.
 *
 * Lazy build thread-safety: the published root pointer is an acquire/release
 * atomic read on the per-packet path (zero locking once built); the one-time
 * construction is serialised by _host_name_trie_lock, mirroring the
 * PTHREAD_MUTEX_INITIALIZER pattern of the core registries (packet_registry.c
 * — see docs/THREADING.md). A failed build is latched in
 * _host_name_trie_init_failed so the OOM path keeps the old "disable hostname
 * classification, log once" behaviour instead of retrying per packet.
 * ------------------------------------------------------------------------ */
typedef struct _hn_edge {
	uint8_t c;
	struct _hn_node *child;
} _hn_edge_t;

typedef struct _hn_node {
	const protocol_match *protocol;
	uint16_t nb_children;
	uint16_t cap_children; /* allocation capacity of edges[] (build time only) */
	_hn_edge_t *edges;     /* sorted by c */
} _hn_node_t;

static _hn_node_t * _host_name_by_tree = NULL;
static pthread_mutex_t _host_name_trie_lock = PTHREAD_MUTEX_INITIALIZER;
static int _host_name_trie_init_failed = 0;
static int _host_name_trie_destroyed = 0; /* latched by _free_tree (destructor) */
static uint64_t _host_name_trie_bytes = 0; /* accounted node+edge bytes */

/* Accounted resident bytes of the lazily-built hostname trie (issue #253):
 * the sum of every live _hn_node_t plus its edges[] allocation. Always
 * exported and never gated on a stats build — the counter moves only at
 * build/free time, so there is no per-packet cost to amortise. */
uint64_t mmt_hostname_trie_resident_bytes(void) {
	return __atomic_load_n(&_host_name_trie_bytes, __ATOMIC_RELAXED);
}

static inline _hn_node_t * _create_new_node(){
	_hn_node_t *ret = (_hn_node_t *) mmt_malloc( sizeof( _hn_node_t ));
	/* Issue #212 (F-BUG-029/030): the mmt_malloc result was written through
	 * unchecked — a NULL ret crashed the trie builder. */
	if( ret == NULL )
		return NULL;
	ret->protocol    = NULL;
	ret->nb_children = 0;
	ret->cap_children = 0;
	ret->edges       = NULL;
	_host_name_trie_bytes += sizeof( _hn_node_t );
	return ret;
}

/* Lookup `c` among a node's sorted edges. Returns the child or NULL.
 * Linear scan: nodes have few children (the root tops out at the number of
 * distinct suffix-final characters), and the edges are contiguous. */
static inline _hn_node_t * _node_child(const _hn_node_t *node, uint8_t c){
	uint16_t i;
	for( i = 0; i < node->nb_children; i++ ){
		if( node->edges[i].c == c )
			return node->edges[i].child;
		if( node->edges[i].c > c )
			break; /* sorted — no point scanning further */
	}
	return NULL;
}

/* Return the child for `c`, inserting a fresh node when absent (sorted
 * insertion into edges[]). NULL on allocation failure. */
static _hn_node_t * _node_child_or_create(_hn_node_t *node, uint8_t c){
	uint16_t i = 0;
	while( i < node->nb_children && node->edges[i].c < c )
		i++;
	if( i < node->nb_children && node->edges[i].c == c )
		return node->edges[i].child;

	_hn_node_t *child = _create_new_node();
	if( child == NULL )
		return NULL;
	if( node->nb_children == node->cap_children ){
		uint16_t new_cap = (node->cap_children == 0) ? 2 : (uint16_t)(node->cap_children * 2);
		_hn_edge_t *grown = (_hn_edge_t *) mmt_realloc(node->edges, new_cap * sizeof(_hn_edge_t));
		if( grown == NULL ){
			mmt_free( child );
			_host_name_trie_bytes -= sizeof( _hn_node_t );
			return NULL;
		}
		_host_name_trie_bytes += (uint64_t)(new_cap - node->cap_children) * sizeof(_hn_edge_t);
		node->edges = grown;
		node->cap_children = new_cap;
	}
	memmove(&node->edges[i + 1], &node->edges[i],
		(node->nb_children - i) * sizeof(_hn_edge_t));
	node->edges[i].c = c;
	node->edges[i].child = child;
	node->nb_children++;
	return child;
}

static void _free_tree(void);
static void _free_tree_node( _hn_node_t *node_ptr );

/* Builds the reversed-hostname trie. Returns 1 on success, 0 on allocation
 * failure — in that case the partial tree is released and _host_name_by_tree
 * stays NULL so the lookup degrades to "no hostname match" instead of
 * dereferencing a missing root (issue #212, F-BUG-029/030).
 * Caller holds _host_name_trie_lock; publishes the root with a release
 * store so the lock-free read path sees a fully-formed tree. */
static int _init_tree(){
	int i=0, j;
	const protocol_match *proto_ptr;
	_hn_node_t *node_ptr, *root;

	if( _host_name_by_tree != NULL )
		return 1;

	root = _create_new_node();
	if( root == NULL )
		return 0;

	i = 0;
	//for each host name
	while ( doted_host_names[i].string_to_match != NULL ){
		proto_ptr = &doted_host_names[i];
		node_ptr  = root;

		//for each character in the host name
		for( j=proto_ptr->str_len-1; j>=0; j-- ){
			node_ptr = _node_child_or_create(node_ptr, (uint8_t) proto_ptr->string_to_match[j]);
			if( node_ptr == NULL ){
				// allocation failure: drop the partial tree, keep root NULL
				_free_tree_node(root);
				_host_name_trie_bytes = 0;
				return 0;
			}
		}

		//we are now in a leaf
		if( node_ptr->protocol != NULL )
			mmt_stderr_log( "Error: Double domain name\"%s\"\n", node_ptr->protocol->string_to_match );

		node_ptr->protocol = proto_ptr;

		//goto to the next hostname
		i++;
	}
	__atomic_store_n(&_host_name_by_tree, root, __ATOMIC_RELEASE);
	return 1;
}

static void _free_tree_node( _hn_node_t *node_ptr ){
	uint16_t i;
	if( node_ptr == NULL )
		return;

	for( i = 0; i < node_ptr->nb_children; i++ )
		_free_tree_node( node_ptr->edges[i].child );

	mmt_free( node_ptr->edges );
	mmt_free( node_ptr );
}

static void _free_tree(void){
	pthread_mutex_lock(&_host_name_trie_lock);
	/* Latch the destroyed state BEFORE dropping the root: a lookup arriving
	 * after the destructor must degrade to "no match" (the dense-trie
	 * behaviour) instead of rebuilding a ~0.5 MB tree nothing will free. */
	__atomic_store_n(&_host_name_trie_destroyed, 1, __ATOMIC_RELEASE);
	if( _host_name_by_tree != NULL ){
		_free_tree_node( _host_name_by_tree );
		/* Publish NULL atomically — the lock-free read path in _ensure_tree
		 * must never observe a mixed plain/atomic access to this word. */
		__atomic_store_n(&_host_name_by_tree, NULL, __ATOMIC_RELEASE);
	}
	_host_name_trie_bytes = 0;
	pthread_mutex_unlock(&_host_name_trie_lock);
}

/* Lazily publish the trie root. The acquire load is the entire per-packet
 * cost once the tree exists; construction is serialised on
 * _host_name_trie_lock and only ever runs once (a latched failure keeps the
 * old permanent-disable behaviour, and a latched destruction keeps a
 * post-destructor lookup from resurrecting — and leaking — the tree). */
static inline _hn_node_t * _ensure_tree(void){
	_hn_node_t *root = __atomic_load_n(&_host_name_by_tree, __ATOMIC_ACQUIRE);
	if( likely( root != NULL ))
		return root;
	if( __atomic_load_n(&_host_name_trie_init_failed, __ATOMIC_ACQUIRE))
		return NULL;
	if( __atomic_load_n(&_host_name_trie_destroyed, __ATOMIC_ACQUIRE))
		return NULL;

	pthread_mutex_lock(&_host_name_trie_lock);
	if( _host_name_by_tree == NULL && !_host_name_trie_init_failed
			&& !_host_name_trie_destroyed ){
		if( !_init_tree() ){
			__atomic_store_n(&_host_name_trie_init_failed, 1, __ATOMIC_RELEASE);
			mmt_stderr_log( "[mmt-dpi] hostname trie init failed (out of memory) - hostname classification disabled\n");
		}
	}
	root = __atomic_load_n(&_host_name_by_tree, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&_host_name_trie_lock);
	return root;
}


__attribute__((constructor)) void _constructor () {
	/* Issue #253 (F-PERF-007): the hostname trie no longer builds here — it
	 * materialises on first use in _ensure_tree(). The IP-range AVL trees
	 * stay eager: they are consulted on every IPv4 packet. */
    _init_proto_avltrees();
}

__attribute__((destructor)) void _destructor () {
	_free_tree();
    _free_proto_avltrees();
}


uint32_t get_proto_id_by_hostname(ipacket_t * ipacket, char *hostname, u_int hostname_len ) {
	int i;
	uint8_t c;
	_hn_node_t *node_ptr = _ensure_tree();
	const protocol_match *proto;

	/* Issue #212 (F-BUG-030): the trie root was dereferenced unguarded — when
	 * _init_tree() fails (allocation), _host_name_by_tree is NULL. */
	if( node_ptr == NULL )
		return PROTO_UNKNOWN;
	proto = node_ptr->protocol;

	for( i=hostname_len-1; i>=0; i-- ){
		c = hostname[i];
		//in a leaf
		node_ptr = _node_child(node_ptr, c);
		if( node_ptr == NULL )
			break;
		//we have
		//  .drivers.google.com
		//  .google.com
		//need to match "toolbarqueries.clients.google.com"
		//=>this matches firstly ".google.com"
		//
		if( node_ptr->protocol != NULL ){
			proto = node_ptr->protocol;
		}
	}


	//give one more chance
	//we have .google.com
	//need to match hostname = "google.com"
	/* Issue #212 (F-BUG-030): for an empty hostname i starts at -1 and this
	 * fallback fired on the trie root — attributing whatever protocol a
	 * degenerate entry might hold — and a NULL protocol on the '.' child used
	 * to overwrite a longer match found during the walk. Require a non-empty
	 * hostname and a real protocol on the fallback node. */
	if( hostname_len > 0 && i == -1 ){
		_hn_node_t *dot = _node_child(node_ptr, '.');
		if( dot != NULL && dot->protocol != NULL )
			proto = dot->protocol;
	}

//	*p = proto;
	if( proto == NULL )
		return PROTO_UNKNOWN;

	ipacket->session->content_flags = ipacket->session->content_flags | proto->content_flags;
	if ( likely( proto->proto_id != PROTO_AKAMAI))
		return proto->proto_id;
	else
		return get_proto_id_from_ak_cdn(ipacket, hostname, hostname_len);
}
