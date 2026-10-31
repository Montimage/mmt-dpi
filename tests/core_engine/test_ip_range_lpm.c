/*
 * test_ip_range_lpm.c — differential test of the IPv4 attribution lookup
 * (issue #557).
 *
 * Issue #557 replaced the per-prefix AVL forest the compiled-in table was
 * loaded into with a const sorted array of disjoint intervals
 * (tools/gen-ip-range-table.py), and memoised get_proto_id_from_address()'s
 * verdict on the flow. This test keeps the forest as the reference: it
 * rebuilds it from the table's prefixes (ip_range_prefixes.inc, written by
 * `gen-ip-range-table.py --prefix-table` from the same data/ip_ranges.txt)
 * with the code mmt_tcpip_classif_utils.c ran before the change — the
 * duplicate-key skip, the extend rule dropped on a built-in collision, the
 * override set consulted first, each prefix length walked from /32 down with
 * the source probed before the destination — and checks that
 * _find_proto_id_by_address() returns the same protocol:
 *
 *   - for the network, last, middle, previous and next address of every
 *     prefix of the table, as source and as destination, against an
 *     unmatched address and against addresses of other prefixes (equal and
 *     different prefix lengths: the source wins a tie);
 *   - for random address pairs and the edges of the address space;
 *   - again with external extend and override rules loaded (built-in
 *     collisions, nested and enclosing rules, /31 and /32, last-rule-wins
 *     duplicates, random rules), through mmt_tcpip_load_ip_ranges_file();
 *   - again after _free_proto_avltrees() / _init_proto_avltrees().
 *
 * It then checks the per-flow memo: one verdict per address orientation,
 * kept for the flow, not shared with another flow or with a flow-less call.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "mmt_core.h"
#include "mmt_tcpip_internal_defs_macros.h"
#include "mmt_tcpip_plugin_structs.h"
#include "avltree.h"

#include "ip_range_prefixes.inc"

int _find_proto_id_by_address(uint32_t ip_src, uint32_t ip_dest);
void _init_proto_avltrees(void);
void _free_proto_avltrees(void);
int mmt_tcpip_load_ip_ranges_file(const char *path);
uint32_t get_proto_id_from_address(ipacket_t *ipacket);

static int g_failures = 0;
static long g_compared = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
        g_failures++; } } while (0)

#define N_PREFIXES ((int) (sizeof(ip_range_prefixes) / sizeof(ip_range_prefixes[0]) - 1))

/* ---------------- reference: the pre-#557 AVL forest -------------------- */

static avltree_t *ref_trees[NETMASK_MAX_NB];
static avltree_t *ref_override[NETMASK_MAX_NB];
#define REF_DYN_MAX 4096
static proto_based_ip_t ref_dyn[REF_DYN_MAX];
static int ref_ndyn = 0;

static void ref_free(void) {
    int i;
    for (i = 0; i < NETMASK_MAX_NB; i++) {
        avltree_free_tree(ref_trees[i]);
        avltree_free_tree(ref_override[i]);
        ref_trees[i] = ref_override[i] = NULL;
    }
    ref_ndyn = 0;
}

/* The former _init_proto_avltrees(). */
static void ref_init(void) {
    int i = 0;
    ref_free();
    while (ip_range_prefixes[i].netmask_nb != 0) {
        int tree_index = ip_range_prefixes[i].netmask_nb;
        if (tree_index <= 0 || tree_index >= NETMASK_MAX_NB) {
            i++;
            continue;
        }
        avltree_t *node = avltree_create(ip_range_prefixes[i].ip_address,
                                         (void *) &ip_range_prefixes[i]);
        if (node != NULL) {
            int is_duplicate = 0;
            ref_trees[tree_index] = avltree_insert_ex(ref_trees[tree_index], node, &is_duplicate);
            if (is_duplicate) {
                avltree_free_node(node);
            }
        }
        i++;
    }
}

/* The former _insert_dynamic_ip_range(). */
static void ref_insert_dynamic(int netmask_nb, uint32_t ip, int proto_id, int is_override) {
    if (ref_ndyn >= REF_DYN_MAX) {
        fprintf(stderr, "  reference rule store full\n");
        exit(2);
    }
    proto_based_ip_t *dyn = &ref_dyn[ref_ndyn++];
    dyn->netmask_nb = netmask_nb;
    dyn->netmask_address = 0xFFFFFFFFu << (32 - netmask_nb);
    dyn->ip_address = ip & dyn->netmask_address;
    dyn->proto_id = proto_id;

    avltree_t **trees = is_override ? ref_override : ref_trees;
    avltree_t *existing = avltree_find(trees[netmask_nb], dyn->ip_address);
    if (existing != NULL) {
        uintptr_t hit = (uintptr_t) existing->data;
        uintptr_t lo = (uintptr_t) ip_range_prefixes;
        uintptr_t hi = (uintptr_t) (ip_range_prefixes + N_PREFIXES + 1);
        if (hit >= lo && hit < hi) {
            return; /* an extend rule never displaces a built-in entry */
        }
        existing->data = (void *) dyn; /* last rule wins */
        return;
    }
    avltree_t *node = avltree_create(dyn->ip_address, (void *) dyn);
    trees[netmask_nb] = avltree_insert(trees[netmask_nb], node);
}

/* The former _find_proto_id_in_trees(). */
static int ref_find_in_trees(avltree_t *const trees[], uint32_t ip_src, uint32_t ip_dest) {
    int i;
    for (i = NETMASK_MAX_NB - 1; i >= 0; i--) {
        if (trees[i] != NULL) {
            proto_based_ip_t *proto = (proto_based_ip_t *) avltree_get_data(trees[i]);
            avltree_t *node_src = avltree_find(trees[i], ip_src & proto->netmask_address);
            if (node_src != NULL) {
                return ((proto_based_ip_t *) avltree_get_data(node_src))->proto_id;
            }
            avltree_t *node_dest = avltree_find(trees[i], ip_dest & proto->netmask_address);
            if (node_dest != NULL) {
                return ((proto_based_ip_t *) avltree_get_data(node_dest))->proto_id;
            }
        }
    }
    return -1;
}

/* The former _find_proto_id_by_address(). */
static int ref_find(uint32_t ip_src, uint32_t ip_dest) {
    int proto_id = ref_find_in_trees(ref_override, ip_src, ip_dest);
    if (proto_id != -1) {
        return proto_id;
    }
    return ref_find_in_trees(ref_trees, ip_src, ip_dest);
}

/* ---------------- comparison ------------------------------------------- */

static int g_reported = 0;

static void compare(uint32_t src, uint32_t dst) {
    int want = ref_find(src, dst);
    int got = _find_proto_id_by_address(src, dst);
    g_compared++;
    if (want != got) {
        g_failures++;
        if (g_reported++ < 20) {
            fprintf(stderr, "  FAIL: src 0x%08x dst 0x%08x: AVL forest %d, interval array %d\n",
                    src, dst, want, got);
        }
    }
}

static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd32(void) {
    /* xorshift64*: deterministic, so a failure reproduces. */
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    return (uint32_t) ((g_rng * 2685821657736338717ull) >> 32);
}

/* An address no prefix of the table or of the rules covers (checked). */
static uint32_t g_unmatched;

static uint32_t prefix_last(const proto_based_ip_t *p) {
    return p->ip_address | ~p->netmask_address;
}

/* The five probes of one prefix: network, last, middle, previous, next. */
static void probes(const proto_based_ip_t *p, uint32_t out[5]) {
    uint32_t last = prefix_last(p);
    out[0] = p->ip_address;
    out[1] = last;
    out[2] = p->ip_address + (uint32_t) ((last - p->ip_address) / 2);
    out[3] = p->ip_address - 1u;
    out[4] = last + 1u;
}

static void compare_prefix_set(const proto_based_ip_t *set, int n) {
    int i, k, j;
    for (i = 0; i < n; i++) {
        uint32_t a[5], b[5];
        probes(&set[i], a);
        /* partners: the next prefix, one half the table away, a random one */
        const proto_based_ip_t *partner[3] = {
            &set[(i + 1) % n], &set[(i + n / 2) % n], &set[rnd32() % (uint32_t) n] };
        for (k = 0; k < 5; k++) {
            compare(a[k], g_unmatched);
            compare(g_unmatched, a[k]);
        }
        for (j = 0; j < 3; j++) {
            probes(partner[j], b);
            for (k = 0; k < 5; k++) {
                compare(a[k], b[k]);
                compare(b[k], a[k]);
            }
        }
    }
}

static void compare_all(const char *phase, const proto_based_ip_t *rules, int nrules) {
    long before = g_compared;
    int failures = g_failures;
    int i;
    static const uint32_t edges[] = { 0x00000000u, 0x00000001u, 0x7FFFFFFFu, 0x80000000u,
                                      0xFFFFFFFEu, 0xFFFFFFFFu };
    compare_prefix_set(ip_range_prefixes, N_PREFIXES);
    if (rules != NULL) {
        compare_prefix_set(rules, nrules);
    }
    for (i = 0; i < 1000000; i++) {
        compare(rnd32(), rnd32());
    }
    for (i = 0; i < (int) (sizeof(edges) / sizeof(edges[0])); i++) {
        int j;
        for (j = 0; j < (int) (sizeof(edges) / sizeof(edges[0])); j++) {
            compare(edges[i], edges[j]);
        }
    }
    fprintf(stderr, "  %s: %ld lookups compared, %d mismatches\n",
            phase, g_compared - before, g_failures - failures);
}

/* ---------------- external rules ---------------------------------------- */

#define N_RULES 600
static proto_based_ip_t g_rules[N_RULES];
static int g_rule_override[N_RULES];
static int g_nrules = 0;

static void add_rule(FILE *fp, uint32_t ip, int len, int proto_id, int is_override) {
    uint32_t mask = 0xFFFFFFFFu << (32 - len);
    proto_based_ip_t *r = &g_rules[g_nrules];
    r->netmask_nb = len;
    r->netmask_address = mask;
    r->ip_address = ip & mask;
    r->proto_id = proto_id;
    g_rule_override[g_nrules] = is_override;
    g_nrules++;
    fprintf(fp, "%u.%u.%u.%u/%d %d%s\n", r->ip_address >> 24, (r->ip_address >> 16) & 255u,
            (r->ip_address >> 8) & 255u, r->ip_address & 255u, len, proto_id,
            is_override ? " override" : "");
}

/* Writes the rules to `path` (numeric protocol ids 500..599) and records them. */
static void make_rules(const char *path) {
    FILE *fp = fopen(path, "w");
    int i;
    if (fp == NULL) {
        perror(path);
        exit(2);
    }
    for (i = 0; i < 100; i++) {
        const proto_based_ip_t *p = &ip_range_prefixes[rnd32() % (uint32_t) N_PREFIXES];
        int len = p->netmask_nb;
        switch (i % 5) {
        case 0: /* same CIDR as a built-in, extend: the built-in stays */
            add_rule(fp, p->ip_address, len, 500 + i % 100, 0);
            break;
        case 1: /* same CIDR as a built-in, override: the rule wins */
            add_rule(fp, p->ip_address, len, 500 + i % 100, 1);
            break;
        case 2: /* nested, longer extend rule inside a built-in */
            add_rule(fp, prefix_last(p), len < 32 ? len + 1 : 32, 500 + i % 100, 0);
            break;
        case 3: /* enclosing, shorter extend rule around a built-in */
            add_rule(fp, p->ip_address, len > 1 ? len - 1 : 1, 500 + i % 100, 0);
            break;
        default: /* /32 extend and /31 override on a built-in's network */
            add_rule(fp, p->ip_address, 32, 500 + i % 100, 0);
            add_rule(fp, p->ip_address, 31, 500 + (i + 1) % 100, 1);
            break;
        }
    }
    /* duplicates of a rule in the same class: last rule wins */
    for (i = 0; i < 40; i++) {
        proto_based_ip_t r = g_rules[i];
        add_rule(fp, r.ip_address, r.netmask_nb, 500 + (r.proto_id + 7) % 100, g_rule_override[i]);
    }
    /* random rules of /8 to /32 (a shorter one would cover most of the
     * space and mask the table), a third of them override */
    while (g_nrules < N_RULES) {
        add_rule(fp, rnd32(), 8 + (int) (rnd32() % 25u), 500 + (int) (rnd32() % 100u),
                 rnd32() % 3u == 0);
    }
    fclose(fp);
}

/* ---------------- per-flow memo ----------------------------------------- */

typedef struct {
    ipacket_t pkt;
    mmt_tcpip_internal_packet_t internal;
    mmt_internal_tcpip_session_t flow;
    struct iphdr ip4;
} memo_ctx_t;

static void memo_ctx(memo_ctx_t *c, int with_flow) {
    memset(c, 0, sizeof(*c));
    c->pkt.internal_packet = &c->internal;
    c->internal.flow = with_flow ? &c->flow : NULL;
    c->internal.iph = (const mmt_una_iphdr_t *) &c->ip4;
}

static uint32_t memo_lookup(memo_ctx_t *c, uint32_t src, uint32_t dst) {
    c->ip4.saddr = htonl(src);
    c->ip4.daddr = htonl(dst);
    return get_proto_id_from_address(&c->pkt);
}

static void test_flow_memo(const char *rules_path) {
    int i, j = -1;
    fprintf(stderr, "  test: per-flow verdict memo\n");
    /* Two prefixes of one length with different protocols: their verdict
     * depends on the orientation (the source wins a tie). */
    for (i = 0; i < N_PREFIXES && j < 0; i++) {
        int k;
        for (k = i + 1; k < N_PREFIXES; k++) {
            if (ip_range_prefixes[k].netmask_nb == ip_range_prefixes[i].netmask_nb &&
                ip_range_prefixes[k].proto_id != ip_range_prefixes[i].proto_id &&
                ref_find(ip_range_prefixes[i].ip_address, 0) == ip_range_prefixes[i].proto_id &&
                ref_find(ip_range_prefixes[k].ip_address, 0) == ip_range_prefixes[k].proto_id) {
                j = k;
                break;
            }
        }
    }
    CHECK(j >= 0, "the table holds two equal-length prefixes of different protocols");
    if (j < 0) {
        return;
    }
    i--;
    uint32_t a = ip_range_prefixes[i].ip_address, b = ip_range_prefixes[j].ip_address;
    uint32_t pa = (uint32_t) ip_range_prefixes[i].proto_id;
    uint32_t pb = (uint32_t) ip_range_prefixes[j].proto_id;

    memo_ctx_t flow, other, none;
    memo_ctx(&flow, 1);
    memo_ctx(&other, 1);
    memo_ctx(&none, 0);
    CHECK(memo_lookup(&flow, a, b) == pa, "a -> b: the source wins the tie");
    CHECK(memo_lookup(&flow, b, a) == pb, "b -> a: the source wins the tie");
    CHECK(flow.flow.ip_range_verdict[0] != 0 && flow.flow.ip_range_verdict[1] != 0,
          "one memo slot per orientation");
    CHECK(memo_lookup(&flow, a, b) == pa && memo_lookup(&flow, b, a) == pb,
          "memo hits return the computed verdicts");
    CHECK(memo_lookup(&other, g_unmatched, g_unmatched) == PROTO_UNKNOWN,
          "an unmatched pair is UNKNOWN");
    CHECK(other.flow.ip_range_verdict[0] == 1, "an UNKNOWN verdict is memoised too");

    /* Rules loaded after the flow computed its verdict do not reach it (the
     * contract loads them at init, before any flow): a fresh flow and a
     * flow-less call see the new rule, the memoised flow keeps its verdict. */
    FILE *fp = fopen(rules_path, "w");
    CHECK(fp != NULL, "memo rule file created");
    if (fp == NULL) {
        return;
    }
    fprintf(fp, "%u.%u.%u.%u/32 777 override\n", a >> 24, (a >> 16) & 255u, (a >> 8) & 255u, a & 255u);
    fclose(fp);
    CHECK(mmt_tcpip_load_ip_ranges_file(rules_path) == 1, "memo override rule loaded");
    memo_ctx_t fresh;
    memo_ctx(&fresh, 1);
    CHECK(memo_lookup(&fresh, a, b) == 777 && memo_lookup(&fresh, b, a) == 777,
          "a fresh flow sees the override rule in both orientations");
    CHECK(memo_lookup(&none, a, b) == 777, "a flow-less call is not memoised");
    CHECK(memo_lookup(&flow, a, b) == pa && memo_lookup(&flow, b, a) == pb,
          "the memoised flow keeps its verdicts");

    /* No IP header: UNKNOWN, and the memo is left alone. */
    memo_ctx_t noip;
    memo_ctx(&noip, 1);
    noip.internal.iph = NULL;
    CHECK(get_proto_id_from_address(&noip.pkt) == PROTO_UNKNOWN, "no IP header -> UNKNOWN");
    CHECK(noip.flow.ip_range_verdict[0] == 0 && noip.flow.ip_range_verdict[1] == 0,
          "no IP header leaves the memo empty");
    remove(rules_path);
}

/* Picks an address that neither the table nor the loaded rules cover. */
static void find_unmatched(void) {
    int tries;
    for (tries = 0, g_unmatched = 0xC0000201u; tries < 65536; tries++, g_unmatched += 0x10000u) {
        if (ref_find(g_unmatched, g_unmatched) == -1) {
            return;
        }
    }
    fprintf(stderr, "  no unmatched address found\n");
    exit(2);
}

int main(int argc, char **argv) {
    const char *rules_path = argc > 1 ? argv[1] : "./ip_range_lpm_rules.txt";
    int i;
    fprintf(stderr, "IP-range LPM differential test (issue #557): %d table prefixes\n", N_PREFIXES);
    CHECK(init_extraction() == 1, "init_extraction");

    ref_init();
    find_unmatched();
    compare_all("built-in table", NULL, 0);

    /* External rules: the reference inserts them with the former code, the
     * library loads them from the same file. */
    make_rules(rules_path);
    int loaded = mmt_tcpip_load_ip_ranges_file(rules_path);
    CHECK(loaded == g_nrules, "every external rule loaded");
    for (i = 0; i < g_nrules; i++) {
        ref_insert_dynamic(g_rules[i].netmask_nb, g_rules[i].ip_address, g_rules[i].proto_id,
                           g_rule_override[i]);
    }
    remove(rules_path);
    find_unmatched();
    compare_all("built-in table + external rules", g_rules, g_nrules);

    /* Teardown and re-init restore the compiled-in table alone. */
    _free_proto_avltrees();
    _init_proto_avltrees();
    ref_init();
    compare_all("after free/re-init", g_rules, g_nrules);

    test_flow_memo(rules_path);

    _free_proto_avltrees();
    ref_free();
    close_extraction();

    if (g_failures != 0) {
        fprintf(stderr, "IP-range LPM differential test: %d failures over %ld lookups\n",
                g_failures, g_compared);
        return 1;
    }
    fprintf(stderr, "IP-range LPM differential test: PASSED (%ld lookups identical)\n", g_compared);
    return 0;
}
