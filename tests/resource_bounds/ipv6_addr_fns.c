/*
 * ipv6_addr_fns.c — exposes the IPv6 session-id address functions under
 * test (issue #379, F-PERF-001) to the C++ bounds harness.
 *
 * ip_session_id_management.c is included directly so the REAL
 * ipv6_addr_hash (file-static) and ipv6_addr_comp are exercised verbatim —
 * the same convention as tests/parser_boundaries/test_udp_bounds_unit.c
 * including proto_udp.c (issue #375): the function under test runs in the
 * test binary unmodified and gcov attributes the lines to the real file.
 */
#include "../../src/mmt_tcpip/lib/protocols/ip_session_id_management.c"

uint64_t test_ipv6_addr_hash(void *ip) {
    return ipv6_addr_hash(ip);
}

bool test_ipv6_addr_comp(void *a, void *b) {
    return ipv6_addr_comp(a, b);
}

/* Thin wrappers over the interned-IP registry path the SDK itself uses:
 * setup_ipv6_internal_context() wires ipv6_addr_comp + ipv6_addr_hash into
 * the open-addressing table, and get_ip6_id/findID6/deleteID6 are the exact
 * functions get_session() drives per packet. */
void *test_ipv6_ctx_new(void) {
    return (void *) setup_ipv6_internal_context();
}

void *test_ipv6_get_id(void *ctx, void *ip, uint32_t *is_new) {
    return (void *) get_ip6_id((internal_ip_proto_context_t *) ctx,
                             (struct in6_addr *) ip, is_new);
}

void *test_ipv6_find_id(void *ctx, void *ip) {
    return (void *) findID6((internal_ip_proto_context_t *) ctx,
                            (struct in6_addr *) ip);
}

void test_ipv6_ctx_destroy(void *ctx) {
    internal_ip_proto_context_t *c = (internal_ip_proto_context_t *) ctx;
    if (c == NULL) return;
    cleanup_ipv6_internal_context(c); /* frees the interned id structs */
    delete_map_space(c->ips_map);
    mmt_free(c);
}
