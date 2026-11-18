/*
 * fi_chain_plugin.c — stub protocol plugins for the load-order cases of the
 * fault_injection suite (issue #115).
 *
 * Built three times by run_tests.sh, against the installed headers:
 *   -DFI_PARENT                  registers fi_parent (FI_PARENT_ID), opts its
 *                                layer in and claims a UDP payload starting
 *                                with "FI115" for it;
 *   -DFI_CHILD                   registers fi_child (FI_CHILD_ID) and its
 *                                classifier under fi_parent with the deferred
 *                                API; fi_child_calls counts the calls;
 *   -DFI_CHILD -DFI_ORPHAN       the same child, under FI_ORPHAN_ID, which no
 *                                plugin registers.
 * The child's file name sorts before the parent's, so its init_proto() runs
 * first; both sort after libmmt_tcpip.so, which registers UDP.
 */
#include <string.h>

#include "mmt_core.h"
#include "plugin_defs.h"

#define FI_PARENT_ID 997
#define FI_CHILD_ID  998
#define FI_ORPHAN_ID 996

#ifdef FI_PARENT
static int fi_claim(ipacket_t *ipacket, unsigned index) {
    classified_proto_t c;
    unsigned off = get_packet_offset_at_index(ipacket, index) + 8; /* past the UDP header */
    if (off + 5 > ipacket->p_hdr->caplen || memcmp(ipacket->data + off, "FI115", 5) != 0) return 0;
    c.proto_id = FI_PARENT_ID;
    c.offset = 8;
    c.status = Classified;
    return set_classified_proto(ipacket, index + 1, c) ? MMT_CLASSIFY_MATCHED : 0;
}

int init_proto(void) {
    protocol_t *p = init_protocol_struct_for_registration(FI_PARENT_ID, "fi_parent");
    uint32_t udp = get_protocol_id_by_name("udp");
    if (p == NULL || udp == 0 || !mmt_protocol_set_process_claimed_layer(p, true)) return 0;
    if (register_protocol(p, FI_PARENT_ID) != PROTO_REGISTERED) return 0;
    return register_classification_function_with_parent_protocol(udp, fi_claim, 1);
}
#endif

#ifdef FI_CHILD
#ifdef FI_ORPHAN
#define FI_CHILD_PARENT FI_ORPHAN_ID
#else
#define FI_CHILD_PARENT FI_PARENT_ID
#endif
int fi_child_calls;

static int fi_child(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    fi_child_calls++;
    return 0;
}

int init_proto(void) {
    protocol_t *p = init_protocol_struct_for_registration(FI_CHILD_ID, "fi_child");
    if (p == NULL || register_protocol(p, FI_CHILD_ID) != PROTO_REGISTERED) return 0;
    return register_classification_function_with_parent_protocol_deferred(FI_CHILD_PARENT, FI_CHILD_ID, fi_child, 10);
}
#endif

int cleanup_proto(void) { return 0; }
