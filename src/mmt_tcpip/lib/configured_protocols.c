#include <stdio.h>
#include <stdlib.h>
#include "mmt_common_internal_include.h"
#include "packet_processing.h" /* issue #540: mmt_classifier_mark_legacy() */
#include "../include/mmt_tcpip_plugin.h"
#include "../include/mmt_tcpip_protocols.h"

/* Issue #212 (F-BUG-041): the ~160 inter-protocol registration calls in
 * init_tcpip_plugin() used to discard
 * register_classification_function_with_parent_protocol()'s return value, so a
 * partially registered classifier set reported full success and the affected
 * protocols silently never classified. mmt_register_classifier() performs one
 * checked registration and, on failure, prints a diagnostic naming the entry
 * and returns 0 — which the inter_proto_table[] loop propagates out of
 * init_tcpip_plugin() as an init failure. The function is exported
 * (non-static) so the phase0 classifier_init harness can drive it with a
 * deliberately bad entry and assert the init-failure signal. */
int mmt_register_classifier(uint32_t parent_proto,
        generic_classification_function classify_fn, int weight,
        const char *name) {
    if (!register_classification_function_with_parent_protocol(parent_proto,
                classify_fn, weight)) {
        mmt_stderr_log(
            "Error registering classification function %s for parent protocol %u (weight %d)\n Exiting\n",
            (name != NULL) ? name : "?", (unsigned) parent_proto, weight);
        return 0;
    }
    return 1;
}

/* Issue #560 (F-PERF-005): the selection mask each protocol translation
 * unit's mmt_init_classify_bitmasks*() call set, recorded under the protocol
 * id its excluded bitmask holds (unique per unit). The protocol inits of
 * init_tcpip_plugin() run before its inter_proto_table[] loop, which copies
 * the entry of each row's excluded_proto into the checker's chain node. */
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE checker_selection[PROTO_MAX_IDENTIFIER];
/* Issue #561: the unit's detection set (its words), and whether the unit's
 * checker keeps its own guard (mmt_checker_keeps_local_guard()). */
static const uint64_t *checker_detection[PROTO_MAX_IDENTIFIER];
static uint8_t checker_local_guard[PROTO_MAX_IDENTIFIER];

void mmt_tcpip_record_checker_guard(uint32_t excluded_proto,
        MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_mask,
        const MMT_PROTOCOL_BITMASK *detection) {
    if (excluded_proto != PROTO_UNKNOWN && excluded_proto < PROTO_MAX_IDENTIFIER) {
        checker_selection[excluded_proto] = selection_mask;
        checker_detection[excluded_proto] = (detection != NULL) ? detection->bitmask : NULL;
        checker_local_guard[excluded_proto] = 0;
    }
}

void mmt_tcpip_record_local_guard(uint32_t excluded_proto) {
    if (excluded_proto != PROTO_UNKNOWN && excluded_proto < PROTO_MAX_IDENTIFIER) {
        checker_local_guard[excluded_proto] = 1;
    }
}

/* Issue #561: each excludable protocol's slot in a flow's dense exclusion
 * set, plus one (0: not excludable — excluded_protocols.def has no row). */
static const uint16_t excluded_slot_of[PROTO_MAX_IDENTIFIER] = {
#define MMT_EXCLUDABLE(protocol) [protocol] = MMT_EXCL_SLOT_##protocol + 1,
#include "excluded_protocols.def"
#undef MMT_EXCLUDABLE
};

/* Issue #561 (F-PERF-005, checker walk part 2): the guard view of a packet
 * about to walk the TCP or UDP chain — what every guarded checker opened
 * with: the packet's selection word, its detection set (one protocol, saved
 * by the TCP/UDP pre-classifier with MMT_SAVE_AS_BITMASK, or none after
 * mmt_reset_internal_packet_scalars()), and the flow's exclusion set, which the
 * walk reads live (an earlier checker of the same walk may exclude). */
static void mmt_tcpip_guard_view(const ipacket_t *ipacket, mmt_classify_guard_view_t *view) {
    const struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint32_t w;
    view->selection = packet->mmt_selection_packet;
    view->detected_word = 0;
    view->detected_bits = 0;
    for (w = 0; w < MMT_PROTOCOL_BITMASK_NUM_WORDS; w++) {
        if (packet->detection_bitmask.bitmask[w] != 0) {
            view->detected_word = w;
            view->detected_bits = packet->detection_bitmask.bitmask[w];
            break;
        }
    }
    view->excluded = (packet->flow != NULL) ? packet->flow->excluded_protos.words : NULL;
}

/* Store one inter_proto_table[] row's guard inputs in its chain node; 0 (an
 * init failure, like a failed legacy mark) when the row names an excluded
 * protocol no translation unit recorded — a wrong excluded_proto column — or
 * one without a dense exclusion slot. Issue #561: the node gets the unit's
 * detection set, so the walk evaluates its guard, unless the unit keeps its
 * own guard. */
static int mmt_set_inter_proto_guard(protocol_t *parent,
        generic_classification_function classify_fn, uint32_t excluded_proto,
        const char *name) {
    if (excluded_proto == PROTO_UNKNOWN) {
        return 1;
    }
    if (excluded_proto >= PROTO_MAX_IDENTIFIER || checker_selection[excluded_proto] == 0
            || excluded_slot_of[excluded_proto] == 0
            || !mmt_classifier_set_guard(parent, classify_fn,
                    checker_selection[excluded_proto], excluded_proto,
                    checker_local_guard[excluded_proto] ? NULL : checker_detection[excluded_proto],
                    (uint16_t) (excluded_slot_of[excluded_proto] - 1))) {
        mmt_stderr_log("Error recording the guard of classification function %s (excluded protocol %u)\n Exiting\n",
                name, (unsigned) excluded_proto);
        return 0;
    }
    return 1;
}

/* Issue #542 (F-CLEAN-012): the registration a MMT_PROTO_SIMPLE row of
 * proto_init_list.def stands for — the body of each of the 506 identical
 * proto_*.c stubs it replaced, so the registry is built by the same calls in
 * the same order. */
static int mmt_register_simple_protocol(mmt_proto_id_t proto_id,
        const char *proto_alias) {
    protocol_t *protocol_struct =
        init_protocol_struct_for_registration(proto_id, proto_alias);
    if (protocol_struct == NULL) {
        return 0;
    }
    return register_protocol(protocol_struct, proto_id);
}

int init_proto() {
    return init_tcpip_plugin();
}

int cleanup_proto(){
    return cleanup_tcpip_plugin();
}

int cleanup_tcpip_plugin(){
    // if(!cleanup_proto_tcp_struct()){
    //     mmt_stderr_log( "No cleanup function for protocol proto_tcp\n");
    // }
    // M9 (issue #26): release the externally-loaded port-hint table. The
    // external IP-range AVL trees are freed by the library destructor via
    // _free_proto_avltrees() (the built-in table is const, issue #557).
    mmt_tcpip_free_external_port_map();
    return 1;
}

int init_tcpip_plugin() {
    // B5 (remote-DoS hardening): every per-protocol registration below used to
    // call exit(0) on failure, killing the host process from inside a shared
    // library. They now `return 0` instead, so a failed initialization is
    // propagated as an error code to the caller (init_proto() ->
    // init_proto_fct() in load_plugin(), and init_extraction()) which can refuse
    // to continue instead of the whole process being torn down.

    /* Protocol init functions — data lives in proto_init_list.def, the same
     * list that declares these functions in mmt_common_internal_include.h
     * (issue #148). Order decides classifier chain order. A MMT_PROTO_SIMPLE
     * row has no init function: its id and alias go to
     * mmt_register_simple_protocol() (issue #542). */
    static const struct {
        int (*init)(void);
        mmt_proto_id_t id;
        const char *alias;
        const char *name;
    } proto_init_table[] = {
#define MMT_PROTO_INIT(init_fn, display_name) { init_fn, 0, NULL, display_name },
#define MMT_PROTO_SIMPLE(proto_id, proto_alias, display_name) \
        { NULL, proto_id, proto_alias, display_name },
#include "proto_init_list.def"
#undef MMT_PROTO_SIMPLE
#undef MMT_PROTO_INIT
    };
    for (size_t i = 0; i < sizeof(proto_init_table)/sizeof(proto_init_table[0]); i++) {
        int ok = (proto_init_table[i].init != NULL)
            ? proto_init_table[i].init()
            : mmt_register_simple_protocol(proto_init_table[i].id,
                    proto_init_table[i].alias);
        if (!ok) {
            mmt_stderr_log( "Error initializing protocol %s\n Exiting\n", proto_init_table[i].name);
            return 0;
        }
    }

    /* Inter-protocol classifier registrations — data lives in
     * inter_proto_classif_list.def (issue #238, F-CLEAN-006: the ~160
     * REGISTER_INTER_PROTO_OR_FAIL calls that used to fill this body were
     * data expressed as code). Order is registration order again.
     * Issue #540 (F-BUG-311): a MMT_INTER_PROTO_LEGACY row registers the
     * same way, in the same place, and its chain node is then marked legacy
     * — walked only under the opt-in `legacy` DPI profile.
     * Issue #560: every row's chain node also gets its checker's guard
     * inputs (excluded_proto and the recorded selection mask). */
    static const struct {
        uint32_t parent;
        generic_classification_function classify_fn;
        int weight;
        const char *name;
        int legacy;
        uint32_t excluded_proto;
    } inter_proto_table[] = {
#define MMT_INTER_PROTO(parent, fn, w, ex) { parent, fn, w, #fn, 0, ex },
#define MMT_INTER_PROTO_LEGACY(parent, fn, w, ex) { parent, fn, w, #fn, 1, ex },
#include "inter_proto_classif_list.def"
#undef MMT_INTER_PROTO_LEGACY
#undef MMT_INTER_PROTO
    };
    /* Issue #561: the TCP and UDP chains' guard view, before any row's guard
     * is recorded (mmt_classifier_set_guard() needs it). */
    if (!mmt_classifier_set_guard_view(get_protocol_struct_by_id(PROTO_TCP), mmt_tcpip_guard_view)
            || !mmt_classifier_set_guard_view(get_protocol_struct_by_id(PROTO_UDP), mmt_tcpip_guard_view)) {
        mmt_stderr_log("Error installing the TCP/UDP classifier guard view\n Exiting\n");
        return 0;
    }
    for (size_t i = 0; i < sizeof(inter_proto_table)/sizeof(inter_proto_table[0]); i++) {
        protocol_t *parent;
        if (!mmt_register_classifier(inter_proto_table[i].parent,
                    inter_proto_table[i].classify_fn,
                    inter_proto_table[i].weight, inter_proto_table[i].name)) {
            return 0;
        }
        parent = get_protocol_struct_by_id(inter_proto_table[i].parent);
        if (inter_proto_table[i].legacy
                && !mmt_classifier_mark_legacy(parent, inter_proto_table[i].classify_fn)) {
            mmt_stderr_log("Error marking legacy classification function %s for parent protocol %u\n Exiting\n",
                    inter_proto_table[i].name, (unsigned) inter_proto_table[i].parent);
            return 0;
        }
        if (!mmt_set_inter_proto_guard(parent, inter_proto_table[i].classify_fn,
                    inter_proto_table[i].excluded_proto, inter_proto_table[i].name)) {
            return 0;
        }
    }

    // M9 (issue #26): now that every tcpip protocol is registered (so protocol
    // names resolve), pull in any externally-supplied IP-range / port-hint data.
    // Both are no-ops unless MMT_DPI_IP_RANGES_FILE / MMT_DPI_PORT_MAP_FILE are
    // set, keeping the default classification byte-identical to the baseline.
    mmt_tcpip_load_external_ip_ranges();
    mmt_tcpip_load_external_port_map();

    return 1;
}

