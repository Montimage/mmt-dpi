#include <stdio.h>
#include <stdlib.h>
#include "mmt_common_internal_include.h"
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
    // M9 (issue #26): release the externally-loaded port-hint table. The IP-range
    // AVL trees (built-in + external) are freed by the library destructor via
    // _free_proto_avltrees().
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
     * (issue #148). Order decides classifier chain order. */
    static const struct { int (*init)(void); const char *name; } proto_init_table[] = {
#define MMT_PROTO_INIT(init_fn, display_name) { init_fn, display_name },
#include "proto_init_list.def"
#undef MMT_PROTO_INIT
    };
    for (size_t i = 0; i < sizeof(proto_init_table)/sizeof(proto_init_table[0]); i++) {
        if (!proto_init_table[i].init()) {
            mmt_stderr_log( "Error initializing protocol %s\n Exiting\n", proto_init_table[i].name);
            return 0;
        }
    }

    /* Inter-protocol classifier registrations — data lives in
     * inter_proto_classif_list.def (issue #238, F-CLEAN-006: the ~160
     * REGISTER_INTER_PROTO_OR_FAIL calls that used to fill this body were
     * data expressed as code). Order is registration order again. */
    static const struct {
        uint32_t parent;
        generic_classification_function classify_fn;
        int weight;
        const char *name;
    } inter_proto_table[] = {
#define MMT_INTER_PROTO(parent, fn, w) { parent, fn, w, #fn },
#include "inter_proto_classif_list.def"
#undef MMT_INTER_PROTO
    };
    for (size_t i = 0; i < sizeof(inter_proto_table)/sizeof(inter_proto_table[0]); i++) {
        if (!mmt_register_classifier(inter_proto_table[i].parent,
                    inter_proto_table[i].classify_fn,
                    inter_proto_table[i].weight, inter_proto_table[i].name)) {
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

