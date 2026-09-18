/*
 * test_rule_engine.c — minimal rule-engine tests for the ENABLESEC
 * security library (issue #126 / F-TEST-003).
 *
 * The security engine (src/mmt_security/tips*.c — tips.c was split along
 * its four responsibilities in issue #235) is only compiled into
 * libmmt_security.so when the SDK is built with ENABLESEC=1; before this
 * suite existed it was never exercised by CI.
 *
 * Scope (kept deliberately minimal per issue #126):
 *   - load a real hand-crafted rule-set XML through the public library
 *     entry point init_sec_lib() (tips.c) -> read_rules() -> processNode()
 *     (tips_xml.c) and verify the parse+construction side effects through observable
 *     core APIs (extraction attributes registered while compiling the
 *     boolean expressions);
 *   - verify the error paths for a missing rule file and malformed XML.
 *
 * Rule-file XML schema is derived from processNode()/read_rules() in
 * src/mmt_security/tips_xml.c; see tests/rule_engine/rules_minimal.xml.
 *
 * Usage: test_rule_engine parse <rules.xml>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mmt_core.h"
#include "proto_meta.h"

/* init_sec_lib() and the enum_print verdict selector come from
 * src/mmt_security/tips_internal.h — a global symbol but not part of the
 * installed SDK headers (the suite adds -I src/mmt_security). */
#include "tips_internal.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (msg)); failures++; } \
    else { printf("ok - %s\n", (msg)); } \
} while (0)

/* Lookup helpers from libmmt_core (declared in mmt_core.h). */
static long meta_proto_id(void) {
    long p = get_protocol_id_by_name("meta");
    return p;
}

/*
 * Load the rule file the same way an mmt-probe style application would and
 * assert the observable effects: the condition leaves referenced in
 * boolean_expression attributes must have been resolved against the
 * registered protocols and registered for extraction on the handler.
 */
static int run_parse(const char *rule_file) {
    char errbuf[MMT_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof (errbuf));

    CHECK(init_extraction() != 0, "init_extraction() registers protocols");

    mmt_handler_t *mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    CHECK(mmt != NULL, "mmt_init_handler() creates a handler");

    /* This call runs the full read_rules()/processNode() chain; any schema
     * or resolution error inside it aborts the process (exit(-1)). */
    init_sec_lib(mmt, strdup(rule_file), BOTH, NULL, NULL);
    printf("ok - init_sec_lib() parsed '%s'\n", rule_file);

    /* Side-effect assertions: every attribute referenced by the rule set's
     * boolean expressions is registered for extraction. */
    long meta = meta_proto_id();
    CHECK(meta > 0, "META protocol is registered");
    CHECK(is_registered_attribute(mmt, meta,
                    get_attribute_id_by_protocol_id_and_attribute_name(meta, "utime")),
            "attribute 'utime' registered via rule expression");
    CHECK(is_registered_attribute(mmt, meta,
                    get_attribute_id_by_protocol_id_and_attribute_name(meta, "packet_len")),
            "attribute 'packet_len' registered via rule expression");
    CHECK(is_registered_attribute(mmt, meta,
                    get_attribute_id_by_protocol_id_and_attribute_name(meta, "packet_index")),
            "attribute 'packet_index' registered via rule expression");

    mmt_close_handler(mmt);
    close_extraction();
    return failures;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    const char *rule_file = argc > 2 ? argv[2] : "";

    if (strcmp(mode, "parse") == 0) {
        return run_parse(rule_file);
    }

    fprintf(stderr, "unknown mode '%s'\n", mode ? mode : "(null)");
    return EXIT_FAILURE;
}
