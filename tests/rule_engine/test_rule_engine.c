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
 *   - verify the error paths for a missing rule file and malformed XML;
 *   - #511/#512: a malformed or unloadable rule file makes init_sec_lib()
 *     return an error — it used to exit() or crash — and frees what it
 *     built (`load-error`, run under LSan); a second init_sec_lib() on
 *     the same handler is refused without leaking or touching the loaded
 *     rules (`reinit`, which since #551 also closes the engine with
 *     close_sec_lib() and loads a new one), also when two threads race for
 *     one handler's engine (`race`, run under TSan).
 *
 * Rule-file XML schema is derived from processNode()/read_rules() in
 * src/mmt_security/tips_xml.c; see tests/rule_engine/rules_minimal.xml.
 *
 * Usage: test_rule_engine parse <rules.xml>
 *        test_rule_engine load-error <rules.xml>
 *        test_rule_engine reinit <rules.xml>
 *        test_rule_engine race <rules.xml>
 */
#include <pthread.h>
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

    /* This call runs the full read_rules()/processNode() chain; a schema or
     * resolution error makes it return non-zero (#512). */
    if (init_sec_lib(mmt, (char *) rule_file, BOTH, NULL, NULL) != 0) {
        fprintf(stderr, "FAIL: init_sec_lib() rejected '%s'\n", rule_file);
        mmt_close_handler(mmt);
        close_extraction();
        return 1;
    }
    printf("ok - init_sec_lib() parsed '%s'\n", rule_file);

    /* Side-effect assertions: every attribute referenced by the rule set's
     * boolean expressions is registered for extraction. */
    long meta = meta_proto_id();
    CHECK(meta > 0, "META protocol is registered");
    CHECK(is_registered_attribute(mmt, meta,
                    get_attribute_id_by_protocol_id_and_attribute_name(meta, "utime")),
            "attribute 'utime' registered by the rule load");
    CHECK(is_registered_attribute(mmt, meta,
                    get_attribute_id_by_protocol_id_and_attribute_name(meta, "packet_len")),
            "attribute 'packet_len' registered via rule expression");
    CHECK(is_registered_attribute(mmt, meta,
                    get_attribute_id_by_protocol_id_and_attribute_name(meta, "packet_index")),
            "attribute 'packet_index' registered via rule expression");

    CHECK(close_sec_lib(mmt) == 0, "close_sec_lib() frees the engine");
    mmt_close_handler(mmt);
    close_extraction();
    return failures;
}

static int count_properties(const mmt_sec_engine_t *e) {
    int n = 0;
    const rule *r;
    for (r = e != NULL ? e->top_rule : NULL; r != NULL; r = r->next) n++;
    return n;
}

/* #512: the rule file must be rejected with an error return, nothing of the
 * failed load may stay reachable (LSan reports what it dropped) and the
 * engine must stay loadable. */
static int run_load_error(const char *rule_file) {
    char errbuf[MMT_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof (errbuf));
    CHECK(init_extraction() != 0, "init_extraction() registers protocols");
    mmt_handler_t *mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    CHECK(mmt != NULL, "mmt_init_handler() creates a handler");
    if (mmt == NULL) return 1;

    CHECK(init_sec_lib(mmt, (char *) rule_file, BOTH, NULL, NULL) != 0,
          "init_sec_lib() returns an error for the invalid rule file");
    /* #551: the engine (rule list and options) is freed and unregistered */
    CHECK(mmt_sec_engine_of(mmt) == NULL, "the failed load leaves no engine, rule or options behind");
    CHECK(close_sec_lib(mmt) == -1, "the handler has no engine to close");

    mmt_close_handler(mmt);
    close_extraction();
    return failures;
}

/* #512, #551: one engine per handler — a second init_sec_lib() on the same
 * handler returns an error, leaks nothing (LSan) and leaves the loaded rule
 * set as it was; close_sec_lib() frees the engine and the handler can load
 * a new one. */
static int run_reinit(const char *rule_file) {
    char errbuf[MMT_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof (errbuf));
    CHECK(init_extraction() != 0, "init_extraction() registers protocols");
    mmt_handler_t *mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    CHECK(mmt != NULL, "mmt_init_handler() creates a handler");
    if (mmt == NULL) return 1;

    CHECK(init_sec_lib(mmt, (char *) rule_file, BOTH, NULL, NULL) == 0, "first init_sec_lib() loads the rules");
    const mmt_sec_engine_t *e = mmt_sec_engine_of(mmt);
    CHECK(e != NULL && e->mmt == mmt, "the engine is registered on its handler");
    const rule *first = e != NULL ? e->top_rule : NULL;
    const OPTIONS_struct *first_op = e != NULL ? e->op : NULL;
    int n = count_properties(e);
    CHECK(n > 0, "the first load built the rule list");
    CHECK(init_sec_lib(mmt, (char *) rule_file, BOTH, NULL, NULL) != 0, "second init_sec_lib() returns an error");
    CHECK(mmt_sec_engine_of(mmt) == e && e->top_rule == first && count_properties(e) == n,
          "the second call appends no duplicate rule set");
    CHECK(e->op == first_op, "the second call keeps the engine options");
    CHECK(close_sec_lib(mmt) == 0 && mmt_sec_engine_of(mmt) == NULL, "close_sec_lib() frees the handler's engine");
    CHECK(init_sec_lib(mmt, (char *) rule_file, BOTH, NULL, NULL) == 0 && mmt_sec_engine_of(mmt) != NULL,
          "the handler loads a new engine after close_sec_lib()");
    CHECK(close_sec_lib(mmt) == 0, "close_sec_lib() frees the second engine");

    mmt_close_handler(mmt);
    close_extraction();
    return failures;
}

typedef struct {
    mmt_handler_t *mmt;
    const char *rule_file;
    int ret;
} race_arg_t;

static void *race_init(void *p) {
    race_arg_t *a = (race_arg_t *) p;
    a->ret = init_sec_lib(a->mmt, (char *) a->rule_file, BOTH, NULL, NULL);
    return NULL;
}

/* #512, #551: two threads race for one handler's engine — exactly one wins;
 * under TSan the claim must not race. */
static int run_race(const char *rule_file) {
    char errbuf[MMT_ERRBUF_SIZE];
    pthread_t t[2];
    race_arg_t a[2];
    int i;
    memset(errbuf, 0, sizeof (errbuf));
    CHECK(init_extraction() != 0, "init_extraction() registers protocols");
    mmt_handler_t *mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    CHECK(mmt != NULL, "mmt_init_handler() creates a handler");
    if (mmt == NULL) return 1;
    for (i = 0; i < 2; i++) {
        a[i].mmt = mmt;
        a[i].rule_file = rule_file;
        a[i].ret = 99;
        if (pthread_create(&t[i], NULL, race_init, &a[i]) != 0) return 1;
    }
    for (i = 0; i < 2; i++) pthread_join(t[i], NULL);
    CHECK((a[0].ret == 0) != (a[1].ret == 0) && (a[0].ret == 0 || a[0].ret == -1) &&
          (a[1].ret == 0 || a[1].ret == -1),
          "exactly one of two concurrent init_sec_lib() calls loads the engine");
    CHECK(close_sec_lib(mmt) == 0, "close_sec_lib() frees the winner's engine");
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
    if (strcmp(mode, "load-error") == 0) {
        return run_load_error(rule_file);
    }
    if (strcmp(mode, "reinit") == 0) {
        return run_reinit(rule_file);
    }
    if (strcmp(mode, "race") == 0) {
        return run_race(rule_file);
    }

    fprintf(stderr, "unknown mode '%s'\n", mode ? mode : "(null)");
    return EXIT_FAILURE;
}
