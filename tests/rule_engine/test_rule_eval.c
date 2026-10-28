/*
 * test_rule_eval.c — characterisation tests for the security-rule
 * evaluator src/mmt_security/tips_eval.c (issue #509 / F-TEST-004).
 *
 * test_rule_engine.c only loads rule files; nothing fed packets through a
 * loaded rule, so the verify() traversal, the THEN/OR/AND/NOT handlers, the
 * timer/counter control and the instance lifecycle ran untested. This
 * driver loads one rule XML from tests/rule_engine/eval/ through the public
 * entry point init_sec_lib(), feeds a scripted sequence of synthetic
 * Ethernet/IPv4/UDP frames through packet_process() — the same path an
 * mmt-probe style application takes (analyse_incoming_packet() in tips.c is
 * the registered packet handler) — and asserts the verdicts the engine
 * reports.
 *
 * These tests pin the CURRENT behaviour, quirks included: the evaluator is
 * changed later (#510-#512) and those fixes must update the expectations
 * here deliberately. Cases whose verdict follows from a quirk rather than
 * from the rule's plain reading say so in their comment.
 *
 * Oracles, per scenario:
 *   - the ROOT rule's nb_satisfied / nb_not_satisfied counters (the
 *     engine's top_rule, tips_internal.h), incremented by
 *     analyse_incoming_packet() for every verdict whatever the print option;
 *   - the result callback given to init_sec_lib(): every reported verdict
 *     string ("respected" / "not_respected") with its property id, and its
 *     JSON history, which must carry no raw control byte (#510). With
 *     RULE_EVAL_HISTORY_LOG set, each history is appended to that file, one
 *     per line, for run_tests.sh to parse with jq.
 *
 * Every scenario runs in a forked child, so a child that crashes or hangs
 * (alarm) fails its scenario instead of the whole run.
 *
 * Issue #551 adds the `two-engines` check: two handlers of one process load
 * different rule files and are fed the same frames — interleaved on one
 * thread, then each from its own thread — and each engine reports only its
 * own rule's verdicts (counters, property id, callback user_args). The
 * `engine-lifecycle` check covers close_sec_lib() and handler reuse.
 *
 * Packet script: each frame is UDP to dest_port `port`, `len` bytes on the
 * wire, timestamped `ms` milliseconds after a fixed epoch. The fixtures
 * select frames by UDP.dest_port and META.packet_len only:
 *   A = 1001, B = 1002, C = 1003, X = 9999 (matches no event).
 *
 * Usage: test_rule_eval <dir-with-eval-fixtures>
 *        test_rule_eval two-engines <dir-with-eval-fixtures>
 *        test_rule_eval engine-lifecycle <dir-with-eval-fixtures>
 *        test_rule_eval probe <rule.xml> <port>:<len>@<ms> ...
 * The probe form replays an ad-hoc script and prints the verdict counts
 * without asserting — for deriving the expectation of a new case.
 */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mmt_core.h"

/* init_sec_lib(), the engine (mmt_sec_engine_of) and the rule layout come
 * from the internal header (not installed; the suite adds -I
 * src/mmt_security). */
#include "tips_internal.h"

#define PORT_A 1001
#define PORT_B 1002
#define PORT_C 1003
#define PORT_X 9999

#define MAX_PKTS 12
#define SCENARIO_TIMEOUT_S 20

typedef struct {
    uint16_t port;  /* UDP destination port */
    uint16_t len;   /* frame length (caplen == len) */
    long ms;        /* timestamp offset from EPOCH_S */
} frame_t;

typedef struct {
    const char *name;      /* printed in the ok/FAIL line */
    const char *fixture;   /* file under the fixture dir */
    frame_t pkts[MAX_PKTS];
    int npkts;
    long exp_satisfied;    /* ROOT nb_satisfied after the script */
    long exp_not_satisfied;/* ROOT nb_not_satisfied after the script */
    int cb_silent;         /* verdicts counted but not passed to the
                            * callback (no history on the instance) */
    int timeout_s;         /* alarm for the scenario; 0 = SCENARIO_TIMEOUT_S */
} scenario_t;

#define F(p, l, t) { (p), (l), (t) }

static const scenario_t scenarios[] = {
    /* ---- THEN, SAME packet (no delay/counter): both events on one frame */
    { "THEN/SAME satisfied: A frame longer than 100 bytes", "then_same.xml",
      { F(PORT_A, 120, 0) }, 1, 1, 0 },
    { "THEN/SAME not satisfied: A frame of 60 bytes", "then_same.xml",
      { F(PORT_A, 60, 0) }, 1, 0, 1 },
    { "THEN/SAME no verdict: left event never seen", "then_same.xml",
      { F(PORT_X, 120, 0), F(PORT_B, 120, 10) }, 2, 0, 0 },

    /* ---- THEN/AFTER, delay window [0, 2] s: A then B */
    { "THEN/AFTER satisfied: A then B 0.7 s later (sub-second borrow)", "then_after.xml",
      { F(PORT_A, 60, 600), F(PORT_B, 60, 1300) }, 2, 1, 0 },
    /* an out-of-order timestamp is only logged (Error 23), not rejected */
    { "THEN/AFTER satisfied: B stamped before A (current behaviour)", "then_after.xml",
      { F(PORT_A, 60, 1000), F(PORT_B, 60, 500) }, 2, 1, 0 },
    { "THEN/AFTER satisfied: B after a non-matching frame", "then_after.xml",
      { F(PORT_A, 60, 0), F(PORT_X, 60, 500), F(PORT_B, 60, 1500) }, 3, 1, 0 },
    { "THEN/AFTER not satisfied: B never arrives before the timeout", "then_after.xml",
      { F(PORT_A, 60, 0), F(PORT_X, 60, 3000) }, 2, 0, 1 },
    { "THEN/AFTER not satisfied: B arrives after the timeout", "then_after.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 2500) }, 2, 0, 1 },

    /* ---- THEN/BEFORE, delay_min = -2 s: A must be preceded by B */
    { "THEN/BEFORE satisfied: B then A 1 s later", "then_before.xml",
      { F(PORT_B, 60, 0), F(PORT_A, 60, 1000) }, 2, 1, 0 },
    { "THEN/BEFORE not satisfied: A without a preceding B", "then_before.xml",
      { F(PORT_A, 60, 0) }, 1, 0, 1 },
    { "THEN/BEFORE not satisfied: B too long before A", "then_before.xml",
      { F(PORT_B, 60, 0), F(PORT_A, 60, 5000) }, 2, 0, 1 },

    /* ---- timeout window [1, 3] s: B must follow A after 1 s, before 3 s */
    { "timeout satisfied: early B ignored, B inside the window", "timeout.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500), F(PORT_B, 60, 2000) }, 3, 1, 0 },
    { "timeout not satisfied: only an early B, then the window expires", "timeout.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500), F(PORT_X, 60, 4000) }, 3, 0, 1 },

    /* ---- counter window [3, 4] packets: B must follow A on the 3rd or
     *      4th packet counted from A */
    { "counter satisfied: early B ignored, B on the 3rd packet", "counter.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 10), F(PORT_B, 60, 20) }, 3, 1, 0 },
    { "counter not satisfied: no B before the 5th packet", "counter.xml",
      { F(PORT_A, 60, 0), F(PORT_X, 60, 10), F(PORT_X, 60, 20),
        F(PORT_X, 60, 30), F(PORT_X, 60, 40) }, 5, 0, 1 },

    /* ---- OR on the right branch: A then (B or C) within 2 s */
    { "OR satisfied: A then C", "or.xml",
      { F(PORT_A, 60, 0), F(PORT_C, 60, 1000) }, 2, 1, 0 },
    { "OR satisfied: A then B", "or.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000) }, 2, 1, 0 },
    { "OR not satisfied: neither B nor C before the timeout", "or.xml",
      { F(PORT_A, 60, 0), F(PORT_X, 60, 1000), F(PORT_X, 60, 3000) }, 3, 0, 1 },

    /* ---- AND on the right branch: A then (B && long) within 2 s */
    { "AND satisfied: A then a long B frame", "and.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 120, 1000) }, 2, 1, 0 },
    { "AND not satisfied: B frame too short, then the timeout", "and.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000), F(PORT_X, 60, 3000) }, 3, 0, 1 },
    /* Quirk pinned: the AND node's sons cannot complete on different
     * frames. check_for_timeout() returns 0 (VALID) for a node with no
     * delay/counter and check_time() passes it on as non-SKIP2, so once a
     * son is valid verify_and_timeout() treats the next frame as an expiry
     * and the node fails (tips_eval.c:681-714, 1133-1148). */
    { "AND not satisfied: sons met on different frames (current behaviour)", "and.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500), F(PORT_X, 120, 1000),
        F(PORT_X, 60, 3000) }, 4, 0, 1 },

    /* ---- NOT as the left branch: not B, then A (SAME situation) */
    { "NOT satisfied: A frame (the negated B absent)", "not.xml",
      { F(PORT_A, 60, 0) }, 1, 1, 0 },
    /* Quirk pinned: the instance created by the X frame stays pending with
     * its NOT timer armed. On ANY next frame the no-delay timer reads as
     * expired (the same check_for_timeout() 0 == VALID as AND), so NOT
     * holds before its son is evaluated, and the right branch A fails on
     * that frame — the second frame's content is irrelevant as long as it
     * is not an A. */
    { "NOT not satisfied: a non-A second frame expires the no-delay NOT timer (current behaviour)", "not.xml",
      { F(PORT_X, 60, 0), F(PORT_B, 60, 1000) }, 2, 0, 1, 1 },
    /* the negated event on a fresh instance: NOT fails, action() returns
     * ELIMINATE and nothing is reported */
    { "NOT no verdict: negated event B present (current behaviour)", "not.xml",
      { F(PORT_B, 60, 0) }, 1, 0, 0 },

    /* ---- BEFORE window [-5, -1] s: B must precede A by 1 to 5 s */
    { "BEFORE window satisfied: B 3 s before A", "before_window.xml",
      { F(PORT_B, 60, 0), F(PORT_A, 60, 3000) }, 2, 1, 0 },
    /* a B too close to A eliminates the instance (TIMEIN is treated as an
     * expiry on the BEFORE side), then A alone is reported */
    { "BEFORE window not satisfied: B only 0.5 s before A", "before_window.xml",
      { F(PORT_B, 60, 0), F(PORT_A, 60, 500) }, 2, 0, 1 },

    /* ---- counter BEFORE window, counter_min = -3 packets */
    { "counter BEFORE satisfied: B two packets before A", "counter_before.xml",
      { F(PORT_B, 60, 0), F(PORT_X, 60, 10), F(PORT_A, 60, 20) }, 3, 1, 0 },
    /* Quirk pinned: the "A without a preceding B" probe (verify_left) only
     * runs for a negative delay_min, so a counter-only BEFORE rule whose B
     * fell out of the window reports nothing. */
    { "counter BEFORE no verdict: B out of the window (current behaviour)", "counter_before.xml",
      { F(PORT_B, 60, 0), F(PORT_X, 60, 10), F(PORT_X, 60, 20),
        F(PORT_X, 60, 30), F(PORT_A, 60, 40) }, 5, 0, 0 },

    /* ---- event reference: B must carry A's packet length (.1 tuple) */
    { "event reference satisfied: B as long as A", "event_ref.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000) }, 2, 1, 0 },
    { "event reference not satisfied: B longer than A, then the timeout", "event_ref.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 70, 1000), F(PORT_X, 60, 3000) }, 3, 0, 1 },

    /* ---- || inside a boolean expression (XOR node) */
    { "|| expression satisfied: first operand", "or_expression.xml",
      { F(PORT_A, 120, 0) }, 1, 1, 0 },
    { "|| expression satisfied: second operand", "or_expression.xml",
      { F(PORT_A, 60, 0) }, 1, 1, 0 },
    { "|| expression not satisfied: neither operand", "or_expression.xml",
      { F(PORT_A, 80, 0) }, 1, 0, 1 },

    /* ---- arithmetic inside a boolean expression (SUB node) */
    { "arithmetic satisfied: len - 20 > 80", "arithmetic.xml",
      { F(PORT_A, 120, 0) }, 1, 1, 0 },
    { "arithmetic not satisfied: len - 20 <= 80", "arithmetic.xml",
      { F(PORT_A, 90, 0) }, 1, 0, 1 },

    /* ---- REPEAT x2 on the left branch, then B within 5 s */
    { "REPEAT satisfied: A twice then B", "repeat.xml",
      { F(PORT_A, 60, 0), F(PORT_A, 60, 100), F(PORT_B, 60, 1000) }, 3, 1, 0 },
    { "REPEAT not satisfied: A twice, no B before the timeout", "repeat.xml",
      { F(PORT_A, 60, 0), F(PORT_A, 60, 100), F(PORT_X, 60, 7000) }, 3, 0, 1 },
    /* the root timer only starts once the left branch completes */
    { "REPEAT no verdict: A only once", "repeat.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000), F(PORT_X, 60, 7000) }, 3, 0, 0 },

    /* ---- nested THEN on the left branch: (A then B) then C */
    { "nested THEN satisfied: A, B, C", "nested_then.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000), F(PORT_C, 60, 2000) }, 3, 1, 0 },
    { "nested THEN not satisfied: A, B, no C before the timeout", "nested_then.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000), F(PORT_X, 60, 9000) }, 3, 0, 1 },
    { "nested THEN no verdict: inner sequence never completes", "nested_then.xml",
      { F(PORT_A, 60, 0), F(PORT_C, 60, 1000), F(PORT_X, 60, 9000) }, 3, 0, 0 },

    /* ---- nested THEN/BEFORE on the left branch: (A preceded by B) then C.
     * Quirk pinned: a BEFORE sequence below the root never completes, so
     * even the in-order B, A, C reports nothing. */
    { "nested BEFORE no verdict: B, A, C (current behaviour)", "nested_before.xml",
      { F(PORT_B, 60, 0), F(PORT_A, 60, 1000), F(PORT_C, 60, 2000) }, 3, 0, 0 },
    { "nested BEFORE no verdict: A without B, then C", "nested_before.xml",
      { F(PORT_A, 60, 0), F(PORT_C, 60, 1000), F(PORT_X, 60, 9000) }, 3, 0, 0 },

    /* ---- JSON history escaping (#510, F-BUG-209): the event descriptions
     * carry a quote, a backslash, tab, newline and carriage return; the
     * on_verdict() raw-control-byte check and run_tests.sh's jq pass over
     * RULE_EVAL_HISTORY_LOG assert the reported history is valid JSON. */
    { "JSON history escaped: quoted/control-character descriptions", "json_escape.xml",
      { F(PORT_A, 120, 0) }, 1, 1, 0 },

    /* ---- keep_state="1" on A THEN AFTER B within [0, 2] s (#510,
     * F-BUG-211): copy_instance() re-creates the instance after each
     * verdict with A's state (and A's timer) kept. Before #510 it parsed
     * the JSON history as XML and every keep_state rule crashed on its
     * first verdict. */
    { "keep_state satisfied: A then B", "keep_state.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500) }, 2, 1, 0 },
    /* run_tests.sh also checks the second verdict's history (the one
     * stamped 1.7 s): the kept event_1 plus the new event_2, once each */
    { "keep_state satisfied twice: the kept A matches a second B", "keep_state.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500), F(PORT_B, 60, 1700) }, 3, 2, 0 },
    { "keep_state not satisfied: the kept A's window still ends 2 s after A", "keep_state.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500), F(PORT_B, 60, 4000) }, 3, 1, 1 },
    /* Expectation changed on purpose by #511/#512 (was 1 satisfied + 2 not
     * satisfied, pinned as "current behaviour" by #510): only a satisfied
     * instance is re-created with its kept state, so the copy that expires
     * at 4 s reports once and is not copied again. */
    { "keep_state expired copy reports once, then is dropped", "keep_state.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500), F(PORT_X, 60, 4000),
        F(PORT_X, 60, 5000) }, 4, 1, 1 },

    /* ---- #511: an existing instance that verify() fails (NOT_VALID) —
     * here a root AND whose no-delay timer reads as expired on the next
     * frame — is eliminated without a verdict. analyse_incoming_packet()
     * used to `continue` without advancing, retrying it forever; the 5 s
     * alarm is the acceptance bound. */
    { "root AND: a NOT_VALID existing instance is eliminated, no endless loop", "and_root.xml",
      { F(PORT_A, 60, 0), F(PORT_X, 60, 1000) }, 2, 0, 0, 0, 5 },

    /* ---- #512 (carry-over of #509): NOT as the right son of a root THEN,
     * A THEN AFTER (NOT B) within 2 s. The backtrack used to climb past the
     * rule instance and dereference NULL. Quirk pinned: the NOT node has no
     * delay of its own, so its timer reads as expired on the frame after A
     * whatever that frame is (the not.xml quirk) — even B satisfies it. */
    { "NOT right son satisfied: A then a non-B frame (current behaviour)", "then_not.xml",
      { F(PORT_A, 60, 0), F(PORT_X, 60, 1000) }, 2, 1, 0 },
    { "NOT right son satisfied: A then B, the NOT timer expires first (current behaviour)", "then_not.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000) }, 2, 1, 0 },
    { "NOT right son no verdict: A alone", "then_not.xml",
      { F(PORT_A, 60, 0) }, 1, 0, 0 },

    /* ---- #511: embedded functions resolved once at load from the
     * libembedded_functions.so run_tests.sh builds; B calls the
     * four-parameter maximum */
    { "embedded functions satisfied: #echo_port A then #sum_ports B", "embedded_funct.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 1000) }, 2, 1, 0 },
    { "embedded functions not satisfied: no B before the timeout", "embedded_funct.xml",
      { F(PORT_A, 60, 0), F(PORT_X, 60, 3000) }, 2, 0, 1 },

    /* ---- #511/#512: the satisfied verdict runs record(...) from
     * MMT_SEC_REACTION_DIR; run_tests.sh checks the recorded arguments and
     * the detection_<n>.data file */
    { "reaction: a satisfied verdict runs the script from the reaction folder", "reaction.xml",
      { F(PORT_A, 120, 0) }, 1, 1, 0 },
};

static int g_cb_respected;
static int g_cb_not_respected;
static int g_cb_other;
static int g_cb_bad_prop;
static int g_cb_raw_ctl;      /* histories holding an unescaped control byte */
static int g_expected_prop;   /* the loaded ROOT rule's property_id */

static void on_verdict(int prop_id, char *verdict, char *type, char *cause,
                       char *history, struct timeval ts, void *user_args)
{
    (void)type; (void)cause; (void)ts; (void)user_args;
    if (prop_id != g_expected_prop) g_cb_bad_prop++;
    if (history != NULL) {
        const char *log = getenv("RULE_EVAL_HISTORY_LOG");
        const unsigned char *h;
        for (h = (const unsigned char *) history; *h != '\0'; h++)
            if (*h < 0x20) { g_cb_raw_ctl++; break; }
        if (log != NULL && *log != '\0') {
            FILE *f = fopen(log, "a");
            if (f != NULL) { fprintf(f, "%s\n", history); fclose(f); }
        }
    }
    if (verdict == NULL) g_cb_other++;
    else if (strcmp(verdict, "respected") == 0) g_cb_respected++;
    else if (strcmp(verdict, "not_respected") == 0) g_cb_not_respected++;
    else g_cb_other++;
}

/* Ethernet II + IPv4 (no options) + UDP, zero payload padded to `len`. */
static void build_frame(uint8_t *buf, const frame_t *f)
{
    static const uint8_t eth[14] = {
        0x02, 0, 0, 0, 0, 0x02,   /* dst */
        0x02, 0, 0, 0, 0, 0x01,   /* src */
        0x08, 0x00                /* IPv4 */
    };
    uint16_t ip_len = (uint16_t)(f->len - 14);
    uint16_t udp_len = (uint16_t)(f->len - 34);

    memset(buf, 0, f->len);
    memcpy(buf, eth, sizeof eth);
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
    ip[8] = 64;                    /* TTL */
    ip[9] = 17;                    /* UDP */
    ip[12] = 10; ip[15] = 1;       /* 10.0.0.1 */
    ip[16] = 10; ip[19] = 2;       /* 10.0.0.2 */
    uint8_t *udp = ip + 20;
    udp[0] = 0x9c; udp[1] = 0x40;  /* src port 40000 */
    udp[2] = (uint8_t)(f->port >> 8); udp[3] = (uint8_t)f->port;
    udp[4] = (uint8_t)(udp_len >> 8); udp[5] = (uint8_t)udp_len;
}

#define EPOCH_S 1700000000L

/* Child side: load the rule, replay the script, compare, exit. */
static void run_scenario(const scenario_t *s, const char *dir)
{
    char path[4096];
    char errbuf[MMT_ERRBUF_SIZE];
    int i;

    alarm(s->timeout_s > 0 ? (unsigned) s->timeout_s : SCENARIO_TIMEOUT_S);
    if (dir != NULL)
        snprintf(path, sizeof path, "%s/%s", dir, s->fixture);
    else
        snprintf(path, sizeof path, "%s", s->fixture);
    memset(errbuf, 0, sizeof errbuf);
    if (!init_extraction()) { printf("FAIL - %s: init_extraction\n", s->name); exit(3); }
    mmt_handler_t *mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (mmt == NULL) { printf("FAIL - %s: mmt_init_handler: %s\n", s->name, errbuf); exit(3); }

    if (init_sec_lib(mmt, path, BOTH, on_verdict, NULL) != 0) {
        printf("FAIL - %s: init_sec_lib() rejected %s\n", s->name, s->fixture);
        exit(3);
    }
    const rule *top_rule = mmt_sec_engine_of(mmt) != NULL ? mmt_sec_engine_of(mmt)->top_rule : NULL;
    if (top_rule == NULL || top_rule->next != NULL) {
        printf("FAIL - %s: %s must load exactly one property\n", s->name, s->fixture);
        exit(3);
    }
    /* each fixture's description is its file name: proves the intended
     * rule was loaded, not merely some rule */
    if (top_rule->description == NULL ||
        strncmp(top_rule->description, s->fixture, strlen(top_rule->description)) != 0 ||
        strcmp(s->fixture + strlen(top_rule->description), ".xml") != 0) {
        if (s->exp_satisfied >= 0) {
            printf("FAIL - %s: %s loaded property '%s'\n", s->name, s->fixture,
                   top_rule->description ? top_rule->description : "(null)");
            exit(3);
        }
    }
    g_expected_prop = top_rule->property_id;

    for (i = 0; i < s->npkts; i++) {
        uint8_t buf[256];
        struct pkthdr hdr;
        memset(&hdr, 0, sizeof hdr);
        build_frame(buf, &s->pkts[i]);
        hdr.ts.tv_sec = EPOCH_S + s->pkts[i].ms / 1000;
        hdr.ts.tv_usec = (s->pkts[i].ms % 1000) * 1000;
        hdr.caplen = hdr.len = s->pkts[i].len;
        packet_process(mmt, &hdr, buf);
    }

    long sat = top_rule->nb_satisfied, not_sat = top_rule->nb_not_satisfied;
    int bad = 0;
    if (s->exp_satisfied < 0) {   /* probe mode: report, assert nothing */
        printf("probe - satisfied=%ld not_satisfied=%ld callback respected=%d not_respected=%d other=%d\n",
               sat, not_sat, g_cb_respected, g_cb_not_respected, g_cb_other);
        fflush(stdout);
        exit(0);
    }
    if (sat != s->exp_satisfied || not_sat != s->exp_not_satisfied) bad = 1;
    /* the callback reports the verdicts the counters record, except the
     * ones the scenario pins as silent (rule_is_satisfied_or_not() skips
     * the callback when the instance carries no JSON history) */
    if (g_cb_respected + g_cb_not_respected != sat + not_sat - s->cb_silent ||
        g_cb_respected > sat || g_cb_not_respected > not_sat ||
        g_cb_other != 0 || g_cb_bad_prop != 0 || g_cb_raw_ctl != 0) bad = 1;
    if (bad) {
        printf("FAIL - %s: satisfied=%ld not_satisfied=%ld (expected %ld/%ld); "
               "callback respected=%d not_respected=%d other=%d bad_prop=%d raw_ctl=%d\n",
               s->name, sat, not_sat, s->exp_satisfied, s->exp_not_satisfied,
               g_cb_respected, g_cb_not_respected, g_cb_other, g_cb_bad_prop, g_cb_raw_ctl);
    } else {
        printf("ok - %s (satisfied=%ld not_satisfied=%ld)\n", s->name, sat, not_sat);
    }
    fflush(stdout);
    if (close_sec_lib(mmt) != 0) {
        printf("FAIL - %s: close_sec_lib() found no engine\n", s->name);
        bad = 1;
    }
    mmt_close_handler(mmt);
    close_extraction();
    /* exit(), not _exit(): gcov counters are flushed at exit. An asserted
     * mismatch (already reported above) exits 3, so the parent only adds a
     * line for an exit the engine itself took. */
    exit(bad ? 3 : 0);
}

/* ---- #551: two engines, two handlers, one process ----------------------
 * then_same.xml (property 1) is satisfied by a long A frame, or_expression.xml
 * (property 11) by a long or a short one: on A120, A60, A80 the first
 * reports 1 satisfied / 2 not satisfied and the second 2 / 1 — the counts
 * each fixture's own scenarios above pin. A shared rule list, options or
 * callback would mix them. */
typedef struct {
    const char *fixture;
    int prop;                 /* the fixture's property_id */
    long exp_sat, exp_not_sat;
    /* written by on_engine_verdict through user_args */
    int respected, not_respected, wrong_prop;
} engine_obs_t;

static void on_engine_verdict(int prop_id, char *verdict, char *type, char *cause,
                              char *history, struct timeval ts, void *user_args)
{
    engine_obs_t *o = (engine_obs_t *) user_args;
    (void)type; (void)cause; (void)history; (void)ts;
    if (prop_id != o->prop) o->wrong_prop++;
    if (verdict != NULL && strcmp(verdict, "respected") == 0) o->respected++;
    else if (verdict != NULL && strcmp(verdict, "not_respected") == 0) o->not_respected++;
    else o->wrong_prop++;
}

static const frame_t two_engine_frames[] = { F(PORT_A, 120, 0), F(PORT_A, 60, 100), F(PORT_A, 80, 200) };
#define N_TWO_ENGINE_FRAMES ((int) (sizeof two_engine_frames / sizeof two_engine_frames[0]))

static void feed(mmt_handler_t *mmt, const frame_t *f)
{
    uint8_t buf[256];
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    build_frame(buf, f);
    hdr.ts.tv_sec = EPOCH_S + f->ms / 1000;
    hdr.ts.tv_usec = (f->ms % 1000) * 1000;
    hdr.caplen = hdr.len = f->len;
    packet_process(mmt, &hdr, buf);
}

/* Loads o->fixture on a new handler; NULL (with a FAIL line) on error. */
static mmt_handler_t *engine_handler(const char *dir, engine_obs_t *o, const char *phase)
{
    char path[4096], errbuf[MMT_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof errbuf);
    snprintf(path, sizeof path, "%s/%s", dir, o->fixture);
    mmt_handler_t *mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (mmt == NULL || init_sec_lib(mmt, path, BOTH, on_engine_verdict, o) != 0) {
        printf("FAIL - two engines (%s): loading %s\n", phase, o->fixture);
        return NULL;
    }
    return mmt;
}

/* One engine's verdicts: its own rule only, with the fixture's counts. */
static int check_engine(mmt_handler_t *mmt, const engine_obs_t *o, const char *phase)
{
    const mmt_sec_engine_t *e = mmt_sec_engine_of(mmt);
    const rule *r = e != NULL ? e->top_rule : NULL;
    if (r == NULL || r->next != NULL || r->property_id != o->prop ||
        r->nb_satisfied != o->exp_sat || r->nb_not_satisfied != o->exp_not_sat ||
        o->respected != o->exp_sat || o->not_respected != o->exp_not_sat || o->wrong_prop != 0) {
        printf("FAIL - two engines (%s): %s: property %d satisfied=%ld not_satisfied=%ld "
               "(expected %d: %ld/%ld); callback respected=%d not_respected=%d wrong=%d\n",
               phase, o->fixture, r != NULL ? r->property_id : -1,
               r != NULL ? r->nb_satisfied : -1L, r != NULL ? r->nb_not_satisfied : -1L,
               o->prop, o->exp_sat, o->exp_not_sat, o->respected, o->not_respected, o->wrong_prop);
        return 1;
    }
    printf("ok - two engines (%s): %s reports only its own verdicts (satisfied=%ld not_satisfied=%ld)\n",
           phase, o->fixture, r->nb_satisfied, r->nb_not_satisfied);
    return 0;
}

static void *feed_thread(void *p)
{
    mmt_handler_t *mmt = (mmt_handler_t *) p;
    int i;
    for (i = 0; i < N_TWO_ENGINE_FRAMES; i++) feed(mmt, &two_engine_frames[i]);
    return NULL;
}

static int run_two_engines(const char *dir)
{
    static const engine_obs_t proto[2] = {
        { "then_same.xml", 1, 1, 2, 0, 0, 0 },
        { "or_expression.xml", 11, 2, 1, 0, 0, 0 },
    };
    engine_obs_t obs[2];
    mmt_handler_t *h[2];
    pthread_t t[2];
    int i, k, bad = 0;

    alarm(SCENARIO_TIMEOUT_S);
    if (!init_extraction()) { printf("FAIL - two engines: init_extraction\n"); return 1; }

    /* phase 1: both engines fed from this thread, frame by frame in turn */
    memcpy(obs, proto, sizeof obs);
    for (i = 0; i < 2; i++)
        if ((h[i] = engine_handler(dir, &obs[i], "one thread")) == NULL) return 1;
    if (mmt_sec_engine_of(h[0]) == mmt_sec_engine_of(h[1])) {
        printf("FAIL - two engines: both handlers report the same engine\n");
        return 1;
    }
    for (k = 0; k < N_TWO_ENGINE_FRAMES; k++)
        for (i = 0; i < 2; i++) feed(h[i], &two_engine_frames[k]);
    for (i = 0; i < 2; i++) {
        bad |= check_engine(h[i], &obs[i], "one thread");
        if (close_sec_lib(h[i]) != 0) { printf("FAIL - two engines: close_sec_lib\n"); bad = 1; }
        mmt_close_handler(h[i]);
    }

    /* phase 2: each engine fed from its own thread, concurrently */
    memcpy(obs, proto, sizeof obs);
    for (i = 0; i < 2; i++)
        if ((h[i] = engine_handler(dir, &obs[i], "two threads")) == NULL) return 1;
    for (i = 0; i < 2; i++)
        if (pthread_create(&t[i], NULL, feed_thread, h[i]) != 0) { perror("pthread_create"); return 1; }
    for (i = 0; i < 2; i++) pthread_join(t[i], NULL);
    for (i = 0; i < 2; i++) {
        bad |= check_engine(h[i], &obs[i], "two threads");
        if (close_sec_lib(h[i]) != 0) { printf("FAIL - two engines: close_sec_lib\n"); bad = 1; }
        mmt_close_handler(h[i]);
    }
    close_extraction();
    fflush(stdout);
    return bad;
}

static int noop_packet_handler(const ipacket_t *ipacket, void *args)
{
    (void)ipacket; (void)args;
    return 0;
}

/* ---- #551: the engine lifecycle on one handler ---------------------------
 * close_sec_lib() frees an engine with live rule instances (run under LSan)
 * and the handler then loads a fresh one; an engine whose handler was closed
 * without close_sec_lib() never answers for, or blocks, a later handler; an
 * application's own packet handler 1 is refused instead of silently starving
 * the engine, and close_sec_lib() then leaves it registered. */
static int run_engine_lifecycle(const char *dir)
{
    char path[4096], errbuf[MMT_ERRBUF_SIZE];
    int bad = 0;
#define LCHECK(cond, msg) do { if (cond) printf("ok - engine lifecycle: %s\n", (msg)); \
        else { printf("FAIL - engine lifecycle: %s\n", (msg)); bad = 1; } } while (0)

    alarm(SCENARIO_TIMEOUT_S);
    memset(errbuf, 0, sizeof errbuf);
    snprintf(path, sizeof path, "%s/then_after.xml", dir);
    if (!init_extraction()) { printf("FAIL - engine lifecycle: init_extraction\n"); return 1; }

    /* close with a live instance, then reload on the same handler */
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL || init_sec_lib(h, path, BOTH, NULL, NULL) != 0) {
        printf("FAIL - engine lifecycle: loading then_after.xml\n");
        return 1;
    }
    const frame_t a = F(PORT_A, 60, 0);
    feed(h, &a);
    const mmt_sec_engine_t *e = mmt_sec_engine_of(h);
    LCHECK(e != NULL && e->top_rule != NULL && e->top_rule->list_of_instances != NULL,
           "an A frame leaves a live instance waiting for B");
    LCHECK(close_sec_lib(h) == 0 && mmt_sec_engine_of(h) == NULL,
           "close_sec_lib() frees the engine and its live instance");
    LCHECK(!is_registered_packet_handler(h, 1), "close_sec_lib() unregisters the engine's packet handler");
    LCHECK(close_sec_lib(h) == -1, "a second close_sec_lib() finds no engine");
    LCHECK(init_sec_lib(h, path, BOTH, NULL, NULL) == 0, "the handler loads a new engine after close_sec_lib()");
    e = mmt_sec_engine_of(h);
    LCHECK(e != NULL && e->top_rule != NULL && e->top_rule->list_of_instances == NULL &&
           e->top_rule->nb_satisfied == 0 && e->packet_count == 0,
           "the new engine starts from a fresh rule list");
    LCHECK(close_sec_lib(h) == 0, "close_sec_lib() frees the new engine");
    mmt_close_handler(h);

    /* a handler closed without close_sec_lib(): a later handler, even at
     * the same address, loads its own engine */
    mmt_handler_t *old = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (old == NULL || init_sec_lib(old, path, BOTH, NULL, NULL) != 0) {
        printf("FAIL - engine lifecycle: loading on the handler to abandon\n");
        return 1;
    }
    uintptr_t old_addr = (uintptr_t) old;
    mmt_close_handler(old);
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) { printf("FAIL - engine lifecycle: mmt_init_handler\n"); return 1; }
    printf("    (the new handler %s the closed one's address)\n",
           (uintptr_t) h == old_addr ? "reuses" : "does not reuse");
    LCHECK(init_sec_lib(h, path, BOTH, NULL, NULL) == 0,
           "init_sec_lib() loads on a new handler after another was closed without close_sec_lib()");
    e = mmt_sec_engine_of(h);
    LCHECK(e != NULL && e->mmt == h && is_registered_packet_handler(h, 1),
           "the new handler's engine is its own, not the abandoned one");
    LCHECK(close_sec_lib(h) == 0, "close_sec_lib() frees it");

    /* an application's own packet handler 1 */
    LCHECK(register_packet_handler(h, 1, noop_packet_handler, NULL) == 1, "the application registers packet handler 1");
    LCHECK(init_sec_lib(h, path, BOTH, NULL, NULL) == -1 && mmt_sec_engine_of(h) == NULL,
           "init_sec_lib() refuses a handler whose packet handler 1 is taken");
    LCHECK(close_sec_lib(h) == -1 && is_registered_packet_handler(h, 1),
           "close_sec_lib() leaves the application's packet handler registered");
    mmt_close_handler(h);
    close_extraction();
    fflush(stdout);
#undef LCHECK
    return bad;
}

int main(int argc, char **argv)
{
    size_t i;
    int failures = 0;
    if (argc >= 3 && strcmp(argv[1], "probe") == 0) {
        static scenario_t p;
        int n;
        p.name = "probe";
        p.fixture = argv[2];
        p.exp_satisfied = -1;
        if (argc - 3 > MAX_PKTS) {
            fprintf(stderr, "too many frames (at most %d)\n", MAX_PKTS);
            return 2;
        }
        for (n = 3; n < argc; n++) {
            unsigned port, len;
            long ms;
            int used = 0;
            if (sscanf(argv[n], "%u:%u@%ld%n", &port, &len, &ms, &used) != 3 ||
                argv[n][used] != '\0' || port > 65535 || len < 42 || len > 256 || ms < 0) {
                fprintf(stderr, "bad frame '%s' (want port:len@ms, port <= 65535, "
                        "42 <= len <= 256, ms >= 0)\n", argv[n]);
                return 2;
            }
            p.pkts[p.npkts].port = (uint16_t)port;
            p.pkts[p.npkts].len = (uint16_t)len;
            p.pkts[p.npkts].ms = ms;
            p.npkts++;
        }
        run_scenario(&p, NULL);
    }
    if (argc == 3 && strcmp(argv[1], "two-engines") == 0)
        return run_two_engines(argv[2]);
    if (argc == 3 && strcmp(argv[1], "engine-lifecycle") == 0)
        return run_engine_lifecycle(argv[2]);
    if (argc != 2) {
        fprintf(stderr, "usage: %s <fixture-dir> | two-engines|engine-lifecycle <fixture-dir> | probe <rule.xml> <port>:<len>@<ms> ...\n", argv[0]);
        return 2;
    }
    for (i = 0; i < sizeof scenarios / sizeof scenarios[0]; i++) {
        const scenario_t *s = &scenarios[i];
        int status = 0;
        fflush(stdout);
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) run_scenario(s, argv[1]);
        if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }
        if (WIFSIGNALED(status)) {
            printf("FAIL - %s: child killed by signal %d%s\n", s->name, WTERMSIG(status),
                   WTERMSIG(status) == SIGALRM ? " (timeout)" : "");
            failures++;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 3) {
            failures++;  /* the child printed its own FAIL line */
        } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            /* the child may have died in an engine exit() before printing */
            printf("FAIL - %s: child exited with status %d\n", s->name,
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            failures++;
        }
    }
    printf("%d/%zu scenarios passed\n",
           (int)(sizeof scenarios / sizeof scenarios[0]) - failures,
           sizeof scenarios / sizeof scenarios[0]);
    return failures ? 1 : 0;
}
