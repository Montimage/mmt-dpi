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
 *   - the ROOT rule's nb_satisfied / nb_not_satisfied counters (top_rule,
 *     tips_internal.h), incremented by analyse_incoming_packet() for every
 *     verdict whatever the print option;
 *   - the result callback given to init_sec_lib(): every reported verdict
 *     string ("respected" / "not_respected") with its property id, and its
 *     JSON history, which must carry no raw control byte (#510). With
 *     RULE_EVAL_HISTORY_LOG set, each history is appended to that file, one
 *     per line, for run_tests.sh to parse with jq.
 *
 * The engine keeps its rule list in process globals (top_rule, the static
 * XML-loader state) and has no unload entry point, so every scenario runs
 * in a forked child: the parent never initialises the engine. A child that
 * crashes or hangs (alarm) fails its scenario instead of the whole run.
 *
 * Packet script: each frame is UDP to dest_port `port`, `len` bytes on the
 * wire, timestamped `ms` milliseconds after a fixed epoch. The fixtures
 * select frames by UDP.dest_port and META.packet_len only:
 *   A = 1001, B = 1002, C = 1003, X = 9999 (matches no event).
 *
 * Usage: test_rule_eval <dir-with-eval-fixtures>
 *        test_rule_eval probe <rule.xml> <port>:<len>@<ms> ...
 * The probe form replays an ad-hoc script and prints the verdict counts
 * without asserting — for deriving the expectation of a new case.
 */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mmt_core.h"

/* init_sec_lib(), top_rule and the rule layout come from the internal
 * header (not installed; the suite adds -I src/mmt_security). */
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
    /* Quirk pinned: copy_instance() also keeps the state of an instance
     * that expired, timer included, so the copy expires again on every
     * later frame — one not_satisfied per frame after the window.
     * Restricting the copy to satisfied verdicts is a follow-up of #510
     * (it changes tips.c, which #511/#512 rework). */
    { "keep_state expired copy reports on every later frame (current behaviour)", "keep_state.xml",
      { F(PORT_A, 60, 0), F(PORT_B, 60, 500), F(PORT_X, 60, 4000),
        F(PORT_X, 60, 5000) }, 4, 1, 2 },
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

    alarm(SCENARIO_TIMEOUT_S);
    if (dir != NULL)
        snprintf(path, sizeof path, "%s/%s", dir, s->fixture);
    else
        snprintf(path, sizeof path, "%s", s->fixture);
    memset(errbuf, 0, sizeof errbuf);
    if (!init_extraction()) { printf("FAIL - %s: init_extraction\n", s->name); exit(3); }
    mmt_handler_t *mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (mmt == NULL) { printf("FAIL - %s: mmt_init_handler: %s\n", s->name, errbuf); exit(3); }

    init_sec_lib(mmt, path, BOTH, on_verdict, NULL);
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
    mmt_close_handler(mmt);
    close_extraction();
    /* exit(), not _exit(): gcov counters are flushed at exit. An asserted
     * mismatch (already reported above) exits 3, so the parent only adds a
     * line for an exit the engine itself took. */
    exit(bad ? 3 : 0);
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
    if (argc != 2) {
        fprintf(stderr, "usage: %s <fixture-dir> | probe <rule.xml> <port>:<len>@<ms> ...\n", argv[0]);
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
