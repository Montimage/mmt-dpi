/*
 * test_fuzz_engine — regression test for issue #210 (F-BUG-094,
 * F-BUG-100, F-BUG-101): the fuzz engine's quality-estimation layer.
 *
 *  - F-BUG-094: init_new_grade_membership_function() allocated exactly
 *    sizeof(metric_grade_membership_function_t) and then pointed
 *    membership_function_parameters at the first byte AFTER the block —
 *    every init_trapez_* caller wrote 16–32 bytes past the allocation.
 *    The fix allocates the trailing storage in the same malloc.
 *  - F-BUG-100: application_quality_estimation_xml_parser() freed the
 *    document on an empty tree and fell through to dereference the dead
 *    pointer, and a missing app_id root attribute left `application`
 *    NULL on the way into register_metric_with_application_struct().
 *  - F-BUG-101: parseNodeparameter() bounded the parameter index only
 *    by the XML child count (5+ elements overflowed the 4-double stack
 *    array; fewer left entries uninitialised) and read
 *    children->content without checking the child exists.
 *  - #447: a model and its estimation context had no destructor, so the
 *    RTP session cleanup leaked both. The free functions must release
 *    every allocation exactly once (heap balance; ASan double-free).
 *  - #455: init_application_quality_estimation_context() is the generic
 *    per-session setup media protocols share (RTP uses it). It binds one
 *    caller value per model metric, refuses a model whose metric count
 *    does not match (estimate_quality_index() dereferences every slot),
 *    and frees the model on every failure path.
 *  - #466: the XML parser built a rules set per <rules> node and kept
 *    only the last one, then attached it to the hard-coded quality
 *    metric id 3 and ignored a failed attach. Every set it builds must
 *    end up on the parsed quality metric or be freed. run_tests.sh runs
 *    this binary with detect_leaks=1 under SANITIZE=asan; the mallinfo2
 *    loop covers the unsanitised runs.
 *  - #468: a second <indexs> quality metric (SINGLE_QUALITY_METRIC mode
 *    holds one) was dropped with its grades; it must be freed and reported.
 *  - #469: a quality metric without usable rules (no <rules>, <rules>
 *    before <kpis>, a rule element without a metric) crashed
 *    estimate_quality_index(); the context helper must refuse the model and
 *    the estimation path must not dereference the missing parts.
 *
 * Under SANITIZE=asan this binary and libmmt_fuzz are both instrumented
 * (run_all_tests.sh -> EXTRA_CFLAGS + SDK_BUILD_PROFILE=asan), so the
 * pre-fix tree aborts on a sanitizer report; the NULL-deref cases
 * (missing app_id, empty elements) crash even unsanitised.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>

#include "fuzz/mmt_quality_estimation_defs.h"
#include "fuzz/mmt_quality_estimation_utilities.h"
#include "fuzz/mmt_quality_estimation_calculation.h"

/* init_voip_quality_estimation_struct() is exported by libmmt_fuzz but
 * not declared in its public headers. */
extern application_quality_estimation_t * init_voip_quality_estimation_struct(void);

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                         \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("ok - %s\n", (msg));                               \
        } else {                                                      \
            printf("not ok - %s\n", (msg));                           \
            g_failures++;                                             \
        }                                                             \
    } while (0)

/* ------------------------------------------------------------------ */
/* XML fixtures — written to a scratch dir, parsed by the real parser.  */
/* ------------------------------------------------------------------ */

static const char * XML_VALID =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n"
    "    <kpi metric_id=\"12\" metric_range_low=\"0.0\" metric_range_high=\"100.0\">\n"
    "      <grades>\n"
    "        <grade grade_value=\"1\">\n"
    "          <membership_function_type>3</membership_function_type>\n"
    "          <parameters>\n"
    "            <membership_function_parameters>2.0</membership_function_parameters>\n"
    "            <membership_function_parameters>5.0</membership_function_parameters>\n"
    "          </parameters>\n"
    "        </grade>\n"
    "        <grade grade_value=\"2\">\n"
    "          <membership_function_type>2</membership_function_type>\n"
    "          <parameters>\n"
    "            <membership_function_parameters>1.0</membership_function_parameters>\n"
    "            <membership_function_parameters>3.0</membership_function_parameters>\n"
    "            <membership_function_parameters>2.5</membership_function_parameters>\n"
    "            <membership_function_parameters>4.5</membership_function_parameters>\n"
    "          </parameters>\n"
    "        </grade>\n"
    "      </grades>\n"
    "    </kpi>\n"
    "    <indexs metric_id=\"3\" metric_range_low=\"1.0\" metric_range_high=\"5.0\">\n"
    "      <index>\n"
    "        <grade grade_value=\"1\">\n"
    "          <membership_function_type>1</membership_function_type>\n"
    "          <parameters>\n"
    "            <membership_function_parameters>2.0</membership_function_parameters>\n"
    "            <membership_function_parameters>2.5</membership_function_parameters>\n"
    "          </parameters>\n"
    "        </grade>\n"
    "      </index>\n"
    "    </indexs>\n"
    "  </kpis>\n"
    "  <rules>\n"
    "    <rule>\n"
    "      <rules_elements>\n"
    "        <element metric_id=\"12\" grade_value=\"1\"/>\n"
    "      </rules_elements>\n"
    "      <output_elements>\n"
    "        <element metric_id=\"3\" grade_value=\"1\"/>\n"
    "      </output_elements>\n"
    "    </rule>\n"
    "  </rules>\n"
    "</application>\n";

/* Missing app_id on the root element: `application` stayed NULL and was
 * passed on into register_metric_with_application_struct() (F-BUG-100). */
static const char * XML_NO_APPID =
    "<?xml version=\"1.0\"?>\n"
    "<application>\n"
    "  <kpis>\n"
    "    <kpi metric_id=\"12\" metric_range_low=\"0.0\" metric_range_high=\"100.0\">\n"
    "      <grades>\n"
    "        <grade grade_value=\"1\">\n"
    "          <membership_function_type>3</membership_function_type>\n"
    "          <parameters>\n"
    "            <membership_function_parameters>2.0</membership_function_parameters>\n"
    "            <membership_function_parameters>5.0</membership_function_parameters>\n"
    "          </parameters>\n"
    "        </grade>\n"
    "      </grades>\n"
    "    </kpi>\n"
    "  </kpis>\n"
    "</application>\n";

/* Five parameter elements overflow the 4-double stack array pre-fix
 * (F-BUG-101). */
static const char * XML_MANY_PARAMS =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n"
    "    <kpi metric_id=\"12\" metric_range_low=\"0.0\" metric_range_high=\"100.0\">\n"
    "      <grades>\n"
    "        <grade grade_value=\"1\">\n"
    "          <membership_function_type>2</membership_function_type>\n"
    "          <parameters>\n"
    "            <membership_function_parameters>1.0</membership_function_parameters>\n"
    "            <membership_function_parameters>3.0</membership_function_parameters>\n"
    "            <membership_function_parameters>2.5</membership_function_parameters>\n"
    "            <membership_function_parameters>4.5</membership_function_parameters>\n"
    "            <membership_function_parameters>9.9</membership_function_parameters>\n"
    "            <membership_function_parameters>9.9</membership_function_parameters>\n"
    "          </parameters>\n"
    "        </grade>\n"
    "      </grades>\n"
    "    </kpi>\n"
    "  </kpis>\n"
    "</application>\n";

/* Self-closing elements have no children: `cur->children` is NULL and the
 * pre-fix children->content read dereferences NULL (F-BUG-101). */
static const char * XML_EMPTY_ELEMENTS =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n"
    "    <kpi metric_id=\"12\" metric_range_low=\"0.0\" metric_range_high=\"100.0\">\n"
    "      <grades>\n"
    "        <grade grade_value=\"1\">\n"
    "          <membership_function_type/>\n"
    "          <parameters>\n"
    "            <membership_function_parameters/>\n"
    "          </parameters>\n"
    "        </grade>\n"
    "      </grades>\n"
    "    </kpi>\n"
    "  </kpis>\n"
    "</application>\n";

/* Fewer parameters than the membership type needs: the tail of the stack
 * array stayed uninitialised pre-fix (F-BUG-101). */
static const char * XML_FEW_PARAMS =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n"
    "    <kpi metric_id=\"12\" metric_range_low=\"0.0\" metric_range_high=\"100.0\">\n"
    "      <grades>\n"
    "        <grade grade_value=\"1\">\n"
    "          <membership_function_type>2</membership_function_type>\n"
    "          <parameters>\n"
    "            <membership_function_parameters>1.0</membership_function_parameters>\n"
    "            <membership_function_parameters>3.0</membership_function_parameters>\n"
    "          </parameters>\n"
    "        </grade>\n"
    "      </grades>\n"
    "    </kpi>\n"
    "  </kpis>\n"
    "</application>\n";

/* #466 fixtures: one metric (12) with one grade, a quality index with one
 * grade, and <rules> sets built from RULE_XML. */
#define KPI_XML \
    "    <kpi metric_id=\"12\" metric_range_low=\"0.0\" metric_range_high=\"100.0\">\n" \
    "      <grades>\n" \
    "        <grade grade_value=\"1\">\n" \
    "          <membership_function_type>3</membership_function_type>\n" \
    "          <parameters>\n" \
    "            <membership_function_parameters>2.0</membership_function_parameters>\n" \
    "            <membership_function_parameters>5.0</membership_function_parameters>\n" \
    "          </parameters>\n" \
    "        </grade>\n" \
    "      </grades>\n" \
    "    </kpi>\n"
#define INDEX_XML(id) \
    "    <indexs metric_id=\"" id "\" metric_range_low=\"1.0\" metric_range_high=\"5.0\">\n" \
    "      <index>\n" \
    "        <grade grade_value=\"1\">\n" \
    "          <membership_function_type>1</membership_function_type>\n" \
    "          <parameters>\n" \
    "            <membership_function_parameters>2.0</membership_function_parameters>\n" \
    "            <membership_function_parameters>2.5</membership_function_parameters>\n" \
    "          </parameters>\n" \
    "        </grade>\n" \
    "      </index>\n" \
    "    </indexs>\n"
#define RULE_XML(id) \
    "    <rule>\n" \
    "      <rules_elements>\n" \
    "        <element metric_id=\"12\" grade_value=\"1\"/>\n" \
    "      </rules_elements>\n" \
    "      <output_elements>\n" \
    "        <element metric_id=\"" id "\" grade_value=\"1\"/>\n" \
    "      </output_elements>\n" \
    "    </rule>\n"

/* Two <rules> nodes (1 rule, then 2): pre-fix the first set leaked. */
static const char * XML_TWO_RULES_NODES =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n" KPI_XML INDEX_XML("3") "  </kpis>\n"
    "  <rules>\n" RULE_XML("3") "  </rules>\n"
    "  <rules>\n" RULE_XML("3") RULE_XML("3") "  </rules>\n"
    "</application>\n";

/* Quality index with an id other than 3: pre-fix the set was attached to
 * id 3 only, so it matched nothing and leaked (rules stayed NULL). */
static const char * XML_QUALITY_ID_7 =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n" KPI_XML INDEX_XML("7") "  </kpis>\n"
    "  <rules>\n" RULE_XML("7") "  </rules>\n"
    "</application>\n";

/* <rules> but no quality index: there is nothing to attach the set to. */
static const char * XML_RULES_NO_INDEX =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n" KPI_XML "  </kpis>\n"
    "  <rules>\n" RULE_XML("3") "  </rules>\n"
    "</application>\n";

/* #468: two quality metrics; the model keeps the first (id 3). */
static const char * XML_TWO_INDEXS =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n" KPI_XML INDEX_XML("3") INDEX_XML("4") "  </kpis>\n"
    "  <rules>\n" RULE_XML("3") "  </rules>\n"
    "</application>\n";

/* #469: a quality metric without rules. */
static const char * XML_NO_RULES =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <kpis>\n" KPI_XML INDEX_XML("3") "  </kpis>\n"
    "</application>\n";

/* #469: <rules> before <kpis>: the rule is built without elements. */
static const char * XML_RULES_BEFORE_KPIS =
    "<?xml version=\"1.0\"?>\n"
    "<application app_id=\"1\">\n"
    "  <rules>\n" RULE_XML("3") "  </rules>\n"
    "  <kpis>\n" KPI_XML INDEX_XML("3") "  </kpis>\n"
    "</application>\n";

static void write_fixture(char *path, size_t size, const char *dir,
        const char *name, const char *content) {
    snprintf(path, size, "%s/%s", dir, name);
    FILE *fp = fopen(path, "w");
    if (!fp) { perror("fopen"); exit(2); }
    fputs(content, fp);
    fclose(fp);
}

int main(void) {
    char dir[] = "/tmp/mmt_fuzz_test.XXXXXX";
    char path[512];
    /* Line-buffered: LeakSanitizer ends the process with _exit(), which
     * would drop the buffered "ok -" lines from the log. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }

    /* --- F-BUG-094: parameter storage must live inside the allocation -- */

    /* Under ASan these calls abort on the pre-fix tree: each write to
     * membership_function_parameters[i] lands past the malloc block. */
    metric_grade_membership_function_t *g =
        init_trapez_center_grade_membership_function(2, 0.5, 2.0, 2.0, 5.0);
    CHECK(g != NULL, "init_trapez_center returns a grade");
    /* parameters[] = {param2, param3, param2-param1, param4-param3} */
    CHECK(g->membership_function_parameters[0] == 2.0 &&
          g->membership_function_parameters[1] == 2.0 &&
          g->membership_function_parameters[2] == 1.5 &&
          g->membership_function_parameters[3] == 3.0,
          "trapez_center parameters stored and read back in-bounds");
    /* A read path through the function pointer table exercises the same
     * storage (ASan would also catch an out-of-bounds read). */
    CHECK(trapezoid_medium(2.0, g) == 1.0,
          "trapezoid_medium reads the stored parameters");
    free(g);

    g = init_trapez_left_grade_membership_function(1, 0.5, 1.0);
    CHECK(g != NULL &&
          g->membership_function_parameters[0] == 0.5 &&
          g->membership_function_parameters[1] == 0.5,
          "trapez_left parameters stored in-bounds");
    free(g);

    g = init_trapez_right_grade_membership_function(3, 2.0, 5.0);
    CHECK(g != NULL &&
          g->membership_function_parameters[0] == 5.0 &&
          g->membership_function_parameters[1] == 3.0,
          "trapez_right parameters stored in-bounds");
    free(g);

    /* The canned VoIP model issues 8 init_trapez_* calls — 8 heap
     * overflows pre-fix. */
    application_quality_estimation_t *voip =
        init_voip_quality_estimation_struct();
    CHECK(voip != NULL, "init_voip_quality_estimation_struct returns a model");
    if (voip) {
        CHECK(voip->nb_metrics == 2 && voip->nb_estimation_metrics == 1,
              "VoIP model registers 2 metrics + 1 estimation metric");
        /* Walk every grade and touch its parameters (ASan read check). */
        int touched = 0;
        for (metric_t *m = voip->metrics; m; m = m->next)
            for (metric_grade_membership_function_t *mg = m->metric_grades;
                    mg; mg = mg->next)
                touched += (int) mg->membership_function_parameters[0];
        CHECK(touched != 0, "VoIP grade parameters are readable");
        /* #336: the model's metrics are keyed by the named ids. */
        CHECK(get_metric_by_id(voip, VOIP_METRIC_ID_LOSS) != NULL &&
              get_metric_by_id(voip, VOIP_METRIC_ID_JITTER) != NULL,
              "VoIP loss/jitter metrics registered under their named ids");
        CHECK(voip->estimation_metrics != NULL &&
              voip->estimation_metrics->metric_id ==
                  VOIP_METRIC_ID_QUALITY_INDEX,
              "VoIP quality index registered under its named id");
    }

    /* #447: the model and its estimation context free every allocation
     * exactly once. ASan reports a double free or a use after free. The
     * leak check repeats the build/free cycle: after a warm-up cycle the
     * allocator reuses the same (tcache/fastbin) chunks, so the in-use heap
     * byte count stays flat, while a leak grows it on every cycle. It is
     * skipped when a sanitizer replaces the allocator (mallinfo2 reads 0). */
    free_internal_application_quality_estimation_struct(NULL);
    free_application_quality_estimation_struct(NULL);
    if (voip) {
        application_quality_estimation_internal_t *ctx =
            init_new_internal_application_quality_estimation_struct(voip);
        CHECK(ctx != NULL, "VoIP estimation context allocates");
        free_internal_application_quality_estimation_struct(ctx);
        free_application_quality_estimation_struct(voip);
        voip = NULL;
    }
#if !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    if (mallinfo2().uordblks != 0) {
        size_t before = mallinfo2().uordblks;
        for (int i = 0; i < 64; i++) {
            application_quality_estimation_t *model =
                init_voip_quality_estimation_struct();
            application_quality_estimation_internal_t *ctx =
                init_new_internal_application_quality_estimation_struct(model);
            free_internal_application_quality_estimation_struct(ctx);
            free_application_quality_estimation_struct(model);
        }
        size_t after = mallinfo2().uordblks;
        CHECK(after <= before,
              "repeated VoIP model/context build+free does not grow the heap");
    }
#endif

    /* #455: the generic context helper binds every metric slot and owns
     * its model. Each refused call must still free the model: the heap
     * balance loop below repeats the success and failure paths. */
    {
        double jitter = 10.0, loss = 1.0;
        double * const two[] = { &jitter, &loss };
        double * const three[] = { &jitter, &loss, &loss };
        double * const with_null[] = { &jitter, NULL };

        CHECK(init_application_quality_estimation_context(NULL, two, 2) == NULL,
              "context helper refuses a NULL model");
        CHECK(init_application_quality_estimation_context(
                  init_voip_quality_estimation_struct(), NULL, 2) == NULL,
              "context helper refuses NULL metric values");
        CHECK(init_application_quality_estimation_context(
                  init_voip_quality_estimation_struct(), two, 1) == NULL,
              "context helper refuses fewer values than model metrics");
        CHECK(init_application_quality_estimation_context(
                  init_voip_quality_estimation_struct(), three, 3) == NULL,
              "context helper refuses more values than model metrics");
        CHECK(init_application_quality_estimation_context(
                  init_voip_quality_estimation_struct(), two, 0) == NULL,
              "context helper refuses a zero value count");
        CHECK(init_application_quality_estimation_context(
                  init_voip_quality_estimation_struct(), with_null, 2) == NULL,
              "context helper refuses a NULL value slot");
        free_application_quality_estimation_context(NULL);

        application_quality_estimation_internal_t *ctx =
            init_application_quality_estimation_context(
                init_voip_quality_estimation_struct(), two, 2);
        CHECK(ctx != NULL && ctx->application_quality_estimation != NULL &&
              ctx->metric_values[0] == &jitter && ctx->metric_values[1] == &loss,
              "context helper binds value i to model metric i");
        if (ctx) {
            const metric_t *q = ctx->application_quality_estimation->estimation_metrics;
            double qi = estimate_quality_index(ctx);
            CHECK(q != NULL && qi >= q->metric_range_low && qi <= q->metric_range_high,
                  "bound context estimates a quality index inside its range");
            free_application_quality_estimation_context(ctx);
        }
    }
#if !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    if (mallinfo2().uordblks != 0) {
        double v0 = 0.0, v1 = 0.0;
        double * const two[] = { &v0, &v1 };
        size_t before = 0;
        for (int i = 0; i < 65; i++) {
            if (i == 1)
                before = mallinfo2().uordblks;   /* after one warm-up cycle */
            free_application_quality_estimation_context(
                init_application_quality_estimation_context(
                    init_voip_quality_estimation_struct(), two, 2));
            (void) init_application_quality_estimation_context(
                init_voip_quality_estimation_struct(), two, 1);
        }
        size_t after = mallinfo2().uordblks;
        CHECK(after <= before,
              "context helper frees its model on success and refusal");
    }
#endif

    /* #336: trapezoid_left has no lower bound -- a value below 0 (or below
     * the metric range) still belongs fully to the left-shoulder grade. */
    g = init_trapez_left_grade_membership_function(1, 0.5, 1.0);
    CHECK(g != NULL && trapezoid_left(-1.0, g) == 1.0 &&
          trapezoid_left(0.5, g) == 1.0 && trapezoid_left(2.0, g) == 0.0,
          "trapezoid_left: open left shoulder, zero past the slope");
    free(g);

    /* --- F-BUG-100/101: XML parser entry point ------------------------ */

    application_quality_estimation_t *app;

    /* Valid model: parses, parameters land inside the grade struct. */
    write_fixture(path, sizeof(path), dir, "valid.xml", XML_VALID);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL, "valid model parses");
    if (app) {
        CHECK(app->app_id == 1 && app->nb_metrics == 1 &&
              app->nb_estimation_metrics == 1,
              "valid model registers metric + quality index");
        metric_t *m = get_metric_by_id(app, 12);
        CHECK(m != NULL && m->nb_grades == 2,
              "metric 12 carries both parsed grades");
        metric_grade_membership_function_t *c = NULL;
        for (metric_grade_membership_function_t *mg = m ? m->metric_grades : NULL;
                mg; mg = mg->next)
            if (mg->membership_function_type == MMT_TRAPEZ_CENTER) c = mg;
        /* {param2, param3, param2-param1, param4-param3} =
         * {3.0, 2.5, 2.0, 2.0} */
        CHECK(c != NULL &&
              c->membership_function_parameters[0] == 3.0 &&
              c->membership_function_parameters[1] == 2.5 &&
              c->membership_function_parameters[2] == 2.0 &&
              c->membership_function_parameters[3] == 2.0,
              "XML-parsed trapez_center parameters stored in-bounds");
        /* #447: an XML-parsed model (rules on the quality index) frees
         * cleanly with its estimation context. */
        application_quality_estimation_internal_t *ctx =
            init_new_internal_application_quality_estimation_struct(app);
        CHECK(ctx != NULL, "XML model estimation context allocates");
        free_internal_application_quality_estimation_struct(ctx);
        free_application_quality_estimation_struct(app);
    }

    /* Missing app_id: pre-fix NULL-deref inside
     * register_metric_with_application_struct; post-fix a clean NULL. */
    write_fixture(path, sizeof(path), dir, "no_appid.xml", XML_NO_APPID);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app == NULL, "model without app_id is refused (returns NULL)");

    /* >4 parameter elements: pre-fix stack write past
     * membership_function_parameters[4]. */
    write_fixture(path, sizeof(path), dir, "many_params.xml", XML_MANY_PARAMS);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL, "model with 6 parameter elements parses (bounded)");
    free_application_quality_estimation_struct(app);

    /* Self-closing elements: children == NULL; pre-fix dereferenced it. */
    write_fixture(path, sizeof(path), dir, "empty_elem.xml", XML_EMPTY_ELEMENTS);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL, "model with empty elements parses (NULL-safe)");
    free_application_quality_estimation_struct(app);

    /* 2 params for a 4-parameter function: post-fix the tail of the
     * stack array is zero-initialised, so parameters[2..3] are 0.0. */
    write_fixture(path, sizeof(path), dir, "few_params.xml", XML_FEW_PARAMS);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL, "model with too few parameters parses");
    if (app) {
        metric_t *m = get_metric_by_id(app, 12);
        metric_grade_membership_function_t *mg =
            m ? m->metric_grades : NULL;
        /* TRAPEZ_CENTER stores {param2, param3, param2-param1,
         * param4-param3}; with the XML supplying only param1=1.0 and
         * param2=3.0 the initialised tail gives param3=param4=0.0, so
         * [1] (param3) and [3] (param4-param3) are 0.0. */
        CHECK(mg != NULL &&
              mg->membership_function_parameters[1] == 0.0 &&
              mg->membership_function_parameters[3] == 0.0,
              "missing parameters read as initialised zeros");
    }
    free_application_quality_estimation_struct(app);

    /* --- #466: every parsed rules set is attached or freed ------------ */

    /* The standalone destructor is NULL-safe and frees a detached set with
     * its rules (LSan checks the latter under SANITIZE=asan). */
    free_application_quality_estimation_rules(NULL);
    {
        application_quality_estimation_rules_t *rs =
            init_new_app_quality_estimation_rules(SUM_AGGREGATION);
        CHECK(rs != NULL &&
              register_application_quality_estimation_rule(rs, init_new_rule_struct(AND_RULE)) &&
              register_application_quality_estimation_rule(rs, init_new_rule_struct(AND_RULE)) &&
              rs->nb_rules == 2,
              "detached rules set with two rules builds");
        free_application_quality_estimation_rules(rs);
    }

    /* Several <rules> nodes: the last set is kept, the earlier ones are
     * freed (LSan under SANITIZE=asan, the heap loop below otherwise). */
    write_fixture(path, sizeof(path), dir, "two_rules.xml", XML_TWO_RULES_NODES);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL && app->estimation_metrics != NULL &&
          app->estimation_metrics->quality_estimation_rules != NULL &&
          app->estimation_metrics->quality_estimation_rules->nb_rules == 2,
          "several <rules> nodes: the last set is attached");
    free_application_quality_estimation_struct(app);

    /* The rules set goes to the parsed quality metric, whatever its id. */
    write_fixture(path, sizeof(path), dir, "quality_id_7.xml", XML_QUALITY_ID_7);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL && app->estimation_metrics != NULL &&
          app->estimation_metrics->metric_id == 7 &&
          app->estimation_metrics->quality_estimation_rules != NULL &&
          app->estimation_metrics->quality_estimation_rules->nb_rules == 1,
          "rules attach to the parsed quality metric (id 7, not 3)");
    free_application_quality_estimation_struct(app);

    /* No quality metric: the model still parses, the set is freed. */
    write_fixture(path, sizeof(path), dir, "rules_no_index.xml", XML_RULES_NO_INDEX);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL && app->estimation_metrics == NULL,
          "rules without a quality metric: model parses, set not attached");
    free_application_quality_estimation_struct(app);

    /* --- #468: a quality metric the model cannot hold is freed -------- */

    free_metric_struct(NULL);
    write_fixture(path, sizeof(path), dir, "two_indexs.xml", XML_TWO_INDEXS);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL && app->nb_estimation_metrics == 1 &&
          app->estimation_metrics != NULL &&
          app->estimation_metrics->metric_id == 3 &&
          app->estimation_metrics->next == NULL &&
          app->estimation_metrics->quality_estimation_rules != NULL,
          "two <indexs>: the first quality metric is kept with its rules");
    free_application_quality_estimation_struct(app);

    /* --- #469: a quality metric without usable rules ------------------ */
    {
        double v = 50.0;
        double * const one[] = { &v };

        /* Positive control: a complete parsed model gets a context. */
        write_fixture(path, sizeof(path), dir, "quality_id_7.xml", XML_QUALITY_ID_7);
        application_quality_estimation_internal_t *ctx =
            init_application_quality_estimation_context(
                application_quality_estimation_xml_parser(path), one, 1);
        CHECK(ctx != NULL, "context helper accepts a parsed model with rules");
        if (ctx) {
            double qi = estimate_quality_index(ctx);
            CHECK(qi >= 1.0 && qi <= 5.0,
                  "parsed model estimates a quality index inside its range");
            free_application_quality_estimation_context(ctx);
        }

        write_fixture(path, sizeof(path), dir, "no_rules.xml", XML_NO_RULES);
        app = application_quality_estimation_xml_parser(path);
        CHECK(app != NULL && app->estimation_metrics != NULL &&
              app->estimation_metrics->quality_estimation_rules == NULL,
              "model without <rules> parses, quality metric has no rules");
        CHECK(init_application_quality_estimation_context(app, one, 1) == NULL,
              "context helper refuses a model without <rules>");

        write_fixture(path, sizeof(path), dir, "rules_before_kpis.xml", XML_RULES_BEFORE_KPIS);
        app = application_quality_estimation_xml_parser(path);
        CHECK(app != NULL && app->estimation_metrics != NULL &&
              app->estimation_metrics->quality_estimation_rules != NULL &&
              app->estimation_metrics->quality_estimation_rules->rules != NULL &&
              app->estimation_metrics->quality_estimation_rules->rules->metric_elements == NULL,
              "<rules> before <kpis>: the rule has no elements");
        CHECK(init_application_quality_estimation_context(app, one, 1) == NULL,
              "context helper refuses <rules> placed before <kpis>");

        /* A rule element without a metric: refused by the helper ... */
        write_fixture(path, sizeof(path), dir, "quality_id_7.xml", XML_QUALITY_ID_7);
        app = application_quality_estimation_xml_parser(path);
        CHECK(app != NULL && app->estimation_metrics != NULL &&
              app->estimation_metrics->quality_estimation_rules != NULL &&
              app->estimation_metrics->quality_estimation_rules->rules != NULL &&
              app->estimation_metrics->quality_estimation_rules->rules->metric_elements != NULL,
              "parsed model has a rule with an input element");
        if (app && app->estimation_metrics && app->estimation_metrics->quality_estimation_rules
                && app->estimation_metrics->quality_estimation_rules->rules
                && app->estimation_metrics->quality_estimation_rules->rules->metric_elements) {
            app->estimation_metrics->quality_estimation_rules->rules->metric_elements->metric = NULL;
            CHECK(init_application_quality_estimation_context(app, one, 1) == NULL,
                  "context helper refuses a rule element without a metric");
        } else {
            free_application_quality_estimation_struct(app);
        }

        /* ... and skipped by the estimation path, which also tolerates a
         * rule without elements and a quality metric without rules (the
         * unvalidated init_new_internal_* context). */
        static const char * const unusable[] = {
            "quality_id_7.xml", "rules_before_kpis.xml", "no_rules.xml"
        };
        for (size_t k = 0; k < sizeof(unusable) / sizeof(unusable[0]); k++) {
            snprintf(path, sizeof(path), "%s/%s", dir, unusable[k]);
            app = application_quality_estimation_xml_parser(path);
            if (app == NULL || app->estimation_metrics == NULL) {
                CHECK(0, "unusable-rules fixture parses");
                free_application_quality_estimation_struct(app);
                continue;
            }
            if (k == 0 && app->estimation_metrics->quality_estimation_rules
                    && app->estimation_metrics->quality_estimation_rules->rules
                    && app->estimation_metrics->quality_estimation_rules->rules->metric_elements)
                app->estimation_metrics->quality_estimation_rules->rules->metric_elements->metric = NULL;
            ctx = init_new_internal_application_quality_estimation_struct(app);
            if (ctx) {
                ctx->metric_values[0] = &v;
                CHECK(estimate_quality_index(ctx) == 0.5,
                      "estimation skips rules it cannot evaluate (no crash)");
                free_internal_application_quality_estimation_struct(ctx);
            }
            free_application_quality_estimation_struct(app);
        }
    }

    /* Heap balance for the models above. libxml2 and the allocator settle
     * over the first cycles (a few hundred bytes in total), so the check
     * allows 16 B per cycle on average: one leaked rules set is several
     * times that on every cycle. */
#if !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    if (mallinfo2().uordblks != 0) {
        static const char * const names[] = {
            "two_rules.xml", "quality_id_7.xml", "rules_no_index.xml",
            "two_indexs.xml", "no_rules.xml", "rules_before_kpis.xml"
        };
        size_t before = 0;
        for (int i = 0; i < 65; i++) {
            if (i == 1)
                before = mallinfo2().uordblks;   /* after one warm-up cycle */
            for (size_t k = 0; k < sizeof(names) / sizeof(names[0]); k++) {
                snprintf(path, sizeof(path), "%s/%s", dir, names[k]);
                free_application_quality_estimation_struct(
                    application_quality_estimation_xml_parser(path));
            }
        }
        size_t after = mallinfo2().uordblks;
        CHECK(after <= before + 64 * 16,
              "repeated parse+free of the #466/#468/#469 models does not grow the heap");
    }
#endif

    printf("----------------------------------------\n");
    printf("%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures) {
        printf("not ok - fuzz-engine regression test FAILED\n");
        return 1;
    }
    printf("ok - fuzz-engine regression test PASSED\n");
    return 0;
}
