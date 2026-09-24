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

#include "fuzz/mmt_quality_estimation_defs.h"
#include "fuzz/mmt_quality_estimation_utilities.h"

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

    /* Self-closing elements: children == NULL; pre-fix dereferenced it. */
    write_fixture(path, sizeof(path), dir, "empty_elem.xml", XML_EMPTY_ELEMENTS);
    app = application_quality_estimation_xml_parser(path);
    CHECK(app != NULL, "model with empty elements parses (NULL-safe)");

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

    printf("----------------------------------------\n");
    printf("%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures) {
        printf("not ok - fuzz-engine regression test FAILED\n");
        return 1;
    }
    printf("ok - fuzz-engine regression test PASSED\n");
    return 0;
}
