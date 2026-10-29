/*
 * test_simple_registration_api.c — the MMT_PROTO_SIMPLE rows of
 * proto_init_list.def register through the production path (issue #542,
 * F-CLEAN-012).
 *
 * 506 registration-only protocols used to be one 20-line proto_*.c stub
 * each: init_protocol_struct_for_registration(PROTO_X, PROTO_X_ALIAS) then
 * register_protocol(). They are now MMT_PROTO_SIMPLE(id, alias, name) rows
 * that init_tcpip_plugin() registers through one generic helper. This test
 * expands the same list in its own translation unit, loads the plugins with
 * init_extraction() and checks, for every row, that the protocol is
 * registered under its id and resolves both ways by its alias — the
 * observable result each deleted stub produced. A row whose registration is
 * skipped, swapped or given the wrong alias fails here.
 */
#include <stdio.h>
#include <string.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            printf("  FAIL: ");                                      \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
            g_failures++;                                            \
        }                                                            \
    } while (0)

typedef struct {
    uint32_t    id;
    const char *alias;
    const char *name;
    const char *id_token;
} simple_row_t;

/* The rows init_tcpip_plugin() registers through mmt_register_simple_protocol(). */
static const simple_row_t simple_rows[] = {
#define MMT_PROTO_INIT(init_fn, display_name)
#define MMT_PROTO_SIMPLE(proto_id, proto_alias, display_name) \
    { proto_id, proto_alias, display_name, #proto_id },
#include "proto_init_list.def"
#undef MMT_PROTO_SIMPLE
#undef MMT_PROTO_INIT
};

#define N_SIMPLE (sizeof(simple_rows) / sizeof(simple_rows[0]))

int main(void) {
    printf("=== MMT_PROTO_SIMPLE registration test (issue #542) ===\n");
    printf("  %zu MMT_PROTO_SIMPLE rows\n", N_SIMPLE);

    /* The 506 converted stubs: a shrinking list means rows were dropped. */
    CHECK(N_SIMPLE >= 506, "expected >= 506 MMT_PROTO_SIMPLE rows, got %zu",
          N_SIMPLE);

    /* Static row sanity: each id and alias is used by one row only (a
     * duplicate id would make the second registration fail at init). */
    for (size_t i = 0; i < N_SIMPLE; i++) {
        CHECK(simple_rows[i].alias != NULL && simple_rows[i].alias[0] != '\0',
              "%s: empty alias", simple_rows[i].id_token);
        CHECK(simple_rows[i].name != NULL && simple_rows[i].name[0] != '\0',
              "%s: empty display name", simple_rows[i].id_token);
        for (size_t j = i + 1; j < N_SIMPLE; j++) {
            CHECK(simple_rows[i].id != simple_rows[j].id,
                  "%s and %s share id %u", simple_rows[i].id_token,
                  simple_rows[j].id_token, (unsigned) simple_rows[i].id);
            CHECK(strcmp(simple_rows[i].alias, simple_rows[j].alias) != 0,
                  "%s and %s share alias \"%s\"", simple_rows[i].id_token,
                  simple_rows[j].id_token, simple_rows[i].alias);
        }
    }

    if (!init_extraction()) {
        printf("  FAIL: init_extraction() failed — init_tcpip_plugin() "
               "refused a row\n");
        return 1;
    }

    for (size_t i = 0; i < N_SIMPLE; i++) {
        const simple_row_t *r = &simple_rows[i];
        CHECK(is_registered_protocol(r->id), "%s (%u) is not registered",
              r->id_token, (unsigned) r->id);
        const char *name = get_protocol_name_by_id(r->id);
        CHECK(name != NULL && strcmp(name, r->alias) == 0,
              "%s: registered as \"%s\", expected alias \"%s\"", r->id_token,
              name != NULL ? name : "(null)", r->alias);
        CHECK(get_protocol_id_by_name(r->alias) == r->id,
              "alias \"%s\" resolves to %u, expected %s (%u)", r->alias,
              (unsigned) get_protocol_id_by_name(r->alias), r->id_token,
              (unsigned) r->id);
    }

    close_extraction();

    printf("  %d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("✗ MMT_PROTO_SIMPLE registration test FAILED\n");
        return 1;
    }
    printf("✓ every MMT_PROTO_SIMPLE row registers under its id and alias\n");
    return 0;
}
