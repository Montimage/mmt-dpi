/*
 * test_fi_plugin_exit.c — the mobile and business-app init_proto() return 0
 * on a protocol-init failure instead of calling exit() (issues #503, #674).
 *
 * Links the real src/mmt_mobile/mmt_mobile_plugin.c and
 * src/mmt_business_app/mmt_business_app.c (their init_proto/cleanup_proto
 * renamed by run_tests.sh so both fit one binary) against stub protocol
 * initializers, then makes each stub fail in turn. Each entry point must
 * return 0 and name the failing protocol on stderr; an atexit() guard turns
 * an exit() from inside the plugin into a test failure, since exit(0) would
 * otherwise look like success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int mobile_init_proto(void);
int ba_init_proto(void);

/* The stub protocol initializer named here fails; every other succeeds. */
static const char *g_failing = "";
static int g_finished;

static int stub(const char *name) { return strcmp(g_failing, name) != 0; }
int init_proto_diameter_struct() { return stub("PROTO_DIAMETER"); }
int init_proto_gtpv2_struct()    { return stub("PROTO_GTPV2"); }
int init_proto_ngap_struct()     { return stub("PROTO_NGAP"); }
int init_proto_nas_5g_struct()   { return stub("PROTO_NAS5G"); }
int init_proto_s1ap()            { return stub("PROTO_S1AP"); }
int init_proto_ips_data()        { return stub("PROTO_IPS_DATA"); }

static void exit_guard(void)
{
    if (!g_finished) {
        fprintf(stdout, "fi-plugin-exit: a plugin init_proto() called exit()\n");
        fflush(stdout);
        _exit(1);
    }
}

/* Runs entry() with protocol `failing` broken; checks the return value and
 * that the captured stderr names the protocol. */
static int check(const char *plugin, int (*entry)(void), const char *failing, int want)
{
    char log[512] = "";
    FILE *cap = tmpfile();
    if (cap == NULL) { perror("tmpfile"); return 1; }
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    dup2(fileno(cap), STDERR_FILENO);

    g_failing = failing;
    const int got = entry();

    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    rewind(cap);
    size_t n = fread(log, 1, sizeof(log) - 1, cap);
    log[n] = '\0';
    fclose(cap);

    int bad = got != want;
    if (want == 0 && strstr(log, failing) == NULL)
        bad = 1;
    printf("    %s %s init_proto() with %s failing -> %d (want %d)%s\n",
           bad ? "✗" : "✓", plugin, *failing ? failing : "nothing", got, want,
           (want == 0 && strstr(log, failing) == NULL) ? ", protocol not logged" : "");
    return bad;
}

int main(void)
{
    static const char *mobile[] = { "PROTO_DIAMETER", "PROTO_GTPV2", "PROTO_NGAP", "PROTO_NAS5G" };
    int failures = 0;
    atexit(exit_guard);

    for (size_t i = 0; i < sizeof(mobile) / sizeof(mobile[0]); i++)
        failures += check("mobile", mobile_init_proto, mobile[i], 0);
    failures += check("mobile", mobile_init_proto, "", 1);
    failures += check("business-app", ba_init_proto, "PROTO_IPS_DATA", 0);
    failures += check("business-app", ba_init_proto, "", 1);

    g_finished = 1;
    return failures ? 1 : 0;
}
