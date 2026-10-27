/*
 * oom_init_exit_sweep — executed "no exit() on the init path" gate for the
 * B5 OOM hardening (issue #16), replacing the source-text scan issue #526
 * (F-TEST-016) named.
 *
 * Runs under LD_PRELOAD of tests/fault_injection/libfi_alloc.so (built from
 * fi_alloc.c with -DFI_INTERPOSE), which counts every malloc/calloc/realloc
 * of the process and its dlopen'd plugins and can fail the Nth one.
 *
 *   1. A clean child runs init_extraction() with fi_begin(0) (count, never
 *      fail) and an fi_set_observer() hook that records the call site of
 *      every allocation — the return addresses of its innermost stack
 *      frames (backtrace). The first allocation index of each distinct call
 *      site is its representative.
 *   2. For every representative N (or every N in 1..count with --all), a
 *      forked child arms fi_begin(N) and calls init_extraction(), so that
 *      allocation of the init path returns NULL. Children run in parallel
 *      (one per online CPU, at most 16). Failing each allocation index
 *      (--all: ~22k inits, about a minute on 16 cores) is too slow for a
 *      per-push gate on a 4-core runner; failing each distinct call site
 *      once reaches every allocation statement on the init path, including
 *      each loop's, at the first iteration.
 *   3. This binary (linked -rdynamic) exports exit(), _exit() and _Exit(),
 *      which therefore win over libc's for every call from the SDK and its
 *      plugins. Inside a sweep child they record which DSO called them
 *      (dladdr on the return address) through a pipe and end the child
 *      with SYS_exit_group; outside a child they forward to libc.
 *
 * Child outcomes:
 *   returned      init_extraction() returned (true or false) — the contract.
 *   gated exit    exit()/_exit()/_Exit() called from libmmt_core or
 *                 libmmt_tcpip — the scope of the old static guard
 *                 (packet_registry.c init_extraction, configured_protocols.c).
 *                 FAILS the gate, as does a caller dladdr cannot resolve.
 *   other exit    the same from any other DSO (the mobile and business-app
 *                 plugins' init_proto paths call exit(0) when a protocol
 *                 fails to register — src/mmt_mobile/mmt_mobile_plugin.c,
 *                 src/mmt_business_app/mmt_business_app.c). Reported with
 *                 per-DSO counts; out of this gate's scope (issue #526).
 *   untrapped     a non-zero exit status the trap never saw (e.g. ld.so
 *                 giving up inside dlopen) and signals (unchecked OOM
 *                 dereferences deeper in init, tests/fault_injection/
 *                 test_fi_engine.c:20-26). Reported with counts, not fatal.
 *
 * Usage: oom_init_exit_sweep [--all]   (run under LD_PRELOAD=libfi_alloc.so)
 * Exit: 0 = no gated exit; 1 = a gated or unresolvable exit was reached;
 *       2 = setup failure (interposer inert, clean init failed, fork error,
 *       an armed allocation that never came).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "mmt_core.h"
#include "fi_alloc.h"

#define TRAP_STATUS   86    /* child status after the trap reported */
#define NOT_INJECTED  87    /* child status: the armed allocation never came */
#define CHILD_TIMEOUT 30    /* seconds; SIGALRM counts as a signal outcome */
#define MAX_WORKERS   16

/* Write end of the report pipe in a sweep child; -1 in the parent. */
static int g_trap_fd = -1;

static __attribute__((noreturn)) void child_exit_group(int status) {
    syscall(SYS_exit_group, status);
    __builtin_unreachable();
}

static __attribute__((noreturn)) void trap(const char *how, int status, void *ra) {
    fi_end();                     /* disarm first: nothing below may fail */
    Dl_info di;
    const char *dso = "?";
    if (dladdr((char *) ra - 1, &di) != 0 && di.dli_fname != NULL && di.dli_fname[0] != '\0') {
        const char *slash = strrchr(di.dli_fname, '/');
        dso = slash ? slash + 1 : di.dli_fname;
    }
    char line[512];
    int n = snprintf(line, sizeof(line), "%s %d %s\n", how, status, dso);
    if (n > 0) {
        ssize_t w = write(g_trap_fd, line, (size_t) n < sizeof(line) ? (size_t) n : sizeof(line) - 1);
        (void) w;
    }
    child_exit_group(TRAP_STATUS);
}

void exit(int status) {
    if (g_trap_fd >= 0) trap("exit", status, __builtin_return_address(0));
    void (*real)(int) = (void (*)(int)) dlsym(RTLD_NEXT, "exit");
    if (real != NULL) real(status);
    child_exit_group(status);
}

void _exit(int status) {
    if (g_trap_fd >= 0) trap("_exit", status, __builtin_return_address(0));
    child_exit_group(status);
}

void _Exit(int status) {
    if (g_trap_fd >= 0) trap("_Exit", status, __builtin_return_address(0));
    child_exit_group(status);
}

/* ---- call-site recording (measuring child only) ------------------------- */

#define SITE_FRAMES 8              /* innermost frames hashed into a site */
#define SITE_SLOTS  (1u << 16)     /* open-addressed set of site hashes */
#define MAX_ALLOCS  (1u << 20)

static uint64_t g_site_set[SITE_SLOTS];
static uint64_t g_reps[MAX_ALLOCS];   /* first allocation index per site */
static uint64_t g_nreps;

/* Hashes the return addresses of the innermost frames. Addresses are only
 * compared within the measuring child, so no symbolization is needed. */
static void observe_site(uint64_t index) {
    void *bt[SITE_FRAMES];
    int n = backtrace(bt, SITE_FRAMES);
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) {
        h ^= (uint64_t) (uintptr_t) bt[i];
        h *= 1099511628211ULL;
    }
    if (h == 0) h = 1;
    for (uint32_t k = 0; k < SITE_SLOTS; k++) {
        uint64_t *slot = &g_site_set[(h + k) & (SITE_SLOTS - 1)];
        if (*slot == h) return;                    /* site already seen */
        if (*slot == 0) {
            *slot = h;
            if (g_nreps < MAX_ALLOCS) g_reps[g_nreps++] = index;
            return;
        }
    }
    if (g_nreps < MAX_ALLOCS) g_reps[g_nreps++] = index;   /* set full: keep it */
}

/* ---- child ---------------------------------------------------------------- */

/* Runs init_extraction() with the fail_at-th allocation failing (0 = none);
 * `report` gets the trap line, or "count <allocs> <rc>" for a measuring run. */
static __attribute__((noreturn)) void child(uint64_t fail_at, int report, int measure) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {           /* init failures log to stderr: keep it quiet */
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
    }
    alarm(CHILD_TIMEOUT);
    /* Every child loads the unwinder before counting starts, so the
     * measuring child's allocation indices match the sweep children's. */
    void *warm[2];
    backtrace(warm, 2);
    if (measure) fi_set_observer(observe_site);
    g_trap_fd = report;
    fi_begin(fail_at);
    int rc = init_extraction() ? 1 : 0;
    uint64_t n = fi_end();
    g_trap_fd = -1;
    /* The fail_at-th allocation must have happened: the allocation sequence
     * is deterministic, so a miss means the indices no longer line up. */
    if (fail_at != 0 && fi_failed_allocs() == 0) child_exit_group(NOT_INJECTED);
    if (measure) {
        fi_set_observer(NULL);
        FILE *out = fdopen(report, "w");
        if (out != NULL) {
            fprintf(out, "count %llu %d %llu\n", (unsigned long long) n, rc,
                    (unsigned long long) g_nreps);
            for (uint64_t i = 0; i < g_nreps; i++)
                fprintf(out, "%llu\n", (unsigned long long) g_reps[i]);
            fflush(out);
        }
    }
    child_exit_group(rc ? 0 : 1);
}

typedef struct {
    pid_t    pid;
    uint64_t n;
    int      fd;
} running_t;

static pid_t spawn(uint64_t fail_at, int measure, int *read_fd) {
    int p[2];
    if (pipe(p) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) {
        close(p[0]);
        child(fail_at, p[1], measure);
    }
    close(p[1]);
    *read_fd = p[0];
    return pid;
}

/* Reads the whole pipe into a growing heap buffer (the measuring report). */
static char *read_all(int fd) {
    size_t cap = 1 << 16, off = 0;
    char *buf = malloc(cap);
    if (buf == NULL) return NULL;
    ssize_t r;
    for (;;) {
        if (off + 1 == cap) {
            char *g = realloc(buf, cap * 2);
            if (g == NULL) { free(buf); close(fd); return NULL; }
            buf = g; cap *= 2;
        }
        r = read(fd, buf + off, cap - 1 - off);
        if (r <= 0) break;
        off += (size_t) r;
    }
    buf[off] = '\0';
    close(fd);
    return buf;
}

static void read_report(int fd, char *buf, size_t cap) {
    size_t off = 0;
    ssize_t r;
    while (off + 1 < cap && (r = read(fd, buf + off, cap - 1 - off)) > 0) off += (size_t) r;
    buf[off] = '\0';
    close(fd);
}

/* ---- tallies ---------------------------------------------------------------- */

#define MAX_KINDS 32
typedef struct { char key[96]; uint64_t count; uint64_t first_n; } tally_t;
typedef struct { tally_t t[MAX_KINDS]; int len; } tallies_t;

static void tally(tallies_t *ts, const char *key, uint64_t n) {
    for (int i = 0; i < ts->len; i++) {
        if (strcmp(ts->t[i].key, key) == 0) {
            ts->t[i].count++;
            if (n < ts->t[i].first_n) ts->t[i].first_n = n;
            return;
        }
    }
    if (ts->len == MAX_KINDS) key = "(other)";
    for (int i = 0; i < ts->len; i++) {
        if (strcmp(ts->t[i].key, key) == 0) {
            ts->t[i].count++;
            if (n < ts->t[i].first_n) ts->t[i].first_n = n;
            return;
        }
    }
    tally_t *t = &ts->t[ts->len++];
    snprintf(t->key, sizeof(t->key), "%s", key);
    t->count = 1;
    t->first_n = n;
}

static void print_tallies(const char *title, const tallies_t *ts) {
    for (int i = 0; i < ts->len; i++)
        printf("    %-12s %-48s %8llu (first at N=%llu)\n", title, ts->t[i].key,
               (unsigned long long) ts->t[i].count, (unsigned long long) ts->t[i].first_n);
}

static int gated_dso(const char *dso) {
    return strncmp(dso, "libmmt_core.so", 14) == 0
        || strncmp(dso, "libmmt_tcpip.so", 15) == 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int all = argc > 1 && strcmp(argv[1], "--all") == 0;
    if (argc > 1 && !all) {
        fprintf(stderr, "usage: %s [--all]\n", argv[0]);
        return 2;
    }

    /* 1. clean measuring run: allocation count + one index per call site */
    int fd;
    pid_t pid = spawn(0, 1, &fd);
    if (pid < 0) { perror("fork"); return 2; }
    char *report = read_all(fd);
    int st = 0;
    waitpid(pid, &st, 0);
    unsigned long long count = 0, nsites = 0;
    int clean_rc = 0, consumed = 0;
    if (report == NULL || !WIFEXITED(st) || WEXITSTATUS(st) != 0
            || sscanf(report, "count %llu %d %llu%n", &count, &clean_rc, &nsites, &consumed) != 3
            || clean_rc != 1) {
        fprintf(stderr, "FAIL: clean init_extraction() did not complete (status 0x%x)\n", st);
        return 2;
    }
    if (count == 0) {
        fprintf(stderr, "FAIL: the allocation interposer is inert (0 allocations counted) — "
                "run under LD_PRELOAD=libfi_alloc.so on a non-sanitizer build\n");
        return 2;
    }
    uint64_t *targets = malloc(sizeof(uint64_t) * (all ? count : nsites));
    if (targets == NULL) { perror("malloc"); return 2; }
    uint64_t ntargets = 0;
    if (all) {
        for (uint64_t n = 1; n <= count; n++) targets[ntargets++] = n;
    } else {
        char *p = report + consumed;
        for (uint64_t i = 0; i < nsites; i++) {
            char *end;
            unsigned long long v = strtoull(p, &end, 10);
            if (end == p || v == 0 || v > count) {
                fprintf(stderr, "FAIL: malformed call-site report (entry %llu)\n",
                        (unsigned long long) i);
                return 2;
            }
            targets[ntargets++] = v;
            p = end;
        }
        if (ntargets == 0) {
            fprintf(stderr, "FAIL: no allocation call site recorded\n");
            return 2;
        }
    }
    free(report);

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int workers = cpus > 0 ? (int) cpus : 2;
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;
    printf("oom_init_exit_sweep: clean init_extraction() makes %llu allocations from %llu "
           "distinct call sites; failing %s (%llu runs, %d workers)\n",
           count, nsites, all ? "every allocation (--all)" : "the first allocation of each site",
           (unsigned long long) ntargets, workers);
    char buf[512];

    /* 2. sweep every allocation index */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    running_t run[MAX_WORKERS];
    int nrun = 0;
    uint64_t next = 0, done = 0;
    uint64_t returned_true = 0, returned_false = 0;
    tallies_t gated = {0}, other = {0}, untrapped = {0};
    uint64_t gated_total = 0, not_injected = 0;

    while (done < ntargets) {
        while (nrun < workers && next < ntargets) {
            pid_t c = spawn(targets[next], 0, &fd);
            if (c < 0) { perror("fork"); return 2; }
            run[nrun].pid = c; run[nrun].n = targets[next]; run[nrun].fd = fd;
            nrun++; next++;
        }
        int wst = 0;
        pid_t w = waitpid(-1, &wst, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            perror("waitpid");
            return 2;
        }
        int i = 0;
        while (i < nrun && run[i].pid != w) i++;
        if (i == nrun) continue;
        uint64_t n = run[i].n;
        read_report(run[i].fd, buf, sizeof(buf));
        run[i] = run[--nrun];
        done++;

        char how[16] = "", dso[256] = "";
        int status = 0;
        if (buf[0] != '\0' && sscanf(buf, "%15s %d %255s", how, &status, dso) == 3) {
            char key[96];
            snprintf(key, sizeof(key), "%s(%d) from %.60s", how, status, dso);
            if (strcmp(dso, "?") == 0 || gated_dso(dso)) {
                tally(&gated, key, n);
                gated_total++;
                if (gated_total <= 10)
                    fprintf(stderr, "FAIL N=%llu: %s on the init path\n",
                            (unsigned long long) n, key);
            } else {
                tally(&other, key, n);
            }
        } else if (WIFEXITED(wst) && WEXITSTATUS(wst) == NOT_INJECTED) {
            not_injected++;
        } else if (WIFEXITED(wst) && WEXITSTATUS(wst) == 0) {
            returned_true++;
        } else if (WIFEXITED(wst) && WEXITSTATUS(wst) == 1) {
            returned_false++;
        } else {
            char key[96];
            if (WIFSIGNALED(wst))
                snprintf(key, sizeof(key), "signal %d (%s)", WTERMSIG(wst), strsignal(WTERMSIG(wst)));
            else
                snprintf(key, sizeof(key), "untrapped exit status %d", WEXITSTATUS(wst));
            tally(&untrapped, key, n);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (double) (t1.tv_sec - t0.tv_sec) + (double) (t1.tv_nsec - t0.tv_nsec) / 1e9;

    uint64_t other_total = 0, untrapped_total = 0;
    for (int i = 0; i < other.len; i++) other_total += other.t[i].count;
    for (int i = 0; i < untrapped.len; i++) untrapped_total += untrapped.t[i].count;
    printf("  %llu runs in %.1f s: returned true %llu, returned false %llu, "
           "gated exit %llu, other-DSO exit %llu, untrapped %llu\n",
           (unsigned long long) ntargets, secs, (unsigned long long) returned_true, (unsigned long long) returned_false,
           (unsigned long long) gated_total, (unsigned long long) other_total,
           (unsigned long long) untrapped_total);
    print_tallies("GATED", &gated);
    print_tallies("other-DSO", &other);
    print_tallies("untrapped", &untrapped);
    if (other_total > 0)
        printf("  note: other-DSO exits are plugin init_proto exit(0) paths, outside this "
               "gate (libmmt_core/libmmt_tcpip) — see docs/DECISIONS.md (issue #526)\n");

    if (not_injected > 0) {
        fprintf(stderr, "FAIL: %llu run(s) never reached their armed allocation — the "
                "init allocation sequence is not deterministic, so the sweep proves "
                "nothing\n", (unsigned long long) not_injected);
        return 2;
    }
    if (gated_total > 0) {
        fprintf(stderr, "FAIL: %llu injected allocation failure(s) reached exit() from "
                "libmmt_core/libmmt_tcpip (or an unresolvable caller) on the init path\n",
                (unsigned long long) gated_total);
        return 1;
    }
    printf("PASS: no allocation failure during init_extraction() reaches exit() "
           "from libmmt_core or libmmt_tcpip\n");
    return 0;
}
