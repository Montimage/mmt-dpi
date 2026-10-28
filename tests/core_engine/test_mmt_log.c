/*
 * test_mmt_log.c — unit tests of the SDK logger (issue #545,
 * src/mmt_core/src/mmt_log.c, contract in private_include/mmt_log.h).
 *
 * Checks: off by default with every event still counted and the arguments
 * of a disabled call never evaluated; MMT_DPI_LOG_LEVEL parsing (in forked
 * children, since the threshold is read once); mmt_log_set_level();
 * stderr-only output and the line format; the per-site rate limit and its
 * "suppressed" report; truncation; and exact counter accounting under
 * concurrent writers (the suite's SANITIZE=tsan mode runs this under TSan).
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "mmt_log.h"

static int failures = 0;
static int checks = 0;

#define CHECK(desc, cond) do {                                          \
        checks++;                                                       \
        if (cond) { printf("  ok   %s\n", desc); }                      \
        else      { printf("  FAIL %s\n", desc); failures++; }          \
    } while (0)

/* ---- capture of fds 1 and 2 into temporary files ----------------------- */

typedef struct {
    int saved_out, saved_err;
    char out_path[64], err_path[64];
} capture_t;

static void capture_begin(capture_t *c) {
    fflush(stdout);
    fflush(stderr);
    snprintf(c->out_path, sizeof(c->out_path), "/tmp/mmt_log_out.XXXXXX");
    snprintf(c->err_path, sizeof(c->err_path), "/tmp/mmt_log_err.XXXXXX");
    int fo = mkstemp(c->out_path);
    int fe = mkstemp(c->err_path);
    if (fo < 0 || fe < 0) {
        perror("mkstemp");
        exit(2);
    }
    c->saved_out = dup(1);
    c->saved_err = dup(2);
    dup2(fo, 1);
    dup2(fe, 2);
    close(fo);
    close(fe);
}

/* Restores fds 1 and 2 and reads both captures (caller frees). */
static void capture_end(capture_t *c, char **out, char **err) {
    char **dst[2] = { out, err };
    const char *paths[2] = { c->out_path, c->err_path };
    fflush(stdout);
    fflush(stderr);
    dup2(c->saved_out, 1);
    dup2(c->saved_err, 2);
    close(c->saved_out);
    close(c->saved_err);
    for (int i = 0; i < 2; i++) {
        FILE *f = fopen(paths[i], "r");
        size_t cap = 1 << 16, len = 0;
        char *buf = calloc(1, cap + 1);
        if (f != NULL && buf != NULL) {
            len = fread(buf, 1, cap, f);
            buf[len] = '\0';
        }
        if (f != NULL)
            fclose(f);
        unlink(paths[i]);
        *dst[i] = buf;
    }
}

static int count_lines(const char *s) {
    int n = 0;
    for (; s != NULL && *s; s++)
        n += (*s == '\n');
    return n;
}

static int side_effects = 0;
static int bump(void) { return ++side_effects; }

static uint64_t coarse_now(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_COARSE
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (uint64_t) ts.tv_sec;
}

/* ---- tests ------------------------------------------------------------ */

static void test_off_by_default(void) {
    printf("off by default:\n");
    mmt_log_stats_t before, after;
    mmt_log_get_stats(&before);
    capture_t c;
    char *out, *err;
    CHECK("threshold starts at OFF", mmt_log_get_level() == MMT_LOG_LEVEL_OFF);
    capture_begin(&c);
    mmt_log_error("error %d", bump());
    mmt_log_warn("warn %d", bump());
    mmt_log_info("info %d", bump());
    mmt_log_debug("debug %d", bump());
    capture_end(&c, &out, &err);
    mmt_log_get_stats(&after);
    CHECK("nothing written to stdout", out[0] == '\0');
    CHECK("nothing written to stderr", err[0] == '\0');
    CHECK("arguments of disabled calls are not evaluated", side_effects == 0);
    CHECK("disabled error/warn/info events are still counted",
          after.events[MMT_LOG_LEVEL_ERROR] == before.events[MMT_LOG_LEVEL_ERROR] + 1
          && after.events[MMT_LOG_LEVEL_WARN] == before.events[MMT_LOG_LEVEL_WARN] + 1
          && after.events[MMT_LOG_LEVEL_INFO] == before.events[MMT_LOG_LEVEL_INFO] + 1);
#ifndef DEBUG
    CHECK("mmt_log_debug compiles out without DEBUG",
          after.events[MMT_LOG_LEVEL_DEBUG] == before.events[MMT_LOG_LEVEL_DEBUG]);
#endif
    CHECK("no line counted as written", after.written == before.written);
    free(out);
    free(err);
}

/* The child reports the level the environment value selects; the parent
 * must not have used the logger yet (a fork inherits the threshold). */
static int level_from_env(const char *value) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        if (value != NULL)
            setenv("MMT_DPI_LOG_LEVEL", value, 1);
        else
            unsetenv("MMT_DPI_LOG_LEVEL");
        _exit(mmt_log_get_level() + 10);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -100;
    return WEXITSTATUS(status) - 10;
}

static void test_env_parsing(void) {
    printf("MMT_DPI_LOG_LEVEL parsing:\n");
    CHECK("unset -> off", level_from_env(NULL) == MMT_LOG_LEVEL_OFF);
    CHECK("\"error\" -> error", level_from_env("error") == MMT_LOG_LEVEL_ERROR);
    CHECK("\"WARN\" -> warn (case-insensitive)", level_from_env("WARN") == MMT_LOG_LEVEL_WARN);
    CHECK("\"warning\" -> warn", level_from_env("warning") == MMT_LOG_LEVEL_WARN);
    CHECK("\"3\" -> info", level_from_env("3") == MMT_LOG_LEVEL_INFO);
    CHECK("\"debug\" -> debug", level_from_env("debug") == MMT_LOG_LEVEL_DEBUG);
    CHECK("\"off\" -> off", level_from_env("off") == MMT_LOG_LEVEL_OFF);
    CHECK("\"loud\" -> default (off)", level_from_env("loud") == MMT_LOG_LEVEL_OFF);
    CHECK("\"5\" -> default (off)", level_from_env("5") == MMT_LOG_LEVEL_OFF);
    CHECK("\"\" -> default (off)", level_from_env("") == MMT_LOG_LEVEL_OFF);
}

static void test_set_level(void) {
    printf("mmt_log_set_level:\n");
    CHECK("returns the previous level", mmt_log_set_level(MMT_LOG_LEVEL_WARN) == MMT_LOG_LEVEL_OFF);
    CHECK("level is applied", mmt_log_get_level() == MMT_LOG_LEVEL_WARN);
    CHECK("out-of-range level refused", mmt_log_set_level(MMT_LOG_LEVEL_DEBUG + 1) == -1);
    CHECK("negative level refused", mmt_log_set_level(-1) == -1);
    CHECK("refused level leaves the threshold", mmt_log_get_level() == MMT_LOG_LEVEL_WARN);
    mmt_log_set_level(MMT_LOG_LEVEL_OFF);
}

static void test_output_format(void) {
    printf("stderr output:\n");
    mmt_log_set_level(MMT_LOG_LEVEL_WARN);
    mmt_log_stats_t before, after;
    mmt_log_get_stats(&before);
    capture_t c;
    char *out, *err;
    capture_begin(&c);
    mmt_log_warn("hello %s\n", "world"); int warn_line = __LINE__;
    mmt_log_error("boom %d", 7); int err_line = __LINE__;
    mmt_log_info("below the threshold %d", bump());
    capture_end(&c, &out, &err);
    mmt_log_get_stats(&after);
    char want_w[128], want_e[128];
    snprintf(want_w, sizeof(want_w), "[mmt-dpi][W] test_mmt_log.c:%d: hello world\n", warn_line);
    snprintf(want_e, sizeof(want_e), "[mmt-dpi][E] test_mmt_log.c:%d: boom 7\n", err_line);
    CHECK("stdout untouched", out[0] == '\0');
    CHECK("warn line: tag, basename:line, one trailing newline", strstr(err, want_w) != NULL);
    CHECK("error line written", strstr(err, want_e) != NULL);
    CHECK("exactly two lines (info filtered)", count_lines(err) == 2);
    CHECK("filtered call's arguments not evaluated", side_effects == 0);
    CHECK("two lines counted as written", after.written == before.written + 2);
    free(out);
    free(err);

    /* A message longer than the line buffer is truncated, still terminated. */
    char big[2048];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    capture_begin(&c);
    mmt_log_warn("%s", big);
    capture_end(&c, &out, &err);
    size_t len = strlen(err);
    CHECK("truncated line is one newline-terminated line",
          count_lines(err) == 1 && len > 0 && len < sizeof(big) && err[len - 1] == '\n');
    free(out);
    free(err);
    mmt_log_set_level(MMT_LOG_LEVEL_OFF);
}

static void burst_from_one_site(int n) {
    for (int i = 0; i < n; i++)
        mmt_log_warn("flood %d", i);
}

static void test_rate_limit(void) {
    printf("per-site rate limit:\n");
    mmt_log_set_level(MMT_LOG_LEVEL_WARN);
    const int calls = 3 * MMT_LOG_SITE_BURST;
    mmt_log_stats_t before, after;
    capture_t c;
    char *out = NULL, *err = NULL;
    /* Retry until the burst falls inside one clock second. */
    for (int attempt = 0; attempt < 5; attempt++) {
        free(out);
        free(err);
        mmt_log_get_stats(&before);
        uint64_t t0 = coarse_now();
        capture_begin(&c);
        burst_from_one_site(calls);
        capture_end(&c, &out, &err);
        mmt_log_get_stats(&after);
        if (coarse_now() == t0)
            break;
        sleep(1); /* the next attempt starts on a fresh window */
    }
    CHECK("site writes at most MMT_LOG_SITE_BURST lines per second",
          count_lines(err) == MMT_LOG_SITE_BURST);
    CHECK("the rest are counted as rate-limited",
          after.rate_limited - before.rate_limited == (uint64_t) (calls - MMT_LOG_SITE_BURST));
    CHECK("every call counted as an event",
          after.events[MMT_LOG_LEVEL_WARN] - before.events[MMT_LOG_LEVEL_WARN] == (uint64_t) calls);
    free(out);
    free(err);

    sleep(2); /* a new window */
    capture_begin(&c);
    burst_from_one_site(1);
    capture_end(&c, &out, &err);
    char want[96];
    snprintf(want, sizeof(want), "(%d earlier line(s) suppressed)\n", calls - MMT_LOG_SITE_BURST);
    CHECK("next window's line reports the suppressed count", strstr(err, want) != NULL);
    free(out);
    free(err);

    /* Another site is not starved by the flooded one. */
    capture_begin(&c);
    burst_from_one_site(calls);
    mmt_log_warn("other site");
    capture_end(&c, &out, &err);
    CHECK("an independent site still writes", strstr(err, "other site\n") != NULL);
    free(out);
    free(err);
    mmt_log_set_level(MMT_LOG_LEVEL_OFF);
}

#define MT_THREADS 8
#define MT_CALLS   20000

static void *mt_writer(void *arg) {
    (void) arg;
    for (int i = 0; i < MT_CALLS; i++) {
        mmt_log_warn("thread flood %d", i);
        mmt_log_error("thread error %d", i);
    }
    return NULL;
}

static void *mt_toggler(void *arg) {
    volatile int *stop = arg;
    while (!__atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
        mmt_log_set_level(MMT_LOG_LEVEL_WARN);
        mmt_log_set_level(MMT_LOG_LEVEL_ERROR);
    }
    return NULL;
}

static void test_concurrency(void) {
    printf("concurrent writers:\n");
    mmt_log_set_level(MMT_LOG_LEVEL_WARN);
    mmt_log_stats_t before, after;
    mmt_log_get_stats(&before);
    capture_t c;
    char *out, *err;
    pthread_t th[MT_THREADS], toggler;
    int stop = 0;
    capture_begin(&c);
    pthread_create(&toggler, NULL, mt_toggler, &stop);
    for (int i = 0; i < MT_THREADS; i++)
        pthread_create(&th[i], NULL, mt_writer, NULL);
    for (int i = 0; i < MT_THREADS; i++)
        pthread_join(th[i], NULL);
    __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
    pthread_join(toggler, NULL);
    capture_end(&c, &out, &err);
    mmt_log_get_stats(&after);
    const uint64_t per_level = (uint64_t) MT_THREADS * MT_CALLS;
    uint64_t written = after.written - before.written;
    uint64_t limited = after.rate_limited - before.rate_limited;
    uint64_t errors = after.write_errors - before.write_errors;
    CHECK("every warn event counted exactly",
          after.events[MMT_LOG_LEVEL_WARN] - before.events[MMT_LOG_LEVEL_WARN] == per_level);
    CHECK("every error event counted exactly",
          after.events[MMT_LOG_LEVEL_ERROR] - before.events[MMT_LOG_LEVEL_ERROR] == per_level);
    CHECK("written + rate-limited never exceeds the events",
          written + limited + errors <= 2 * per_level);
    CHECK("the flood is rate-limited", limited > 0);
    CHECK("written lines match the counter", (uint64_t) count_lines(err) == written);
    CHECK("no write errors", errors == 0);
    CHECK("stdout untouched", out[0] == '\0');
    free(out);
    free(err);
    mmt_log_set_level(MMT_LOG_LEVEL_OFF);
}

int main(void) {
    /* The threshold is read from the environment once: start from default. */
    unsetenv("MMT_DPI_LOG_LEVEL");
    /* First: each child must read the environment before the parent's
     * threshold is initialised, since a fork inherits it. */
    test_env_parsing();
    test_off_by_default();
    test_set_level();
    test_output_format();
    test_rate_limit();
    test_concurrency();
    printf("\n%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
