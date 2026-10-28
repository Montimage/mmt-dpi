/*
 * mmt_log.c — the SDK's internal logger (issue #545). Contract: mmt_log.h.
 *
 * All shared state is plain integers updated with GCC __atomic builtins, so
 * concurrent packet-processing threads never race (TSan-clean) and the
 * disabled path costs one atomic increment and one atomic load.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "mmt_log.h"

#define MMT_LOG_UNSET (-1)
#define MMT_LOG_MSG_MAX 512
#define MMT_LOG_LINE_MAX (MMT_LOG_MSG_MAX + 160)

#ifdef DEBUG
#define MMT_LOG_DEFAULT_LEVEL MMT_LOG_LEVEL_DEBUG /* make SHOWLOG=1 */
#else
#define MMT_LOG_DEFAULT_LEVEL MMT_LOG_LEVEL_OFF
#endif

static int mmt_log_threshold = MMT_LOG_UNSET;
static uint64_t mmt_log_events[MMT_LOG_LEVEL_COUNT];
static uint64_t mmt_log_written;
static uint64_t mmt_log_rate_limited;
static uint64_t mmt_log_write_errors;

static const char mmt_log_tag[MMT_LOG_LEVEL_COUNT] = { '-', 'E', 'W', 'I', 'D' };

static int mmt_log_valid(int level) {
    return level >= MMT_LOG_LEVEL_OFF && level <= MMT_LOG_LEVEL_DEBUG;
}

/* off|error|warn|warning|info|debug, or a single digit 0-4; -1 otherwise. */
static int mmt_log_parse_level(const char *s) {
    static const char *const names[MMT_LOG_LEVEL_COUNT] = {
        "off", "error", "warn", "info", "debug"
    };
    if (s == NULL || *s == '\0')
        return -1;
    if (s[0] >= '0' && s[0] <= '4' && s[1] == '\0')
        return s[0] - '0';
    if (strcasecmp(s, "warning") == 0)
        return MMT_LOG_LEVEL_WARN;
    for (int i = 0; i < MMT_LOG_LEVEL_COUNT; i++)
        if (strcasecmp(s, names[i]) == 0)
            return i;
    return -1;
}

/* The threshold, initialised once from MMT_DPI_LOG_LEVEL on first use. */
static int mmt_log_threshold_get(void) {
    int t = __atomic_load_n(&mmt_log_threshold, __ATOMIC_ACQUIRE);
    if (t != MMT_LOG_UNSET)
        return t;
    int initial = mmt_log_parse_level(getenv("MMT_DPI_LOG_LEVEL"));
    if (initial < 0)
        initial = MMT_LOG_DEFAULT_LEVEL;
    int expected = MMT_LOG_UNSET;
    /* A concurrent first use or mmt_log_set_level() may win; keep theirs. */
    __atomic_compare_exchange_n(&mmt_log_threshold, &expected, initial, 0,
                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    return __atomic_load_n(&mmt_log_threshold, __ATOMIC_ACQUIRE);
}

int mmt_log_event(int level) {
    if (level <= MMT_LOG_LEVEL_OFF || level > MMT_LOG_LEVEL_DEBUG)
        return 0;
    __atomic_fetch_add(&mmt_log_events[level], 1, __ATOMIC_RELAXED);
    return level <= mmt_log_threshold_get();
}

int mmt_log_set_level(int level) {
    if (!mmt_log_valid(level))
        return -1;
    int previous = mmt_log_threshold_get();
    __atomic_store_n(&mmt_log_threshold, level, __ATOMIC_RELEASE);
    return previous;
}

int mmt_log_get_level(void) {
    return mmt_log_threshold_get();
}

void mmt_log_get_stats(mmt_log_stats_t *out) {
    if (out == NULL)
        return;
    for (int i = 0; i < MMT_LOG_LEVEL_COUNT; i++)
        out->events[i] = __atomic_load_n(&mmt_log_events[i], __ATOMIC_RELAXED);
    out->written      = __atomic_load_n(&mmt_log_written, __ATOMIC_RELAXED);
    out->rate_limited = __atomic_load_n(&mmt_log_rate_limited, __ATOMIC_RELAXED);
    out->write_errors = __atomic_load_n(&mmt_log_write_errors, __ATOMIC_RELAXED);
}

static uint64_t mmt_log_now_seconds(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_COARSE
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) == 0)
        return (uint64_t) ts.tv_sec;
#endif
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t) ts.tv_sec;
    return (uint64_t) time(NULL);
}

/* Admits a line from site under the per-second burst. On admission *dropped
 * receives the lines the site dropped since it last wrote one. The window
 * reset is approximate under contention (a concurrent increment can land in
 * either window) but every access is atomic. */
static int mmt_log_site_admit(mmt_log_site_t *site, uint32_t *dropped) {
    uint64_t now = mmt_log_now_seconds();
    uint64_t window = __atomic_load_n(&site->window, __ATOMIC_RELAXED);
    if (window != now
        && __atomic_compare_exchange_n(&site->window, &window, now, 0,
                                       __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        __atomic_store_n(&site->count, 0, __ATOMIC_RELAXED);
    if (__atomic_fetch_add(&site->count, 1, __ATOMIC_RELAXED) >= MMT_LOG_SITE_BURST) {
        __atomic_fetch_add(&site->suppressed, 1, __ATOMIC_RELAXED);
        return 0;
    }
    *dropped = __atomic_exchange_n(&site->suppressed, 0, __ATOMIC_RELAXED);
    return 1;
}

void mmt_log_write(mmt_log_site_t *site, int level, const char *file, int line,
                   const char *fmt, ...) {
    if (level <= MMT_LOG_LEVEL_OFF || level > MMT_LOG_LEVEL_DEBUG || fmt == NULL)
        return;
    if (level > mmt_log_threshold_get())
        return;

    uint32_t dropped = 0;
    if (site != NULL && !mmt_log_site_admit(site, &dropped)) {
        __atomic_fetch_add(&mmt_log_rate_limited, 1, __ATOMIC_RELAXED);
        return;
    }

    char msg[MMT_LOG_MSG_MAX];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n < 0)
        msg[0] = '\0';
    size_t len = strlen(msg);
    while (len > 0 && (msg[len - 1] == '\n' || msg[len - 1] == '\r'))
        msg[--len] = '\0';

    const char *base = "?";
    if (file != NULL) {
        const char *slash = strrchr(file, '/');
        base = slash != NULL ? slash + 1 : file;
    }

    char out[MMT_LOG_LINE_MAX];
    int m;
    if (dropped > 0)
        m = snprintf(out, sizeof(out), "[mmt-dpi][%c] %s:%d: %s (%u earlier line(s) suppressed)\n",
                     mmt_log_tag[level], base, line, msg, (unsigned) dropped);
    else
        m = snprintf(out, sizeof(out), "[mmt-dpi][%c] %s:%d: %s\n",
                     mmt_log_tag[level], base, line, msg);
    if (m < 0) {
        __atomic_fetch_add(&mmt_log_write_errors, 1, __ATOMIC_RELAXED);
        return;
    }
    size_t out_len = (size_t) m;
    if (out_len >= sizeof(out)) { /* truncated: keep the line terminated */
        out_len = sizeof(out) - 1;
        out[out_len - 1] = '\n';
    }
    if (fwrite(out, 1, out_len, stderr) == out_len)
        __atomic_fetch_add(&mmt_log_written, 1, __ATOMIC_RELAXED);
    else
        __atomic_fetch_add(&mmt_log_write_errors, 1, __ATOMIC_RELAXED);
}
