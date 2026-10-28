#ifndef MMT_LOG_H_
#define MMT_LOG_H_

/*
 * mmt_log.h — the SDK's internal, level-gated, rate-limited logger
 * (issue #545, F-CLEAN-013).
 *
 * Packet-path diagnostics go through mmt_log_error/warn/info/debug instead
 * of a per-module printf family. The logger is:
 *
 *   - off by default: nothing is written unless the threshold is raised,
 *     through the MMT_DPI_LOG_LEVEL environment variable (off, error, warn,
 *     info, debug, or 0-4; read once, on first use) or mmt_log_set_level().
 *     A SHOWLOG=1 build (-DDEBUG) defaults to debug instead;
 *   - stderr only: it never writes to stdout;
 *   - rate-limited per call site: at most MMT_LOG_SITE_BURST lines per
 *     second from one site, the rest counted and reported on the site's next
 *     written line, so a flood of malformed PDUs cannot become a syscall
 *     storm even with logging on;
 *   - counted: every event is counted per level whether or not it is
 *     written, together with the lines written, rate-limited and failed
 *     (mmt_log_get_stats()), so failures stay visible with logging off;
 *   - thread-safe: all shared state is updated with atomic builtins, and each
 *     line is formatted locally and written with a single fwrite().
 *
 * mmt_log_debug() compiles to nothing unless the build defines DEBUG
 * (make SHOWLOG=1): debug lines may carry decoded, subscriber-identifying
 * fields (F-SEC-016), so a release build cannot be made to print them.
 * Arguments of a disabled call are not evaluated.
 */

#include <stdint.h>
#include "../public_include/mmt_exports.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mmt_log_level_e {
    MMT_LOG_LEVEL_OFF   = 0,
    MMT_LOG_LEVEL_ERROR = 1,
    MMT_LOG_LEVEL_WARN  = 2,
    MMT_LOG_LEVEL_INFO  = 3,
    MMT_LOG_LEVEL_DEBUG = 4
} mmt_log_level_t;

#define MMT_LOG_LEVEL_COUNT 5

/* Lines one call site may write per second before it is rate-limited. */
#define MMT_LOG_SITE_BURST 10

/* Per-call-site rate-limit state; a zero-initialised static per site. */
typedef struct mmt_log_site_s {
    uint64_t window;     /* monotonic second the count belongs to */
    uint32_t count;      /* lines attempted in that second */
    uint32_t suppressed; /* lines dropped since the site last wrote one */
} mmt_log_site_t;

typedef struct mmt_log_stats_s {
    uint64_t events[MMT_LOG_LEVEL_COUNT]; /* calls per level, written or not */
    uint64_t written;      /* lines written to stderr */
    uint64_t rate_limited; /* lines dropped by the per-site rate limit */
    uint64_t write_errors; /* lines whose write to stderr failed */
} mmt_log_stats_t;

/* Counts one event at level and returns non-zero when level is enabled. */
MMTAPI int MMTCALL mmt_log_event(int level);

/* Writes one line at level unless the site is rate-limited. Call it through
 * the macros below, which supply the site, file and line. */
MMTAPI void MMTCALL mmt_log_write(mmt_log_site_t *site, int level,
                                  const char *file, int line,
                                  const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

/* Sets the threshold (MMT_LOG_LEVEL_OFF..MMT_LOG_LEVEL_DEBUG) and returns
 * the previous one, or -1 (no change) for an out-of-range level. */
MMTAPI int MMTCALL mmt_log_set_level(int level);

MMTAPI int MMTCALL mmt_log_get_level(void);

/* Copies the counters; out may not be NULL. */
MMTAPI void MMTCALL mmt_log_get_stats(mmt_log_stats_t *out);

/* A void expression (GNU statement expression), so it also fits the
 * expression contexts of the macros it replaces, e.g. (void)mmt_debug_log(). */
#define mmt_log_at(level, ...) ((void) __extension__ ({                     \
        if (mmt_log_event(level)) {                                         \
            static mmt_log_site_t mmt_log_site_;                            \
            mmt_log_write(&mmt_log_site_, (level), __FILE__, __LINE__,      \
                          __VA_ARGS__);                                     \
        }                                                                   \
    }))

#define mmt_log_error(...) mmt_log_at(MMT_LOG_LEVEL_ERROR, __VA_ARGS__)
#define mmt_log_warn(...)  mmt_log_at(MMT_LOG_LEVEL_WARN, __VA_ARGS__)
#define mmt_log_info(...)  mmt_log_at(MMT_LOG_LEVEL_INFO, __VA_ARGS__)

#ifdef DEBUG
#define mmt_log_debug(...) mmt_log_at(MMT_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
#define mmt_log_debug(...) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* MMT_LOG_H_ */
