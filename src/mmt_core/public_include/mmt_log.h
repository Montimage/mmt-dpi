/**
 * @file
 * The SDK logger: level-gated, rate-limited diagnostics written to stderr
 * (issue #545, F-CLEAN-013).
 *
 * Library code and out-of-tree protocol plugins log through
 * mmt_log_error(), mmt_log_warn(), mmt_log_info() and mmt_log_debug().
 * The header is installed (issue #66) but no other installed header
 * includes it: a plugin opts in with `#include "mmt_log.h"`, and every name
 * it defines carries the `mmt_log`/`MMT_LOG` prefix. It replaces the
 * unprefixed debug()/log_err()/log_warn()/log_info() macros that the
 * installed headers stopped defining in 1.10.0 (issue #537).
 *
 * The logger is:
 *
 *   - off by default: nothing is written unless the threshold is raised,
 *     through the MMT_DPI_LOG_LEVEL environment variable (off, error, warn,
 *     info, debug, or 0-4; read once, on first use) or mmt_log_set_level().
 *     A libmmt_core built with SHOWLOG=1 (-DDEBUG) defaults to debug;
 *   - stderr only: it never writes to stdout;
 *   - rate-limited per call site: at most #MMT_LOG_SITE_BURST lines per
 *     second from one site, the rest counted and reported on the site's next
 *     written line, so a flood of malformed PDUs cannot become a syscall
 *     storm even with logging on;
 *   - counted: every event is counted per level whether or not it is
 *     written, together with the lines written, rate-limited and failed
 *     (mmt_log_get_stats()), so failures stay visible with logging off;
 *   - thread-safe: all shared state is updated with atomic builtins, and each
 *     line is formatted locally and written with a single fwrite().
 *
 * mmt_log_debug() compiles to nothing unless the translation unit that
 * calls it opts in: a plugin defines MMT_LOG_ENABLE_DEBUG (-DMMT_LOG_ENABLE_DEBUG);
 * the SDK's own sources (_MMT_BUILD_SDK) keep their convention, DEBUG, which
 * make SHOWLOG=1 sets. A plugin's own DEBUG does not enable it: debug lines
 * may carry decoded, subscriber-identifying fields (F-SEC-016), so they need
 * an opt-in nothing else sets, and a release build cannot be made to print
 * them. Arguments of a disabled call are not evaluated.
 *
 * The macros use a GNU statement expression and a per-call-site static, so
 * they need GCC or Clang (the SDK's supported toolchains).
 */

#ifndef MMT_LOG_H_
#define MMT_LOG_H_

#include <stdint.h>
#include "mmt_exports.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Log levels, from off to the most verbose. */
typedef enum mmt_log_level_e {
    MMT_LOG_LEVEL_OFF   = 0, /**< nothing is written (the default threshold) */
    MMT_LOG_LEVEL_ERROR = 1, /**< failures */
    MMT_LOG_LEVEL_WARN  = 2, /**< recoverable anomalies, e.g. a malformed PDU */
    MMT_LOG_LEVEL_INFO  = 3, /**< notable events */
    MMT_LOG_LEVEL_DEBUG = 4  /**< traces; compiled in only on opt-in (see mmt_log_debug()) */
} mmt_log_level_t;

/** Number of levels in mmt_log_level_t, MMT_LOG_LEVEL_OFF included. */
#define MMT_LOG_LEVEL_COUNT 5

/**
 * Slots of mmt_log_stats_t::events, at least #MMT_LOG_LEVEL_COUNT: the slots
 * past the last level are reserved for levels a later release may add, and
 * are 0.
 */
#define MMT_LOG_EVENT_SLOTS 8

/** Lines one call site may write per second before it is rate-limited. */
#define MMT_LOG_SITE_BURST 10

/**
 * Per-call-site rate-limit state; a zero-initialised static per site. Its
 * layout is compiled into every plugin that logs, so it carries reserved
 * words for a later release.
 */
typedef struct mmt_log_site_s {
    uint64_t window;      /**< monotonic second the count belongs to */
    uint32_t count;       /**< lines attempted in that second */
    uint32_t suppressed;  /**< lines dropped since the site last wrote one */
    uint64_t reserved[2]; /**< 0; reserved, never read or written by the logger */
} mmt_log_site_t;

/** Logger counters, copied out by mmt_log_get_stats(). */
typedef struct mmt_log_stats_s {
    /** Calls per level, written or not, indexed by mmt_log_level_t; the
     *  slots from #MMT_LOG_LEVEL_COUNT on are reserved and 0. */
    uint64_t events[MMT_LOG_EVENT_SLOTS];
    uint64_t written;      /**< lines written to stderr */
    uint64_t rate_limited; /**< lines dropped by the per-site rate limit */
    uint64_t write_errors; /**< lines whose write to stderr failed */
    uint64_t reserved[4];  /**< reserved for later counters; 0 */
} mmt_log_stats_t;

/**
 * Counts one event at a level and tells whether that level is enabled.
 * @param level MMT_LOG_LEVEL_ERROR..MMT_LOG_LEVEL_DEBUG
 * @return non-zero when level is at or below the threshold; 0 when it is
 *         not, or when level is out of range (then nothing is counted)
 */
MMTAPI int MMTCALL mmt_log_event(int level);

/**
 * Writes one line at a level unless the call site is rate-limited. Call it
 * through mmt_log_error() and its siblings, which supply the site, file and
 * line.
 * @param site  the call site's rate-limit state, or NULL for no rate limit
 * @param level MMT_LOG_LEVEL_ERROR..MMT_LOG_LEVEL_DEBUG; nothing is written
 *              for another value, nor above the threshold
 * @param file  source file named in the line (its last path component)
 * @param line  source line named in the line
 * @param fmt   printf format of the message; NULL writes nothing
 */
MMTAPI void MMTCALL mmt_log_write(mmt_log_site_t *site, int level,
                                  const char *file, int line,
                                  const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

/**
 * Sets the threshold.
 * @param level MMT_LOG_LEVEL_OFF..MMT_LOG_LEVEL_DEBUG
 * @return the previous threshold, or -1 (no change) for an out-of-range level
 */
MMTAPI int MMTCALL mmt_log_set_level(int level);

/**
 * Returns the threshold, reading MMT_DPI_LOG_LEVEL on first use.
 * @return MMT_LOG_LEVEL_OFF..MMT_LOG_LEVEL_DEBUG
 */
MMTAPI int MMTCALL mmt_log_get_level(void);

/**
 * Copies the logger counters; the reserved event slots and words are set
 * to 0.
 * @param out destination; NULL copies nothing
 */
MMTAPI void MMTCALL mmt_log_get_stats(mmt_log_stats_t *out);

/**
 * Logs one printf-style line at a level, with the caller's file and line and
 * its own rate-limit state. A void expression (GNU statement expression),
 * so it also fits expression contexts; its arguments are evaluated only when
 * the level is enabled.
 */
#define mmt_log_at(level, ...) ((void) __extension__ ({                     \
        if (mmt_log_event(level)) {                                         \
            static mmt_log_site_t mmt_log_site_;                            \
            mmt_log_write(&mmt_log_site_, (level), __FILE__, __LINE__,      \
                          __VA_ARGS__);                                     \
        }                                                                   \
    }))

/** Logs one printf-style line at the error level. */
#define mmt_log_error(...) mmt_log_at(MMT_LOG_LEVEL_ERROR, __VA_ARGS__)
/** Logs one printf-style line at the warn level. */
#define mmt_log_warn(...)  mmt_log_at(MMT_LOG_LEVEL_WARN, __VA_ARGS__)
/** Logs one printf-style line at the info level. */
#define mmt_log_info(...)  mmt_log_at(MMT_LOG_LEVEL_INFO, __VA_ARGS__)

#if defined(MMT_LOG_ENABLE_DEBUG) || (defined(_MMT_BUILD_SDK) && defined(DEBUG))
/** Logs one printf-style line at the debug level; nothing without the opt-in. */
#define mmt_log_debug(...) mmt_log_at(MMT_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
/** Logs one printf-style line at the debug level; nothing without the opt-in. */
#define mmt_log_debug(...) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* MMT_LOG_H_ */
