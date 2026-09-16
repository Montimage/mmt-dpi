#ifndef __dbg_h__
#define __dbg_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) fprintf(stderr, "[ERROR] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...) fprintf(stderr, "[WARN] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_info(M, ...) fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define check(A, M, ...) if(!(A)) { log_err(M, ##__VA_ARGS__); errno=0; goto error; }

#define sentinel(M, ...)  { log_err(M, ##__VA_ARGS__); errno=0; goto error; }

#define check_mem(A) check((A), "Out of memory.")

#define check_debug(A, M, ...) if(!(A)) { debug(M, ##__VA_ARGS__); errno=0; goto error; }

/*
 * Issue #246 (F-PERF-009): unconditional printf/fprintf on packet paths
 * reached by network-controlled input turn stderr's unbuffered writes into
 * a per-packet syscall storm — e.g. duplicate TCP segments on a
 * retransmission-heavy flow — collapsing throughput toward the syscall
 * ceiling. Writes from library code go through these macros instead:
 *
 *   mmt_debug_log(fmt, ...)     packet-path diagnostics and traces; emits
 *                               to stderr only in -DDEBUG builds
 *                               (make SHOWLOG=1) and expands to a no-op
 *                               expression otherwise.
 *   mmt_stderr_log(fmt, ...)    unconditional stderr write reserved for
 *                               one-shot init/configuration failures the
 *                               operator must see — never on a packet path.
 *   mmt_stream_printf(f, ...)   caller-directed FILE* writes for the
 *                               print/dump API (mmt_print_*, attribute
 *                               formatters, fhexdump): the destination
 *                               stream is supplied by the caller.
 */
#ifdef DEBUG
#define mmt_debug_log(...) fprintf(stderr, __VA_ARGS__)
#else
#define mmt_debug_log(...) ((void)0)
#endif

#define mmt_stderr_log(...) fprintf(stderr, __VA_ARGS__)

#define mmt_stream_printf(...) fprintf(__VA_ARGS__)

#endif