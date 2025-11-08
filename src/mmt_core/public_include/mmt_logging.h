#ifndef MMT_LOGGING_H
#define MMT_LOGGING_H

/**
 * MMT Logging Framework
 * Phase 5: Error Handling and Logging Framework
 *
 * Comprehensive logging system with:
 * - Multiple log levels (ERROR, WARN, INFO, DEBUG, TRACE)
 * - Log categories for filtering (PROTOCOL, SESSION, MEMORY, etc.)
 * - Custom callbacks for log output
 * - Thread-safe operation
 * - Performance optimized
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Log Levels
 * Higher levels include all lower levels
 */
typedef enum {
    MMT_LOG_NONE = 0,     /* No logging */
    MMT_LOG_ERROR = 1,    /* Error conditions that need immediate attention */
    MMT_LOG_WARN = 2,     /* Warning conditions that might cause issues */
    MMT_LOG_INFO = 3,     /* Informational messages about normal operations */
    MMT_LOG_DEBUG = 4,    /* Debug messages for development */
    MMT_LOG_TRACE = 5     /* Trace messages (very verbose, function entry/exit) */
} mmt_log_level_t;

/**
 * Log Categories
 * Used for filtering logs by component
 */
typedef enum {
    MMT_LOG_CAT_GENERAL = 0,    /* General/uncategorized */
    MMT_LOG_CAT_PROTOCOL,       /* Protocol classification */
    MMT_LOG_CAT_SESSION,        /* Session management */
    MMT_LOG_CAT_MEMORY,         /* Memory allocation/pools */
    MMT_LOG_CAT_PACKET,         /* Packet processing */
    MMT_LOG_CAT_THREAD,         /* Thread safety/concurrency */
    MMT_LOG_CAT_IO,             /* File/network I/O */
    MMT_LOG_CAT_CONFIG,         /* Configuration */
    MMT_LOG_CAT_PERFORMANCE,    /* Performance metrics */
    MMT_LOG_CAT_SECURITY,       /* Security events */
    MMT_LOG_CAT_MAX             /* Number of categories */
} mmt_log_category_t;

/**
 * Log callback function type
 * Called for each log message
 *
 * @param level Log level
 * @param category Log category
 * @param file Source file name
 * @param line Line number
 * @param function Function name
 * @param message Formatted message string
 */
typedef void (*mmt_log_callback_t)(
    mmt_log_level_t level,
    mmt_log_category_t category,
    const char *file,
    int line,
    const char *function,
    const char *message
);

/**
 * Log output mode
 */
typedef enum {
    MMT_LOG_OUTPUT_NONE = 0,     /* No output */
    MMT_LOG_OUTPUT_STDOUT,       /* Standard output */
    MMT_LOG_OUTPUT_STDERR,       /* Standard error */
    MMT_LOG_OUTPUT_FILE,         /* File output */
    MMT_LOG_OUTPUT_SYSLOG,       /* Syslog */
    MMT_LOG_OUTPUT_CALLBACK      /* Custom callback */
} mmt_log_output_t;

/**
 * Log configuration structure
 */
typedef struct {
    mmt_log_level_t global_level;                     /* Global log level */
    mmt_log_level_t category_levels[MMT_LOG_CAT_MAX]; /* Per-category levels */
    bool category_enabled[MMT_LOG_CAT_MAX];           /* Category enable flags */
    mmt_log_output_t output_mode;                     /* Output mode */
    const char *log_file_path;                        /* File path for file output */
    mmt_log_callback_t callback;                      /* Custom callback */
    bool include_timestamp;                           /* Include timestamp in logs */
    bool include_thread_id;                           /* Include thread ID */
    bool color_output;                                /* Use ANSI colors (terminal) */
} mmt_log_config_t;

/**
 * Initialize logging system with default configuration
 * Must be called before any logging
 */
void mmt_log_init(void);

/**
 * Initialize logging system with custom configuration
 * @param config Configuration structure
 */
void mmt_log_init_with_config(const mmt_log_config_t *config);

/**
 * Shutdown logging system
 * Flushes buffers and closes log files
 */
void mmt_log_shutdown(void);

/**
 * Set global log level
 * Messages below this level are not logged
 *
 * @param level New log level
 */
void mmt_log_set_level(mmt_log_level_t level);

/**
 * Get current global log level
 * @return Current log level
 */
mmt_log_level_t mmt_log_get_level(void);

/**
 * Set log level for specific category
 * Category level overrides global level
 *
 * @param category Log category
 * @param level Log level for this category
 */
void mmt_log_set_category_level(mmt_log_category_t category, mmt_log_level_t level);

/**
 * Get log level for specific category
 * @param category Log category
 * @return Log level for category
 */
mmt_log_level_t mmt_log_get_category_level(mmt_log_category_t category);

/**
 * Enable or disable a log category
 * Disabled categories produce no output regardless of level
 *
 * @param category Log category
 * @param enabled true to enable, false to disable
 */
void mmt_log_set_category_enabled(mmt_log_category_t category, bool enabled);

/**
 * Check if category is enabled
 * @param category Log category
 * @return true if enabled, false if disabled
 */
bool mmt_log_is_category_enabled(mmt_log_category_t category);

/**
 * Set log output mode
 * @param mode Output mode
 */
void mmt_log_set_output_mode(mmt_log_output_t mode);

/**
 * Set log file path (for file output mode)
 * @param path File path
 * @return 0 on success, -1 on error
 */
int mmt_log_set_file_path(const char *path);

/**
 * Set custom log callback
 * @param callback Callback function
 */
void mmt_log_set_callback(mmt_log_callback_t callback);

/**
 * Enable/disable timestamps in log output
 * @param enabled true to enable, false to disable
 */
void mmt_log_set_timestamp_enabled(bool enabled);

/**
 * Enable/disable thread ID in log output
 * @param enabled true to enable, false to disable
 */
void mmt_log_set_thread_id_enabled(bool enabled);

/**
 * Enable/disable color output
 * @param enabled true to enable, false to disable
 */
void mmt_log_set_color_enabled(bool enabled);

/**
 * Core logging function
 * Generally you should use the convenience macros instead
 *
 * @param level Log level
 * @param category Log category
 * @param file Source file
 * @param line Line number
 * @param function Function name
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void mmt_log(mmt_log_level_t level, mmt_log_category_t category,
             const char *file, int line, const char *function,
             const char *format, ...) __attribute__((format(printf, 6, 7)));

/**
 * Check if a log message would be output
 * Useful to avoid expensive computations for disabled log levels
 *
 * @param level Log level
 * @param category Log category
 * @return true if message would be logged, false otherwise
 */
bool mmt_log_is_enabled(mmt_log_level_t level, mmt_log_category_t category);

/**
 * Flush log buffers
 * Ensures all pending log messages are written
 */
void mmt_log_flush(void);

/*
 * ============================================================================
 * Convenience Macros
 * ============================================================================
 */

/**
 * Category-specific logging macros
 * Use these to log messages with a specific category
 */
#define MMT_LOG_ERROR_CAT(cat, ...) \
    mmt_log(MMT_LOG_ERROR, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define MMT_LOG_WARN_CAT(cat, ...) \
    mmt_log(MMT_LOG_WARN, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define MMT_LOG_INFO_CAT(cat, ...) \
    mmt_log(MMT_LOG_INFO, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define MMT_LOG_DEBUG_CAT(cat, ...) \
    mmt_log(MMT_LOG_DEBUG, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define MMT_LOG_TRACE_CAT(cat, ...) \
    mmt_log(MMT_LOG_TRACE, cat, __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * Simplified macros (use GENERAL category)
 * Use these for general logging without a specific category
 */
#define MMT_LOG_ERROR(...) MMT_LOG_ERROR_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_WARN(...)  MMT_LOG_WARN_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_INFO(...)  MMT_LOG_INFO_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_DEBUG(...) MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_TRACE(...) MMT_LOG_TRACE_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)

/**
 * Conditional logging (only if condition is true)
 */
#define MMT_LOG_ERROR_IF(cond, ...) \
    do { if (cond) { MMT_LOG_ERROR(__VA_ARGS__); } } while(0)

#define MMT_LOG_WARN_IF(cond, ...) \
    do { if (cond) { MMT_LOG_WARN(__VA_ARGS__); } } while(0)

#define MMT_LOG_INFO_IF(cond, ...) \
    do { if (cond) { MMT_LOG_INFO(__VA_ARGS__); } } while(0)

#define MMT_LOG_DEBUG_IF(cond, ...) \
    do { if (cond) { MMT_LOG_DEBUG(__VA_ARGS__); } } while(0)

/**
 * Conditional logging (only once per location)
 * Useful to avoid log spam
 */
#define MMT_LOG_ERROR_ONCE(...) \
    do { \
        static bool _logged = false; \
        if (!_logged) { \
            MMT_LOG_ERROR(__VA_ARGS__); \
            _logged = true; \
        } \
    } while(0)

#define MMT_LOG_WARN_ONCE(...) \
    do { \
        static bool _logged = false; \
        if (!_logged) { \
            MMT_LOG_WARN(__VA_ARGS__); \
            _logged = true; \
        } \
    } while(0)

/**
 * Function entry/exit tracing
 * Useful for debugging call flows
 */
#define MMT_LOG_TRACE_ENTER() \
    MMT_LOG_TRACE("Entering %s", __func__)

#define MMT_LOG_TRACE_EXIT() \
    MMT_LOG_TRACE("Exiting %s", __func__)

#define MMT_LOG_TRACE_EXIT_WITH(retval) \
    MMT_LOG_TRACE("Exiting %s with return value: %d", __func__, (int)(retval))

/**
 * Performance measurement logging
 */
#define MMT_LOG_PERF(cat, msg, ...) \
    MMT_LOG_INFO_CAT(MMT_LOG_CAT_PERFORMANCE, msg, __VA_ARGS__)

/**
 * Security event logging
 */
#define MMT_LOG_SECURITY(msg, ...) \
    MMT_LOG_WARN_CAT(MMT_LOG_CAT_SECURITY, msg, __VA_ARGS__)

/**
 * Get string name for log level
 * @param level Log level
 * @return String name (e.g., "ERROR", "WARN")
 */
const char* mmt_log_level_to_string(mmt_log_level_t level);

/**
 * Get string name for log category
 * @param category Log category
 * @return String name (e.g., "PROTOCOL", "SESSION")
 */
const char* mmt_log_category_to_string(mmt_log_category_t category);

#endif /* MMT_LOGGING_H */
