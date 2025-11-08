/**
 * MMT Logging System Implementation
 * Phase 5: Error Handling and Logging Framework
 *
 * Thread-safe, high-performance logging with multiple output modes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "../public_include/mmt_logging.h"

/* ANSI color codes for terminal output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_GRAY    "\033[90m"

/* Maximum log message size */
#define MMT_LOG_MAX_MESSAGE_SIZE 4096

/* Global logging configuration */
static mmt_log_config_t g_log_config = {
    .global_level = MMT_LOG_INFO,
    .output_mode = MMT_LOG_OUTPUT_STDERR,
    .log_file_path = NULL,
    .callback = NULL,
    .include_timestamp = true,
    .include_thread_id = false,
    .color_output = false
};

/* File handle for file output */
static FILE *g_log_file = NULL;

/* Mutex for thread-safe logging */
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Initialization flag */
static bool g_log_initialized = false;

/* Log level names */
static const char* g_log_level_names[] = {
    [MMT_LOG_NONE]  = "NONE",
    [MMT_LOG_ERROR] = "ERROR",
    [MMT_LOG_WARN]  = "WARN",
    [MMT_LOG_INFO]  = "INFO",
    [MMT_LOG_DEBUG] = "DEBUG",
    [MMT_LOG_TRACE] = "TRACE"
};

/* Log category names */
static const char* g_log_category_names[] = {
    [MMT_LOG_CAT_GENERAL]     = "GENERAL",
    [MMT_LOG_CAT_PROTOCOL]    = "PROTOCOL",
    [MMT_LOG_CAT_SESSION]     = "SESSION",
    [MMT_LOG_CAT_MEMORY]      = "MEMORY",
    [MMT_LOG_CAT_PACKET]      = "PACKET",
    [MMT_LOG_CAT_THREAD]      = "THREAD",
    [MMT_LOG_CAT_IO]          = "IO",
    [MMT_LOG_CAT_CONFIG]      = "CONFIG",
    [MMT_LOG_CAT_PERFORMANCE] = "PERF",
    [MMT_LOG_CAT_SECURITY]    = "SECURITY"
};

/* Get color code for log level */
static const char* get_level_color(mmt_log_level_t level)
{
    if (!g_log_config.color_output) {
        return "";
    }

    switch (level) {
        case MMT_LOG_ERROR: return COLOR_RED;
        case MMT_LOG_WARN:  return COLOR_YELLOW;
        case MMT_LOG_INFO:  return COLOR_GREEN;
        case MMT_LOG_DEBUG: return COLOR_CYAN;
        case MMT_LOG_TRACE: return COLOR_GRAY;
        default:            return COLOR_RESET;
    }
}

/* Get reset color code */
static const char* get_color_reset(void)
{
    return g_log_config.color_output ? COLOR_RESET : "";
}

/* Get current thread ID */
static long get_thread_id(void)
{
    return (long)syscall(SYS_gettid);
}

/* Format timestamp */
static void format_timestamp(char *buffer, size_t size)
{
    struct timespec ts;
    struct tm tm_info;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);

    snprintf(buffer, size, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm_info.tm_year + 1900,
             tm_info.tm_mon + 1,
             tm_info.tm_mday,
             tm_info.tm_hour,
             tm_info.tm_min,
             tm_info.tm_sec,
             ts.tv_nsec / 1000000);
}

void mmt_log_init(void)
{
    pthread_mutex_lock(&g_log_mutex);

    if (!g_log_initialized) {
        /* Initialize all categories to NONE so they fall back to global level */
        for (int i = 0; i < MMT_LOG_CAT_MAX; i++) {
            g_log_config.category_levels[i] = MMT_LOG_NONE;
            g_log_config.category_enabled[i] = true;
        }

        g_log_initialized = true;
    }

    pthread_mutex_unlock(&g_log_mutex);
}

void mmt_log_init_with_config(const mmt_log_config_t *config)
{
    if (config == NULL) {
        mmt_log_init();
        return;
    }

    pthread_mutex_lock(&g_log_mutex);

    /* Copy configuration */
    memcpy(&g_log_config, config, sizeof(mmt_log_config_t));

    /* Open log file if needed */
    if (g_log_config.output_mode == MMT_LOG_OUTPUT_FILE &&
        g_log_config.log_file_path != NULL) {
        g_log_file = fopen(g_log_config.log_file_path, "a");
        if (g_log_file == NULL) {
            /* Fall back to stderr if file open fails */
            g_log_config.output_mode = MMT_LOG_OUTPUT_STDERR;
        }
    }

    g_log_initialized = true;

    pthread_mutex_unlock(&g_log_mutex);
}

void mmt_log_shutdown(void)
{
    pthread_mutex_lock(&g_log_mutex);

    if (g_log_file != NULL) {
        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }

    g_log_initialized = false;

    pthread_mutex_unlock(&g_log_mutex);
}

void mmt_log_set_level(mmt_log_level_t level)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.global_level = level;
    pthread_mutex_unlock(&g_log_mutex);
}

mmt_log_level_t mmt_log_get_level(void)
{
    mmt_log_level_t level;
    pthread_mutex_lock(&g_log_mutex);
    level = g_log_config.global_level;
    pthread_mutex_unlock(&g_log_mutex);
    return level;
}

void mmt_log_set_category_level(mmt_log_category_t category, mmt_log_level_t level)
{
    if (category >= MMT_LOG_CAT_MAX) return;

    pthread_mutex_lock(&g_log_mutex);
    g_log_config.category_levels[category] = level;
    pthread_mutex_unlock(&g_log_mutex);
}

mmt_log_level_t mmt_log_get_category_level(mmt_log_category_t category)
{
    if (category >= MMT_LOG_CAT_MAX) return MMT_LOG_NONE;

    mmt_log_level_t level;
    pthread_mutex_lock(&g_log_mutex);
    level = g_log_config.category_levels[category];
    pthread_mutex_unlock(&g_log_mutex);
    return level;
}

void mmt_log_set_category_enabled(mmt_log_category_t category, bool enabled)
{
    if (category >= MMT_LOG_CAT_MAX) return;

    pthread_mutex_lock(&g_log_mutex);
    g_log_config.category_enabled[category] = enabled;
    pthread_mutex_unlock(&g_log_mutex);
}

bool mmt_log_is_category_enabled(mmt_log_category_t category)
{
    if (category >= MMT_LOG_CAT_MAX) return false;

    bool enabled;
    pthread_mutex_lock(&g_log_mutex);
    enabled = g_log_config.category_enabled[category];
    pthread_mutex_unlock(&g_log_mutex);
    return enabled;
}

void mmt_log_set_output_mode(mmt_log_output_t mode)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.output_mode = mode;
    pthread_mutex_unlock(&g_log_mutex);
}

int mmt_log_set_file_path(const char *path)
{
    if (path == NULL) return -1;

    pthread_mutex_lock(&g_log_mutex);

    /* Close existing file if open */
    if (g_log_file != NULL) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    /* Open new log file */
    g_log_file = fopen(path, "a");
    if (g_log_file == NULL) {
        pthread_mutex_unlock(&g_log_mutex);
        return -1;
    }

    g_log_config.log_file_path = path;
    g_log_config.output_mode = MMT_LOG_OUTPUT_FILE;

    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}

void mmt_log_set_callback(mmt_log_callback_t callback)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.callback = callback;
    if (callback != NULL) {
        g_log_config.output_mode = MMT_LOG_OUTPUT_CALLBACK;
    }
    pthread_mutex_unlock(&g_log_mutex);
}

void mmt_log_set_timestamp_enabled(bool enabled)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.include_timestamp = enabled;
    pthread_mutex_unlock(&g_log_mutex);
}

void mmt_log_set_thread_id_enabled(bool enabled)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.include_thread_id = enabled;
    pthread_mutex_unlock(&g_log_mutex);
}

void mmt_log_set_color_enabled(bool enabled)
{
    pthread_mutex_lock(&g_log_mutex);
    g_log_config.color_output = enabled;
    pthread_mutex_unlock(&g_log_mutex);
}

bool mmt_log_is_enabled(mmt_log_level_t level, mmt_log_category_t category)
{
    if (!g_log_initialized) return false;
    if (category >= MMT_LOG_CAT_MAX) return false;

    /* Check if category is enabled */
    if (!g_log_config.category_enabled[category]) return false;

    /* Check level against category level (or global if not set) */
    mmt_log_level_t threshold = g_log_config.category_levels[category];
    if (threshold == MMT_LOG_NONE) {
        threshold = g_log_config.global_level;
    }

    return (level <= threshold);
}

void mmt_log(mmt_log_level_t level, mmt_log_category_t category,
             const char *file, int line, const char *function,
             const char *format, ...)
{
    if (!g_log_initialized) {
        mmt_log_init();
    }

    /* Early exit if logging is disabled for this level/category */
    if (!mmt_log_is_enabled(level, category)) {
        return;
    }

    /* Format the user message */
    char message_buffer[MMT_LOG_MAX_MESSAGE_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(message_buffer, sizeof(message_buffer), format, args);
    va_end(args);

    /* Thread safety */
    pthread_mutex_lock(&g_log_mutex);

    /* Handle callback mode */
    if (g_log_config.output_mode == MMT_LOG_OUTPUT_CALLBACK &&
        g_log_config.callback != NULL) {
        g_log_config.callback(level, category, file, line, function, message_buffer);
        pthread_mutex_unlock(&g_log_mutex);
        return;
    }

    /* Build complete log line */
    char log_line[MMT_LOG_MAX_MESSAGE_SIZE * 2];
    char *ptr = log_line;
    size_t remaining = sizeof(log_line);
    int written;

    /* Timestamp */
    if (g_log_config.include_timestamp) {
        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));
        written = snprintf(ptr, remaining, "[%s] ", timestamp);
        ptr += written;
        remaining -= written;
    }

    /* Thread ID */
    if (g_log_config.include_thread_id) {
        written = snprintf(ptr, remaining, "[%ld] ", get_thread_id());
        ptr += written;
        remaining -= written;
    }

    /* Log level (with color) */
    const char *level_color = get_level_color(level);
    const char *color_reset = get_color_reset();
    const char *level_name = mmt_log_level_to_string(level);

    written = snprintf(ptr, remaining, "%s[%s]%s ", level_color, level_name, color_reset);
    ptr += written;
    remaining -= written;

    /* Category */
    const char *cat_name = mmt_log_category_to_string(category);
    written = snprintf(ptr, remaining, "[%s] ", cat_name);
    ptr += written;
    remaining -= written;

    /* Source location */
    const char *filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;
    written = snprintf(ptr, remaining, "%s:%d:%s() - ", filename, line, function);
    ptr += written;
    remaining -= written;

    /* Message */
    written = snprintf(ptr, remaining, "%s\n", message_buffer);
    ptr += written;
    remaining -= written;

    /* Output to appropriate destination */
    switch (g_log_config.output_mode) {
        case MMT_LOG_OUTPUT_STDOUT:
            fputs(log_line, stdout);
            fflush(stdout);
            break;

        case MMT_LOG_OUTPUT_STDERR:
            fputs(log_line, stderr);
            fflush(stderr);
            break;

        case MMT_LOG_OUTPUT_FILE:
            if (g_log_file != NULL) {
                fputs(log_line, g_log_file);
                fflush(g_log_file);
            }
            break;

        case MMT_LOG_OUTPUT_NONE:
        case MMT_LOG_OUTPUT_SYSLOG:
        case MMT_LOG_OUTPUT_CALLBACK:
        default:
            /* Already handled or not implemented */
            break;
    }

    pthread_mutex_unlock(&g_log_mutex);
}

void mmt_log_flush(void)
{
    pthread_mutex_lock(&g_log_mutex);

    if (g_log_file != NULL) {
        fflush(g_log_file);
    }

    pthread_mutex_unlock(&g_log_mutex);
}

const char* mmt_log_level_to_string(mmt_log_level_t level)
{
    if (level >= 0 && level <= MMT_LOG_TRACE) {
        return g_log_level_names[level];
    }
    return "UNKNOWN";
}

const char* mmt_log_category_to_string(mmt_log_category_t category)
{
    if (category >= 0 && category < MMT_LOG_CAT_MAX) {
        return g_log_category_names[category];
    }
    return "UNKNOWN";
}
