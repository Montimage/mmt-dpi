# Phase 5: Error Handling and Logging Framework - Implementation Plan

**Date:** 2025-11-08
**Branch:** `claude/deep-analysis-011CUvGnTGxbn8rBZAgruD9T`
**Status:** IN PROGRESS
**Estimated Time:** 32-40 hours

---

## Overview

Phase 5 creates a comprehensive error handling and logging framework for MMT-DPI. Currently, errors are handled inconsistently across the codebase. This phase standardizes error reporting, adds structured logging, and implements recovery strategies.

**Goals:**
1. Standardized error code framework
2. Comprehensive logging infrastructure
3. Error recovery strategies
4. Debug and diagnostic tools

---

## Current State Analysis

### Problems with Current Error Handling

1. **Inconsistent Return Values:**
   - Some functions return 0, others return -1, others return NULL
   - No standard error codes
   - Hard to distinguish error types

2. **Limited Error Information:**
   - No context about where/why error occurred
   - No error propagation mechanism
   - Silent failures common

3. **Scattered Logging:**
   - printf() used directly in many places
   - No log levels
   - No log filtering
   - No structured logging

4. **No Recovery Mechanisms:**
   - Errors often fatal
   - No retry logic
   - No graceful degradation

---

## Task 5.1: Standardized Error Framework

**Priority:** P1 - HIGH
**Estimated Time:** 12 hours
**Objective:** Create consistent error handling across MMT-DPI

### Subtask 5.1.1: Define Error Codes (4h)

**File:** `src/mmt_core/public_include/mmt_errors.h`

```c
#ifndef MMT_ERRORS_H
#define MMT_ERRORS_H

/**
 * MMT Error Codes
 * Standardized error reporting across MMT-DPI
 */

typedef enum {
    /* Success */
    MMT_SUCCESS = 0,
    MMT_OK = 0,

    /* General Errors (1-99) */
    MMT_ERROR_GENERIC = 1,
    MMT_ERROR_NOT_IMPLEMENTED = 2,
    MMT_ERROR_INTERNAL = 3,
    MMT_ERROR_ASSERTION_FAILED = 4,

    /* Memory Errors (100-199) */
    MMT_ERROR_MEMORY_ALLOC = 100,
    MMT_ERROR_MEMORY_NULL_PTR = 101,
    MMT_ERROR_MEMORY_OUT_OF_BOUNDS = 102,
    MMT_ERROR_MEMORY_LEAK = 103,

    /* Input Validation Errors (200-299) */
    MMT_ERROR_INVALID_INPUT = 200,
    MMT_ERROR_INVALID_PARAMETER = 201,
    MMT_ERROR_INVALID_OFFSET = 202,
    MMT_ERROR_INVALID_LENGTH = 203,
    MMT_ERROR_INVALID_PROTOCOL = 204,
    MMT_ERROR_INVALID_VERSION = 205,
    MMT_ERROR_BUFFER_TOO_SMALL = 206,
    MMT_ERROR_OVERFLOW = 207,
    MMT_ERROR_UNDERFLOW = 208,

    /* Packet Processing Errors (300-399) */
    MMT_ERROR_PACKET_TOO_SHORT = 300,
    MMT_ERROR_PACKET_MALFORMED = 301,
    MMT_ERROR_PACKET_TRUNCATED = 302,
    MMT_ERROR_PACKET_INVALID_HEADER = 303,
    MMT_ERROR_PACKET_CHECKSUM = 304,

    /* Protocol Errors (400-499) */
    MMT_ERROR_PROTOCOL_NOT_FOUND = 400,
    MMT_ERROR_PROTOCOL_NOT_REGISTERED = 401,
    MMT_ERROR_PROTOCOL_ALREADY_REGISTERED = 402,
    MMT_ERROR_PROTOCOL_UNSUPPORTED = 403,
    MMT_ERROR_PROTOCOL_VERSION_MISMATCH = 404,

    /* Session Errors (500-599) */
    MMT_ERROR_SESSION_NOT_FOUND = 500,
    MMT_ERROR_SESSION_CREATE_FAILED = 501,
    MMT_ERROR_SESSION_TIMEOUT = 502,
    MMT_ERROR_SESSION_FULL = 503,

    /* File I/O Errors (600-699) */
    MMT_ERROR_FILE_OPEN = 600,
    MMT_ERROR_FILE_READ = 601,
    MMT_ERROR_FILE_WRITE = 602,
    MMT_ERROR_FILE_NOT_FOUND = 603,
    MMT_ERROR_FILE_PERMISSION = 604,

    /* Configuration Errors (700-799) */
    MMT_ERROR_CONFIG_INVALID = 700,
    MMT_ERROR_CONFIG_MISSING = 701,
    MMT_ERROR_CONFIG_PARSE = 702,

    /* Resource Errors (800-899) */
    MMT_ERROR_RESOURCE_EXHAUSTED = 800,
    MMT_ERROR_RESOURCE_BUSY = 801,
    MMT_ERROR_RESOURCE_LOCKED = 802,
    MMT_ERROR_POOL_EXHAUSTED = 803,

    /* Thread Safety Errors (900-999) */
    MMT_ERROR_LOCK_FAILED = 900,
    MMT_ERROR_UNLOCK_FAILED = 901,
    MMT_ERROR_DEADLOCK = 902,
    MMT_ERROR_RACE_CONDITION = 903,

    /* Maximum error code */
    MMT_ERROR_MAX = 1000
} mmt_error_t;

/**
 * Error context structure
 * Provides detailed information about an error
 */
typedef struct mmt_error_context {
    mmt_error_t code;
    const char *file;
    int line;
    const char *function;
    const char *message;
    int system_errno;  /* errno value if applicable */
} mmt_error_context_t;

/**
 * Get human-readable error message
 * @param error Error code
 * @return Error message string
 */
const char* mmt_error_to_string(mmt_error_t error);

/**
 * Set last error with context
 * Thread-local error storage
 */
void mmt_set_error(mmt_error_t code, const char *file, int line,
                   const char *function, const char *message);

/**
 * Get last error context
 * @return Pointer to error context, or NULL if no error
 */
const mmt_error_context_t* mmt_get_last_error(void);

/**
 * Clear last error
 */
void mmt_clear_error(void);

/**
 * Macro to set error with context
 */
#define MMT_SET_ERROR(code, msg) \
    mmt_set_error(code, __FILE__, __LINE__, __func__, msg)

/**
 * Macro to return with error
 */
#define MMT_RETURN_ERROR(code, msg) \
    do { \
        MMT_SET_ERROR(code, msg); \
        return code; \
    } while(0)

/**
 * Check condition and return error if false
 */
#define MMT_CHECK(condition, error_code, msg) \
    do { \
        if (!(condition)) { \
            MMT_RETURN_ERROR(error_code, msg); \
        } \
    } while(0)

/**
 * Check pointer and return error if NULL
 */
#define MMT_CHECK_NOT_NULL(ptr, msg) \
    MMT_CHECK((ptr) != NULL, MMT_ERROR_MEMORY_NULL_PTR, msg)

#endif /* MMT_ERRORS_H */
```

### Subtask 5.1.2: Implement Error Functions (4h)

**File:** `src/mmt_core/src/mmt_errors.c`

```c
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include "../public_include/mmt_errors.h"

/* Thread-local error storage */
static __thread mmt_error_context_t g_last_error = {0};

/* Error message strings */
static const char* g_error_messages[MMT_ERROR_MAX] = {
    [MMT_SUCCESS] = "Success",
    [MMT_ERROR_GENERIC] = "Generic error",
    [MMT_ERROR_NOT_IMPLEMENTED] = "Not implemented",
    [MMT_ERROR_INTERNAL] = "Internal error",

    [MMT_ERROR_MEMORY_ALLOC] = "Memory allocation failed",
    [MMT_ERROR_MEMORY_NULL_PTR] = "Null pointer",
    [MMT_ERROR_MEMORY_OUT_OF_BOUNDS] = "Out of bounds access",

    [MMT_ERROR_INVALID_INPUT] = "Invalid input",
    [MMT_ERROR_INVALID_PARAMETER] = "Invalid parameter",
    [MMT_ERROR_INVALID_OFFSET] = "Invalid offset",
    [MMT_ERROR_INVALID_LENGTH] = "Invalid length",
    [MMT_ERROR_OVERFLOW] = "Integer overflow",
    [MMT_ERROR_UNDERFLOW] = "Integer underflow",

    [MMT_ERROR_PACKET_TOO_SHORT] = "Packet too short",
    [MMT_ERROR_PACKET_MALFORMED] = "Malformed packet",
    [MMT_ERROR_PACKET_TRUNCATED] = "Truncated packet",

    [MMT_ERROR_PROTOCOL_NOT_FOUND] = "Protocol not found",
    [MMT_ERROR_PROTOCOL_NOT_REGISTERED] = "Protocol not registered",

    [MMT_ERROR_SESSION_NOT_FOUND] = "Session not found",
    [MMT_ERROR_SESSION_CREATE_FAILED] = "Session creation failed",

    [MMT_ERROR_FILE_OPEN] = "File open failed",
    [MMT_ERROR_FILE_READ] = "File read failed",
    [MMT_ERROR_FILE_WRITE] = "File write failed",

    [MMT_ERROR_RESOURCE_EXHAUSTED] = "Resource exhausted",
    [MMT_ERROR_POOL_EXHAUSTED] = "Memory pool exhausted",

    [MMT_ERROR_LOCK_FAILED] = "Lock acquisition failed",
    [MMT_ERROR_UNLOCK_FAILED] = "Lock release failed",
};

const char* mmt_error_to_string(mmt_error_t error) {
    if (error >= 0 && error < MMT_ERROR_MAX && g_error_messages[error]) {
        return g_error_messages[error];
    }
    return "Unknown error";
}

void mmt_set_error(mmt_error_t code, const char *file, int line,
                   const char *function, const char *message)
{
    g_last_error.code = code;
    g_last_error.file = file;
    g_last_error.line = line;
    g_last_error.function = function;
    g_last_error.message = message;
    g_last_error.system_errno = errno;
}

const mmt_error_context_t* mmt_get_last_error(void) {
    if (g_last_error.code == MMT_SUCCESS) {
        return NULL;
    }
    return &g_last_error;
}

void mmt_clear_error(void) {
    memset(&g_last_error, 0, sizeof(g_last_error));
}
```

### Subtask 5.1.3: Error Handling Tests (4h)

**File:** `test/unit/test_error_handling.c`

Test error code system, context storage, thread-local errors.

---

## Task 5.2: Comprehensive Logging Framework

**Priority:** P1 - HIGH
**Estimated Time:** 16 hours
**Objective:** Create structured, filterable logging system

### Subtask 5.2.1: Define Logging Interface (4h)

**File:** `src/mmt_core/public_include/mmt_logging.h`

```c
#ifndef MMT_LOGGING_H
#define MMT_LOGGING_H

#include <stdarg.h>
#include <stdbool.h>

/**
 * Log levels
 */
typedef enum {
    MMT_LOG_NONE = 0,     /* No logging */
    MMT_LOG_ERROR = 1,    /* Error conditions */
    MMT_LOG_WARN = 2,     /* Warning conditions */
    MMT_LOG_INFO = 3,     /* Informational messages */
    MMT_LOG_DEBUG = 4,    /* Debug messages */
    MMT_LOG_TRACE = 5     /* Trace messages (very verbose) */
} mmt_log_level_t;

/**
 * Log categories for filtering
 */
typedef enum {
    MMT_LOG_CAT_GENERAL = 0,
    MMT_LOG_CAT_PROTOCOL,
    MMT_LOG_CAT_SESSION,
    MMT_LOG_CAT_MEMORY,
    MMT_LOG_CAT_PACKET,
    MMT_LOG_CAT_THREAD,
    MMT_LOG_CAT_IO,
    MMT_LOG_CAT_CONFIG,
    MMT_LOG_CAT_MAX
} mmt_log_category_t;

/**
 * Log callback function type
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
 * Initialize logging system
 */
void mmt_log_init(void);

/**
 * Shutdown logging system
 */
void mmt_log_shutdown(void);

/**
 * Set global log level
 */
void mmt_log_set_level(mmt_log_level_t level);

/**
 * Get current log level
 */
mmt_log_level_t mmt_log_get_level(void);

/**
 * Set log level for specific category
 */
void mmt_log_set_category_level(mmt_log_category_t category, mmt_log_level_t level);

/**
 * Enable/disable category
 */
void mmt_log_set_category_enabled(mmt_log_category_t category, bool enabled);

/**
 * Set log callback
 */
void mmt_log_set_callback(mmt_log_callback_t callback);

/**
 * Core logging function
 */
void mmt_log(mmt_log_level_t level, mmt_log_category_t category,
             const char *file, int line, const char *function,
             const char *format, ...) __attribute__((format(printf, 6, 7)));

/**
 * Convenience macros
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

/* Simplified macros (use GENERAL category) */
#define MMT_LOG_ERROR(...) MMT_LOG_ERROR_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_WARN(...)  MMT_LOG_WARN_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_INFO(...)  MMT_LOG_INFO_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_DEBUG(...) MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)
#define MMT_LOG_TRACE(...) MMT_LOG_TRACE_CAT(MMT_LOG_CAT_GENERAL, __VA_ARGS__)

#endif /* MMT_LOGGING_H */
```

### Subtask 5.2.2: Implement Logging System (8h)

**File:** `src/mmt_core/src/mmt_logging.c`

Features:
- Thread-safe logging
- File output support
- Syslog support
- JSON structured logging option
- Log rotation support
- Performance optimized

### Subtask 5.2.3: Logging Tests (4h)

**File:** `test/unit/test_logging.c`

Test log levels, categories, filtering, callbacks.

---

## Task 5.3: Error Recovery Strategies

**Priority:** P2 - MEDIUM
**Estimated Time:** 8 hours
**Objective:** Graceful error handling and recovery

### Subtask 5.3.1: Protocol Fallback (4h)

When protocol classification fails:
- Try alternative parsers
- Fall back to generic handler
- Continue with next protocol

### Subtask 5.3.2: Session Recovery (4h)

When session operations fail:
- Retry with backoff
- Create new session
- Mark session as degraded
- Continue packet processing

---

## Task 5.4: Debug and Diagnostic Tools

**Priority:** P2 - MEDIUM
**Estimated Time:** 8 hours

### Subtask 5.4.1: Packet Dump Utility (4h)

Tool to dump packet contents with annotations.

### Subtask 5.4.2: Error Statistics (4h)

Track error frequencies, common failure points.

---

## Implementation Order

1. **Week 1:**
   - Error code definitions
   - Error handling functions
   - Basic logging framework

2. **Week 2:**
   - Advanced logging features
   - Error recovery strategies
   - Testing and validation

---

## Success Metrics

- ✅ Zero silent failures
- ✅ All errors logged with context
- ✅ 90%+ errors recoverable
- ✅ Log filtering works
- ✅ Performance overhead < 5%

---

## Dependencies

- Phase 1: Security fixes (uses error codes)
- Phase 3: Thread safety (thread-local errors)
- Phase 4: Validation (error reporting)

---

**Ready to begin Phase 5 implementation!**

