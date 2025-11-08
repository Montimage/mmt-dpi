#ifndef MMT_ERRORS_H
#define MMT_ERRORS_H

/**
 * MMT Error Codes
 * Phase 5: Error Handling and Logging Framework
 *
 * Standardized error reporting across MMT-DPI
 * Provides consistent error codes, context tracking, and error propagation
 */

#include <stddef.h>

/**
 * MMT Error Code Enumeration
 * Organized by category with ranges for easy identification
 */
typedef enum {
    /* Success (0) */
    MMT_SUCCESS = 0,
    MMT_OK = 0,

    /* General Errors (1-99) */
    MMT_ERROR_GENERIC = 1,
    MMT_ERROR_NOT_IMPLEMENTED = 2,
    MMT_ERROR_INTERNAL = 3,
    MMT_ERROR_ASSERTION_FAILED = 4,
    MMT_ERROR_UNKNOWN = 5,

    /* Memory Errors (100-199) */
    MMT_ERROR_MEMORY_ALLOC = 100,
    MMT_ERROR_MEMORY_NULL_PTR = 101,
    MMT_ERROR_MEMORY_OUT_OF_BOUNDS = 102,
    MMT_ERROR_MEMORY_LEAK = 103,
    MMT_ERROR_MEMORY_DOUBLE_FREE = 104,
    MMT_ERROR_MEMORY_CORRUPTION = 105,

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
    MMT_ERROR_INVALID_STATE = 209,
    MMT_ERROR_INVALID_FORMAT = 210,

    /* Packet Processing Errors (300-399) */
    MMT_ERROR_PACKET_TOO_SHORT = 300,
    MMT_ERROR_PACKET_MALFORMED = 301,
    MMT_ERROR_PACKET_TRUNCATED = 302,
    MMT_ERROR_PACKET_INVALID_HEADER = 303,
    MMT_ERROR_PACKET_CHECKSUM = 304,
    MMT_ERROR_PACKET_FRAGMENTED = 305,
    MMT_ERROR_PACKET_REASSEMBLY_FAILED = 306,

    /* Protocol Errors (400-499) */
    MMT_ERROR_PROTOCOL_NOT_FOUND = 400,
    MMT_ERROR_PROTOCOL_NOT_REGISTERED = 401,
    MMT_ERROR_PROTOCOL_ALREADY_REGISTERED = 402,
    MMT_ERROR_PROTOCOL_UNSUPPORTED = 403,
    MMT_ERROR_PROTOCOL_VERSION_MISMATCH = 404,
    MMT_ERROR_PROTOCOL_PARSE_FAILED = 405,
    MMT_ERROR_PROTOCOL_INVALID_STATE = 406,

    /* Session Errors (500-599) */
    MMT_ERROR_SESSION_NOT_FOUND = 500,
    MMT_ERROR_SESSION_CREATE_FAILED = 501,
    MMT_ERROR_SESSION_TIMEOUT = 502,
    MMT_ERROR_SESSION_FULL = 503,
    MMT_ERROR_SESSION_INVALID = 504,
    MMT_ERROR_SESSION_EXPIRED = 505,

    /* File I/O Errors (600-699) */
    MMT_ERROR_FILE_OPEN = 600,
    MMT_ERROR_FILE_READ = 601,
    MMT_ERROR_FILE_WRITE = 602,
    MMT_ERROR_FILE_NOT_FOUND = 603,
    MMT_ERROR_FILE_PERMISSION = 604,
    MMT_ERROR_FILE_EOF = 605,
    MMT_ERROR_FILE_CORRUPT = 606,

    /* Configuration Errors (700-799) */
    MMT_ERROR_CONFIG_INVALID = 700,
    MMT_ERROR_CONFIG_MISSING = 701,
    MMT_ERROR_CONFIG_PARSE = 702,
    MMT_ERROR_CONFIG_VALUE_OUT_OF_RANGE = 703,

    /* Resource Errors (800-899) */
    MMT_ERROR_RESOURCE_EXHAUSTED = 800,
    MMT_ERROR_RESOURCE_BUSY = 801,
    MMT_ERROR_RESOURCE_LOCKED = 802,
    MMT_ERROR_POOL_EXHAUSTED = 803,
    MMT_ERROR_POOL_INVALID = 804,

    /* Thread Safety Errors (900-999) */
    MMT_ERROR_LOCK_FAILED = 900,
    MMT_ERROR_UNLOCK_FAILED = 901,
    MMT_ERROR_DEADLOCK = 902,
    MMT_ERROR_RACE_CONDITION = 903,
    MMT_ERROR_THREAD_CREATE_FAILED = 904,

    /* Maximum error code */
    MMT_ERROR_MAX = 1000
} mmt_error_t;

/**
 * Error context structure
 * Provides detailed information about an error including:
 * - Error code
 * - Source location (file, line, function)
 * - Custom message
 * - System errno if applicable
 */
typedef struct mmt_error_context {
    mmt_error_t code;           /* Error code */
    const char *file;           /* Source file where error occurred */
    int line;                   /* Line number where error occurred */
    const char *function;       /* Function name where error occurred */
    const char *message;        /* Custom error message */
    int system_errno;           /* System errno value if applicable */
} mmt_error_context_t;

/**
 * Get human-readable error message for an error code
 * @param error Error code
 * @return Constant string describing the error
 */
const char* mmt_error_to_string(mmt_error_t error);

/**
 * Set last error with full context
 * Thread-local error storage - each thread has independent error state
 *
 * @param code Error code
 * @param file Source file (typically __FILE__)
 * @param line Line number (typically __LINE__)
 * @param function Function name (typically __func__)
 * @param message Custom error message (can be NULL)
 */
void mmt_set_error(mmt_error_t code, const char *file, int line,
                   const char *function, const char *message);

/**
 * Get last error context for current thread
 * @return Pointer to error context, or NULL if no error set
 */
const mmt_error_context_t* mmt_get_last_error(void);

/**
 * Clear last error for current thread
 */
void mmt_clear_error(void);

/**
 * Check if an error is currently set for current thread
 * @return true if error is set, false otherwise
 */
int mmt_has_error(void);

/**
 * Convenience macro to set error with automatic context
 * Usage: MMT_SET_ERROR(MMT_ERROR_MEMORY_ALLOC, "Failed to allocate buffer");
 */
#define MMT_SET_ERROR(code, msg) \
    mmt_set_error(code, __FILE__, __LINE__, __func__, msg)

/**
 * Macro to return error code after setting error context
 * Usage: MMT_RETURN_ERROR(MMT_ERROR_INVALID_INPUT, "Packet is NULL");
 */
#define MMT_RETURN_ERROR(code, msg) \
    do { \
        MMT_SET_ERROR(code, msg); \
        return code; \
    } while(0)

/**
 * Check condition and return error if false
 * Usage: MMT_CHECK(ptr != NULL, MMT_ERROR_MEMORY_NULL_PTR, "Buffer is NULL");
 */
#define MMT_CHECK(condition, error_code, msg) \
    do { \
        if (!(condition)) { \
            MMT_RETURN_ERROR(error_code, msg); \
        } \
    } while(0)

/**
 * Check pointer is not NULL, return error if NULL
 * Usage: MMT_CHECK_NOT_NULL(buffer, "Buffer is NULL");
 */
#define MMT_CHECK_NOT_NULL(ptr, msg) \
    MMT_CHECK((ptr) != NULL, MMT_ERROR_MEMORY_NULL_PTR, msg)

/**
 * Check condition and return 0 if false (for protocol handlers)
 * Protocol classification functions return 0 for "not classified"
 * Usage: MMT_CHECK_PROTOCOL(pkt != NULL, "Packet is NULL");
 */
#define MMT_CHECK_PROTOCOL(condition, msg) \
    do { \
        if (!(condition)) { \
            MMT_SET_ERROR(MMT_ERROR_INVALID_INPUT, msg); \
            return 0; \
        } \
    } while(0)

/**
 * Check condition and return NULL if false (for pointer-returning functions)
 * Usage: MMT_CHECK_NULL_RETURN(session != NULL, "Session not found");
 */
#define MMT_CHECK_NULL_RETURN(condition, error_code, msg) \
    do { \
        if (!(condition)) { \
            MMT_SET_ERROR(error_code, msg); \
            return NULL; \
        } \
    } while(0)

/**
 * Check memory allocation result, return error if NULL
 * Usage: MMT_CHECK_ALLOC(ptr, "Failed to allocate session");
 */
#define MMT_CHECK_ALLOC(ptr, msg) \
    MMT_CHECK_NOT_NULL(ptr, msg)

/**
 * Propagate error from called function
 * If the called function set an error, return same error code
 * Usage:
 *   int result = some_function();
 *   MMT_PROPAGATE_ERROR(result);
 */
#define MMT_PROPAGATE_ERROR(result) \
    do { \
        if ((result) != MMT_SUCCESS && mmt_has_error()) { \
            return (result); \
        } \
    } while(0)

#endif /* MMT_ERRORS_H */
