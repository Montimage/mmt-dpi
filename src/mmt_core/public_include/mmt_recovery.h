#ifndef MMT_RECOVERY_H
#define MMT_RECOVERY_H

/**
 * MMT Recovery Strategies
 * Phase 5: Error Handling and Logging Framework
 *
 * Provides error recovery mechanisms for graceful degradation:
 * - Protocol fallback when classification fails
 * - Session recovery with retry logic
 * - Degraded mode operation
 */

#include <stdbool.h>
#include <stdint.h>
#include "mmt_errors.h"
#include "mmt_logging.h"

/**
 * Recovery action result
 */
typedef enum {
    MMT_RECOVERY_SUCCESS = 0,      /* Recovery succeeded */
    MMT_RECOVERY_FAILED,           /* Recovery failed */
    MMT_RECOVERY_RETRY,            /* Should retry operation */
    MMT_RECOVERY_SKIP,             /* Skip and continue */
    MMT_RECOVERY_ABORT             /* Abort processing */
} mmt_recovery_result_t;

/**
 * Protocol fallback options
 */
typedef enum {
    MMT_FALLBACK_NONE = 0,         /* No fallback */
    MMT_FALLBACK_GENERIC,          /* Use generic parser */
    MMT_FALLBACK_NEXT_LAYER,       /* Try next protocol layer */
    MMT_FALLBACK_ALTERNATIVE,      /* Try alternative parser */
    MMT_FALLBACK_RAW               /* Treat as raw data */
} mmt_fallback_strategy_t;

/**
 * Session recovery options
 */
typedef enum {
    MMT_SESSION_RECOVERY_NONE = 0, /* No recovery */
    MMT_SESSION_RECOVERY_RETRY,    /* Retry operation */
    MMT_SESSION_RECOVERY_CREATE,   /* Create new session */
    MMT_SESSION_RECOVERY_DEGRADE,  /* Mark as degraded */
    MMT_SESSION_RECOVERY_SKIP      /* Skip session operation */
} mmt_session_recovery_t;

/**
 * Recovery statistics
 */
typedef struct {
    uint64_t protocol_fallbacks;         /* Protocol fallback count */
    uint64_t session_recoveries;         /* Session recovery count */
    uint64_t successful_recoveries;      /* Successful recovery count */
    uint64_t failed_recoveries;          /* Failed recovery count */
    uint64_t retry_attempts;             /* Total retry attempts */
} mmt_recovery_stats_t;

/*
 * ============================================================================
 * Protocol Fallback Functions
 * ============================================================================
 */

/**
 * Attempt protocol fallback when classification fails
 *
 * @param protocol_id Failed protocol ID
 * @param packet Packet data
 * @param offset Current offset in packet
 * @param strategy Fallback strategy to use
 * @return Recovery result
 */
mmt_recovery_result_t mmt_protocol_fallback(
    uint32_t protocol_id,
    const void *packet,
    uint32_t offset,
    mmt_fallback_strategy_t strategy
);

/**
 * Check if protocol has fallback available
 *
 * @param protocol_id Protocol ID to check
 * @return true if fallback available, false otherwise
 */
bool mmt_protocol_has_fallback(uint32_t protocol_id);

/**
 * Get recommended fallback strategy for protocol
 *
 * @param protocol_id Protocol ID
 * @return Recommended fallback strategy
 */
mmt_fallback_strategy_t mmt_protocol_get_fallback_strategy(uint32_t protocol_id);

/**
 * Register custom fallback handler for protocol
 *
 * @param protocol_id Protocol ID
 * @param handler Fallback handler function
 * @return MMT_SUCCESS on success, error code otherwise
 */
typedef mmt_recovery_result_t (*mmt_fallback_handler_t)(
    const void *packet,
    uint32_t offset
);

mmt_error_t mmt_protocol_register_fallback(
    uint32_t protocol_id,
    mmt_fallback_handler_t handler
);

/*
 * ============================================================================
 * Session Recovery Functions
 * ============================================================================
 */

/**
 * Retry configuration for session operations
 */
typedef struct {
    uint32_t max_retries;           /* Maximum retry attempts */
    uint32_t base_delay_ms;         /* Base delay in milliseconds */
    bool exponential_backoff;       /* Use exponential backoff */
    uint32_t max_delay_ms;          /* Maximum delay between retries */
} mmt_retry_config_t;

/**
 * Attempt session recovery after operation failure
 *
 * @param session_key Session key
 * @param error Error that occurred
 * @param strategy Recovery strategy
 * @param retry_config Retry configuration (can be NULL for defaults)
 * @return Recovery result
 */
mmt_recovery_result_t mmt_session_recover(
    const void *session_key,
    mmt_error_t error,
    mmt_session_recovery_t strategy,
    const mmt_retry_config_t *retry_config
);

/**
 * Execute operation with automatic retry
 *
 * @param operation Function to execute
 * @param context Context passed to operation
 * @param retry_config Retry configuration
 * @return Operation result (last attempt)
 */
typedef mmt_error_t (*mmt_retryable_operation_t)(void *context);

mmt_error_t mmt_execute_with_retry(
    mmt_retryable_operation_t operation,
    void *context,
    const mmt_retry_config_t *retry_config
);

/**
 * Mark session as degraded
 *
 * @param session_key Session key
 * @return MMT_SUCCESS on success, error code otherwise
 */
mmt_error_t mmt_session_mark_degraded(const void *session_key);

/**
 * Check if session is in degraded mode
 *
 * @param session_key Session key
 * @return true if degraded, false otherwise
 */
bool mmt_session_is_degraded(const void *session_key);

/**
 * Attempt to restore degraded session
 *
 * @param session_key Session key
 * @return MMT_SUCCESS if restored, error code otherwise
 */
mmt_error_t mmt_session_restore(const void *session_key);

/*
 * ============================================================================
 * Recovery Statistics
 * ============================================================================
 */

/**
 * Get recovery statistics
 *
 * @param stats Pointer to statistics structure to fill
 */
void mmt_recovery_get_stats(mmt_recovery_stats_t *stats);

/**
 * Reset recovery statistics
 */
void mmt_recovery_reset_stats(void);

/**
 * Print recovery statistics summary
 */
void mmt_recovery_print_stats(void);

/*
 * ============================================================================
 * Default Configurations
 * ============================================================================
 */

/**
 * Default retry configuration
 */
extern const mmt_retry_config_t MMT_DEFAULT_RETRY_CONFIG;

/*
 * ============================================================================
 * Convenience Macros
 * ============================================================================
 */

/**
 * Try operation with automatic fallback
 *
 * Usage:
 *   MMT_TRY_WITH_FALLBACK(
 *       classify_protocol(packet),
 *       mmt_protocol_fallback(proto_id, packet, offset, MMT_FALLBACK_GENERIC)
 *   );
 */
#define MMT_TRY_WITH_FALLBACK(operation, fallback) \
    do { \
        if (!(operation)) { \
            MMT_LOG_WARN("Operation failed, attempting fallback"); \
            fallback; \
        } \
    } while(0)

/**
 * Execute with automatic retry on error
 *
 * Usage:
 *   mmt_error_t result;
 *   MMT_RETRY_ON_ERROR(result, create_session(key), NULL);
 */
#define MMT_RETRY_ON_ERROR(result_var, operation, retry_cfg) \
    do { \
        result_var = mmt_execute_with_retry( \
            (mmt_retryable_operation_t)operation, \
            NULL, \
            retry_cfg ? retry_cfg : &MMT_DEFAULT_RETRY_CONFIG \
        ); \
    } while(0)

/**
 * Continue processing on non-fatal error
 *
 * Usage:
 *   MMT_CONTINUE_ON_ERROR(result, MMT_ERROR_SESSION_NOT_FOUND);
 */
#define MMT_CONTINUE_ON_ERROR(result, expected_error) \
    do { \
        if ((result) == (expected_error)) { \
            MMT_LOG_DEBUG("Non-fatal error, continuing: %s", \
                         mmt_error_to_string(result)); \
            result = MMT_SUCCESS; \
        } \
    } while(0)

/**
 * Skip operation if session is degraded
 *
 * Usage:
 *   MMT_SKIP_IF_DEGRADED(session_key, return MMT_SUCCESS);
 */
#define MMT_SKIP_IF_DEGRADED(session_key, skip_action) \
    do { \
        if (mmt_session_is_degraded(session_key)) { \
            MMT_LOG_DEBUG("Skipping operation for degraded session"); \
            skip_action; \
        } \
    } while(0)

#endif /* MMT_RECOVERY_H */
