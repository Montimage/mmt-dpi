/**
 * MMT Recovery Strategies Implementation
 * Phase 5: Error Handling and Logging Framework
 *
 * Implements error recovery mechanisms for graceful degradation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "../public_include/mmt_recovery.h"
#include "../public_include/mmt_errors.h"
#include "../public_include/mmt_logging.h"

/* Maximum number of protocol fallback handlers */
#define MAX_FALLBACK_HANDLERS 256

/* Default retry configuration */
const mmt_retry_config_t MMT_DEFAULT_RETRY_CONFIG = {
	.max_retries = 3, .base_delay_ms = 10, .exponential_backoff = true, .max_delay_ms = 1000};

/* Global recovery statistics */
static mmt_recovery_stats_t g_recovery_stats = {0};

/* Fallback handler registry */
static mmt_fallback_handler_t g_fallback_handlers[MAX_FALLBACK_HANDLERS] = {NULL};

/* Degraded session tracking (simplified) */
#define MAX_DEGRADED_SESSIONS 1024
static bool g_degraded_sessions[MAX_DEGRADED_SESSIONS] = {false};

/*
 * ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * Calculate delay for retry attempt
 */
static uint32_t calculate_retry_delay(uint32_t attempt, const mmt_retry_config_t *config)
{
	uint32_t delay = config->base_delay_ms;

	if (config->exponential_backoff) {
		/* Exponential backoff: delay = base * 2^attempt */
		for (uint32_t i = 0; i < attempt && delay < config->max_delay_ms; i++) {
			delay *= 2;
		}
	}

	/* Cap at maximum delay */
	if (delay > config->max_delay_ms) {
		delay = config->max_delay_ms;
	}

	return delay;
}

/**
 * Sleep for specified milliseconds
 */
static void sleep_ms(uint32_t ms)
{
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;
	nanosleep(&ts, NULL);
}

/**
 * Hash session key for degraded tracking (simplified)
 */
static uint32_t hash_session_key(const void *key)
{
	/* Simple hash for demonstration */
	uintptr_t ptr = (uintptr_t)key;
	return (uint32_t)(ptr % MAX_DEGRADED_SESSIONS);
}

/*
 * ============================================================================
 * Protocol Fallback Implementation
 * ============================================================================
 */

mmt_recovery_result_t mmt_protocol_fallback(uint32_t protocol_id, const void *packet, uint32_t offset,
											mmt_fallback_strategy_t strategy)
{
	MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_PROTOCOL, "Attempting protocol fallback: proto=%u, strategy=%d", protocol_id,
					  strategy);

	g_recovery_stats.protocol_fallbacks++;

	switch (strategy) {
		case MMT_FALLBACK_NONE:
			MMT_LOG_DEBUG("No fallback configured");
			g_recovery_stats.failed_recoveries++;
			return MMT_RECOVERY_FAILED;

		case MMT_FALLBACK_GENERIC:
			MMT_LOG_INFO_CAT(MMT_LOG_CAT_PROTOCOL, "Using generic parser for protocol %u", protocol_id);
			/* In real implementation, would call generic parser */
			g_recovery_stats.successful_recoveries++;
			return MMT_RECOVERY_SUCCESS;

		case MMT_FALLBACK_NEXT_LAYER:
			MMT_LOG_INFO_CAT(MMT_LOG_CAT_PROTOCOL, "Skipping to next protocol layer");
			g_recovery_stats.successful_recoveries++;
			return MMT_RECOVERY_SKIP;

		case MMT_FALLBACK_ALTERNATIVE:
			/* Check if custom fallback handler registered */
			if (protocol_id < MAX_FALLBACK_HANDLERS && g_fallback_handlers[protocol_id] != NULL) {
				MMT_LOG_INFO_CAT(MMT_LOG_CAT_PROTOCOL, "Using custom fallback handler");
				mmt_recovery_result_t result = g_fallback_handlers[protocol_id](packet, offset);
				if (result == MMT_RECOVERY_SUCCESS) {
					g_recovery_stats.successful_recoveries++;
				} else {
					g_recovery_stats.failed_recoveries++;
				}
				return result;
			} else {
				MMT_LOG_WARN_CAT(MMT_LOG_CAT_PROTOCOL, "No alternative parser available");
				g_recovery_stats.failed_recoveries++;
				return MMT_RECOVERY_FAILED;
			}

		case MMT_FALLBACK_RAW:
			MMT_LOG_INFO_CAT(MMT_LOG_CAT_PROTOCOL, "Treating as raw data");
			g_recovery_stats.successful_recoveries++;
			return MMT_RECOVERY_SUCCESS;

		default:
			MMT_LOG_ERROR_CAT(MMT_LOG_CAT_PROTOCOL, "Unknown fallback strategy: %d", strategy);
			g_recovery_stats.failed_recoveries++;
			return MMT_RECOVERY_FAILED;
	}
}

bool mmt_protocol_has_fallback(uint32_t protocol_id)
{
	/* Check if custom fallback registered */
	if (protocol_id < MAX_FALLBACK_HANDLERS && g_fallback_handlers[protocol_id] != NULL) {
		return true;
	}

	/* Generic fallback always available */
	return true;
}

mmt_fallback_strategy_t mmt_protocol_get_fallback_strategy(uint32_t protocol_id)
{
	/* Check if custom handler available */
	if (protocol_id < MAX_FALLBACK_HANDLERS && g_fallback_handlers[protocol_id] != NULL) {
		return MMT_FALLBACK_ALTERNATIVE;
	}

	/* Default to generic parser */
	return MMT_FALLBACK_GENERIC;
}

mmt_error_t mmt_protocol_register_fallback(uint32_t protocol_id, mmt_fallback_handler_t handler)
{
	if (protocol_id >= MAX_FALLBACK_HANDLERS) {
		MMT_RETURN_ERROR(MMT_ERROR_INVALID_PROTOCOL, "Protocol ID out of range");
	}

	if (handler == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_INVALID_PARAMETER, "Handler is NULL");
	}

	g_fallback_handlers[protocol_id] = handler;

	MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_PROTOCOL, "Registered fallback handler for protocol %u", protocol_id);

	return MMT_SUCCESS;
}

/*
 * ============================================================================
 * Session Recovery Implementation
 * ============================================================================
 */

mmt_recovery_result_t mmt_session_recover(const void *session_key, mmt_error_t error, mmt_session_recovery_t strategy,
										  const mmt_retry_config_t *retry_config)
{
	MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_SESSION, "Attempting session recovery: error=%d, strategy=%d", error, strategy);

	g_recovery_stats.session_recoveries++;

	/* Use default config if none provided */
	if (retry_config == NULL) {
		retry_config = &MMT_DEFAULT_RETRY_CONFIG;
	}

	switch (strategy) {
		case MMT_SESSION_RECOVERY_NONE:
			MMT_LOG_DEBUG("No recovery configured");
			g_recovery_stats.failed_recoveries++;
			return MMT_RECOVERY_FAILED;

		case MMT_SESSION_RECOVERY_RETRY:
			MMT_LOG_INFO_CAT(MMT_LOG_CAT_SESSION, "Will retry operation");
			g_recovery_stats.successful_recoveries++;
			return MMT_RECOVERY_RETRY;

		case MMT_SESSION_RECOVERY_CREATE:
			MMT_LOG_INFO_CAT(MMT_LOG_CAT_SESSION, "Creating new session");
			/* In real implementation, would create session */
			g_recovery_stats.successful_recoveries++;
			return MMT_RECOVERY_SUCCESS;

		case MMT_SESSION_RECOVERY_DEGRADE:
			MMT_LOG_WARN_CAT(MMT_LOG_CAT_SESSION, "Marking session as degraded");
			mmt_session_mark_degraded(session_key);
			g_recovery_stats.successful_recoveries++;
			return MMT_RECOVERY_SUCCESS;

		case MMT_SESSION_RECOVERY_SKIP:
			MMT_LOG_INFO_CAT(MMT_LOG_CAT_SESSION, "Skipping session operation");
			g_recovery_stats.successful_recoveries++;
			return MMT_RECOVERY_SKIP;

		default:
			MMT_LOG_ERROR_CAT(MMT_LOG_CAT_SESSION, "Unknown recovery strategy: %d", strategy);
			g_recovery_stats.failed_recoveries++;
			return MMT_RECOVERY_FAILED;
	}
}

mmt_error_t mmt_execute_with_retry(mmt_retryable_operation_t operation, void *context,
								   const mmt_retry_config_t *retry_config)
{
	if (operation == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_INVALID_PARAMETER, "Operation is NULL");
	}

	/* Use default config if none provided */
	if (retry_config == NULL) {
		retry_config = &MMT_DEFAULT_RETRY_CONFIG;
	}

	mmt_error_t result = MMT_ERROR_GENERIC;
	uint32_t attempt = 0;

	MMT_LOG_DEBUG("Executing operation with retry: max_retries=%u", retry_config->max_retries);

	/* Initial attempt */
	result = operation(context);
	if (result == MMT_SUCCESS) {
		MMT_LOG_DEBUG("Operation succeeded on first attempt");
		g_recovery_stats.successful_recoveries++;
		return MMT_SUCCESS;
	}

	/* Retry attempts */
	for (attempt = 1; attempt <= retry_config->max_retries; attempt++) {
		/* Calculate and apply delay */
		uint32_t delay_ms = calculate_retry_delay(attempt - 1, retry_config);

		MMT_LOG_DEBUG("Retry attempt %u/%u after %ums delay", attempt, retry_config->max_retries, delay_ms);

		sleep_ms(delay_ms);
		g_recovery_stats.retry_attempts++;

		/* Retry operation */
		result = operation(context);
		if (result == MMT_SUCCESS) {
			MMT_LOG_INFO("Operation succeeded after %u retries", attempt);
			g_recovery_stats.successful_recoveries++;
			return MMT_SUCCESS;
		}

		MMT_LOG_WARN("Retry attempt %u failed: %s", attempt, mmt_error_to_string(result));
	}

	/* All retries exhausted */
	MMT_LOG_ERROR("Operation failed after %u retries", retry_config->max_retries);
	g_recovery_stats.failed_recoveries++;
	return result;
}

mmt_error_t mmt_session_mark_degraded(const void *session_key)
{
	if (session_key == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_INVALID_PARAMETER, "Session key is NULL");
	}

	uint32_t hash = hash_session_key(session_key);
	g_degraded_sessions[hash] = true;

	MMT_LOG_WARN_CAT(MMT_LOG_CAT_SESSION, "Session marked as degraded: hash=%u", hash);

	return MMT_SUCCESS;
}

bool mmt_session_is_degraded(const void *session_key)
{
	if (session_key == NULL) {
		return false;
	}

	uint32_t hash = hash_session_key(session_key);
	return g_degraded_sessions[hash];
}

mmt_error_t mmt_session_restore(const void *session_key)
{
	if (session_key == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_INVALID_PARAMETER, "Session key is NULL");
	}

	uint32_t hash = hash_session_key(session_key);

	if (!g_degraded_sessions[hash]) {
		MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_SESSION, "Session not degraded, no restore needed");
		return MMT_SUCCESS;
	}

	g_degraded_sessions[hash] = false;

	MMT_LOG_INFO_CAT(MMT_LOG_CAT_SESSION, "Session restored from degraded state: hash=%u", hash);

	return MMT_SUCCESS;
}

/*
 * ============================================================================
 * Statistics Implementation
 * ============================================================================
 */

void mmt_recovery_get_stats(mmt_recovery_stats_t *stats)
{
	if (stats == NULL) {
		return;
	}

	memcpy(stats, &g_recovery_stats, sizeof(mmt_recovery_stats_t));
}

void mmt_recovery_reset_stats(void)
{
	memset(&g_recovery_stats, 0, sizeof(mmt_recovery_stats_t));
	MMT_LOG_INFO("Recovery statistics reset");
}

void mmt_recovery_print_stats(void)
{
	printf("\n");
	printf("================================================\n");
	printf(" Recovery Statistics\n");
	printf("================================================\n");
	printf("Protocol fallbacks:      %lu\n", g_recovery_stats.protocol_fallbacks);
	printf("Session recoveries:      %lu\n", g_recovery_stats.session_recoveries);
	printf("Successful recoveries:   %lu\n", g_recovery_stats.successful_recoveries);
	printf("Failed recoveries:       %lu\n", g_recovery_stats.failed_recoveries);
	printf("Retry attempts:          %lu\n", g_recovery_stats.retry_attempts);

	if (g_recovery_stats.protocol_fallbacks + g_recovery_stats.session_recoveries > 0) {
		uint64_t total = g_recovery_stats.protocol_fallbacks + g_recovery_stats.session_recoveries;
		double success_rate = (double)g_recovery_stats.successful_recoveries / total * 100.0;
		printf("Success rate:            %.1f%%\n", success_rate);
	}

	printf("================================================\n\n");
}
