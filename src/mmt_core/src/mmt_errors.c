/**
 * MMT Error Handling Implementation
 * Phase 5: Error Handling and Logging Framework
 *
 * Thread-safe error tracking with detailed context
 */

#include <string.h>
#include <errno.h>
#include "../public_include/mmt_errors.h"

/* Thread-local error storage - each thread has independent error state */
static __thread mmt_error_context_t g_last_error = {0};

/**
 * Error message strings
 * Indexed by error code for fast lookup
 */
static const char *g_error_messages[MMT_ERROR_MAX] = {
	/* Success */
	[MMT_SUCCESS] = "Success",

	/* General Errors (1-99) */
	[MMT_ERROR_GENERIC] = "Generic error",
	[MMT_ERROR_NOT_IMPLEMENTED] = "Not implemented",
	[MMT_ERROR_INTERNAL] = "Internal error",
	[MMT_ERROR_ASSERTION_FAILED] = "Assertion failed",
	[MMT_ERROR_UNKNOWN] = "Unknown error",

	/* Memory Errors (100-199) */
	[MMT_ERROR_MEMORY_ALLOC] = "Memory allocation failed",
	[MMT_ERROR_MEMORY_NULL_PTR] = "Null pointer dereference",
	[MMT_ERROR_MEMORY_OUT_OF_BOUNDS] = "Out of bounds memory access",
	[MMT_ERROR_MEMORY_LEAK] = "Memory leak detected",
	[MMT_ERROR_MEMORY_DOUBLE_FREE] = "Double free detected",
	[MMT_ERROR_MEMORY_CORRUPTION] = "Memory corruption detected",

	/* Input Validation Errors (200-299) */
	[MMT_ERROR_INVALID_INPUT] = "Invalid input",
	[MMT_ERROR_INVALID_PARAMETER] = "Invalid parameter",
	[MMT_ERROR_INVALID_OFFSET] = "Invalid offset",
	[MMT_ERROR_INVALID_LENGTH] = "Invalid length",
	[MMT_ERROR_INVALID_PROTOCOL] = "Invalid protocol",
	[MMT_ERROR_INVALID_VERSION] = "Invalid version",
	[MMT_ERROR_BUFFER_TOO_SMALL] = "Buffer too small",
	[MMT_ERROR_OVERFLOW] = "Integer overflow",
	[MMT_ERROR_UNDERFLOW] = "Integer underflow",
	[MMT_ERROR_INVALID_STATE] = "Invalid state",
	[MMT_ERROR_INVALID_FORMAT] = "Invalid format",

	/* Packet Processing Errors (300-399) */
	[MMT_ERROR_PACKET_TOO_SHORT] = "Packet too short",
	[MMT_ERROR_PACKET_MALFORMED] = "Malformed packet",
	[MMT_ERROR_PACKET_TRUNCATED] = "Truncated packet",
	[MMT_ERROR_PACKET_INVALID_HEADER] = "Invalid packet header",
	[MMT_ERROR_PACKET_CHECKSUM] = "Packet checksum error",
	[MMT_ERROR_PACKET_FRAGMENTED] = "Fragmented packet",
	[MMT_ERROR_PACKET_REASSEMBLY_FAILED] = "Packet reassembly failed",

	/* Protocol Errors (400-499) */
	[MMT_ERROR_PROTOCOL_NOT_FOUND] = "Protocol not found",
	[MMT_ERROR_PROTOCOL_NOT_REGISTERED] = "Protocol not registered",
	[MMT_ERROR_PROTOCOL_ALREADY_REGISTERED] = "Protocol already registered",
	[MMT_ERROR_PROTOCOL_UNSUPPORTED] = "Protocol not supported",
	[MMT_ERROR_PROTOCOL_VERSION_MISMATCH] = "Protocol version mismatch",
	[MMT_ERROR_PROTOCOL_PARSE_FAILED] = "Protocol parsing failed",
	[MMT_ERROR_PROTOCOL_INVALID_STATE] = "Invalid protocol state",

	/* Session Errors (500-599) */
	[MMT_ERROR_SESSION_NOT_FOUND] = "Session not found",
	[MMT_ERROR_SESSION_CREATE_FAILED] = "Session creation failed",
	[MMT_ERROR_SESSION_TIMEOUT] = "Session timeout",
	[MMT_ERROR_SESSION_FULL] = "Session table full",
	[MMT_ERROR_SESSION_INVALID] = "Invalid session",
	[MMT_ERROR_SESSION_EXPIRED] = "Session expired",

	/* File I/O Errors (600-699) */
	[MMT_ERROR_FILE_OPEN] = "File open failed",
	[MMT_ERROR_FILE_READ] = "File read failed",
	[MMT_ERROR_FILE_WRITE] = "File write failed",
	[MMT_ERROR_FILE_NOT_FOUND] = "File not found",
	[MMT_ERROR_FILE_PERMISSION] = "File permission denied",
	[MMT_ERROR_FILE_EOF] = "End of file",
	[MMT_ERROR_FILE_CORRUPT] = "File corrupted",

	/* Configuration Errors (700-799) */
	[MMT_ERROR_CONFIG_INVALID] = "Invalid configuration",
	[MMT_ERROR_CONFIG_MISSING] = "Missing configuration",
	[MMT_ERROR_CONFIG_PARSE] = "Configuration parse error",
	[MMT_ERROR_CONFIG_VALUE_OUT_OF_RANGE] = "Configuration value out of range",

	/* Resource Errors (800-899) */
	[MMT_ERROR_RESOURCE_EXHAUSTED] = "Resource exhausted",
	[MMT_ERROR_RESOURCE_BUSY] = "Resource busy",
	[MMT_ERROR_RESOURCE_LOCKED] = "Resource locked",
	[MMT_ERROR_POOL_EXHAUSTED] = "Memory pool exhausted",
	[MMT_ERROR_POOL_INVALID] = "Invalid memory pool",

	/* Thread Safety Errors (900-999) */
	[MMT_ERROR_LOCK_FAILED] = "Lock acquisition failed",
	[MMT_ERROR_UNLOCK_FAILED] = "Lock release failed",
	[MMT_ERROR_DEADLOCK] = "Deadlock detected",
	[MMT_ERROR_RACE_CONDITION] = "Race condition detected",
	[MMT_ERROR_THREAD_CREATE_FAILED] = "Thread creation failed",
};

const char *mmt_error_to_string(mmt_error_t error)
{
	/* Validate error code is in range */
	if (error < 0 || error >= MMT_ERROR_MAX) {
		return "Invalid error code";
	}

	/* Return error message if defined */
	if (g_error_messages[error] != NULL) {
		return g_error_messages[error];
	}

	/* Default for undefined error codes */
	return "Unknown error";
}

void mmt_set_error(mmt_error_t code, const char *file, int line, const char *function, const char *message)
{
	/* Store error context in thread-local storage */
	g_last_error.code = code;
	g_last_error.file = file;
	g_last_error.line = line;
	g_last_error.function = function;
	g_last_error.message = message;
	g_last_error.system_errno = errno; /* Capture current errno */
}

const mmt_error_context_t *mmt_get_last_error(void)
{
	/* Return NULL if no error is set */
	if (g_last_error.code == MMT_SUCCESS) {
		return NULL;
	}

	/* Return pointer to thread-local error context */
	return &g_last_error;
}

void mmt_clear_error(void)
{
	/* Zero out thread-local error context */
	memset(&g_last_error, 0, sizeof(g_last_error));
}

int mmt_has_error(void)
{
	/* Return true if error code is not success */
	return (g_last_error.code != MMT_SUCCESS);
}
