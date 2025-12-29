#ifndef MMT_DEBUG_H
#define MMT_DEBUG_H

/**
 * MMT Debug and Diagnostic Tools
 * Phase 5: Error Handling and Logging Framework
 *
 * Provides debugging and diagnostic utilities:
 * - Packet hexdump with annotations
 * - Error statistics and tracking
 * - Performance profiling
 * - Memory diagnostics
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "mmt_errors.h"

/*
 * ============================================================================
 * Packet Dump Utilities
 * ============================================================================
 */

/**
 * Dump format options
 */
typedef enum {
	MMT_DUMP_HEX = 0x01,      /* Hexadecimal dump */
	MMT_DUMP_ASCII = 0x02,    /* ASCII representation */
	MMT_DUMP_ANNOTATE = 0x04, /* Add protocol annotations */
	MMT_DUMP_OFFSETS = 0x08,  /* Show byte offsets */
	MMT_DUMP_COLORS = 0x10,   /* Use ANSI colors */
	MMT_DUMP_FULL = 0xFF      /* All options */
} mmt_dump_flags_t;

/**
 * Dump packet data to output
 *
 * @param data Packet data
 * @param length Data length
 * @param offset Starting offset for display
 * @param flags Dump flags
 * @param output Output file (NULL for stdout)
 */
void mmt_dump_packet(const uint8_t *data, size_t length, size_t offset, uint32_t flags, FILE *output);

/**
 * Dump packet with protocol annotation
 *
 * @param data Packet data
 * @param length Data length
 * @param protocol_name Protocol name
 * @param output Output file (NULL for stdout)
 */
void mmt_dump_packet_annotated(const uint8_t *data, size_t length, const char *protocol_name, FILE *output);

/**
 * Dump specific packet range
 *
 * @param data Packet data
 * @param start Start offset
 * @param end End offset
 * @param label Label for this range
 * @param output Output file (NULL for stdout)
 */
void mmt_dump_packet_range(const uint8_t *data, size_t start, size_t end, const char *label, FILE *output);

/**
 * Dump packet to string buffer
 *
 * @param data Packet data
 * @param length Data length
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param flags Dump flags
 * @return Number of bytes written
 */
size_t mmt_dump_packet_to_string(const uint8_t *data, size_t length, char *buffer, size_t buffer_size, uint32_t flags);

/**
 * Save packet dump to file
 *
 * @param data Packet data
 * @param length Data length
 * @param filename Output filename
 * @param flags Dump flags
 * @return MMT_SUCCESS on success, error code otherwise
 */
mmt_error_t mmt_dump_packet_to_file(const uint8_t *data, size_t length, const char *filename, uint32_t flags);

/*
 * ============================================================================
 * Error Statistics
 * ============================================================================
 */

/**
 * Error statistics entry
 */
typedef struct {
	mmt_error_t error_code;    /* Error code */
	uint64_t count;            /* Occurrence count */
	const char *last_file;     /* Last file where error occurred */
	int last_line;             /* Last line number */
	const char *last_function; /* Last function name */
	const char *last_message;  /* Last error message */
} mmt_error_stat_entry_t;

/**
 * Error statistics summary
 */
typedef struct {
	uint64_t total_errors;           /* Total error count */
	uint64_t unique_errors;          /* Unique error types */
	mmt_error_t most_frequent_error; /* Most common error */
	uint64_t most_frequent_count;    /* Count of most common */
} mmt_error_stats_summary_t;

/**
 * Enable error statistics tracking
 *
 * @param enabled true to enable, false to disable
 */
void mmt_error_stats_enable(bool enabled);

/**
 * Check if error statistics are enabled
 *
 * @return true if enabled, false otherwise
 */
bool mmt_error_stats_is_enabled(void);

/**
 * Record error occurrence for statistics
 *
 * @param error_code Error code
 * @param file Source file
 * @param line Line number
 * @param function Function name
 * @param message Error message
 */
void mmt_error_stats_record(mmt_error_t error_code, const char *file, int line, const char *function,
							const char *message);

/**
 * Get error statistics for specific error
 *
 * @param error_code Error code
 * @param entry Output entry (can be NULL to just get count)
 * @return Error occurrence count
 */
uint64_t mmt_error_stats_get(mmt_error_t error_code, mmt_error_stat_entry_t *entry);

/**
 * Get overall error statistics summary
 *
 * @param summary Output summary structure
 */
void mmt_error_stats_get_summary(mmt_error_stats_summary_t *summary);

/**
 * Get top N most frequent errors
 *
 * @param entries Output array
 * @param max_entries Maximum entries to return
 * @return Number of entries filled
 */
size_t mmt_error_stats_get_top_errors(mmt_error_stat_entry_t *entries, size_t max_entries);

/**
 * Print error statistics report
 *
 * @param output Output file (NULL for stdout)
 * @param top_n Number of top errors to show (0 for all)
 */
void mmt_error_stats_print(FILE *output, size_t top_n);

/**
 * Reset error statistics
 */
void mmt_error_stats_reset(void);

/**
 * Save error statistics to file
 *
 * @param filename Output filename
 * @return MMT_SUCCESS on success, error code otherwise
 */
mmt_error_t mmt_error_stats_save(const char *filename);

/*
 * ============================================================================
 * Memory Diagnostics
 * ============================================================================
 */

/**
 * Memory allocation tracking entry
 */
typedef struct {
	void *address;        /* Allocation address */
	size_t size;          /* Allocation size */
	const char *file;     /* Source file */
	int line;             /* Line number */
	const char *function; /* Function name */
} mmt_mem_alloc_entry_t;

/**
 * Memory statistics
 */
typedef struct {
	uint64_t total_allocations;       /* Total allocations */
	uint64_t total_deallocations;     /* Total deallocations */
	uint64_t current_allocations;     /* Current active allocations */
	uint64_t peak_allocations;        /* Peak allocation count */
	uint64_t total_bytes_allocated;   /* Total bytes allocated */
	uint64_t current_bytes_allocated; /* Current bytes allocated */
	uint64_t peak_bytes_allocated;    /* Peak bytes allocated */
} mmt_mem_stats_t;

/**
 * Enable memory tracking
 *
 * @param enabled true to enable, false to disable
 */
void mmt_mem_tracking_enable(bool enabled);

/**
 * Check if memory tracking is enabled
 *
 * @return true if enabled, false otherwise
 */
bool mmt_mem_tracking_is_enabled(void);

/**
 * Get memory statistics
 *
 * @param stats Output statistics structure
 */
void mmt_mem_get_stats(mmt_mem_stats_t *stats);

/**
 * Print memory statistics
 *
 * @param output Output file (NULL for stdout)
 */
void mmt_mem_print_stats(FILE *output);

/**
 * Check for memory leaks
 *
 * @param output Output file (NULL for stdout)
 * @return Number of leaks detected
 */
size_t mmt_mem_check_leaks(FILE *output);

/*
 * ============================================================================
 * Performance Profiling
 * ============================================================================
 */

/**
 * Profiling point
 */
typedef struct mmt_profile_point mmt_profile_point_t;

/**
 * Start profiling a code section
 *
 * @param name Profile point name
 * @return Profile point handle
 */
mmt_profile_point_t *mmt_profile_start(const char *name);

/**
 * End profiling for a code section
 *
 * @param point Profile point handle
 */
void mmt_profile_end(mmt_profile_point_t *point);

/**
 * Get elapsed time for profile point (in nanoseconds)
 *
 * @param point Profile point handle
 * @return Elapsed time in nanoseconds
 */
uint64_t mmt_profile_get_elapsed(const mmt_profile_point_t *point);

/**
 * Print profiling report
 *
 * @param output Output file (NULL for stdout)
 */
void mmt_profile_print_report(FILE *output);

/**
 * Reset profiling data
 */
void mmt_profile_reset(void);

/*
 * ============================================================================
 * Convenience Macros
 * ============================================================================
 */

/**
 * Quick hexdump to stdout
 */
#define MMT_HEXDUMP(data, len) \
	mmt_dump_packet((const uint8_t *)(data), (len), 0, MMT_DUMP_HEX | MMT_DUMP_ASCII | MMT_DUMP_OFFSETS, NULL)

/**
 * Annotated packet dump
 */
#define MMT_DUMP_PROTOCOL(data, len, proto) mmt_dump_packet_annotated((const uint8_t *)(data), (len), (proto), NULL)

/**
 * Profile code section
 */
#define MMT_PROFILE_BEGIN(name) mmt_profile_point_t *_profile_##name = mmt_profile_start(#name)

#define MMT_PROFILE_END(name) mmt_profile_end(_profile_##name)

/**
 * Record error for statistics (if enabled)
 */
#define MMT_ERROR_STATS_RECORD(code, msg)                                    \
	do {                                                                     \
		if (mmt_error_stats_is_enabled()) {                                  \
			mmt_error_stats_record(code, __FILE__, __LINE__, __func__, msg); \
		}                                                                    \
	} while (0)

#endif /* MMT_DEBUG_H */
