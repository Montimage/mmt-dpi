/**
 * MMT Debug and Diagnostic Tools Implementation
 * Phase 5: Error Handling and Logging Framework
 *
 * Implements debugging and diagnostic utilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "../public_include/mmt_debug.h"
#include "../public_include/mmt_errors.h"
#include "../public_include/mmt_logging.h"

/* ANSI color codes */
#define COLOR_RESET "\033[0m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"

/* Maximum error codes to track */
#define MAX_ERROR_CODES 1000

/* Bytes per line for hexdump */
#define BYTES_PER_LINE 16

/*
 * ============================================================================
 * Packet Dump Implementation
 * ============================================================================
 */

/**
 * Print hexdump line
 */
static void print_hex_line(const uint8_t *data, size_t offset, size_t length, uint32_t flags, FILE *output)
{
	FILE *out = output ? output : stdout;
	bool use_colors = (flags & MMT_DUMP_COLORS) != 0;
	bool show_ascii = (flags & MMT_DUMP_ASCII) != 0;
	size_t i;

	/* Print offset */
	if (flags & MMT_DUMP_OFFSETS) {
		if (use_colors) {
			fprintf(out, "%s%08zx%s  ", COLOR_CYAN, offset, COLOR_RESET);
		} else {
			fprintf(out, "%08zx  ", offset);
		}
	}

	/* Print hex bytes */
	for (i = 0; i < BYTES_PER_LINE; i++) {
		if (i < length) {
			if (use_colors) {
				fprintf(out, "%s%02x%s ", COLOR_GREEN, data[i], COLOR_RESET);
			} else {
				fprintf(out, "%02x ", data[i]);
			}
		} else {
			fprintf(out, "   ");
		}

		/* Extra space after 8 bytes */
		if (i == 7) {
			fprintf(out, " ");
		}
	}

	/* Print ASCII */
	if (show_ascii) {
		fprintf(out, " |");
		for (i = 0; i < length && i < BYTES_PER_LINE; i++) {
			char c = isprint(data[i]) ? data[i] : '.';
			if (use_colors) {
				fprintf(out, "%s%c%s", COLOR_YELLOW, c, COLOR_RESET);
			} else {
				fprintf(out, "%c", c);
			}
		}
		fprintf(out, "|");
	}

	fprintf(out, "\n");
}

void mmt_dump_packet(const uint8_t *data, size_t length, size_t offset, uint32_t flags, FILE *output)
{
	if (data == NULL || length == 0) {
		return;
	}

	FILE *out = output ? output : stdout;
	size_t pos = 0;

	while (pos < length) {
		size_t line_len = (length - pos > BYTES_PER_LINE) ? BYTES_PER_LINE : (length - pos);
		print_hex_line(data + pos, offset + pos, line_len, flags, out);
		pos += line_len;
	}

	fprintf(out, "\n");
}

void mmt_dump_packet_annotated(const uint8_t *data, size_t length, const char *protocol_name, FILE *output)
{
	FILE *out = output ? output : stdout;

	fprintf(out, "\n");
	fprintf(out, "================================================\n");
	fprintf(out, " Protocol: %s (Length: %zu bytes)\n", protocol_name, length);
	fprintf(out, "================================================\n\n");

	mmt_dump_packet(data, length, 0, MMT_DUMP_HEX | MMT_DUMP_ASCII | MMT_DUMP_OFFSETS, out);
}

void mmt_dump_packet_range(const uint8_t *data, size_t start, size_t end, const char *label, FILE *output)
{
	FILE *out = output ? output : stdout;

	if (end <= start) {
		return;
	}

	fprintf(out, "\n%s [offset %zu-%zu]:\n", label, start, end);
	mmt_dump_packet(data + start, end - start, start, MMT_DUMP_HEX | MMT_DUMP_ASCII | MMT_DUMP_OFFSETS, out);
}

size_t mmt_dump_packet_to_string(const uint8_t *data, size_t length, char *buffer, size_t buffer_size, uint32_t flags)
{
	if (data == NULL || buffer == NULL || buffer_size == 0) {
		return 0;
	}

	size_t written = 0;
	size_t pos = 0;

	while (pos < length && written < buffer_size - 1) {
		size_t line_len = (length - pos > BYTES_PER_LINE) ? BYTES_PER_LINE : (length - pos);

		/* Write offset */
		if (flags & MMT_DUMP_OFFSETS) {
			int n = snprintf(buffer + written, buffer_size - written, "%08zx  ", pos);
			if (n > 0)
				written += n;
		}

		/* Write hex bytes */
		for (size_t i = 0; i < line_len && written < buffer_size - 1; i++) {
			int n = snprintf(buffer + written, buffer_size - written, "%02x ", data[pos + i]);
			if (n > 0)
				written += n;
		}

		/* Write ASCII */
		if ((flags & MMT_DUMP_ASCII) && written < buffer_size - 1) {
			int n = snprintf(buffer + written, buffer_size - written, " |");
			if (n > 0)
				written += n;

			for (size_t i = 0; i < line_len && written < buffer_size - 1; i++) {
				char c = isprint(data[pos + i]) ? data[pos + i] : '.';
				buffer[written++] = c;
			}

			if (written < buffer_size - 1) {
				buffer[written++] = '|';
			}
		}

		if (written < buffer_size - 1) {
			buffer[written++] = '\n';
		}

		pos += line_len;
	}

	buffer[written] = '\0';
	return written;
}

mmt_error_t mmt_dump_packet_to_file(const uint8_t *data, size_t length, const char *filename, uint32_t flags)
{
	if (data == NULL || filename == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_INVALID_PARAMETER, "Invalid parameters");
	}

	FILE *f = fopen(filename, "w");
	if (f == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_FILE_OPEN, "Failed to open file");
	}

	mmt_dump_packet(data, length, 0, flags, f);
	fclose(f);

	return MMT_SUCCESS;
}

/*
 * ============================================================================
 * Error Statistics Implementation
 * ============================================================================
 */

/* Error statistics storage */
static bool g_error_stats_enabled = false;
static uint64_t g_error_counts[MAX_ERROR_CODES] = {0};
static mmt_error_stat_entry_t g_error_entries[MAX_ERROR_CODES];

void mmt_error_stats_enable(bool enabled)
{
	g_error_stats_enabled = enabled;
	if (enabled) {
		MMT_LOG_INFO("Error statistics tracking enabled");
	}
}

bool mmt_error_stats_is_enabled(void)
{
	return g_error_stats_enabled;
}

void mmt_error_stats_record(mmt_error_t error_code, const char *file, int line, const char *function,
							const char *message)
{
	if (!g_error_stats_enabled) {
		return;
	}

	if (error_code < 0 || error_code >= MAX_ERROR_CODES) {
		return;
	}

	/* Increment count */
	g_error_counts[error_code]++;

	/* Update entry */
	g_error_entries[error_code].error_code = error_code;
	g_error_entries[error_code].count = g_error_counts[error_code];
	g_error_entries[error_code].last_file = file;
	g_error_entries[error_code].last_line = line;
	g_error_entries[error_code].last_function = function;
	g_error_entries[error_code].last_message = message;
}

uint64_t mmt_error_stats_get(mmt_error_t error_code, mmt_error_stat_entry_t *entry)
{
	if (error_code < 0 || error_code >= MAX_ERROR_CODES) {
		return 0;
	}

	if (entry != NULL) {
		memcpy(entry, &g_error_entries[error_code], sizeof(mmt_error_stat_entry_t));
	}

	return g_error_counts[error_code];
}

void mmt_error_stats_get_summary(mmt_error_stats_summary_t *summary)
{
	if (summary == NULL) {
		return;
	}

	memset(summary, 0, sizeof(mmt_error_stats_summary_t));

	for (int i = 0; i < MAX_ERROR_CODES; i++) {
		if (g_error_counts[i] > 0) {
			summary->total_errors += g_error_counts[i];
			summary->unique_errors++;

			if (g_error_counts[i] > summary->most_frequent_count) {
				summary->most_frequent_count = g_error_counts[i];
				summary->most_frequent_error = i;
			}
		}
	}
}

size_t mmt_error_stats_get_top_errors(mmt_error_stat_entry_t *entries, size_t max_entries)
{
	if (entries == NULL || max_entries == 0) {
		return 0;
	}

	/* Simple selection sort for top N */
	size_t count = 0;

	for (size_t n = 0; n < max_entries; n++) {
		uint64_t max_count = 0;
		int max_idx = -1;

		/* Find next highest */
		for (int i = 0; i < MAX_ERROR_CODES; i++) {
			if (g_error_counts[i] > max_count) {
				/* Check if already added */
				bool already_added = false;
				for (size_t j = 0; j < n; j++) {
					if (entries[j].error_code == i) {
						already_added = true;
						break;
					}
				}

				if (!already_added) {
					max_count = g_error_counts[i];
					max_idx = i;
				}
			}
		}

		if (max_idx >= 0) {
			memcpy(&entries[count], &g_error_entries[max_idx], sizeof(mmt_error_stat_entry_t));
			count++;
		} else {
			break;
		}
	}

	return count;
}

void mmt_error_stats_print(FILE *output, size_t top_n)
{
	FILE *out = output ? output : stdout;

	mmt_error_stats_summary_t summary;
	mmt_error_stats_get_summary(&summary);

	fprintf(out, "\n");
	fprintf(out, "================================================\n");
	fprintf(out, " Error Statistics Summary\n");
	fprintf(out, "================================================\n");
	fprintf(out, "Total errors:        %lu\n", summary.total_errors);
	fprintf(out, "Unique error types:  %lu\n", summary.unique_errors);

	if (summary.unique_errors > 0) {
		fprintf(out, "Most frequent:       %s (%lu occurrences)\n", mmt_error_to_string(summary.most_frequent_error),
				summary.most_frequent_count);
	}

	fprintf(out, "\n");

	/* Print top errors */
	if (top_n == 0) {
		top_n = 10; /* Default to top 10 */
	}

	fprintf(out, "Top %zu Errors:\n", top_n);
	fprintf(out, "------------------------------------------------\n");

	mmt_error_stat_entry_t *entries = calloc(top_n, sizeof(mmt_error_stat_entry_t));
	if (entries == NULL) {
		return;
	}

	size_t count = mmt_error_stats_get_top_errors(entries, top_n);

	for (size_t i = 0; i < count; i++) {
		fprintf(out, "%2zu. [%3d] %s\n", i + 1, entries[i].error_code, mmt_error_to_string(entries[i].error_code));
		fprintf(out, "    Count: %lu\n", entries[i].count);
		if (entries[i].last_file) {
			fprintf(out, "    Last:  %s:%d in %s()\n", entries[i].last_file, entries[i].last_line,
					entries[i].last_function);
		}
		if (entries[i].last_message) {
			fprintf(out, "    Msg:   %s\n", entries[i].last_message);
		}
		fprintf(out, "\n");
	}

	fprintf(out, "================================================\n\n");

	free(entries);
}

void mmt_error_stats_reset(void)
{
	memset(g_error_counts, 0, sizeof(g_error_counts));
	memset(g_error_entries, 0, sizeof(g_error_entries));
	MMT_LOG_INFO("Error statistics reset");
}

mmt_error_t mmt_error_stats_save(const char *filename)
{
	if (filename == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_INVALID_PARAMETER, "Filename is NULL");
	}

	FILE *f = fopen(filename, "w");
	if (f == NULL) {
		MMT_RETURN_ERROR(MMT_ERROR_FILE_OPEN, "Failed to open file");
	}

	mmt_error_stats_print(f, 0);
	fclose(f);

	MMT_LOG_INFO("Error statistics saved to %s", filename);
	return MMT_SUCCESS;
}

/*
 * ============================================================================
 * Memory Diagnostics (Stub Implementation)
 * ============================================================================
 */

static bool g_mem_tracking_enabled = false;
static mmt_mem_stats_t g_mem_stats = {0};

void mmt_mem_tracking_enable(bool enabled)
{
	g_mem_tracking_enabled = enabled;
}

bool mmt_mem_tracking_is_enabled(void)
{
	return g_mem_tracking_enabled;
}

void mmt_mem_get_stats(mmt_mem_stats_t *stats)
{
	if (stats != NULL) {
		memcpy(stats, &g_mem_stats, sizeof(mmt_mem_stats_t));
	}
}

void mmt_mem_print_stats(FILE *output)
{
	FILE *out = output ? output : stdout;

	fprintf(out, "\n");
	fprintf(out, "================================================\n");
	fprintf(out, " Memory Statistics\n");
	fprintf(out, "================================================\n");
	fprintf(out, "Total allocations:     %lu\n", g_mem_stats.total_allocations);
	fprintf(out, "Total deallocations:   %lu\n", g_mem_stats.total_deallocations);
	fprintf(out, "Current allocations:   %lu\n", g_mem_stats.current_allocations);
	fprintf(out, "Peak allocations:      %lu\n", g_mem_stats.peak_allocations);
	fprintf(out, "Total bytes allocated: %lu\n", g_mem_stats.total_bytes_allocated);
	fprintf(out, "Current bytes:         %lu\n", g_mem_stats.current_bytes_allocated);
	fprintf(out, "Peak bytes:            %lu\n", g_mem_stats.peak_bytes_allocated);
	fprintf(out, "================================================\n\n");
}

size_t mmt_mem_check_leaks(FILE *output)
{
	FILE *out = output ? output : stdout;

	if (g_mem_stats.current_allocations > 0) {
		fprintf(out, "WARNING: %lu allocations not freed\n", g_mem_stats.current_allocations);
		fprintf(out, "         %lu bytes still allocated\n", g_mem_stats.current_bytes_allocated);
		return g_mem_stats.current_allocations;
	}

	fprintf(out, "No memory leaks detected\n");
	return 0;
}

/*
 * ============================================================================
 * Performance Profiling (Stub Implementation)
 * ============================================================================
 */

struct mmt_profile_point {
	const char *name;
	struct timespec start_time;
	uint64_t elapsed_ns;
};

mmt_profile_point_t *mmt_profile_start(const char *name)
{
	mmt_profile_point_t *point = malloc(sizeof(mmt_profile_point_t));
	if (point == NULL) {
		return NULL;
	}

	point->name = name;
	clock_gettime(CLOCK_MONOTONIC, &point->start_time);
	point->elapsed_ns = 0;

	return point;
}

void mmt_profile_end(mmt_profile_point_t *point)
{
	if (point == NULL) {
		return;
	}

	struct timespec end_time;
	clock_gettime(CLOCK_MONOTONIC, &end_time);

	point->elapsed_ns =
		(end_time.tv_sec - point->start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - point->start_time.tv_nsec);

	MMT_LOG_PERF(MMT_LOG_CAT_PERFORMANCE, "%s: %lu ns", point->name, point->elapsed_ns);

	free(point);
}

uint64_t mmt_profile_get_elapsed(const mmt_profile_point_t *point)
{
	return point ? point->elapsed_ns : 0;
}

void mmt_profile_print_report(FILE *output)
{
	FILE *out = output ? output : stdout;

	fprintf(out, "\n");
	fprintf(out, "================================================\n");
	fprintf(out, " Performance Profiling Report\n");
	fprintf(out, "================================================\n");
	fprintf(out, "(See log output for detailed timings)\n");
	fprintf(out, "================================================\n\n");
}

void mmt_profile_reset(void)
{
	MMT_LOG_INFO("Profiling data reset");
}
