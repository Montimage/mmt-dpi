/**
 * Recovery and Debug Utilities Test Suite
 * Phase 5: Error Handling and Logging Framework
 *
 * Tests recovery strategies, packet dump, and error statistics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../src/mmt_core/public_include/mmt_recovery.h"
#include "../../src/mmt_core/public_include/mmt_debug.h"
#include "../../src/mmt_core/public_include/mmt_errors.h"
#include "../../src/mmt_core/public_include/mmt_logging.h"

/* Test utilities */
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("✗ FAIL: %s\n", msg); \
            return 0; \
        } \
    } while(0)

#define RUN_TEST(test) \
    do { \
        printf("Running: %s... ", #test); \
        if (test()) { \
            printf("✓ PASS\n"); \
            tests_passed++; \
        } else { \
            tests_failed++; \
        } \
        tests_run++; \
    } while(0)

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/*
 * ============================================================================
 * Recovery Strategy Tests
 * ============================================================================
 */

/**
 * Test: Protocol fallback
 */
int test_protocol_fallback(void)
{
    uint8_t packet[] = {0x01, 0x02, 0x03, 0x04};
    uint32_t proto_id = 100;

    /* Test generic fallback */
    mmt_recovery_result_t result = mmt_protocol_fallback(
        proto_id, packet, 0, MMT_FALLBACK_GENERIC);
    TEST_ASSERT(result == MMT_RECOVERY_SUCCESS, "Generic fallback succeeds");

    /* Test next layer fallback */
    result = mmt_protocol_fallback(proto_id, packet, 0, MMT_FALLBACK_NEXT_LAYER);
    TEST_ASSERT(result == MMT_RECOVERY_SKIP, "Next layer fallback skips");

    /* Test raw fallback */
    result = mmt_protocol_fallback(proto_id, packet, 0, MMT_FALLBACK_RAW);
    TEST_ASSERT(result == MMT_RECOVERY_SUCCESS, "Raw fallback succeeds");

    return 1;
}

/**
 * Test: Protocol has fallback
 */
int test_protocol_has_fallback(void)
{
    uint32_t proto_id = 100;

    /* All protocols have at least generic fallback */
    bool has_fallback = mmt_protocol_has_fallback(proto_id);
    TEST_ASSERT(has_fallback, "Protocol has fallback available");

    return 1;
}

/**
 * Test: Session recovery
 */
int test_session_recovery(void)
{
    void *session_key = (void*)0x1234;

    /* Test retry recovery */
    mmt_recovery_result_t result = mmt_session_recover(
        session_key, MMT_ERROR_SESSION_NOT_FOUND,
        MMT_SESSION_RECOVERY_RETRY, NULL);
    TEST_ASSERT(result == MMT_RECOVERY_RETRY, "Retry recovery returns RETRY");

    /* Test create recovery */
    result = mmt_session_recover(
        session_key, MMT_ERROR_SESSION_NOT_FOUND,
        MMT_SESSION_RECOVERY_CREATE, NULL);
    TEST_ASSERT(result == MMT_RECOVERY_SUCCESS, "Create recovery succeeds");

    /* Test degrade recovery */
    result = mmt_session_recover(
        session_key, MMT_ERROR_SESSION_TIMEOUT,
        MMT_SESSION_RECOVERY_DEGRADE, NULL);
    TEST_ASSERT(result == MMT_RECOVERY_SUCCESS, "Degrade recovery succeeds");

    /* Test skip recovery */
    result = mmt_session_recover(
        session_key, MMT_ERROR_SESSION_INVALID,
        MMT_SESSION_RECOVERY_SKIP, NULL);
    TEST_ASSERT(result == MMT_RECOVERY_SKIP, "Skip recovery skips");

    return 1;
}

/**
 * Helper: Operation that succeeds after retries
 */
static int g_retry_counter = 0;

static mmt_error_t retryable_operation_success(void *context)
{
    (void)context;
    g_retry_counter++;

    /* Succeed on 3rd attempt */
    if (g_retry_counter >= 3) {
        return MMT_SUCCESS;
    }

    return MMT_ERROR_GENERIC;
}

/**
 * Test: Execute with retry
 */
int test_execute_with_retry(void)
{
    g_retry_counter = 0;

    mmt_retry_config_t config = {
        .max_retries = 5,
        .base_delay_ms = 1,  /* Short delay for testing */
        .exponential_backoff = false,
        .max_delay_ms = 10
    };

    mmt_error_t result = mmt_execute_with_retry(
        retryable_operation_success, NULL, &config);

    TEST_ASSERT(result == MMT_SUCCESS, "Retry succeeds eventually");
    TEST_ASSERT(g_retry_counter == 3, "Operation tried 3 times");

    return 1;
}

/**
 * Helper: Operation that always fails
 */
static mmt_error_t retryable_operation_fail(void *context)
{
    (void)context;
    return MMT_ERROR_GENERIC;
}

/**
 * Test: Execute with retry exhaustion
 */
int test_retry_exhaustion(void)
{
    mmt_retry_config_t config = {
        .max_retries = 2,
        .base_delay_ms = 1,
        .exponential_backoff = false,
        .max_delay_ms = 10
    };

    mmt_error_t result = mmt_execute_with_retry(
        retryable_operation_fail, NULL, &config);

    TEST_ASSERT(result != MMT_SUCCESS, "Retry fails after exhaustion");

    return 1;
}

/**
 * Test: Session degraded marking
 */
int test_session_degraded(void)
{
    void *session_key = (void*)0x5678;

    /* Initially not degraded */
    TEST_ASSERT(!mmt_session_is_degraded(session_key),
                "Session initially not degraded");

    /* Mark as degraded */
    mmt_error_t err = mmt_session_mark_degraded(session_key);
    TEST_ASSERT(err == MMT_SUCCESS, "Mark degraded succeeds");
    TEST_ASSERT(mmt_session_is_degraded(session_key),
                "Session is degraded");

    /* Restore session */
    err = mmt_session_restore(session_key);
    TEST_ASSERT(err == MMT_SUCCESS, "Restore succeeds");
    TEST_ASSERT(!mmt_session_is_degraded(session_key),
                "Session restored");

    return 1;
}

/**
 * Test: Recovery statistics
 */
int test_recovery_statistics(void)
{
    mmt_recovery_stats_t stats;

    /* Reset stats */
    mmt_recovery_reset_stats();
    mmt_recovery_get_stats(&stats);
    TEST_ASSERT(stats.protocol_fallbacks == 0, "Stats initially zero");

    /* Trigger some recoveries */
    uint8_t packet[] = {0xAA, 0xBB};
    mmt_protocol_fallback(100, packet, 0, MMT_FALLBACK_GENERIC);
    mmt_protocol_fallback(101, packet, 0, MMT_FALLBACK_RAW);

    void *key = (void*)0x9999;
    mmt_session_recover(key, MMT_ERROR_SESSION_NOT_FOUND,
                       MMT_SESSION_RECOVERY_CREATE, NULL);

    /* Check stats */
    mmt_recovery_get_stats(&stats);
    TEST_ASSERT(stats.protocol_fallbacks == 2, "Two protocol fallbacks");
    TEST_ASSERT(stats.session_recoveries == 1, "One session recovery");
    TEST_ASSERT(stats.successful_recoveries == 3, "Three successful recoveries");

    return 1;
}

/*
 * ============================================================================
 * Debug Utilities Tests
 * ============================================================================
 */

/**
 * Test: Packet dump
 */
int test_packet_dump(void)
{
    uint8_t packet[] = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x68,
        0xc0, 0xa8, 0x00, 0x01
    };

    /* Test hexdump to stdout (just ensure no crash) */
    mmt_dump_packet(packet, sizeof(packet), 0,
                   MMT_DUMP_HEX | MMT_DUMP_ASCII | MMT_DUMP_OFFSETS,
                   NULL);

    /* Test dump to string */
    char buffer[1024];
    size_t written = mmt_dump_packet_to_string(
        packet, sizeof(packet), buffer, sizeof(buffer),
        MMT_DUMP_HEX | MMT_DUMP_ASCII);

    TEST_ASSERT(written > 0, "Dump to string returns data");
    TEST_ASSERT(strlen(buffer) == written, "Written bytes match string length");

    return 1;
}

/**
 * Test: Packet dump annotated
 */
int test_packet_dump_annotated(void)
{
    uint8_t packet[] = {0x08, 0x00, 0x45, 0x00};

    /* Should not crash */
    mmt_dump_packet_annotated(packet, sizeof(packet), "TEST_PROTOCOL", NULL);

    return 1;
}

/**
 * Test: Packet dump range
 */
int test_packet_dump_range(void)
{
    uint8_t packet[100];
    for (int i = 0; i < 100; i++) {
        packet[i] = i;
    }

    /* Should not crash */
    mmt_dump_packet_range(packet, 10, 30, "Test Range", NULL);

    return 1;
}

/**
 * Test: Error statistics
 */
int test_error_statistics(void)
{
    /* Enable error statistics */
    mmt_error_stats_enable(true);
    TEST_ASSERT(mmt_error_stats_is_enabled(), "Error stats enabled");

    /* Reset stats */
    mmt_error_stats_reset();

    /* Record some errors */
    mmt_error_stats_record(MMT_ERROR_MEMORY_ALLOC, __FILE__, __LINE__,
                           __func__, "Test allocation error");
    mmt_error_stats_record(MMT_ERROR_MEMORY_ALLOC, __FILE__, __LINE__,
                           __func__, "Another allocation error");
    mmt_error_stats_record(MMT_ERROR_INVALID_INPUT, __FILE__, __LINE__,
                           __func__, "Invalid input");

    /* Check counts */
    mmt_error_stat_entry_t entry;
    uint64_t count = mmt_error_stats_get(MMT_ERROR_MEMORY_ALLOC, &entry);
    TEST_ASSERT(count == 2, "Memory alloc error recorded twice");
    TEST_ASSERT(entry.count == 2, "Entry count matches");

    count = mmt_error_stats_get(MMT_ERROR_INVALID_INPUT, NULL);
    TEST_ASSERT(count == 1, "Invalid input error recorded once");

    /* Get summary */
    mmt_error_stats_summary_t summary;
    mmt_error_stats_get_summary(&summary);
    TEST_ASSERT(summary.total_errors == 3, "Total 3 errors");
    TEST_ASSERT(summary.unique_errors == 2, "2 unique error types");
    TEST_ASSERT(summary.most_frequent_error == MMT_ERROR_MEMORY_ALLOC,
                "Memory alloc is most frequent");

    return 1;
}

/**
 * Test: Top errors
 */
int test_top_errors(void)
{
    mmt_error_stats_enable(true);
    mmt_error_stats_reset();

    /* Record various errors */
    for (int i = 0; i < 5; i++) {
        mmt_error_stats_record(MMT_ERROR_PACKET_TOO_SHORT, __FILE__, __LINE__,
                              __func__, "Short packet");
    }
    for (int i = 0; i < 3; i++) {
        mmt_error_stats_record(MMT_ERROR_PROTOCOL_NOT_FOUND, __FILE__, __LINE__,
                              __func__, "Protocol not found");
    }
    for (int i = 0; i < 7; i++) {
        mmt_error_stats_record(MMT_ERROR_SESSION_NOT_FOUND, __FILE__, __LINE__,
                              __func__, "Session not found");
    }

    /* Get top 3 errors */
    mmt_error_stat_entry_t entries[3];
    size_t count = mmt_error_stats_get_top_errors(entries, 3);

    TEST_ASSERT(count == 3, "Got 3 top errors");
    TEST_ASSERT(entries[0].error_code == MMT_ERROR_SESSION_NOT_FOUND,
                "Top error is session not found (7 times)");
    TEST_ASSERT(entries[0].count == 7, "Top error count is 7");
    TEST_ASSERT(entries[1].error_code == MMT_ERROR_PACKET_TOO_SHORT,
                "Second error is packet too short (5 times)");
    TEST_ASSERT(entries[2].error_code == MMT_ERROR_PROTOCOL_NOT_FOUND,
                "Third error is protocol not found (3 times)");

    return 1;
}

/**
 * Test: Memory statistics
 */
int test_memory_statistics(void)
{
    mmt_mem_tracking_enable(true);
    TEST_ASSERT(mmt_mem_tracking_is_enabled(), "Memory tracking enabled");

    mmt_mem_stats_t stats;
    mmt_mem_get_stats(&stats);

    /* Just ensure no crash */
    mmt_mem_print_stats(NULL);
    size_t leaks = mmt_mem_check_leaks(NULL);
    (void)leaks;  /* May or may not have leaks */

    return 1;
}

/**
 * Test: Performance profiling
 */
int test_performance_profiling(void)
{
    /* Start profiling */
    mmt_profile_point_t *point = mmt_profile_start("test_operation");
    TEST_ASSERT(point != NULL, "Profile point created");

    /* Simulate some work */
    usleep(1000);  /* 1ms */

    /* End profiling */
    mmt_profile_end(point);

    /* Print report (should not crash) */
    mmt_profile_print_report(NULL);

    return 1;
}

/*
 * ============================================================================
 * Integration Tests
 * ============================================================================
 */

/**
 * Test: Recovery with error stats
 */
int test_recovery_with_stats(void)
{
    mmt_error_stats_enable(true);
    mmt_error_stats_reset();
    mmt_recovery_reset_stats();

    /* Trigger recovery with error recording */
    uint8_t packet[] = {0x00, 0x01};
    mmt_error_stats_record(MMT_ERROR_PROTOCOL_PARSE_FAILED,
                          __FILE__, __LINE__, __func__,
                          "Parse failed, attempting fallback");

    mmt_recovery_result_t result = mmt_protocol_fallback(
        200, packet, 0, MMT_FALLBACK_GENERIC);

    TEST_ASSERT(result == MMT_RECOVERY_SUCCESS, "Recovery succeeded");

    /* Check that both systems tracked the event */
    mmt_error_stats_summary_t err_stats;
    mmt_error_stats_get_summary(&err_stats);
    TEST_ASSERT(err_stats.total_errors > 0, "Error was recorded");

    mmt_recovery_stats_t rec_stats;
    mmt_recovery_get_stats(&rec_stats);
    TEST_ASSERT(rec_stats.protocol_fallbacks > 0, "Fallback was recorded");

    return 1;
}

/*
 * ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int main(void)
{
    /* Initialize logging (suppress output for tests) */
    mmt_log_init();
    mmt_log_set_output_mode(MMT_LOG_OUTPUT_NONE);

    printf("================================================\n");
    printf(" Recovery and Debug Test Suite\n");
    printf(" Phase 5: Error Handling and Logging\n");
    printf("================================================\n\n");

    printf("--- Testing Recovery Strategies ---\n");
    RUN_TEST(test_protocol_fallback);
    RUN_TEST(test_protocol_has_fallback);
    RUN_TEST(test_session_recovery);
    RUN_TEST(test_execute_with_retry);
    RUN_TEST(test_retry_exhaustion);
    RUN_TEST(test_session_degraded);
    RUN_TEST(test_recovery_statistics);

    printf("\n--- Testing Debug Utilities ---\n");
    RUN_TEST(test_packet_dump);
    RUN_TEST(test_packet_dump_annotated);
    RUN_TEST(test_packet_dump_range);
    RUN_TEST(test_error_statistics);
    RUN_TEST(test_top_errors);
    RUN_TEST(test_memory_statistics);
    RUN_TEST(test_performance_profiling);

    printf("\n--- Testing Integration ---\n");
    RUN_TEST(test_recovery_with_stats);

    printf("\n================================================\n");
    printf(" Test Results\n");
    printf("================================================\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("\n");

    if (tests_failed == 0) {
        printf("✓ ALL RECOVERY & DEBUG TESTS PASSED!\n");
        return 0;
    } else {
        printf("✗ SOME TESTS FAILED\n");
        return 1;
    }
}
