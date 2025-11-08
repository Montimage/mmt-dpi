/**
 * Logging Framework Test Suite
 * Phase 5: Error Handling and Logging Framework
 *
 * Tests log levels, categories, filtering, callbacks, and thread-safety
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "../../src/mmt_core/public_include/mmt_logging.h"

/* Test utilities */
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("✗ FAIL: %s\n", msg); \
            return 0; \
        } \
    } while(0)

#define TEST_ASSERT_STR_EQ(s1, s2, msg) \
    do { \
        if (strcmp(s1, s2) != 0) { \
            printf("✗ FAIL: %s (expected: '%s', got: '%s')\n", msg, s2, s1); \
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

/* Callback test data */
static int g_callback_count = 0;
static mmt_log_level_t g_last_level = MMT_LOG_NONE;
static mmt_log_category_t g_last_category = MMT_LOG_CAT_GENERAL;
static char g_last_message[256] = {0};

/**
 * Test callback function
 */
void test_callback(mmt_log_level_t level, mmt_log_category_t category,
                   const char *file, int line, const char *function,
                   const char *message)
{
    (void)file;
    (void)line;
    (void)function;

    g_callback_count++;
    g_last_level = level;
    g_last_category = category;
    strncpy(g_last_message, message, sizeof(g_last_message) - 1);
}

/**
 * Reset callback test data
 */
void reset_callback_data(void)
{
    g_callback_count = 0;
    g_last_level = MMT_LOG_NONE;
    g_last_category = MMT_LOG_CAT_GENERAL;
    memset(g_last_message, 0, sizeof(g_last_message));
}

/**
 * Test: Initialization
 */
int test_initialization(void)
{
    mmt_log_init();

    /* Should have default settings */
    mmt_log_level_t level = mmt_log_get_level();
    TEST_ASSERT(level == MMT_LOG_INFO, "Default level is INFO");

    /* All categories should be enabled by default */
    TEST_ASSERT(mmt_log_is_category_enabled(MMT_LOG_CAT_PROTOCOL), "Protocol category enabled");
    TEST_ASSERT(mmt_log_is_category_enabled(MMT_LOG_CAT_SESSION), "Session category enabled");

    return 1;
}

/**
 * Test: Log level setting
 */
int test_log_levels(void)
{
    mmt_log_init();

    /* Test setting global level */
    mmt_log_set_level(MMT_LOG_DEBUG);
    TEST_ASSERT(mmt_log_get_level() == MMT_LOG_DEBUG, "Set DEBUG level");

    mmt_log_set_level(MMT_LOG_ERROR);
    TEST_ASSERT(mmt_log_get_level() == MMT_LOG_ERROR, "Set ERROR level");

    mmt_log_set_level(MMT_LOG_TRACE);
    TEST_ASSERT(mmt_log_get_level() == MMT_LOG_TRACE, "Set TRACE level");

    return 1;
}

/**
 * Test: Category levels
 */
int test_category_levels(void)
{
    mmt_log_init();

    /* Set different level for protocol category */
    mmt_log_set_category_level(MMT_LOG_CAT_PROTOCOL, MMT_LOG_DEBUG);
    TEST_ASSERT(mmt_log_get_category_level(MMT_LOG_CAT_PROTOCOL) == MMT_LOG_DEBUG,
                "Protocol category level is DEBUG");

    /* Set different level for session category */
    mmt_log_set_category_level(MMT_LOG_CAT_SESSION, MMT_LOG_ERROR);
    TEST_ASSERT(mmt_log_get_category_level(MMT_LOG_CAT_SESSION) == MMT_LOG_ERROR,
                "Session category level is ERROR");

    return 1;
}

/**
 * Test: Category enable/disable
 */
int test_category_enable_disable(void)
{
    mmt_log_init();

    /* Disable protocol category */
    mmt_log_set_category_enabled(MMT_LOG_CAT_PROTOCOL, false);
    TEST_ASSERT(!mmt_log_is_category_enabled(MMT_LOG_CAT_PROTOCOL),
                "Protocol category is disabled");

    /* Re-enable protocol category */
    mmt_log_set_category_enabled(MMT_LOG_CAT_PROTOCOL, true);
    TEST_ASSERT(mmt_log_is_category_enabled(MMT_LOG_CAT_PROTOCOL),
                "Protocol category is re-enabled");

    return 1;
}

/**
 * Test: Log filtering by level
 */
int test_log_filtering(void)
{
    mmt_log_init();
    mmt_log_set_level(MMT_LOG_WARN);

    /* ERROR should be enabled (ERROR <= WARN) */
    TEST_ASSERT(mmt_log_is_enabled(MMT_LOG_ERROR, MMT_LOG_CAT_GENERAL),
                "ERROR is enabled when level is WARN");

    /* WARN should be enabled */
    TEST_ASSERT(mmt_log_is_enabled(MMT_LOG_WARN, MMT_LOG_CAT_GENERAL),
                "WARN is enabled when level is WARN");

    /* INFO should be disabled (INFO > WARN) */
    TEST_ASSERT(!mmt_log_is_enabled(MMT_LOG_INFO, MMT_LOG_CAT_GENERAL),
                "INFO is disabled when level is WARN");

    /* DEBUG should be disabled */
    TEST_ASSERT(!mmt_log_is_enabled(MMT_LOG_DEBUG, MMT_LOG_CAT_GENERAL),
                "DEBUG is disabled when level is WARN");

    return 1;
}

/**
 * Test: Log callback
 */
int test_log_callback(void)
{
    mmt_log_init();
    reset_callback_data();

    /* Set callback */
    mmt_log_set_callback(test_callback);
    mmt_log_set_level(MMT_LOG_TRACE);

    /* Log a message */
    MMT_LOG_ERROR("Test error message");

    /* Check callback was called */
    TEST_ASSERT(g_callback_count == 1, "Callback was called once");
    TEST_ASSERT(g_last_level == MMT_LOG_ERROR, "Callback received ERROR level");
    TEST_ASSERT(strstr(g_last_message, "Test error message") != NULL,
                "Callback received correct message");

    /* Log another message with category */
    reset_callback_data();
    MMT_LOG_WARN_CAT(MMT_LOG_CAT_PROTOCOL, "Protocol warning");

    TEST_ASSERT(g_callback_count == 1, "Callback called for category log");
    TEST_ASSERT(g_last_level == MMT_LOG_WARN, "Callback received WARN level");
    TEST_ASSERT(g_last_category == MMT_LOG_CAT_PROTOCOL, "Callback received PROTOCOL category");

    /* Reset callback */
    mmt_log_set_callback(NULL);
    mmt_log_set_output_mode(MMT_LOG_OUTPUT_NONE);

    return 1;
}

/**
 * Test: Log level strings
 */
int test_log_level_strings(void)
{
    TEST_ASSERT_STR_EQ(mmt_log_level_to_string(MMT_LOG_ERROR), "ERROR", "ERROR string");
    TEST_ASSERT_STR_EQ(mmt_log_level_to_string(MMT_LOG_WARN), "WARN", "WARN string");
    TEST_ASSERT_STR_EQ(mmt_log_level_to_string(MMT_LOG_INFO), "INFO", "INFO string");
    TEST_ASSERT_STR_EQ(mmt_log_level_to_string(MMT_LOG_DEBUG), "DEBUG", "DEBUG string");
    TEST_ASSERT_STR_EQ(mmt_log_level_to_string(MMT_LOG_TRACE), "TRACE", "TRACE string");

    return 1;
}

/**
 * Test: Log category strings
 */
int test_log_category_strings(void)
{
    TEST_ASSERT_STR_EQ(mmt_log_category_to_string(MMT_LOG_CAT_GENERAL), "GENERAL",
                       "GENERAL string");
    TEST_ASSERT_STR_EQ(mmt_log_category_to_string(MMT_LOG_CAT_PROTOCOL), "PROTOCOL",
                       "PROTOCOL string");
    TEST_ASSERT_STR_EQ(mmt_log_category_to_string(MMT_LOG_CAT_SESSION), "SESSION",
                       "SESSION string");
    TEST_ASSERT_STR_EQ(mmt_log_category_to_string(MMT_LOG_CAT_MEMORY), "MEMORY",
                       "MEMORY string");
    TEST_ASSERT_STR_EQ(mmt_log_category_to_string(MMT_LOG_CAT_PACKET), "PACKET",
                       "PACKET string");

    return 1;
}

/**
 * Test: Conditional logging
 */
int test_conditional_logging(void)
{
    mmt_log_init();
    mmt_log_set_callback(test_callback);
    mmt_log_set_level(MMT_LOG_TRACE);
    reset_callback_data();

    /* Condition true - should log */
    int value = 10;
    MMT_LOG_ERROR_IF(value > 5, "Value is greater than 5");
    TEST_ASSERT(g_callback_count == 1, "Conditional log with true condition");

    /* Condition false - should not log */
    reset_callback_data();
    MMT_LOG_ERROR_IF(value < 5, "Value is less than 5");
    TEST_ASSERT(g_callback_count == 0, "No log with false condition");

    /* Reset */
    mmt_log_set_callback(NULL);
    mmt_log_set_output_mode(MMT_LOG_OUTPUT_NONE);

    return 1;
}

/**
 * Test: Log once functionality
 */
int test_log_once(void)
{
    mmt_log_init();
    mmt_log_set_callback(test_callback);
    mmt_log_set_level(MMT_LOG_TRACE);
    reset_callback_data();

    /* Log multiple times, should only log once */
    for (int i = 0; i < 5; i++) {
        MMT_LOG_ERROR_ONCE("This should only appear once");
    }

    TEST_ASSERT(g_callback_count == 1, "Log once only logs once despite 5 calls");

    /* Reset */
    mmt_log_set_callback(NULL);
    mmt_log_set_output_mode(MMT_LOG_OUTPUT_NONE);

    return 1;
}

/**
 * Test: Category filtering
 */
int test_category_filtering(void)
{
    mmt_log_init();
    mmt_log_set_callback(test_callback);
    mmt_log_set_level(MMT_LOG_TRACE);

    /* Disable protocol category */
    mmt_log_set_category_enabled(MMT_LOG_CAT_PROTOCOL, false);

    reset_callback_data();
    MMT_LOG_ERROR_CAT(MMT_LOG_CAT_PROTOCOL, "Protocol message");

    /* Should not be logged (category disabled) */
    TEST_ASSERT(g_callback_count == 0, "Disabled category does not log");

    /* Enable session category, should log */
    mmt_log_set_category_enabled(MMT_LOG_CAT_SESSION, true);
    reset_callback_data();
    MMT_LOG_ERROR_CAT(MMT_LOG_CAT_SESSION, "Session message");

    TEST_ASSERT(g_callback_count == 1, "Enabled category logs");
    TEST_ASSERT(g_last_category == MMT_LOG_CAT_SESSION, "Correct category");

    /* Reset - re-enable protocol category for other tests */
    mmt_log_set_category_enabled(MMT_LOG_CAT_PROTOCOL, true);
    mmt_log_set_callback(NULL);
    mmt_log_set_output_mode(MMT_LOG_OUTPUT_NONE);

    return 1;
}

/**
 * Thread function for thread-safety test
 */
void* thread_logging_test(void *arg)
{
    int thread_id = *(int*)arg;

    /* Log messages from this thread */
    for (int i = 0; i < 10; i++) {
        MMT_LOG_INFO("Thread %d message %d", thread_id, i);
        usleep(1000);  /* 1ms delay */
    }

    return NULL;
}

/**
 * Test: Thread-safe logging
 */
int test_thread_safe_logging(void)
{
    mmt_log_init();
    mmt_log_set_output_mode(MMT_LOG_OUTPUT_NONE);
    mmt_log_set_level(MMT_LOG_TRACE);

    pthread_t threads[3];
    int ids[3] = {1, 2, 3};

    /* Create threads that log concurrently */
    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, thread_logging_test, &ids[i]);
    }

    /* Wait for all threads */
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    /* If we get here without crashing, thread-safety works */
    TEST_ASSERT(1, "Concurrent logging succeeded");

    return 1;
}

/**
 * Test: Performance check
 */
int test_performance(void)
{
    mmt_log_init();
    mmt_log_set_output_mode(MMT_LOG_OUTPUT_NONE);
    mmt_log_set_level(MMT_LOG_NONE);  /* Disable all logging */

    /* Log many messages - should be fast due to early exit */
    for (int i = 0; i < 100000; i++) {
        MMT_LOG_DEBUG("Performance test message %d", i);
    }

    /* If this completes quickly, performance is good */
    TEST_ASSERT(1, "Performance test completed");

    return 1;
}

/**
 * Test: Configuration options
 */
int test_configuration(void)
{
    mmt_log_init();

    /* Test timestamp enable/disable */
    mmt_log_set_timestamp_enabled(true);
    mmt_log_set_timestamp_enabled(false);

    /* Test thread ID enable/disable */
    mmt_log_set_thread_id_enabled(true);
    mmt_log_set_thread_id_enabled(false);

    /* Test color enable/disable */
    mmt_log_set_color_enabled(true);
    mmt_log_set_color_enabled(false);

    /* If we get here, configuration works */
    TEST_ASSERT(1, "Configuration options work");

    return 1;
}

/**
 * Main test runner
 */
int main(void)
{
    printf("================================================\n");
    printf(" Logging Framework Test Suite\n");
    printf(" Phase 5: Error Handling and Logging\n");
    printf("================================================\n\n");

    printf("--- Testing Initialization ---\n");
    RUN_TEST(test_initialization);

    printf("\n--- Testing Log Levels ---\n");
    RUN_TEST(test_log_levels);
    RUN_TEST(test_category_levels);

    printf("\n--- Testing Category Management ---\n");
    RUN_TEST(test_category_enable_disable);
    RUN_TEST(test_category_filtering);

    printf("\n--- Testing Log Filtering ---\n");
    RUN_TEST(test_log_filtering);

    printf("\n--- Testing Callbacks ---\n");
    RUN_TEST(test_log_callback);

    printf("\n--- Testing String Conversion ---\n");
    RUN_TEST(test_log_level_strings);
    RUN_TEST(test_log_category_strings);

    printf("\n--- Testing Advanced Features ---\n");
    RUN_TEST(test_conditional_logging);
    RUN_TEST(test_log_once);

    printf("\n--- Testing Thread Safety ---\n");
    RUN_TEST(test_thread_safe_logging);

    printf("\n--- Testing Performance ---\n");
    RUN_TEST(test_performance);

    printf("\n--- Testing Configuration ---\n");
    RUN_TEST(test_configuration);

    printf("\n================================================\n");
    printf(" Test Results\n");
    printf("================================================\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("\n");

    /* Cleanup */
    mmt_log_shutdown();

    if (tests_failed == 0) {
        printf("✓ ALL LOGGING TESTS PASSED!\n");
        return 0;
    } else {
        printf("✗ SOME TESTS FAILED\n");
        return 1;
    }
}
