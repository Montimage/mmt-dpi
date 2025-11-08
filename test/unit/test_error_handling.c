/**
 * Error Handling Framework Test Suite
 * Phase 5: Error Handling and Logging Framework
 *
 * Tests error code system, context storage, and thread-local errors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include "../../src/mmt_core/public_include/mmt_errors.h"

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

/**
 * Test: Error message strings
 */
int test_error_messages(void)
{
    const char *msg;

    /* Test success */
    msg = mmt_error_to_string(MMT_SUCCESS);
    TEST_ASSERT_STR_EQ(msg, "Success", "Success message");

    /* Test memory errors */
    msg = mmt_error_to_string(MMT_ERROR_MEMORY_ALLOC);
    TEST_ASSERT_STR_EQ(msg, "Memory allocation failed", "Memory alloc message");

    msg = mmt_error_to_string(MMT_ERROR_MEMORY_NULL_PTR);
    TEST_ASSERT_STR_EQ(msg, "Null pointer dereference", "Null pointer message");

    /* Test validation errors */
    msg = mmt_error_to_string(MMT_ERROR_INVALID_INPUT);
    TEST_ASSERT_STR_EQ(msg, "Invalid input", "Invalid input message");

    msg = mmt_error_to_string(MMT_ERROR_OVERFLOW);
    TEST_ASSERT_STR_EQ(msg, "Integer overflow", "Overflow message");

    /* Test packet errors */
    msg = mmt_error_to_string(MMT_ERROR_PACKET_TOO_SHORT);
    TEST_ASSERT_STR_EQ(msg, "Packet too short", "Packet too short message");

    /* Test protocol errors */
    msg = mmt_error_to_string(MMT_ERROR_PROTOCOL_NOT_FOUND);
    TEST_ASSERT_STR_EQ(msg, "Protocol not found", "Protocol not found message");

    /* Test session errors */
    msg = mmt_error_to_string(MMT_ERROR_SESSION_NOT_FOUND);
    TEST_ASSERT_STR_EQ(msg, "Session not found", "Session not found message");

    /* Test invalid error code */
    msg = mmt_error_to_string(MMT_ERROR_MAX + 100);
    TEST_ASSERT_STR_EQ(msg, "Invalid error code", "Invalid error code message");

    return 1;
}

/**
 * Test: Setting and getting errors
 */
int test_set_get_error(void)
{
    const mmt_error_context_t *ctx;

    /* Clear any previous error */
    mmt_clear_error();

    /* Initially should have no error */
    ctx = mmt_get_last_error();
    TEST_ASSERT(ctx == NULL, "Initially no error");
    TEST_ASSERT(!mmt_has_error(), "has_error returns false initially");

    /* Set an error */
    mmt_set_error(MMT_ERROR_MEMORY_ALLOC, __FILE__, __LINE__, __func__, "Test error");

    /* Should now have error */
    TEST_ASSERT(mmt_has_error(), "has_error returns true after setting");

    /* Get error context */
    ctx = mmt_get_last_error();
    TEST_ASSERT(ctx != NULL, "Error context not NULL");
    TEST_ASSERT(ctx->code == MMT_ERROR_MEMORY_ALLOC, "Correct error code");
    TEST_ASSERT(ctx->file != NULL, "File is set");
    TEST_ASSERT(ctx->line > 0, "Line is set");
    TEST_ASSERT(ctx->function != NULL, "Function is set");
    TEST_ASSERT_STR_EQ(ctx->message, "Test error", "Message is correct");

    return 1;
}

/**
 * Test: Clearing errors
 */
int test_clear_error(void)
{
    const mmt_error_context_t *ctx;

    /* Set an error */
    mmt_set_error(MMT_ERROR_INVALID_INPUT, __FILE__, __LINE__, __func__, "Test");

    /* Verify error is set */
    TEST_ASSERT(mmt_has_error(), "Error is set");

    /* Clear error */
    mmt_clear_error();

    /* Verify error is cleared */
    TEST_ASSERT(!mmt_has_error(), "Error is cleared");
    ctx = mmt_get_last_error();
    TEST_ASSERT(ctx == NULL, "Error context is NULL after clear");

    return 1;
}

/**
 * Test: MMT_SET_ERROR macro
 */
int test_set_error_macro(void)
{
    const mmt_error_context_t *ctx;

    mmt_clear_error();

    /* Use macro to set error */
    MMT_SET_ERROR(MMT_ERROR_OVERFLOW, "Overflow test");

    /* Verify error was set */
    TEST_ASSERT(mmt_has_error(), "Macro sets error");
    ctx = mmt_get_last_error();
    TEST_ASSERT(ctx != NULL, "Context not NULL");
    TEST_ASSERT(ctx->code == MMT_ERROR_OVERFLOW, "Correct error code");
    TEST_ASSERT_STR_EQ(ctx->message, "Overflow test", "Correct message");
    TEST_ASSERT(ctx->file != NULL, "File is set by macro");
    TEST_ASSERT(ctx->line > 0, "Line is set by macro");
    TEST_ASSERT(ctx->function != NULL, "Function is set by macro");

    return 1;
}

/**
 * Test: MMT_CHECK macro
 */
int test_error_check_passing(void)
{
    mmt_clear_error();

    /* This should NOT trigger error */
    int value = 10;
    MMT_CHECK(value > 5, MMT_ERROR_INVALID_INPUT, "Value too small");

    /* Error should not be set */
    TEST_ASSERT(!mmt_has_error(), "Check passes, no error set");

    return 1;
}

/**
 * Helper function to test MMT_CHECK failure
 */
static mmt_error_t helper_check_fail(int value)
{
    MMT_CHECK(value > 100, MMT_ERROR_INVALID_INPUT, "Value must be > 100");
    return MMT_SUCCESS;
}

/**
 * Test: MMT_CHECK macro failure
 */
int test_error_check_failing(void)
{
    mmt_clear_error();

    /* This should trigger error and return */
    mmt_error_t result = helper_check_fail(50);

    /* Check macro should have returned error */
    TEST_ASSERT(result == MMT_ERROR_INVALID_INPUT, "Check fails, returns error");
    TEST_ASSERT(mmt_has_error(), "Error is set");

    const mmt_error_context_t *ctx = mmt_get_last_error();
    TEST_ASSERT(ctx != NULL, "Context exists");
    TEST_ASSERT(ctx->code == MMT_ERROR_INVALID_INPUT, "Correct error code");

    return 1;
}

/**
 * Test: MMT_CHECK_NOT_NULL macro
 */
int test_check_not_null(void)
{
    mmt_clear_error();

    /* Valid pointer - should pass */
    int value = 42;
    int *ptr = &value;
    MMT_CHECK_NOT_NULL(ptr, "Pointer is NULL");
    TEST_ASSERT(!mmt_has_error(), "Valid pointer passes");

    /* Clear for next test */
    mmt_clear_error();

    return 1;
}

/**
 * Helper function to test MMT_CHECK_NOT_NULL with NULL
 */
static mmt_error_t helper_check_null(void *ptr)
{
    MMT_CHECK_NOT_NULL(ptr, "Pointer should not be NULL");
    return MMT_SUCCESS;
}

/**
 * Test: MMT_CHECK_NOT_NULL with NULL pointer
 */
int test_check_not_null_fails(void)
{
    mmt_clear_error();

    /* NULL pointer - should fail */
    mmt_error_t result = helper_check_null(NULL);

    TEST_ASSERT(result == MMT_ERROR_MEMORY_NULL_PTR, "NULL check returns error");
    TEST_ASSERT(mmt_has_error(), "Error is set for NULL");

    return 1;
}

/**
 * Test: Error code ranges
 */
int test_error_code_ranges(void)
{
    /* Test that error codes are in expected ranges */
    TEST_ASSERT(MMT_ERROR_MEMORY_ALLOC >= 100 && MMT_ERROR_MEMORY_ALLOC < 200,
                "Memory errors in 100-199 range");
    TEST_ASSERT(MMT_ERROR_INVALID_INPUT >= 200 && MMT_ERROR_INVALID_INPUT < 300,
                "Validation errors in 200-299 range");
    TEST_ASSERT(MMT_ERROR_PACKET_TOO_SHORT >= 300 && MMT_ERROR_PACKET_TOO_SHORT < 400,
                "Packet errors in 300-399 range");
    TEST_ASSERT(MMT_ERROR_PROTOCOL_NOT_FOUND >= 400 && MMT_ERROR_PROTOCOL_NOT_FOUND < 500,
                "Protocol errors in 400-499 range");
    TEST_ASSERT(MMT_ERROR_SESSION_NOT_FOUND >= 500 && MMT_ERROR_SESSION_NOT_FOUND < 600,
                "Session errors in 500-599 range");
    TEST_ASSERT(MMT_ERROR_FILE_OPEN >= 600 && MMT_ERROR_FILE_OPEN < 700,
                "File errors in 600-699 range");
    TEST_ASSERT(MMT_ERROR_LOCK_FAILED >= 900 && MMT_ERROR_LOCK_FAILED < 1000,
                "Thread errors in 900-999 range");

    return 1;
}

/**
 * Thread function for thread-local storage test
 */
static void* thread_error_test(void *arg)
{
    int thread_id = *(int*)arg;
    mmt_error_t expected_error;

    /* Each thread sets different error */
    if (thread_id == 1) {
        expected_error = MMT_ERROR_MEMORY_ALLOC;
        MMT_SET_ERROR(expected_error, "Thread 1 error");
    } else {
        expected_error = MMT_ERROR_PROTOCOL_NOT_FOUND;
        MMT_SET_ERROR(expected_error, "Thread 2 error");
    }

    /* Small delay to ensure concurrent execution */
    usleep(10000);  /* 10ms */

    /* Verify thread-local error is correct */
    const mmt_error_context_t *ctx = mmt_get_last_error();
    if (ctx == NULL) {
        return (void*)0;  /* FAIL */
    }

    if (ctx->code != expected_error) {
        return (void*)0;  /* FAIL */
    }

    return (void*)1;  /* PASS */
}

/**
 * Test: Thread-local error storage
 */
int test_thread_local_errors(void)
{
    pthread_t thread1, thread2;
    int id1 = 1, id2 = 2;
    void *result1, *result2;

    /* Create two threads that set different errors */
    pthread_create(&thread1, NULL, thread_error_test, &id1);
    pthread_create(&thread2, NULL, thread_error_test, &id2);

    /* Wait for threads */
    pthread_join(thread1, &result1);
    pthread_join(thread2, &result2);

    /* Both threads should have succeeded (kept separate errors) */
    TEST_ASSERT(result1 == (void*)1, "Thread 1 maintained its error");
    TEST_ASSERT(result2 == (void*)1, "Thread 2 maintained its error");

    return 1;
}

/**
 * Test: errno capture
 */
int test_errno_capture(void)
{
    mmt_clear_error();

    /* Set errno to a specific value */
    errno = EACCES;

    /* Set MMT error */
    MMT_SET_ERROR(MMT_ERROR_FILE_PERMISSION, "Permission denied");

    /* Check that errno was captured */
    const mmt_error_context_t *ctx = mmt_get_last_error();
    TEST_ASSERT(ctx != NULL, "Error context exists");
    TEST_ASSERT(ctx->system_errno == EACCES, "errno was captured");

    return 1;
}

/**
 * Test: Multiple error overwrites
 */
int test_error_overwrite(void)
{
    mmt_clear_error();

    /* Set first error */
    MMT_SET_ERROR(MMT_ERROR_MEMORY_ALLOC, "First error");

    /* Set second error (should overwrite) */
    MMT_SET_ERROR(MMT_ERROR_OVERFLOW, "Second error");

    /* Should have second error */
    const mmt_error_context_t *ctx = mmt_get_last_error();
    TEST_ASSERT(ctx != NULL, "Error context exists");
    TEST_ASSERT(ctx->code == MMT_ERROR_OVERFLOW, "Second error overwrites first");
    TEST_ASSERT_STR_EQ(ctx->message, "Second error", "Second message");

    return 1;
}

/**
 * Main test runner
 */
int main(void)
{
    printf("================================================\n");
    printf(" Error Handling Framework Test Suite\n");
    printf(" Phase 5: Error Handling and Logging\n");
    printf("================================================\n\n");

    printf("--- Testing Error Messages ---\n");
    RUN_TEST(test_error_messages);

    printf("\n--- Testing Error Set/Get/Clear ---\n");
    RUN_TEST(test_set_get_error);
    RUN_TEST(test_clear_error);

    printf("\n--- Testing Error Macros ---\n");
    RUN_TEST(test_set_error_macro);
    RUN_TEST(test_error_check_passing);
    RUN_TEST(test_error_check_failing);
    RUN_TEST(test_check_not_null);
    RUN_TEST(test_check_not_null_fails);

    printf("\n--- Testing Error Code Organization ---\n");
    RUN_TEST(test_error_code_ranges);

    printf("\n--- Testing Thread Safety ---\n");
    RUN_TEST(test_thread_local_errors);

    printf("\n--- Testing Advanced Features ---\n");
    RUN_TEST(test_errno_capture);
    RUN_TEST(test_error_overwrite);

    printf("\n================================================\n");
    printf(" Test Results\n");
    printf("================================================\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("\n");

    if (tests_failed == 0) {
        printf("✓ ALL ERROR HANDLING TESTS PASSED!\n");
        return 0;
    } else {
        printf("✗ SOME TESTS FAILED\n");
        return 1;
    }
}
