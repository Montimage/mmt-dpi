/**
 * Validation Framework Test Suite
 * Phase 4: Input Validation Framework
 *
 * Tests all validation functions and macros to ensure correct behavior
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "../../src/mmt_core/public_include/mmt_safe_access.h"
#include "../../src/mmt_core/public_include/mmt_safe_math.h"

/* Mock pcap_pkthdr for testing */
struct pcap_pkthdr {
    uint32_t caplen;
    uint32_t len;
};

/* Test suite statistics */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Helper to create mock packet */
static ipacket_t* create_mock_packet(size_t size) {
    ipacket_t *pkt = calloc(1, sizeof(ipacket_t));
    if (!pkt) return NULL;

    pkt->p_hdr = calloc(1, sizeof(struct pcap_pkthdr));
    if (!pkt->p_hdr) {
        free(pkt);
        return NULL;
    }

    pkt->p_hdr->caplen = size;
    pkt->p_hdr->len = size;

    /* Cast away const for test purposes */
    uint8_t *data = calloc(1, size);
    if (!data) {
        free(pkt->p_hdr);
        free(pkt);
        return NULL;
    }
    pkt->data = (const uint8_t*)data;

    return pkt;
}

static void free_mock_packet(ipacket_t *pkt) {
    if (pkt) {
        /* Cast away const for freeing */
        free((void*)pkt->data);
        free(pkt->p_hdr);
        free(pkt);
    }
}

/* Test macros */
#define TEST_ASSERT(condition, msg) \
    do { \
        if (!(condition)) { \
            printf("  ✗ FAIL: %s\n", msg); \
            tests_failed++; \
            return; \
        } \
    } while(0)

#define RUN_TEST(test_func) \
    do { \
        tests_run++; \
        printf("Running: " #test_func "... "); \
        fflush(stdout); \
        test_func(); \
        tests_passed++; \
        printf("✓ PASS\n"); \
    } while(0)

/*===========================================================================
 * Test Cases: mmt_validate_offset()
 *===========================================================================*/

void test_validate_offset_valid() {
    ipacket_t *pkt = create_mock_packet(100);
    TEST_ASSERT(pkt != NULL, "Failed to create mock packet");

    // Valid accesses
    TEST_ASSERT(mmt_validate_offset(pkt, 0, 50), "Valid offset 0-50 failed");
    TEST_ASSERT(mmt_validate_offset(pkt, 50, 50), "Valid offset 50-100 failed");
    TEST_ASSERT(mmt_validate_offset(pkt, 0, 100), "Valid offset 0-100 failed");
    TEST_ASSERT(mmt_validate_offset(pkt, 99, 1), "Valid offset 99-100 failed");
    TEST_ASSERT(mmt_validate_offset(pkt, 0, 0), "Valid zero-length access failed");

    free_mock_packet(pkt);
}

void test_validate_offset_out_of_bounds() {
    ipacket_t *pkt = create_mock_packet(100);
    TEST_ASSERT(pkt != NULL, "Failed to create mock packet");

    // Out of bounds accesses
    TEST_ASSERT(!mmt_validate_offset(pkt, 90, 20), "Out of bounds not detected");
    TEST_ASSERT(!mmt_validate_offset(pkt, 100, 1), "At-boundary+1 not detected");
    TEST_ASSERT(!mmt_validate_offset(pkt, 101, 0), "Beyond packet not detected");
    TEST_ASSERT(!mmt_validate_offset(pkt, 1000, 10), "Far beyond not detected");

    free_mock_packet(pkt);
}

void test_validate_offset_overflow() {
    ipacket_t *pkt = create_mock_packet(100);
    TEST_ASSERT(pkt != NULL, "Failed to create mock packet");

    // Integer overflow cases
    TEST_ASSERT(!mmt_validate_offset(pkt, UINT32_MAX, 1), "UINT32_MAX overflow not detected");
    TEST_ASSERT(!mmt_validate_offset(pkt, UINT32_MAX - 10, 20), "Near-max overflow not detected");
    TEST_ASSERT(!mmt_validate_offset(pkt, UINT32_MAX / 2, UINT32_MAX / 2 + 100), "Large overflow not detected");

    free_mock_packet(pkt);
}

void test_validate_offset_null_checks() {
    // Null packet pointer
    TEST_ASSERT(!mmt_validate_offset(NULL, 0, 10), "Null packet not detected");

    // Null p_hdr
    ipacket_t pkt_no_hdr;
    memset(&pkt_no_hdr, 0, sizeof(pkt_no_hdr));
    pkt_no_hdr.p_hdr = NULL;
    TEST_ASSERT(!mmt_validate_offset(&pkt_no_hdr, 0, 10), "Null p_hdr not detected");
}

/*===========================================================================
 * Test Cases: mmt_safe_packet_ptr()
 *===========================================================================*/

void test_safe_packet_ptr_valid() {
    ipacket_t *pkt = create_mock_packet(100);
    TEST_ASSERT(pkt != NULL, "Failed to create mock packet");

    // Set some test data (cast away const for test purposes)
    uint8_t *data = (uint8_t*)pkt->data;
    data[50] = 0xAA;
    data[51] = 0xBB;

    // Valid pointer retrieval
    const uint8_t *ptr = mmt_safe_packet_ptr(pkt, 50, 2);
    TEST_ASSERT(ptr != NULL, "Safe pointer should not be NULL");
    TEST_ASSERT(ptr == &pkt->data[50], "Pointer should point to correct location");
    TEST_ASSERT(*ptr == 0xAA, "Data should be accessible");

    free_mock_packet(pkt);
}

void test_safe_packet_ptr_invalid() {
    ipacket_t *pkt = create_mock_packet(100);
    TEST_ASSERT(pkt != NULL, "Failed to create mock packet");

    // Invalid pointer retrievals
    const uint8_t *ptr1 = mmt_safe_packet_ptr(pkt, 90, 20);
    TEST_ASSERT(ptr1 == NULL, "Out of bounds should return NULL");

    const uint8_t *ptr2 = mmt_safe_packet_ptr(pkt, UINT32_MAX, 1);
    TEST_ASSERT(ptr2 == NULL, "Overflow should return NULL");

    const uint8_t *ptr3 = mmt_safe_packet_ptr(NULL, 0, 10);
    TEST_ASSERT(ptr3 == NULL, "Null packet should return NULL");

    free_mock_packet(pkt);
}

/*===========================================================================
 * Test Cases: MMT_SAFE_CAST()
 *===========================================================================*/

struct test_header {
    uint16_t field1;
    uint32_t field2;
    uint8_t field3;
};

void test_safe_cast_valid() {
    ipacket_t *pkt = create_mock_packet(100);
    TEST_ASSERT(pkt != NULL, "Failed to create mock packet");

    // Set test data (cast away const for test purposes)
    uint8_t *data = (uint8_t*)pkt->data;
    struct test_header *hdr = (struct test_header*)&data[10];
    hdr->field1 = 0x1234;
    hdr->field2 = 0xABCDEF00;
    hdr->field3 = 0x42;

    // Safe cast
    const struct test_header *cast_hdr = MMT_SAFE_CAST(pkt, 10, struct test_header);
    TEST_ASSERT(cast_hdr != NULL, "Safe cast should succeed");
    TEST_ASSERT(cast_hdr->field1 == 0x1234, "Field1 should be accessible");
    TEST_ASSERT(cast_hdr->field2 == 0xABCDEF00, "Field2 should be accessible");
    TEST_ASSERT(cast_hdr->field3 == 0x42, "Field3 should be accessible");

    free_mock_packet(pkt);
}

void test_safe_cast_invalid() {
    ipacket_t *pkt = create_mock_packet(100);
    TEST_ASSERT(pkt != NULL, "Failed to create mock packet");

    // Cast that would extend beyond packet
    const struct test_header *cast_hdr1 = MMT_SAFE_CAST(pkt, 95, struct test_header);
    TEST_ASSERT(cast_hdr1 == NULL, "Out of bounds cast should return NULL");

    // Cast at exact boundary
    const struct test_header *cast_hdr2 = MMT_SAFE_CAST(pkt, 100, struct test_header);
    TEST_ASSERT(cast_hdr2 == NULL, "Boundary cast should return NULL");

    free_mock_packet(pkt);
}

/*===========================================================================
 * Test Cases: Safe Math Operations
 *===========================================================================*/

void test_safe_add_u32() {
    uint32_t result;

    // Valid additions
    TEST_ASSERT(mmt_safe_add_u32(100, 200, &result), "Valid addition 100+200 failed");
    TEST_ASSERT(result == 300, "Result should be 300");

    TEST_ASSERT(mmt_safe_add_u32(0, 0, &result), "Addition 0+0 failed");
    TEST_ASSERT(result == 0, "Result should be 0");

    TEST_ASSERT(mmt_safe_add_u32(UINT32_MAX - 1, 1, &result), "Max-1+1 failed");
    TEST_ASSERT(result == UINT32_MAX, "Result should be UINT32_MAX");

    // Overflow cases
    TEST_ASSERT(!mmt_safe_add_u32(UINT32_MAX, 1, &result), "Overflow not detected");
    TEST_ASSERT(!mmt_safe_add_u32(UINT32_MAX, UINT32_MAX, &result), "Double overflow not detected");
    TEST_ASSERT(!mmt_safe_add_u32(UINT32_MAX - 100, 200, &result), "Near-max overflow not detected");
}

void test_safe_mul_u32() {
    uint32_t result;

    // Valid multiplications
    TEST_ASSERT(mmt_safe_mul_u32(100, 200, &result), "Valid multiplication 100*200 failed");
    TEST_ASSERT(result == 20000, "Result should be 20000");

    TEST_ASSERT(mmt_safe_mul_u32(0, 100, &result), "Multiplication 0*100 failed");
    TEST_ASSERT(result == 0, "Result should be 0");

    TEST_ASSERT(mmt_safe_mul_u32(1, UINT32_MAX, &result), "Multiplication 1*MAX failed");
    TEST_ASSERT(result == UINT32_MAX, "Result should be UINT32_MAX");

    // Overflow cases
    TEST_ASSERT(!mmt_safe_mul_u32(UINT32_MAX, 2, &result), "Overflow not detected");
    TEST_ASSERT(!mmt_safe_mul_u32(UINT32_MAX / 2, 3, &result), "Partial overflow not detected");
    TEST_ASSERT(!mmt_safe_mul_u32(65536, 65536, &result), "Large multiplication overflow not detected");
}

void test_safe_sub_u32() {
    uint32_t result;

    // Valid subtractions
    TEST_ASSERT(mmt_safe_sub_u32(200, 100, &result), "Valid subtraction 200-100 failed");
    TEST_ASSERT(result == 100, "Result should be 100");

    TEST_ASSERT(mmt_safe_sub_u32(100, 100, &result), "Subtraction 100-100 failed");
    TEST_ASSERT(result == 0, "Result should be 0");

    TEST_ASSERT(mmt_safe_sub_u32(UINT32_MAX, 1, &result), "Subtraction MAX-1 failed");
    TEST_ASSERT(result == UINT32_MAX - 1, "Result should be MAX-1");

    // Underflow cases
    TEST_ASSERT(!mmt_safe_sub_u32(100, 200, &result), "Underflow not detected");
    TEST_ASSERT(!mmt_safe_sub_u32(0, 1, &result), "Zero underflow not detected");
    TEST_ASSERT(!mmt_safe_sub_u32(1, 2, &result), "Small underflow not detected");
}

void test_safe_shl_u16() {
    uint16_t result;

    // Valid shifts
    TEST_ASSERT(mmt_safe_shl_u16(1, 0, &result), "Shift by 0 failed");
    TEST_ASSERT(result == 1, "Result should be 1");

    TEST_ASSERT(mmt_safe_shl_u16(1, 8, &result), "Shift 1<<8 failed");
    TEST_ASSERT(result == 256, "Result should be 256");

    TEST_ASSERT(mmt_safe_shl_u16(0x1FFF, 3, &result), "Shift 0x1FFF<<3 failed");
    TEST_ASSERT(result == 0xFFF8, "Result should be 0xFFF8");

    // Overflow cases
    TEST_ASSERT(!mmt_safe_shl_u16(1, 16, &result), "Shift >= 16 not detected");
    TEST_ASSERT(!mmt_safe_shl_u16(0x4000, 3, &result), "Shift overflow not detected");
    TEST_ASSERT(!mmt_safe_shl_u16(0xFFFF, 1, &result), "Max shift overflow not detected");
}

/*===========================================================================
 * Main Test Runner
 *===========================================================================*/

int main() {
    printf("\n");
    printf("================================================\n");
    printf(" Validation Framework Test Suite\n");
    printf(" Phase 4: Input Validation\n");
    printf("================================================\n");
    printf("\n");

    printf("--- Testing mmt_validate_offset() ---\n");
    RUN_TEST(test_validate_offset_valid);
    RUN_TEST(test_validate_offset_out_of_bounds);
    RUN_TEST(test_validate_offset_overflow);
    RUN_TEST(test_validate_offset_null_checks);

    printf("\n--- Testing mmt_safe_packet_ptr() ---\n");
    RUN_TEST(test_safe_packet_ptr_valid);
    RUN_TEST(test_safe_packet_ptr_invalid);

    printf("\n--- Testing MMT_SAFE_CAST() ---\n");
    RUN_TEST(test_safe_cast_valid);
    RUN_TEST(test_safe_cast_invalid);

    printf("\n--- Testing Safe Math Operations ---\n");
    RUN_TEST(test_safe_add_u32);
    RUN_TEST(test_safe_mul_u32);
    RUN_TEST(test_safe_sub_u32);
    RUN_TEST(test_safe_shl_u16);

    printf("\n");
    printf("================================================\n");
    printf(" Test Results\n");
    printf("================================================\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("\n");

    if (tests_failed == 0) {
        printf("✓ ALL VALIDATION FRAMEWORK TESTS PASSED!\n");
        printf("\n");
        return 0;
    } else {
        printf("✗ SOME TESTS FAILED\n");
        printf("\n");
        return 1;
    }
}
