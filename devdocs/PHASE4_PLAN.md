# Phase 4: Input Validation Framework - Implementation Plan

**Date:** 2025-11-08
**Branch:** `claude/deep-analysis-011CUvGnTGxbn8rBZAgruD9T`
**Status:** IN PROGRESS
**Estimated Time:** 40-60 hours

---

## Overview

Phase 4 builds on Phase 1 security fixes by creating a systematic input validation framework. While Phase 1 fixed specific vulnerabilities reactively, Phase 4 establishes proactive validation infrastructure to prevent future issues.

**Goals:**

1. Create reusable validation framework
2. Add systematic bounds checking across all protocols
3. Establish fuzzing infrastructure
4. Document validation patterns for new protocol development

---

## Task 4.1: Create Validation Framework

**Priority:** P1 - HIGH
**Estimated Time:** 16 hours
**Objective:** Build reusable validation infrastructure

### Subtask 4.1.1: Create Safe Access Header (4h)

**File:** `src/mmt_core/public_include/mmt_safe_access.h`

**Implementation:**

```c
#ifndef MMT_SAFE_ACCESS_H
#define MMT_SAFE_ACCESS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "data_defs.h"

/* Validation error codes */
typedef enum {
    MMT_VALIDATE_OK = 0,
    MMT_VALIDATE_NULL_PTR,
    MMT_VALIDATE_OVERFLOW,
    MMT_VALIDATE_OUT_OF_BOUNDS,
    MMT_VALIDATE_INVALID_LENGTH,
    MMT_VALIDATE_INVALID_OFFSET
} mmt_validate_result_t;

/**
 * Validate that offset + len is within packet bounds
 * @param pkt Packet to check
 * @param offset Starting offset
 * @param len Length to access
 * @return MMT_VALIDATE_OK if safe, error code otherwise
 */
static inline mmt_validate_result_t mmt_validate_offset(
    const ipacket_t *pkt,
    uint32_t offset,
    uint32_t len)
{
    if (pkt == NULL || pkt->p_hdr == NULL) {
        return MMT_VALIDATE_NULL_PTR;
    }

    // Check for integer overflow
    if (offset > UINT32_MAX - len) {
        return MMT_VALIDATE_OVERFLOW;
    }

    uint32_t end_offset = offset + len;

    // Check bounds
    if (end_offset > pkt->p_hdr->caplen) {
        return MMT_VALIDATE_OUT_OF_BOUNDS;
    }

    return MMT_VALIDATE_OK;
}

/**
 * Get a safe pointer to packet data
 * @param pkt Packet
 * @param offset Starting offset
 * @param len Length required
 * @return Pointer to data if safe, NULL otherwise
 */
static inline const uint8_t* mmt_safe_packet_ptr(
    const ipacket_t *pkt,
    uint32_t offset,
    uint32_t len)
{
    if (mmt_validate_offset(pkt, offset, len) != MMT_VALIDATE_OK) {
        return NULL;
    }
    return &pkt->data[offset];
}

/**
 * Safe cast to structure type with validation
 */
#define MMT_SAFE_CAST(pkt, offset, type) \
    ((const type*)(mmt_validate_offset(pkt, offset, sizeof(type)) == MMT_VALIDATE_OK ? \
     &pkt->data[offset] : NULL))

/**
 * Validate minimum packet size for protocol
 */
static inline bool mmt_validate_min_size(
    const ipacket_t *pkt,
    uint32_t offset,
    uint32_t min_size)
{
    if (pkt == NULL || pkt->p_hdr == NULL) {
        return false;
    }

    if (offset > pkt->p_hdr->caplen) {
        return false;
    }

    uint32_t remaining = pkt->p_hdr->caplen - offset;
    return (remaining >= min_size);
}

/**
 * Validate string length and null termination
 */
static inline bool mmt_validate_string(
    const char *str,
    size_t max_len)
{
    if (str == NULL) {
        return false;
    }

    // Check for null terminator within max_len
    for (size_t i = 0; i < max_len; i++) {
        if (str[i] == '\0') {
            return true;
        }
    }

    return false;  // No null terminator found
}

/**
 * Validate array index
 */
static inline bool mmt_validate_index(
    size_t index,
    size_t array_size)
{
    return (index < array_size);
}

#endif /* MMT_SAFE_ACCESS_H */
```

**Testing:**

```bash
cat > test/unit/test_safe_access.c << 'EOF'
#include <stdio.h>
#include <assert.h>
#include "../../src/mmt_core/public_include/mmt_safe_access.h"

void test_validate_offset() {
    // Mock packet
    struct pcap_pkthdr hdr = {.caplen = 100};
    uint8_t data[100];
    ipacket_t pkt = {.p_hdr = &hdr, .data = data};

    // Valid access
    assert(mmt_validate_offset(&pkt, 0, 50) == MMT_VALIDATE_OK);
    printf("✓ Valid offset check passed\n");

    // Out of bounds
    assert(mmt_validate_offset(&pkt, 90, 20) == MMT_VALIDATE_OUT_OF_BOUNDS);
    printf("✓ Out of bounds detected\n");

    // Overflow check
    assert(mmt_validate_offset(&pkt, UINT32_MAX - 10, 20) == MMT_VALIDATE_OVERFLOW);
    printf("✓ Overflow detected\n");
}

int main() {
    test_validate_offset();
    printf("✓ All safe access tests passed\n");
    return 0;
}
EOF
```

**Acceptance Criteria:**

- [ ] Header compiles without errors
- [ ] All validation functions implemented
- [ ] Unit tests pass
- [ ] Zero false positives in testing

---

### Subtask 4.1.2: Create Safe Math Operations (4h)

**File:** `src/mmt_core/public_include/mmt_safe_math.h`

**Implementation:**

```c
#ifndef MMT_SAFE_MATH_H
#define MMT_SAFE_MATH_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/**
 * Safe addition for uint32_t
 * @param a First operand
 * @param b Second operand
 * @param result Pointer to store result
 * @return true if operation succeeded, false if overflow
 */
static inline bool mmt_safe_add_u32(uint32_t a, uint32_t b, uint32_t *result) {
    if (UINT32_MAX - a < b) {
        return false;  // Overflow would occur
    }
    *result = a + b;
    return true;
}

/**
 * Safe multiplication for uint32_t
 * @param a First operand
 * @param b Second operand
 * @param result Pointer to store result
 * @return true if operation succeeded, false if overflow
 */
static inline bool mmt_safe_mul_u32(uint32_t a, uint32_t b, uint32_t *result) {
    if (a != 0 && b > UINT32_MAX / a) {
        return false;  // Overflow would occur
    }
    *result = a * b;
    return true;
}

/**
 * Safe subtraction for uint32_t
 * @param a First operand (minuend)
 * @param b Second operand (subtrahend)
 * @param result Pointer to store result
 * @return true if operation succeeded, false if underflow
 */
static inline bool mmt_safe_sub_u32(uint32_t a, uint32_t b, uint32_t *result) {
    if (a < b) {
        return false;  // Underflow would occur
    }
    *result = a - b;
    return true;
}

/**
 * Safe left shift for uint16_t
 * @param value Value to shift
 * @param shift Number of positions to shift
 * @param result Pointer to store result
 * @return true if operation succeeded, false if overflow
 */
static inline bool mmt_safe_shl_u16(uint16_t value, unsigned int shift, uint16_t *result) {
    if (shift >= 16) {
        return false;  // Shift too large
    }

    // Check if shift would cause overflow
    if (value >> (16 - shift) != 0) {
        return false;
    }

    *result = value << shift;
    return true;
}

/**
 * Safe conversion uint16_t to uint8_t
 * @param value Value to convert
 * @param result Pointer to store result
 * @return true if conversion safe, false if truncation would occur
 */
static inline bool mmt_safe_u16_to_u8(uint16_t value, uint8_t *result) {
    if (value > UINT8_MAX) {
        return false;
    }
    *result = (uint8_t)value;
    return true;
}

/**
 * Check if value is power of 2
 */
static inline bool mmt_is_power_of_2(uint32_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

/**
 * Align value up to next power of 2
 */
static inline uint32_t mmt_align_up_pow2(uint32_t value, uint32_t alignment) {
    if (!mmt_is_power_of_2(alignment)) {
        return value;  // Invalid alignment
    }
    return (value + alignment - 1) & ~(alignment - 1);
}

#endif /* MMT_SAFE_MATH_H */
```

**Testing:**

```bash
cat > test/unit/test_safe_math.c << 'EOF'
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include "../../src/mmt_core/public_include/mmt_safe_math.h"

void test_safe_add() {
    uint32_t result;

    // Valid addition
    assert(mmt_safe_add_u32(100, 200, &result));
    assert(result == 300);
    printf("✓ Safe addition works\n");

    // Overflow detection
    assert(!mmt_safe_add_u32(UINT32_MAX, 1, &result));
    printf("✓ Addition overflow detected\n");
}

void test_safe_mul() {
    uint32_t result;

    // Valid multiplication
    assert(mmt_safe_mul_u32(100, 200, &result));
    assert(result == 20000);
    printf("✓ Safe multiplication works\n");

    // Overflow detection
    assert(!mmt_safe_mul_u32(UINT32_MAX, 2, &result));
    printf("✓ Multiplication overflow detected\n");
}

int main() {
    test_safe_add();
    test_safe_mul();
    printf("✓ All safe math tests passed\n");
    return 0;
}
EOF
```

---

### Subtask 4.1.3: Create Protocol Validation Macros (4h)

**File:** `src/mmt_core/public_include/mmt_protocol_validation.h`

**Implementation:**

```c
#ifndef MMT_PROTOCOL_VALIDATION_H
#define MMT_PROTOCOL_VALIDATION_H

#include "mmt_safe_access.h"
#include "mmt_safe_math.h"

/**
 * Validate protocol minimum header size
 */
#define MMT_VALIDATE_MIN_HEADER(ipacket, offset, header_type, proto_name) \
    do { \
        if (!mmt_validate_min_size(ipacket, offset, sizeof(header_type))) { \
            MMT_LOG(proto_name, MMT_LOG_ERROR, \
                    "Packet too small for " #header_type " header"); \
            return 0; \
        } \
    } while(0)

/**
 * Validate and extract header pointer
 */
#define MMT_GET_HEADER_PTR(ipacket, offset, header_type, ptr_name, proto_name) \
    const header_type *ptr_name = MMT_SAFE_CAST(ipacket, offset, header_type); \
    if (ptr_name == NULL) { \
        MMT_LOG(proto_name, MMT_LOG_ERROR, \
                "Failed to access " #header_type " header"); \
        return 0; \
    }

/**
 * Validate field value is within range
 */
#define MMT_VALIDATE_RANGE(value, min, max, field_name, proto_name) \
    do { \
        if ((value) < (min) || (value) > (max)) { \
            MMT_LOG(proto_name, MMT_LOG_WARNING, \
                    #field_name " value %u out of range [%u, %u]", \
                    (unsigned)(value), (unsigned)(min), (unsigned)(max)); \
            return 0; \
        } \
    } while(0)

/**
 * Validate variable-length field
 */
#define MMT_VALIDATE_VAR_LENGTH(ipacket, offset, length, max_length, proto_name) \
    do { \
        if ((length) > (max_length)) { \
            MMT_LOG(proto_name, MMT_LOG_WARNING, \
                    "Variable length %u exceeds maximum %u", \
                    (unsigned)(length), (unsigned)(max_length)); \
            return 0; \
        } \
        if (mmt_validate_offset(ipacket, offset, length) != MMT_VALIDATE_OK) { \
            MMT_LOG(proto_name, MMT_LOG_ERROR, \
                    "Variable length field extends beyond packet"); \
            return 0; \
        } \
    } while(0)

/**
 * Validate protocol version
 */
#define MMT_VALIDATE_VERSION(version, expected, proto_name) \
    do { \
        if ((version) != (expected)) { \
            MMT_LOG(proto_name, MMT_LOG_WARNING, \
                    "Unexpected protocol version %u (expected %u)", \
                    (unsigned)(version), (unsigned)(expected)); \
            return 0; \
        } \
    } while(0)

/**
 * Validate flags/bitmask
 */
#define MMT_VALIDATE_FLAGS(flags, valid_mask, proto_name) \
    do { \
        if (((flags) & ~(valid_mask)) != 0) { \
            MMT_LOG(proto_name, MMT_LOG_DEBUG, \
                    "Invalid flags 0x%X (valid mask: 0x%X)", \
                    (unsigned)(flags), (unsigned)(valid_mask)); \
        } \
    } while(0)

/**
 * Validate array index
 */
#define MMT_VALIDATE_INDEX(index, array_size, array_name, proto_name) \
    do { \
        if (!mmt_validate_index(index, array_size)) { \
            MMT_LOG(proto_name, MMT_LOG_ERROR, \
                    "Index %u out of bounds for " #array_name " (size %u)", \
                    (unsigned)(index), (unsigned)(array_size)); \
            return 0; \
        } \
    } while(0)

/**
 * Validate pointer is not NULL
 */
#define MMT_VALIDATE_NOT_NULL(ptr, ptr_name, proto_name) \
    do { \
        if ((ptr) == NULL) { \
            MMT_LOG(proto_name, MMT_LOG_ERROR, \
                    #ptr_name " is NULL"); \
            return 0; \
        } \
    } while(0)

#endif /* MMT_PROTOCOL_VALIDATION_H */
```

**Usage Example:**

```c
// In proto_example.c
#include "mmt_protocol_validation.h"

int classify_example_protocol(ipacket_t *ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    // Validate minimum size
    MMT_VALIDATE_MIN_HEADER(ipacket, offset, example_header_t, PROTO_EXAMPLE);

    // Get header pointer safely
    MMT_GET_HEADER_PTR(ipacket, offset, example_header_t, hdr, PROTO_EXAMPLE);

    // Validate version
    MMT_VALIDATE_VERSION(hdr->version, 1, PROTO_EXAMPLE);

    // Validate length field
    uint16_t payload_len = ntohs(hdr->length);
    MMT_VALIDATE_VAR_LENGTH(ipacket, offset + sizeof(example_header_t),
                            payload_len, 65535, PROTO_EXAMPLE);

    // Continue with classification...
    return 1;
}
```

---

### Subtask 4.1.4: Create Validation Testing Framework (4h)

**File:** `test/validation/test_validation_framework.c`

**Implementation:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../src/mmt_core/public_include/mmt_safe_access.h"
#include "../../src/mmt_core/public_include/mmt_safe_math.h"

/* Test suite structure */
typedef struct {
    const char *name;
    void (*test_func)(void);
    int passed;
} test_case_t;

/* Test results */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Helper to create mock packet */
static ipacket_t* create_mock_packet(size_t size) {
    ipacket_t *pkt = calloc(1, sizeof(ipacket_t));
    pkt->p_hdr = calloc(1, sizeof(struct pcap_pkthdr));
    pkt->p_hdr->caplen = size;
    pkt->data = calloc(1, size);
    return pkt;
}

static void free_mock_packet(ipacket_t *pkt) {
    if (pkt) {
        free(pkt->p_hdr);
        free(pkt->data);
        free(pkt);
    }
}

/* Test cases */

void test_valid_access() {
    ipacket_t *pkt = create_mock_packet(100);

    assert(mmt_validate_offset(pkt, 0, 50) == MMT_VALIDATE_OK);
    assert(mmt_validate_offset(pkt, 50, 50) == MMT_VALIDATE_OK);
    assert(mmt_validate_offset(pkt, 0, 100) == MMT_VALIDATE_OK);

    free_mock_packet(pkt);
}

void test_out_of_bounds() {
    ipacket_t *pkt = create_mock_packet(100);

    assert(mmt_validate_offset(pkt, 90, 20) == MMT_VALIDATE_OUT_OF_BOUNDS);
    assert(mmt_validate_offset(pkt, 100, 1) == MMT_VALIDATE_OUT_OF_BOUNDS);
    assert(mmt_validate_offset(pkt, 101, 0) == MMT_VALIDATE_OUT_OF_BOUNDS);

    free_mock_packet(pkt);
}

void test_overflow_detection() {
    ipacket_t *pkt = create_mock_packet(100);

    assert(mmt_validate_offset(pkt, UINT32_MAX, 1) == MMT_VALIDATE_OVERFLOW);
    assert(mmt_validate_offset(pkt, UINT32_MAX - 10, 20) == MMT_VALIDATE_OVERFLOW);

    free_mock_packet(pkt);
}

void test_null_packet() {
    assert(mmt_validate_offset(NULL, 0, 10) == MMT_VALIDATE_NULL_PTR);

    ipacket_t pkt_no_hdr = {.p_hdr = NULL};
    assert(mmt_validate_offset(&pkt_no_hdr, 0, 10) == MMT_VALIDATE_NULL_PTR);
}

void test_safe_math_add() {
    uint32_t result;

    assert(mmt_safe_add_u32(100, 200, &result));
    assert(result == 300);

    assert(!mmt_safe_add_u32(UINT32_MAX, 1, &result));
    assert(!mmt_safe_add_u32(UINT32_MAX - 100, 200, &result));
}

void test_safe_math_mul() {
    uint32_t result;

    assert(mmt_safe_mul_u32(100, 200, &result));
    assert(result == 20000);

    assert(!mmt_safe_mul_u32(UINT32_MAX, 2, &result));
    assert(!mmt_safe_mul_u32(UINT32_MAX / 2, 3, &result));
}

void test_safe_math_sub() {
    uint32_t result;

    assert(mmt_safe_sub_u32(200, 100, &result));
    assert(result == 100);

    assert(!mmt_safe_sub_u32(100, 200, &result));
    assert(!mmt_safe_sub_u32(0, 1, &result));
}

/* Test runner */

void run_test(const char *name, void (*test_func)(void)) {
    tests_run++;
    printf("Running: %s... ", name);
    fflush(stdout);

    test_func();

    tests_passed++;
    printf("PASS\n");
}

int main() {
    printf("=== Validation Framework Test Suite ===\n\n");

    run_test("Valid packet access", test_valid_access);
    run_test("Out of bounds detection", test_out_of_bounds);
    run_test("Overflow detection", test_overflow_detection);
    run_test("Null pointer handling", test_null_packet);
    run_test("Safe addition", test_safe_math_add);
    run_test("Safe multiplication", test_safe_math_mul);
    run_test("Safe subtraction", test_safe_math_sub);

    printf("\n=== Test Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    if (tests_failed == 0) {
        printf("\n✓ All validation framework tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed\n");
        return 1;
    }
}
```

**Compile and run:**

```bash
gcc -o test/validation/test_validation_framework \
    test/validation/test_validation_framework.c \
    -I src/mmt_core/public_include -lpcap

./test/validation/test_validation_framework
```

---

## Task 4.2: Apply Validation to Top Protocols

**Priority:** P1 - HIGH
**Estimated Time:** 24 hours
**Objective:** Add systematic validation to most-used protocols

### Subtask 4.2.1: TCP Protocol Validation (4h)

**File:** `src/mmt_tcpip/lib/protocols/proto_tcp.c`

Add comprehensive validation:

```c
#include "../../mmt_core/public_include/mmt_protocol_validation.h"

int classify_tcp(ipacket_t *ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);

    // Validate minimum TCP header size (20 bytes)
    MMT_VALIDATE_MIN_HEADER(ipacket, offset, struct tcphdr, PROTO_TCP);

    // Get header pointer safely
    MMT_GET_HEADER_PTR(ipacket, offset, struct tcphdr, tcp_hdr, PROTO_TCP);

    // Validate data offset (must be >= 5 for 20-byte header)
    uint8_t data_offset = tcp_hdr->th_off;
    MMT_VALIDATE_RANGE(data_offset, 5, 15, "TCP data offset", PROTO_TCP);

    // Calculate actual header length
    uint32_t header_len = data_offset * 4;

    // Validate header fits in packet
    if (mmt_validate_offset(ipacket, offset, header_len) != MMT_VALIDATE_OK) {
        MMT_LOG(PROTO_TCP, MMT_LOG_ERROR, "TCP header extends beyond packet");
        return 0;
    }

    // Validate TCP options if present
    if (header_len > 20) {
        uint32_t options_len = header_len - 20;
        if (mmt_validate_offset(ipacket, offset + 20, options_len) != MMT_VALIDATE_OK) {
            MMT_LOG(PROTO_TCP, MMT_LOG_ERROR, "TCP options extend beyond packet");
            return 0;
        }
    }

    // Continue with classification...
    return 1;
}
```

---

### Subtask 4.2.2: UDP Protocol Validation (4h)

### Subtask 4.2.3: IP Protocol Validation (4h)

### Subtask 4.2.4: HTTP Protocol Validation (4h)

### Subtask 4.2.5: DNS Protocol Validation (4h)

### Subtask 4.2.6: TLS/SSL Protocol Validation (4h)

*(Implementation follows same pattern as TCP)*

---

## Task 4.3: Create Fuzzing Infrastructure

**Priority:** P2 - MEDIUM
**Estimated Time:** 16 hours
**Objective:** Automated testing for edge cases

### Subtask 4.3.1: Protocol Fuzzer Setup (8h)

**File:** `test/fuzzing/protocol_fuzzer.c`

```c
/* AFL/libFuzzer compatible fuzzer */
#include <stdint.h>
#include <stddef.h>
#include "../../src/mmt_core/public_include/mmt_core.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 14) return 0;  // Minimum Ethernet frame

    // Create mock packet
    struct pcap_pkthdr hdr = {
        .caplen = size,
        .len = size
    };

    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, NULL);
    if (!handler) return 0;

    // Process packet (validation will be tested)
    packet_t pkt = {
        .data = (uint8_t*)data,
        .p_hdr = &hdr
    };

    mmt_process_packet(handler, &hdr, data);

    mmt_close_handler(handler);
    return 0;
}
```

**Build with AFL:**

```bash
afl-gcc -o test/fuzzing/protocol_fuzzer \
    test/fuzzing/protocol_fuzzer.c \
    -Lsdk/lib -lmmt_core -lmmt_tcpip
```

**Run fuzzing:**

```bash
afl-fuzz -i test/pcap_samples -o findings test/fuzzing/protocol_fuzzer
```

---

### Subtask 4.3.2: Crash Test Suite (8h)

Create test cases for known edge cases:

```bash
# Malformed packets
# Zero-length packets
# Maximum-length fields
# Invalid offsets
# Overflow conditions
```

---

## Task 4.4: Documentation and Guidelines

**Priority:** P2 - MEDIUM
**Estimated Time:** 8 hours

### Create Developer Guidelines

**File:** `VALIDATION_GUIDELINES.md`

Contents:

- How to use validation framework
- Common validation patterns
- Examples for new protocols
- Testing requirements
- Fuzzing setup instructions

---

## Summary

**Total Tasks:** 4 major tasks, 15+ subtasks
**Estimated Time:** 40-60 hours
**Priority:** HIGH (builds on Phase 1)

**Key Deliverables:**

1. ✅ Validation framework headers (safe_access, safe_math, protocol_validation)
2. ⏳ Applied to top 6 protocols (TCP, UDP, IP, HTTP, DNS, TLS)
3. ⏳ Fuzzing infrastructure
4. ⏳ Developer documentation

**Dependencies:**

- Phase 1 security fixes (completed)
- Phase 3 thread safety (completed for locking, assists validation)

**Success Metrics:**

- Zero crashes on malformed packets
- 100% validation coverage on top protocols
- Fuzzing runs for 24+ hours without crashes
- Developer guidelines complete

---

**Ready to begin implementation. Starting with Task 4.1.1: Safe Access Header...**
