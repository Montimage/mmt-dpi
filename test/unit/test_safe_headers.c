#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../../src/mmt_core/public_include/mmt_safe_math.h"
#include "../../src/mmt_core/public_include/mmt_safe_string.h"

void test_safe_add_u32() {
    uint32_t result;

    // Normal addition
    assert(mmt_safe_add_u32(100, 200, &result) == true);
    assert(result == 300);

    // Overflow case
    assert(mmt_safe_add_u32(UINT32_MAX, 1, &result) == false);
    assert(mmt_safe_add_u32(UINT32_MAX - 10, 20, &result) == false);

    printf("✓ mmt_safe_add_u32 tests passed\n");
}

void test_safe_mul_u32() {
    uint32_t result;

    // Normal multiplication
    assert(mmt_safe_mul_u32(100, 200, &result) == true);
    assert(result == 20000);

    // Overflow case
    assert(mmt_safe_mul_u32(UINT32_MAX, 2, &result) == false);
    assert(mmt_safe_mul_u32(0x10000, 0x10000, &result) == false);

    printf("✓ mmt_safe_mul_u32 tests passed\n");
}

void test_safe_shl_u16() {
    uint16_t result;

    // Normal shift
    assert(mmt_safe_shl_u16(1, 3, &result) == true);
    assert(result == 8);

    // Max 13-bit value shifted by 3 (fits in 16 bits)
    assert(mmt_safe_shl_u16(0x1fff, 3, &result) == true);
    assert(result == 0xfff8);

    // Overflow case
    assert(mmt_safe_shl_u16(0x4000, 3, &result) == false);
    assert(mmt_safe_shl_u16(1, 16, &result) == false);

    printf("✓ mmt_safe_shl_u16 tests passed\n");
}

void test_strlcpy() {
    char dest[10];
    size_t ret;

    // Normal copy
    ret = mmt_strlcpy(dest, "hello", sizeof(dest));
    assert(strcmp(dest, "hello") == 0);
    assert(ret == 5);

    // Truncation case
    ret = mmt_strlcpy(dest, "very long string", sizeof(dest));
    assert(strlen(dest) == 9);  // sizeof(dest) - 1
    assert(dest[9] == '\0');    // Null terminated
    assert(ret == 16);          // Returns source length

    printf("✓ mmt_strlcpy tests passed\n");
}

void test_strlcat() {
    char dest[20] = "hello";
    size_t ret;

    // Normal concatenation
    ret = mmt_strlcat(dest, " world", sizeof(dest));
    assert(strcmp(dest, "hello world") == 0);
    assert(ret == 11);

    // Truncation case
    strcpy(dest, "hello");
    ret = mmt_strlcat(dest, " this is a very long string", sizeof(dest));
    assert(strlen(dest) == 19);  // sizeof(dest) - 1
    assert(dest[19] == '\0');    // Null terminated

    printf("✓ mmt_strlcat tests passed\n");
}

int main() {
    printf("Testing safe header functions...\n");
    printf("================================\n\n");

    test_safe_add_u32();
    test_safe_mul_u32();
    test_safe_shl_u16();
    test_strlcpy();
    test_strlcat();

    printf("\n================================\n");
    printf("✓ All safe header tests passed!\n");
    return 0;
}
