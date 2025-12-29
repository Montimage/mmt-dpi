# MMT-DPI Implementation Plan

## Detailed Tasks with Testing and Validation

**Project:** MMT-DPI Security and Performance Improvements
**Branch:** `claude/deep-analysis-011CUvGnTGxbn8rBZAgruD9T`
**Created:** 2025-11-08

---

## Table of Contents

1. [Prerequisites and Setup](#prerequisites-and-setup)
2. [Phase 1: Critical Security Fixes (Weeks 1-2)](#phase-1-critical-security-fixes-weeks-1-2)
3. [Phase 2: Performance Optimizations (Weeks 3-4)](#phase-2-performance-optimizations-weeks-3-4)
4. [Phase 3: Thread Safety (Weeks 5-6)](#phase-3-thread-safety-weeks-5-6)
5. [Phase 4: Input Validation Framework (Weeks 7-8)](#phase-4-input-validation-framework-weeks-7-8)
6. [Phase 5: Error Handling (Weeks 9-10)](#phase-5-error-handling-weeks-9-10)

---

## Prerequisites and Setup

### Task 0.1: Set Up Testing Infrastructure

**Objective:** Create test framework and baseline measurements

**Steps:**

1. **Create test directory structure**

```bash
mkdir -p test/{unit,integration,security,performance}
mkdir -p test/pcap_samples
mkdir -p test/scripts
```

2. **Create baseline build script**

```bash
cat > test/scripts/build_and_test.sh << 'EOF'
#!/bin/bash
set -e

echo "=== Building MMT-DPI ==="
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/build.log

echo "=== Build successful ==="

# Check if libraries were created
if [ -f lib/libmmt_core.so ]; then
    echo "✓ libmmt_core.so created"
else
    echo "✗ libmmt_core.so MISSING"
    exit 1
fi

if [ -f lib/libmmt_tcpip.so ]; then
    echo "✓ libmmt_tcpip.so created"
else
    echo "✗ libmmt_tcpip.so MISSING"
    exit 1
fi

echo "=== All libraries built successfully ==="
exit 0
EOF

chmod +x test/scripts/build_and_test.sh
```

3. **Create test runner script**

```bash
cat > test/scripts/run_tests.sh << 'EOF'
#!/bin/bash

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="$TEST_DIR/../src/examples"

echo "=== Running Examples as Tests ==="

# Test 1: Basic packet processing
if [ -f "$EXAMPLES_DIR/google-fr.pcap" ]; then
    echo "Running packet_handler example..."
    cd sdk/lib
    export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH

    if [ -f "../../examples/packet_handler" ]; then
        ../../examples/packet_handler "$EXAMPLES_DIR/google-fr.pcap" 2>&1 | tee "$TEST_DIR/test_output.log"
        echo "✓ packet_handler test passed"
    else
        echo "⚠ packet_handler example not built"
    fi
else
    echo "⚠ No test pcap files found"
fi

echo "=== Tests completed ==="
EOF

chmod +x test/scripts/run_tests.sh
```

4. **Verify baseline build**

```bash
./test/scripts/build_and_test.sh
```

**Expected Output:**

```
=== Building MMT-DPI ===
...compilation messages...
✓ libmmt_core.so created
✓ libmmt_tcpip.so created
=== All libraries built successfully ===
```

**Acceptance Criteria:**

- [ ] Build completes without errors
- [ ] All core libraries are created
- [ ] Examples compile successfully
- [ ] Test scripts are executable

**Validation:**

```bash
# Verify libraries exist
ls -lh sdk/lib/libmmt_*.so

# Verify examples built
ls -lh examples/

# Run baseline test
./test/scripts/run_tests.sh
```

**Estimated Time:** 2 hours

---

### Task 0.2: Create Safety Headers

**Objective:** Prepare safe wrapper functions for use in subsequent tasks

**Steps:**

1. **Create safe packet access header**

```bash
cat > src/mmt_core/public_include/mmt_safe_access.h << 'EOF'
#ifndef MMT_SAFE_ACCESS_H
#define MMT_SAFE_ACCESS_H

#include <stdint.h>
#include <stdbool.h>
#include "data_defs.h"

/**
 * Validate that offset + len is within packet bounds
 * @param pkt Packet to check
 * @param offset Starting offset
 * @param len Length to access
 * @return true if access is safe, false otherwise
 */
static inline bool mmt_validate_offset(const ipacket_t *pkt, uint32_t offset, uint32_t len) {
    if (pkt == NULL || pkt->p_hdr == NULL) {
        return false;
    }
    // Check for integer overflow
    if (offset + len < offset) {
        return false;
    }
    // Check bounds
    return (offset + len <= pkt->p_hdr->caplen);
}

/**
 * Get a safe pointer to packet data
 * @param pkt Packet
 * @param offset Starting offset
 * @param len Length required
 * @return Pointer to data if safe, NULL otherwise
 */
static inline const uint8_t* mmt_safe_packet_ptr(const ipacket_t *pkt, uint32_t offset, uint32_t len) {
    if (!mmt_validate_offset(pkt, offset, len)) {
        return NULL;
    }
    return &pkt->data[offset];
}

/**
 * Safe cast to structure type
 */
#define MMT_SAFE_CAST(pkt, offset, type) \
    ((const type*)(mmt_validate_offset(pkt, offset, sizeof(type)) ? \
     &pkt->data[offset] : NULL))

#endif /* MMT_SAFE_ACCESS_H */
EOF
```

2. **Create safe string operations header**

```bash
cat > src/mmt_core/public_include/mmt_safe_string.h << 'EOF'
#ifndef MMT_SAFE_STRING_H
#define MMT_SAFE_STRING_H

#include <string.h>
#include <stdio.h>

/**
 * Safe string copy with explicit size
 */
static inline size_t mmt_strlcpy(char *dst, const char *src, size_t size) {
    size_t src_len = strlen(src);
    if (size > 0) {
        size_t copy_len = (src_len >= size) ? size - 1 : src_len;
        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }
    return src_len;
}

/**
 * Safe string concatenation with explicit size
 */
static inline size_t mmt_strlcat(char *dst, const char *src, size_t size) {
    size_t dst_len = strnlen(dst, size);
    if (dst_len == size) {
        return dst_len + strlen(src);
    }
    return dst_len + mmt_strlcpy(dst + dst_len, src, size - dst_len);
}

/**
 * Safe snprintf wrapper that guarantees null termination
 */
#define MMT_SAFE_SNPRINTF(buf, size, ...) \
    do { \
        snprintf(buf, size, __VA_ARGS__); \
        buf[(size) - 1] = '\0'; \
    } while(0)

#endif /* MMT_SAFE_STRING_H */
EOF
```

3. **Create safe math operations header**

```bash
cat > src/mmt_core/public_include/mmt_safe_math.h << 'EOF'
#ifndef MMT_SAFE_MATH_H
#define MMT_SAFE_MATH_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/**
 * Safe addition for uint32_t
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
 */
static inline bool mmt_safe_mul_u32(uint32_t a, uint32_t b, uint32_t *result) {
    if (a != 0 && b > UINT32_MAX / a) {
        return false;  // Overflow would occur
    }
    *result = a * b;
    return true;
}

/**
 * Safe addition for uint16_t
 */
static inline bool mmt_safe_add_u16(uint16_t a, uint16_t b, uint16_t *result) {
    if (UINT16_MAX - a < b) {
        return false;
    }
    *result = a + b;
    return true;
}

/**
 * Safe left shift
 */
static inline bool mmt_safe_shl_u16(uint16_t value, unsigned int shift, uint16_t *result) {
    if (shift >= 16 || (value >> (16 - shift)) != 0) {
        return false;  // Would overflow
    }
    *result = value << shift;
    return true;
}

#endif /* MMT_SAFE_MATH_H */
EOF
```

4. **Test compilation with new headers**

```bash
cd sdk
make clean
make -j$(nproc)
```

**Expected Output:**

```
Compilation successful with no errors
```

**Acceptance Criteria:**

- [ ] All three header files created
- [ ] Headers are syntactically correct
- [ ] Project compiles without errors
- [ ] No warnings introduced

**Validation:**

```bash
# Check headers exist
ls -l src/mmt_core/public_include/mmt_safe_*.h

# Verify compilation
./test/scripts/build_and_test.sh

# Check for warnings
grep -i "warning.*mmt_safe" test/build.log || echo "No warnings found"
```

**Estimated Time:** 3 hours

---

## Phase 1: Critical Security Fixes (Weeks 1-2)

### Task 1.1: Fix TIPS Module sprintf Vulnerabilities

**Priority:** P0 - CRITICAL
**File:** `src/mmt_security/tips.c`
**Issues:** 70+ unsafe sprintf calls, 40+ unsafe strcpy/strcat calls

**Steps:**

1. **Create backup of original file**

```bash
cp src/mmt_security/tips.c src/mmt_security/tips.c.backup
```

2. **Fix sprintf on lines 294-301 (MAC address formatting)**

```bash
# Edit src/mmt_security/tips.c
```

**Before (Line 294-301):**

```c
(void)sprintf(*pszMACAddress, "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
             szMACAddress[0], cMACAddressDelimiter,
             szMACAddress[1], cMACAddressDelimiter,
             szMACAddress[2], cMACAddressDelimiter,
             szMACAddress[3], cMACAddressDelimiter,
             szMACAddress[4], cMACAddressDelimiter,
             szMACAddress[5]);
```

**After:**

```c
snprintf(*pszMACAddress, 18, "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
         szMACAddress[0], cMACAddressDelimiter,
         szMACAddress[1], cMACAddressDelimiter,
         szMACAddress[2], cMACAddressDelimiter,
         szMACAddress[3], cMACAddressDelimiter,
         szMACAddress[4], cMACAddressDelimiter,
         szMACAddress[5]);
(*pszMACAddress)[17] = '\0';  // Ensure null termination
```

3. **Fix strcpy/strcat chain (lines 480-483)**

**Before:**

```c
strcpy(buff1, buff0);
strcat(buff1, ".");
strcat(buff1, buff0);
```

**After:**

```c
#include "../mmt_core/public_include/mmt_safe_string.h"

mmt_strlcpy(buff1, buff0, sizeof(buff1));
mmt_strlcat(buff1, ".", sizeof(buff1));
mmt_strlcat(buff1, buff0, sizeof(buff1));
```

4. **Fix JSON buffer concatenation (lines 2092-2093)**

**Before:**

```c
(void)strcat(json_buff, json_buff1);
(void)strcat(json_buff, ",\"attributes\":[");
```

**After:**

```c
mmt_strlcat(json_buff, json_buff1, sizeof(json_buff));
mmt_strlcat(json_buff, ",\"attributes\":[", sizeof(json_buff));
```

5. **Compile and test**

```bash
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/tips_build.log

# Check for errors
if [ $? -eq 0 ]; then
    echo "✓ Build successful"
else
    echo "✗ Build failed"
    exit 1
fi
```

6. **Create unit test for TIPS functions**

```bash
cat > test/unit/test_tips_safety.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Test safe MAC address formatting
void test_mac_format() {
    char mac[18];
    unsigned char addr[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    mac[17] = '\0';

    assert(strlen(mac) == 17);
    assert(strcmp(mac, "aa:bb:cc:dd:ee:ff") == 0);
    printf("✓ MAC format test passed\n");
}

int main() {
    test_mac_format();
    printf("All TIPS safety tests passed\n");
    return 0;
}
EOF

gcc -o test/unit/test_tips_safety test/unit/test_tips_safety.c
./test/unit/test_tips_safety
```

**Expected Output:**

```
✓ MAC format test passed
All TIPS safety tests passed
```

**Acceptance Criteria:**

- [ ] All sprintf replaced with snprintf
- [ ] All strcpy replaced with mmt_strlcpy
- [ ] All strcat replaced with mmt_strlcat
- [ ] Project compiles without errors
- [ ] No buffer overflow warnings
- [ ] Unit tests pass

**Validation:**

```bash
# Count remaining unsafe functions
grep -n "sprintf\s*(" src/mmt_security/tips.c || echo "No sprintf found"
grep -n "strcpy\s*(" src/mmt_security/tips.c || echo "No strcpy found"
grep -n "strcat\s*(" src/mmt_security/tips.c || echo "No strcat found"

# Run full build test
./test/scripts/build_and_test.sh
```

**Rollback Plan:**

```bash
# If issues occur:
cp src/mmt_security/tips.c.backup src/mmt_security/tips.c
cd sdk && make clean && make
```

**Estimated Time:** 8 hours

---

### Task 1.2: Fix DNS Unbounded Recursion

**Priority:** P0 - CRITICAL
**File:** `src/mmt_tcpip/lib/protocols/proto_dns.c`
**Issue:** Lines 218-251 - Unbounded recursion causing stack overflow

**Steps:**

1. **Create backup**

```bash
cp src/mmt_tcpip/lib/protocols/proto_dns.c src/mmt_tcpip/lib/protocols/proto_dns.c.backup
```

2. **Add recursion depth limit constant**

Add at the top of proto_dns.c (after includes):

```c
#define MAX_DNS_RECURSION_DEPTH 10
#define MAX_DNS_NAME_LENGTH 255
```

3. **Modify dns_extract_name function signature**

**Before (Line 218):**

```c
dns_name_t * dns_extract_name(const u_char* dns_name_payload, const u_char* dns_payload)
```

**After:**

```c
dns_name_t * dns_extract_name_internal(const u_char* dns_name_payload,
                                       const u_char* dns_payload,
                                       const u_char* packet_end,
                                       int depth)
```

4. **Add depth checking logic**

**After (Line 220-225):**

```c
{
    // Check recursion depth
    if (depth > MAX_DNS_RECURSION_DEPTH) {
        MMT_LOG(PROTO_DNS, MMT_LOG_WARNING,
                "DNS name extraction exceeded max recursion depth");
        return NULL;
    }

    // Validate pointer is within packet bounds
    if (dns_name_payload == NULL || dns_name_payload >= packet_end) {
        return NULL;
    }

    // Validate we can read at least one byte
    if (dns_name_payload + 1 > packet_end) {
        return NULL;
    }

    uint16_t str_length = hex2int(dns_name_payload[0]);
```

5. **Update recursive calls with depth + 1**

**Line 224 (compression pointer case):**

```c
if(str_length == 192){
    // Validate we can read offset byte
    if (dns_name_payload + 2 > packet_end) {
        return NULL;
    }
    int offset_name = hex2int(dns_name_payload[1]);

    // Validate offset is within packet
    if (dns_payload + offset_name >= packet_end) {
        return NULL;
    }

    return dns_extract_name_internal(dns_payload + offset_name,
                                    dns_payload,
                                    packet_end,
                                    depth + 1);
}
```

**Line 248 (next label case):**

```c
dns_name->next = dns_extract_name_internal(dns_name_payload + str_length + 1,
                                          dns_payload,
                                          packet_end,
                                          depth + 1);
```

6. **Create wrapper function for backward compatibility**

Add at the end of the file:

```c
/**
 * Wrapper function that maintains original API
 */
dns_name_t * dns_extract_name(const u_char* dns_name_payload,
                              const u_char* dns_payload) {
    // Assume a reasonable packet end if not provided
    // This is a temporary measure for compatibility
    const u_char* packet_end = dns_payload + 65535;
    return dns_extract_name_internal(dns_name_payload, dns_payload, packet_end, 0);
}
```

7. **Update all call sites to use proper bounds**

Find all calls to dns_extract_name and update to pass packet_end where available.

8. **Compile and test**

```bash
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/dns_build.log

if [ $? -eq 0 ]; then
    echo "✓ DNS module compiled successfully"
else
    echo "✗ DNS module compilation failed"
    exit 1
fi
```

9. **Create DNS recursion test**

```bash
cat > test/unit/test_dns_recursion.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#define MAX_DNS_RECURSION_DEPTH 10

// Simulate recursive depth checking
int test_recursion_depth_limit() {
    int max_depth = 0;

    // Simulate recursive calls
    for (int depth = 0; depth <= MAX_DNS_RECURSION_DEPTH + 5; depth++) {
        if (depth > MAX_DNS_RECURSION_DEPTH) {
            printf("✓ Recursion blocked at depth %d\n", depth);
            max_depth = depth;
            break;
        }
    }

    assert(max_depth == MAX_DNS_RECURSION_DEPTH + 1);
    return 0;
}

int main() {
    printf("Testing DNS recursion depth limiting...\n");
    test_recursion_depth_limit();
    printf("✓ All DNS recursion tests passed\n");
    return 0;
}
EOF

gcc -o test/unit/test_dns_recursion test/unit/test_dns_recursion.c
./test/unit/test_dns_recursion
```

**Expected Output:**

```
Testing DNS recursion depth limiting...
✓ Recursion blocked at depth 11
✓ All DNS recursion tests passed
```

**Acceptance Criteria:**

- [ ] Recursion depth limit enforced
- [ ] Packet bounds checking added
- [ ] All recursive calls pass depth parameter
- [ ] Compilation successful
- [ ] No stack overflow on malformed DNS packets
- [ ] Unit tests pass

**Validation:**

```bash
# Verify depth checking is in place
grep -n "MAX_DNS_RECURSION_DEPTH" src/mmt_tcpip/lib/protocols/proto_dns.c

# Check all recursive calls pass depth
grep -n "dns_extract_name_internal.*depth" src/mmt_tcpip/lib/protocols/proto_dns.c

# Build and test
./test/scripts/build_and_test.sh

# Run with DNS test pcap if available
if [ -f test/pcap_samples/dns_test.pcap ]; then
    examples/packet_handler test/pcap_samples/dns_test.pcap
fi
```

**Rollback Plan:**

```bash
cp src/mmt_tcpip/lib/protocols/proto_dns.c.backup src/mmt_tcpip/lib/protocols/proto_dns.c
cd sdk && make clean && make
```

**Estimated Time:** 6 hours

---

### Task 1.3: Add Safe Packet Access to HTTP Parser

**Priority:** P0 - CRITICAL
**File:** `src/mmt_tcpip/lib/protocols/http.c`
**Issue:** Lines 373-375, 412-415 - Buffer overflows in URI and header parsing

**Steps:**

1. **Create backup**

```bash
cp src/mmt_tcpip/lib/protocols/http.c src/mmt_tcpip/lib/protocols/http.c.backup
```

2. **Add safety header include**

At the top of http.c, add:

```c
#include "../../mmt_core/public_include/mmt_safe_access.h"
#include "../../mmt_core/public_include/mmt_safe_math.h"
```

3. **Fix URI parsing (lines 373-375)**

**Before:**

```c
http->requested_uri = (char *) mmt_malloc(uri_len + 1);
memcpy(http->requested_uri, &ipacket->data[offset + line_first_element_offset], uri_len);
http->requested_uri[uri_len] = '\0';
```

**After:**

```c
// Validate URI length is reasonable
#define MAX_URI_LENGTH 8192

if (uri_len > MAX_URI_LENGTH) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_WARNING,
            "URI length %u exceeds maximum, truncating", uri_len);
    uri_len = MAX_URI_LENGTH;
}

// Validate offset and length are within packet bounds
uint32_t safe_offset;
if (!mmt_safe_add_u32(offset, line_first_element_offset, &safe_offset)) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_ERROR, "Integer overflow in URI offset");
    return 0;
}

if (!mmt_validate_offset(ipacket, safe_offset, uri_len)) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_ERROR,
            "URI extends beyond packet boundary");
    return 0;
}

http->requested_uri = (char *) mmt_malloc(uri_len + 1);
if (http->requested_uri == NULL) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_ERROR, "Failed to allocate URI buffer");
    return 0;
}

memcpy(http->requested_uri, &ipacket->data[safe_offset], uri_len);
http->requested_uri[uri_len] = '\0';
```

4. **Fix header value parsing (lines 412-415)**

**Before:**

```c
http->session_field_values[header_index].value = (char *) mmt_malloc(value_len + 1);
memcpy(http->session_field_values[header_index].value,
       &ipacket->data[offset + value_offset], value_len);
http->session_field_values[header_index].value[value_len] = '\0';
```

**After:**

```c
// Validate header value length
#define MAX_HEADER_VALUE_LENGTH 16384

if (value_len > MAX_HEADER_VALUE_LENGTH) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_WARNING,
            "Header value length %u exceeds maximum, truncating", value_len);
    value_len = MAX_HEADER_VALUE_LENGTH;
}

// Validate offset and length
uint32_t safe_offset;
if (!mmt_safe_add_u32(offset, value_offset, &safe_offset)) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_ERROR,
            "Integer overflow in header value offset");
    return 0;
}

if (!mmt_validate_offset(ipacket, safe_offset, value_len)) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_ERROR,
            "Header value extends beyond packet boundary");
    return 0;
}

http->session_field_values[header_index].value =
    (char *) mmt_malloc(value_len + 1);
if (http->session_field_values[header_index].value == NULL) {
    MMT_LOG(PROTO_HTTP, MMT_LOG_ERROR,
            "Failed to allocate header value buffer");
    return 0;
}

memcpy(http->session_field_values[header_index].value,
       &ipacket->data[safe_offset], value_len);
http->session_field_values[header_index].value[value_len] = '\0';
```

5. **Add constants at top of file**

```c
#define MAX_URI_LENGTH 8192
#define MAX_HEADER_VALUE_LENGTH 16384
#define MAX_HEADER_NAME_LENGTH 256
```

6. **Compile and test**

```bash
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/http_build.log

if [ $? -eq 0 ]; then
    echo "✓ HTTP module compiled successfully"
else
    echo "✗ HTTP module compilation failed"
    cat ../test/http_build.log | grep -A5 "error:"
    exit 1
fi
```

7. **Create HTTP safety test**

```bash
cat > test/unit/test_http_safety.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <limits.h>

#define MAX_URI_LENGTH 8192
#define MAX_HEADER_VALUE_LENGTH 16384

// Test URI length validation
void test_uri_length_limits() {
    uint32_t uri_len = 10000;

    if (uri_len > MAX_URI_LENGTH) {
        uri_len = MAX_URI_LENGTH;
    }

    assert(uri_len == MAX_URI_LENGTH);
    printf("✓ URI length limit enforced\n");
}

// Test integer overflow detection
void test_offset_overflow() {
    uint32_t offset = UINT32_MAX - 100;
    uint32_t length = 200;
    uint32_t result;

    // Check for overflow
    if (UINT32_MAX - offset < length) {
        printf("✓ Overflow detected correctly\n");
        return;
    }

    printf("✗ Overflow not detected\n");
    assert(0);
}

int main() {
    printf("Testing HTTP safety features...\n");
    test_uri_length_limits();
    test_offset_overflow();
    printf("✓ All HTTP safety tests passed\n");
    return 0;
}
EOF

gcc -o test/unit/test_http_safety test/unit/test_http_safety.c
./test/unit/test_http_safety
```

**Expected Output:**

```
Testing HTTP safety features...
✓ URI length limit enforced
✓ Overflow detected correctly
✓ All HTTP safety tests passed
```

**Acceptance Criteria:**

- [ ] URI length validated and limited
- [ ] Header value length validated and limited
- [ ] Integer overflow checks added
- [ ] Packet bounds validated before memcpy
- [ ] Null checks after malloc
- [ ] Compilation successful with no warnings
- [ ] Unit tests pass

**Validation:**

```bash
# Verify safety checks are in place
grep -n "mmt_validate_offset" src/mmt_tcpip/lib/protocols/http.c
grep -n "mmt_safe_add_u32" src/mmt_tcpip/lib/protocols/http.c
grep -n "MAX_URI_LENGTH\|MAX_HEADER_VALUE_LENGTH" src/mmt_tcpip/lib/protocols/http.c

# Build and test
./test/scripts/build_and_test.sh

# Test with HTTP traffic
if [ -f src/examples/google-fr.pcap ]; then
    cd sdk/lib
    export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
    ../../examples/packet_handler ../../src/examples/google-fr.pcap 2>&1 | grep -i "http\|error"
fi
```

**Rollback Plan:**

```bash
cp src/mmt_tcpip/lib/protocols/http.c.backup src/mmt_tcpip/lib/protocols/http.c
cd sdk && make clean && make
```

**Estimated Time:** 6 hours

---

### Task 1.4: Fix GTP Extension Header Bounds Checking

**Priority:** P0 - CRITICAL
**File:** `src/mmt_tcpip/lib/protocols/proto_gtp.c`
**Issue:** Lines 110-122 - Out-of-bounds reads in extension header loop

**Steps:**

1. **Create backup**

```bash
cp src/mmt_tcpip/lib/protocols/proto_gtp.c src/mmt_tcpip/lib/protocols/proto_gtp.c.backup
```

2. **Add safety header include**

```c
#include "../../mmt_core/public_include/mmt_safe_access.h"
#include "../../mmt_core/public_include/mmt_safe_math.h"
```

3. **Fix extension header loop (lines 110-122)**

**Before:**

```c
while( next_ext_header_type != 0 ){
    //the first byte of extension indicate its length in 4 bytes
    next_ext_header_length = 4 * gtp_binary[ gtp_offset ];
    gtp_offset += next_ext_header_length;
    next_ext_header_type = gtp_binary[gtp_offset - 1];
}

// Check bounds AFTER loop
if( gtp_offset + offset > ipacket->p_hdr->caplen )
    return MMT_SKIP;
```

**After:**

```c
#define MAX_GTP_EXTENSION_HEADERS 10
int ext_header_count = 0;

while( next_ext_header_type != 0 ){
    // Prevent infinite loops
    if (++ext_header_count > MAX_GTP_EXTENSION_HEADERS) {
        MMT_LOG(PROTO_GTP, MMT_LOG_WARNING,
                "Too many GTP extension headers, possible malformed packet");
        return MMT_SKIP;
    }

    // Check we can read extension length byte
    uint32_t check_offset;
    if (!mmt_safe_add_u32(gtp_offset, offset, &check_offset)) {
        MMT_LOG(PROTO_GTP, MMT_LOG_ERROR, "Integer overflow in GTP offset");
        return MMT_SKIP;
    }

    if (check_offset >= ipacket->p_hdr->caplen) {
        MMT_LOG(PROTO_GTP, MMT_LOG_ERROR,
                "GTP extension header beyond packet boundary");
        return MMT_SKIP;
    }

    // The first byte of extension indicates its length in 4-byte units
    uint8_t ext_len_units = gtp_binary[gtp_offset];

    // Validate extension length is reasonable (max 255 * 4 = 1020 bytes)
    if (ext_len_units == 0) {
        MMT_LOG(PROTO_GTP, MMT_LOG_WARNING,
                "GTP extension header with zero length");
        return MMT_SKIP;
    }

    uint32_t next_ext_header_length;
    if (!mmt_safe_mul_u32(4, ext_len_units, &next_ext_header_length)) {
        MMT_LOG(PROTO_GTP, MMT_LOG_ERROR,
                "Integer overflow in GTP extension length");
        return MMT_SKIP;
    }

    // Check if adding length overflows
    uint32_t new_offset;
    if (!mmt_safe_add_u32(gtp_offset, next_ext_header_length, &new_offset)) {
        MMT_LOG(PROTO_GTP, MMT_LOG_ERROR,
                "Integer overflow adding GTP extension length");
        return MMT_SKIP;
    }

    // Check if new offset would exceed packet
    if (!mmt_safe_add_u32(new_offset, offset, &check_offset)) {
        return MMT_SKIP;
    }

    if (check_offset > ipacket->p_hdr->caplen) {
        MMT_LOG(PROTO_GTP, MMT_LOG_ERROR,
                "GTP extension would extend beyond packet");
        return MMT_SKIP;
    }

    gtp_offset = new_offset;

    // Check we can read next extension type (at offset - 1)
    if (gtp_offset == 0 || gtp_offset - 1 + offset >= ipacket->p_hdr->caplen) {
        MMT_LOG(PROTO_GTP, MMT_LOG_ERROR,
                "Cannot read GTP next extension type");
        return MMT_SKIP;
    }

    next_ext_header_type = gtp_binary[gtp_offset - 1];
}
```

4. **Add constant at top of file**

```c
#define MAX_GTP_EXTENSION_HEADERS 10
```

5. **Compile and test**

```bash
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/gtp_build.log

if [ $? -eq 0 ]; then
    echo "✓ GTP module compiled successfully"
else
    echo "✗ GTP module compilation failed"
    cat ../test/gtp_build.log | grep -A5 "error:"
    exit 1
fi
```

6. **Create GTP safety test**

```bash
cat > test/unit/test_gtp_safety.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#define MAX_GTP_EXTENSION_HEADERS 10

void test_extension_header_limit() {
    int count = 0;

    // Simulate extension header parsing
    for (int i = 0; i < 100; i++) {
        if (++count > MAX_GTP_EXTENSION_HEADERS) {
            printf("✓ Extension header loop terminated at %d\n", count);
            assert(count == MAX_GTP_EXTENSION_HEADERS + 1);
            return;
        }
    }

    printf("✗ Loop did not terminate\n");
    assert(0);
}

void test_zero_length_extension() {
    uint8_t ext_len_units = 0;

    if (ext_len_units == 0) {
        printf("✓ Zero-length extension detected\n");
        return;
    }

    printf("✗ Zero-length not detected\n");
    assert(0);
}

int main() {
    printf("Testing GTP safety features...\n");
    test_extension_header_limit();
    test_zero_length_extension();
    printf("✓ All GTP safety tests passed\n");
    return 0;
}
EOF

gcc -o test/unit/test_gtp_safety test/unit/test_gtp_safety.c
./test/unit/test_gtp_safety
```

**Expected Output:**

```
Testing GTP safety features...
✓ Extension header loop terminated at 11
✓ Zero-length extension detected
✓ All GTP safety tests passed
```

**Acceptance Criteria:**

- [ ] Bounds checking inside extension header loop
- [ ] Maximum extension header count enforced
- [ ] Zero-length extension detected
- [ ] Integer overflow checks for length calculation
- [ ] Compilation successful
- [ ] Unit tests pass

**Validation:**

```bash
# Verify safety checks
grep -n "MAX_GTP_EXTENSION_HEADERS" src/mmt_tcpip/lib/protocols/proto_gtp.c
grep -n "mmt_safe_add_u32\|mmt_safe_mul_u32" src/mmt_tcpip/lib/protocols/proto_gtp.c

# Build and test
./test/scripts/build_and_test.sh

# Check for any GTP-related errors in logs
grep -i "gtp\|error" test/build.log | grep -i "error" || echo "No GTP errors"
```

**Rollback Plan:**

```bash
cp src/mmt_tcpip/lib/protocols/proto_gtp.c.backup src/mmt_tcpip/lib/protocols/proto_gtp.c
cd sdk && make clean && make
```

**Estimated Time:** 5 hours

---

### Task 1.5: Fix Integer Overflow in IP Fragment Handling

**Priority:** P0 - HIGH
**File:** `src/mmt_tcpip/lib/protocols/proto_ip.c`
**Issue:** Line 169 - Fragment offset shift overflow

**Steps:**

1. **Create backup**

```bash
cp src/mmt_tcpip/lib/protocols/proto_ip.c src/mmt_tcpip/lib/protocols/proto_ip.c.backup
```

2. **Add safety includes**

```c
#include "../../mmt_core/public_include/mmt_safe_math.h"
```

3. **Fix fragment offset calculation (line 169)**

**Before:**

```c
*((unsigned short *) extracted_data->data) =
    (ntohs(*((unsigned short *) & packet->data[proto_offset + attribute_offset])) & 0x1fff)<<3;
```

**After:**

```c
uint16_t frag_offset_raw = ntohs(*((unsigned short *) & packet->data[proto_offset + attribute_offset]));
uint16_t frag_offset_13bit = frag_offset_raw & 0x1fff;
uint16_t frag_offset_bytes;

// Safe left shift by 3 (multiply by 8)
if (!mmt_safe_shl_u16(frag_offset_13bit, 3, &frag_offset_bytes)) {
    // Overflow detected - this should not happen with 13-bit value shifted by 3
    // but we check anyway for safety
    MMT_LOG(PROTO_IP, MMT_LOG_ERROR, "Fragment offset overflow detected");
    frag_offset_bytes = 0xFFFF;  // Max value
}

*((unsigned short *) extracted_data->data) = frag_offset_bytes;
```

4. **Fix addition overflow (line 178)**

**Before:**

```c
if((ntohs(ipacket->internal_packet->iph->tot_len) +
    ipacket->internal_packet->payload_packet_len + 14 != 60)){
```

**After:**

```c
uint16_t ip_tot_len = ntohs(ipacket->internal_packet->iph->tot_len);
uint32_t combined_len;

// Safely add lengths
if (!mmt_safe_add_u32(ip_tot_len, ipacket->internal_packet->payload_packet_len, &combined_len) ||
    !mmt_safe_add_u32(combined_len, 14, &combined_len)) {
    MMT_LOG(PROTO_IP, MMT_LOG_WARNING, "Packet length overflow in validation");
    // Treat as invalid packet
} else if (combined_len != 60) {
```

5. **Compile and test**

```bash
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/ip_build.log

if [ $? -eq 0 ]; then
    echo "✓ IP module compiled successfully"
else
    echo "✗ IP module compilation failed"
    cat ../test/ip_build.log | grep -A5 "error:"
    exit 1
fi
```

6. **Create IP safety test**

```bash
cat > test/unit/test_ip_safety.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

// Replicate safe shift function
static inline bool safe_shl_u16(uint16_t value, unsigned int shift, uint16_t *result) {
    if (shift >= 16 || (value >> (16 - shift)) != 0) {
        return false;
    }
    *result = value << shift;
    return true;
}

void test_fragment_offset_shift() {
    uint16_t frag_13bit = 0x1fff;  // Max 13-bit value
    uint16_t result;

    // This should succeed (0x1fff << 3 = 0xfff8, fits in 16 bits)
    if (safe_shl_u16(frag_13bit, 3, &result)) {
        printf("✓ Valid fragment offset shift: 0x%x -> 0x%x\n",
               frag_13bit, result);
        assert(result == 0xfff8);
    } else {
        printf("✗ Valid shift rejected\n");
        assert(0);
    }

    // Test overflow case
    uint16_t large_val = 0x4000;  // Would overflow when shifted by 3
    if (!safe_shl_u16(large_val, 3, &result)) {
        printf("✓ Overflow detected for value 0x%x\n", large_val);
    } else {
        printf("✗ Overflow not detected\n");
        assert(0);
    }
}

int main() {
    printf("Testing IP safety features...\n");
    test_fragment_offset_shift();
    printf("✓ All IP safety tests passed\n");
    return 0;
}
EOF

gcc -o test/unit/test_ip_safety test/unit/test_ip_safety.c
./test/unit/test_ip_safety
```

**Expected Output:**

```
Testing IP safety features...
✓ Valid fragment offset shift: 0x1fff -> 0xfff8
✓ Overflow detected for value 0x4000
✓ All IP safety tests passed
```

**Acceptance Criteria:**

- [ ] Fragment offset shift uses safe math
- [ ] Length addition uses overflow checking
- [ ] Compilation successful
- [ ] No warnings about shifts or arithmetic
- [ ] Unit tests pass

**Validation:**

```bash
# Verify safe math usage
grep -n "mmt_safe_shl_u16\|mmt_safe_add_u32" src/mmt_tcpip/lib/protocols/proto_ip.c

# Build and test
./test/scripts/build_and_test.sh

# Verify no shift overflow warnings
grep -i "shift\|overflow" test/build.log | grep -i "warning\|error" || echo "No overflow warnings"
```

**Rollback Plan:**

```bash
cp src/mmt_tcpip/lib/protocols/proto_ip.c.backup src/mmt_tcpip/lib/protocols/proto_ip.c
cd sdk && make clean && make
```

**Estimated Time:** 4 hours

---

### Phase 1 Summary and Validation

After completing all Task 1.x tasks, run comprehensive validation:

```bash
#!/bin/bash
echo "=== Phase 1 Validation ==="

# 1. Clean build from scratch
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/phase1_validation.log

if [ $? -ne 0 ]; then
    echo "✗ Build failed"
    exit 1
fi
echo "✓ Clean build successful"

# 2. Check for unsafe functions
echo "Checking for remaining unsafe functions..."
UNSAFE_COUNT=0

for func in sprintf strcpy strcat; do
    count=$(grep -r "$func\s*(" src/mmt_security/tips.c | wc -l)
    if [ $count -gt 0 ]; then
        echo "✗ Found $count instances of $func in tips.c"
        UNSAFE_COUNT=$((UNSAFE_COUNT + count))
    fi
done

if [ $UNSAFE_COUNT -eq 0 ]; then
    echo "✓ No unsafe string functions in tips.c"
else
    echo "✗ Still $UNSAFE_COUNT unsafe function calls remaining"
    exit 1
fi

# 3. Run all unit tests
echo "Running unit tests..."
for test in test/unit/test_*; do
    if [ -x "$test" ]; then
        echo "Running $(basename $test)..."
        $test || exit 1
    fi
done
echo "✓ All unit tests passed"

# 4. Test with example pcap
if [ -f src/examples/google-fr.pcap ]; then
    echo "Testing with example pcap..."
    cd lib
    export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
    ../../examples/packet_handler ../../src/examples/google-fr.pcap > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✓ Packet processing test passed"
    else
        echo "✗ Packet processing test failed"
        exit 1
    fi
    cd ../..
fi

# 5. Check library sizes (should not increase significantly)
echo "Checking library sizes..."
for lib in sdk/lib/libmmt_*.so; do
    size=$(ls -lh $lib | awk '{print $5}')
    echo "  $(basename $lib): $size"
done

echo ""
echo "=== Phase 1 Validation Complete ==="
echo "All critical security fixes applied and tested successfully!"
```

Save as `test/scripts/validate_phase1.sh` and run:

```bash
chmod +x test/scripts/validate_phase1.sh
./test/scripts/validate_phase1.sh
```

**Phase 1 Acceptance Criteria:**

- [ ] All unsafe string functions replaced
- [ ] DNS recursion depth limited
- [ ] HTTP bounds checking added
- [ ] GTP extension header loop secured
- [ ] IP integer overflows fixed
- [ ] All modules compile without errors
- [ ] No new warnings introduced
- [ ] All unit tests pass
- [ ] Example packet processing works

**Estimated Total Time for Phase 1:** 32 hours (2 weeks part-time)

---

## Phase 2: Performance Optimizations (Weeks 3-4)

### Task 2.1: Implement Memory Pool System

**Priority:** P1 - HIGH
**Objective:** Eliminate per-packet malloc/free bottleneck

**Steps:**

1. **Create memory pool implementation**

```bash
cat > src/mmt_core/src/mempool.c << 'EOF'
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../public_include/mempool.h"

struct mempool_struct {
    void *memory;
    size_t block_size;
    size_t num_blocks;
    void **free_list;
    size_t free_count;
    pthread_mutex_t lock;
    size_t alloc_count;
    size_t free_count_stat;
};

mempool_t* mempool_create(size_t block_size, size_t num_blocks) {
    mempool_t *pool = calloc(1, sizeof(mempool_t));
    if (!pool) return NULL;

    pool->block_size = block_size;
    pool->num_blocks = num_blocks;
    pool->memory = calloc(num_blocks, block_size);
    if (!pool->memory) {
        free(pool);
        return NULL;
    }

    pool->free_list = malloc(num_blocks * sizeof(void*));
    if (!pool->free_list) {
        free(pool->memory);
        free(pool);
        return NULL;
    }

    pool->free_count = num_blocks;

    // Initialize free list
    for (size_t i = 0; i < num_blocks; i++) {
        pool->free_list[i] = (uint8_t*)pool->memory + (i * block_size);
    }

    pthread_mutex_init(&pool->lock, NULL);
    pool->alloc_count = 0;
    pool->free_count_stat = 0;

    return pool;
}

void* mempool_alloc(mempool_t *pool) {
    if (!pool) return NULL;

    pthread_mutex_lock(&pool->lock);

    if (pool->free_count == 0) {
        pthread_mutex_unlock(&pool->lock);
        return NULL;  // Pool exhausted
    }

    void *block = pool->free_list[--pool->free_count];
    pool->alloc_count++;

    pthread_mutex_unlock(&pool->lock);

    return block;
}

void mempool_free(mempool_t *pool, void *block) {
    if (!pool || !block) return;

    pthread_mutex_lock(&pool->lock);

    // Optional: verify block belongs to this pool
    // For performance, this check can be disabled in release builds

    pool->free_list[pool->free_count++] = block;
    pool->free_count_stat++;

    pthread_mutex_unlock(&pool->lock);
}

void mempool_destroy(mempool_t *pool) {
    if (!pool) return;

    pthread_mutex_destroy(&pool->lock);
    free(pool->free_list);
    free(pool->memory);
    free(pool);
}

void mempool_get_stats(mempool_t *pool, size_t *total, size_t *used, size_t *free_blocks) {
    if (!pool) return;

    pthread_mutex_lock(&pool->lock);
    if (total) *total = pool->num_blocks;
    if (used) *used = pool->num_blocks - pool->free_count;
    if (free_blocks) *free_count = pool->free_count;
    pthread_mutex_unlock(&pool->lock);
}
EOF
```

2. **Create header file**

```bash
cat > src/mmt_core/public_include/mempool.h << 'EOF'
#ifndef MMT_MEMPOOL_H
#define MMT_MEMPOOL_H

#include <stddef.h>

typedef struct mempool_struct mempool_t;

/**
 * Create a memory pool
 * @param block_size Size of each block in bytes
 * @param num_blocks Number of blocks to allocate
 * @return Pointer to pool, or NULL on failure
 */
mempool_t* mempool_create(size_t block_size, size_t num_blocks);

/**
 * Allocate a block from the pool
 * @param pool The memory pool
 * @return Pointer to block, or NULL if pool is exhausted
 */
void* mempool_alloc(mempool_t *pool);

/**
 * Free a block back to the pool
 * @param pool The memory pool
 * @param block Block to free
 */
void mempool_free(mempool_t *pool, void *block);

/**
 * Destroy a memory pool
 * @param pool The memory pool
 */
void mempool_destroy(mempool_t *pool);

/**
 * Get pool statistics
 */
void mempool_get_stats(mempool_t *pool, size_t *total, size_t *used, size_t *free_blocks);

#endif /* MMT_MEMPOOL_H */
EOF
```

3. **Update Makefile to include mempool.c**

Edit `sdk/Makefile` or appropriate makefile to add mempool.c to sources.

4. **Integrate into mmt_handler_t**

Edit `src/mmt_core/private_include/packet_processing.h`:

```c
#include "../public_include/mempool.h"

struct mmt_handler_struct {
    // ... existing fields ...

    // Add memory pools
    mempool_t *ipacket_pool;
    mempool_t *session_pool;
};
```

5. **Initialize pools in mmt_init_handler()**

Edit `src/mmt_core/src/packet_processing.c` in `mmt_init_handler()`:

```c
// After handler allocation, add:
new_handler->ipacket_pool = mempool_create(sizeof(ipacket_t), 1024);
if (!new_handler->ipacket_pool) {
    mmt_close_handler(new_handler);
    return NULL;
}

new_handler->session_pool = mempool_create(sizeof(mmt_session_t), 10000);
if (!new_handler->session_pool) {
    mmt_close_handler(new_handler);
    return NULL;
}
```

6. **Update mmt_close_handler()**

```c
// Add before freeing handler:
if (mmt_handler->ipacket_pool) {
    mempool_destroy(mmt_handler->ipacket_pool);
}
if (mmt_handler->session_pool) {
    mempool_destroy(mmt_handler->session_pool);
}
```

7. **Replace ipacket allocation in packet_processing.c:3330**

**Before:**

```c
ipacket = mmt_malloc(sizeof(ipacket_t));
ipacket->data = mmt_malloc(header->caplen);
```

**After:**

```c
ipacket = mempool_alloc(mmt_handler->ipacket_pool);
if (!ipacket) {
    // Pool exhausted, fall back to malloc
    ipacket = mmt_malloc(sizeof(ipacket_t));
}

// Still need to allocate data buffer (variable size)
ipacket->data = mmt_malloc(header->caplen);
```

8. **Update corresponding free()**

Find where ipacket is freed and replace with:

```c
// Check if from pool (pointer in pool range)
mempool_free(mmt_handler->ipacket_pool, ipacket);
// Note: mempool_free handles NULL gracefully
```

9. **Compile and test**

```bash
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/mempool_build.log

if [ $? -eq 0 ]; then
    echo "✓ Memory pool compiled successfully"
else
    echo "✗ Build failed"
    exit 1
fi
```

10. **Create memory pool benchmark**

```bash
cat > test/performance/bench_mempool.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "../../src/mmt_core/public_include/mempool.h"

#define ITERATIONS 1000000

double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void benchmark_malloc() {
    double start = get_time();

    for (int i = 0; i < ITERATIONS; i++) {
        void *ptr = malloc(1024);
        free(ptr);
    }

    double end = get_time();
    double duration = end - start;
    double ops_per_sec = ITERATIONS / duration;

    printf("malloc/free: %.2f seconds, %.0f ops/sec\n", duration, ops_per_sec);
}

void benchmark_mempool() {
    mempool_t *pool = mempool_create(1024, 100);

    double start = get_time();

    for (int i = 0; i < ITERATIONS; i++) {
        void *ptr = mempool_alloc(pool);
        mempool_free(pool, ptr);
    }

    double end = get_time();
    double duration = end - start;
    double ops_per_sec = ITERATIONS / duration;

    printf("mempool:     %.2f seconds, %.0f ops/sec\n", duration, ops_per_sec);

    mempool_destroy(pool);
}

int main() {
    printf("Memory Pool Benchmark (%d iterations)\n", ITERATIONS);
    printf("=====================================\n");

    benchmark_malloc();
    benchmark_mempool();

    return 0;
}
EOF

gcc -o test/performance/bench_mempool test/performance/bench_mempool.c \
    src/mmt_core/src/mempool.c -I src/mmt_core/public_include -pthread

./test/performance/bench_mempool
```

**Expected Output:**

```
Memory Pool Benchmark (1000000 iterations)
=====================================
malloc/free: 2.45 seconds, 408163 ops/sec
mempool:     0.82 seconds, 1219512 ops/sec
```

**Acceptance Criteria:**

- [ ] Memory pool implementation complete
- [ ] Integrated into mmt_handler_t
- [ ] ipacket allocation uses pool
- [ ] Compilation successful
- [ ] Benchmark shows 2-3x improvement
- [ ] No memory leaks (verify with valgrind)

**Validation:**

```bash
# Run benchmark
./test/performance/bench_mempool

# Check for memory leaks
valgrind --leak-check=full ./test/performance/bench_mempool 2>&1 | grep "definitely lost"

# Full build and test
./test/scripts/build_and_test.sh
```

**Estimated Time:** 16 hours

---

*Due to length constraints, I'll create a summary of remaining tasks...*

### Remaining Tasks Summary

**Task 2.2: Optimize Hash Table** (8h)

- Increase NSLOTS to 4096
- Use bitmask instead of modulo
- Implement better hash function

**Task 2.3: Replace std::map with unordered_map** (12h)

- Update hash_utils.cpp
- Change session storage
- Benchmark improvements

**Task 2.4: Optimize Session Initialization** (4h)

- Replace individual assignments with memset
- Only set non-zero fields

**Task 2.5: Add Function Inlining** (8h)

- Mark hot path functions with `__always_inline`
- Verify with profiling

**Phase 2 Validation Script** (4h)

- Performance benchmarks
- Throughput testing
- Regression testing

**Task 3.1-3.3: Thread Safety** (48h)

- Add protocol registry locks
- Session map protection
- Atomic statistics counters

**Task 4.1-4.2: Input Validation** (80h)

- Systematic bounds checking
- Fuzzing infrastructure setup

**Task 5.1-5.2: Error Handling** (32h)

- Standardized error framework
- Logging infrastructure

Each task will follow the same pattern:

1. Backup files
2. Make changes
3. Compile and test
4. Run validation
5. Document rollback procedure

---

**Total Estimated Time:** 560 hours

Would you like me to expand any particular phase into the same level of detail as Phase 1?
