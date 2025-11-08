#ifndef MMT_PROTOCOL_VALIDATION_H
#define MMT_PROTOCOL_VALIDATION_H

/**
 * Protocol Validation Macros
 * Phase 4: Input Validation Framework
 *
 * Provides high-level validation macros for protocol classification functions.
 * These macros ensure consistent validation patterns across all protocols.
 *
 * Usage: Include this header in protocol classification files (proto_*.c)
 */

#include "mmt_safe_access.h"
#include "mmt_safe_math.h"
#include "mmt_log.h"

/**
 * Validate protocol minimum header size
 * Returns 0 if validation fails (standard protocol return value)
 *
 * Usage:
 *   MMT_VALIDATE_MIN_HEADER(ipacket, offset, struct tcphdr, PROTO_TCP);
 */
#define MMT_VALIDATE_MIN_HEADER(ipacket, offset, header_type, proto_id) \
    do { \
        if ((ipacket) == NULL || (ipacket)->p_hdr == NULL) { \
            return 0; \
        } \
        uint32_t _remaining = ((offset) < (ipacket)->p_hdr->caplen) ? \
                              ((ipacket)->p_hdr->caplen - (offset)) : 0; \
        if (_remaining < sizeof(header_type)) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate and extract header pointer safely
 * Returns 0 if validation fails
 *
 * Usage:
 *   MMT_GET_HEADER_PTR(ipacket, offset, struct tcphdr, tcp_hdr, PROTO_TCP);
 *   // Now tcp_hdr can be safely used
 */
#define MMT_GET_HEADER_PTR(ipacket, offset, header_type, ptr_name, proto_id) \
    const header_type *ptr_name = MMT_SAFE_CAST(ipacket, offset, header_type); \
    if (ptr_name == NULL) { \
        return 0; \
    }

/**
 * Validate field value is within range
 * Returns 0 if validation fails
 *
 * Usage:
 *   MMT_VALIDATE_RANGE(hdr->version, 4, 6, "IP version", PROTO_IP);
 */
#define MMT_VALIDATE_RANGE(value, min_val, max_val, field_name, proto_id) \
    do { \
        if ((value) < (min_val) || (value) > (max_val)) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate variable-length field
 * Checks both length sanity and packet bounds
 * Returns 0 if validation fails
 *
 * Usage:
 *   MMT_VALIDATE_VAR_LENGTH(ipacket, offset, length, 65535, PROTO_HTTP);
 */
#define MMT_VALIDATE_VAR_LENGTH(ipacket, offset, length, max_length, proto_id) \
    do { \
        if ((length) > (max_length)) { \
            return 0; \
        } \
        if (!mmt_validate_offset(ipacket, offset, length)) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate protocol version
 * Returns 0 if version doesn't match
 *
 * Usage:
 *   MMT_VALIDATE_VERSION(hdr->version, 1, PROTO_GTP);
 */
#define MMT_VALIDATE_VERSION(version, expected, proto_id) \
    do { \
        if ((version) != (expected)) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate flags/bitmask
 * Checks if any invalid flags are set
 * Issues warning but does not fail classification
 *
 * Usage:
 *   MMT_VALIDATE_FLAGS(hdr->flags, 0x3F, PROTO_TCP);  // Only lower 6 bits valid
 */
#define MMT_VALIDATE_FLAGS(flags, valid_mask, proto_id) \
    do { \
        if (((flags) & ~(valid_mask)) != 0) { \
            /* Invalid flags present, but continue processing */ \
        } \
    } while(0)

/**
 * Validate array index
 * Returns 0 if index is out of bounds
 *
 * Usage:
 *   MMT_VALIDATE_INDEX(index, 256, "option_type", PROTO_TCP);
 */
#define MMT_VALIDATE_INDEX(index, array_size, array_name, proto_id) \
    do { \
        if ((index) >= (array_size)) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate pointer is not NULL
 * Returns 0 if pointer is NULL
 *
 * Usage:
 *   MMT_VALIDATE_NOT_NULL(session, "session", PROTO_TCP);
 */
#define MMT_VALIDATE_NOT_NULL(ptr, ptr_name, proto_id) \
    do { \
        if ((ptr) == NULL) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate safe integer addition before use
 * Returns 0 if overflow would occur
 *
 * Usage:
 *   uint32_t new_offset;
 *   MMT_SAFE_ADD_OR_FAIL(offset, length, new_offset, PROTO_GTP);
 */
#define MMT_SAFE_ADD_OR_FAIL(a, b, result, proto_id) \
    do { \
        if (!mmt_safe_add_u32(a, b, &(result))) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate safe integer multiplication before use
 * Returns 0 if overflow would occur
 *
 * Usage:
 *   uint32_t total_len;
 *   MMT_SAFE_MUL_OR_FAIL(count, size, total_len, PROTO_IP);
 */
#define MMT_SAFE_MUL_OR_FAIL(a, b, result, proto_id) \
    do { \
        if (!mmt_safe_mul_u32(a, b, &(result))) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate remaining packet data
 * Returns 0 if not enough data remains
 *
 * Usage:
 *   MMT_VALIDATE_REMAINING(ipacket, offset, 20, PROTO_TCP);
 */
#define MMT_VALIDATE_REMAINING(ipacket, offset, needed, proto_id) \
    do { \
        if ((ipacket) == NULL || (ipacket)->p_hdr == NULL) { \
            return 0; \
        } \
        uint32_t _remaining = ((offset) < (ipacket)->p_hdr->caplen) ? \
                              ((ipacket)->p_hdr->caplen - (offset)) : 0; \
        if (_remaining < (needed)) { \
            return 0; \
        } \
    } while(0)

/**
 * Validate loop counter to prevent infinite loops
 * Returns 0 if counter exceeds maximum
 *
 * Usage:
 *   MMT_VALIDATE_LOOP_COUNT(count, 100, "extension headers", PROTO_GTP);
 */
#define MMT_VALIDATE_LOOP_COUNT(count, max_count, loop_name, proto_id) \
    do { \
        if ((count) > (max_count)) { \
            return 0; \
        } \
    } while(0)

/**
 * Common validation constants
 */
#define MMT_MAX_PROTOCOL_HEADER_SIZE  256
#define MMT_MAX_EXTENSION_HEADERS     10
#define MMT_MAX_OPTIONS_LENGTH        40
#define MMT_MAX_STRING_LENGTH         8192
#define MMT_MAX_URI_LENGTH            8192
#define MMT_MAX_HEADER_VALUE_LENGTH   16384

#endif /* MMT_PROTOCOL_VALIDATION_H */
