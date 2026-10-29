/*
 * decoder.h
 *
 *  Created on: Dec 7, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_UTIL_DECODER_H_
#define SRC_MMT_5G_NAS_UTIL_DECODER_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "branch_optimization.h"
#include "../../../mmt_core/private_include/mmt_log.h" /* issue #545 */

#define DECODE_U8(buffer, value, size)                   \
    value = *(uint8_t*)(buffer);                         \
    size += sizeof(uint8_t)

/*
 * F-BUG-090: multi-byte reads must not cast the wire pointer to a wider
 * integer pointer — the buffer is arbitrarily aligned, so the cast
 * dereference is undefined behaviour. Copy into a fixed-size local instead.
 */
#define DECODE_U16(buffer, value, size) do {             \
    uint16_t _dec_u16;                                   \
    memcpy( &_dec_u16, (buffer), sizeof( _dec_u16 ));    \
    value = ntohs( _dec_u16 );                           \
    size += sizeof(uint16_t);                            \
} while (0)

#define DECODE_U24(buffer, value, size) do {             \
    uint8_t _dec_u24[3];                                 \
    memcpy( _dec_u24, (buffer), sizeof( _dec_u24 ));     \
    value = ((uint32_t) _dec_u24[0] << 16)               \
          | ((uint32_t) _dec_u24[1] <<  8)               \
          |  (uint32_t) _dec_u24[2];                     \
    size += sizeof(uint8_t) + sizeof(uint16_t);          \
} while (0)

#define DECODE_U32(buffer, value, size) do {             \
    uint32_t _dec_u32;                                   \
    memcpy( &_dec_u32, (buffer), sizeof( _dec_u32 ));    \
    value = ntohl( _dec_u32 );                           \
    size += sizeof(uint32_t);                            \
} while (0)

#if (BYTE_ORDER == LITTLE_ENDIAN)
# define DECODE_LENGTH_U16(buffer, value, size)          \
    value = ((*(buffer)) << 8) | (*((buffer) + 1));      \
    size += sizeof(uint16_t)
#else
# define DECODE_LENGTH_U16(buffer, value, size)          \
    value = (*(buffer)) | (*((buffer) + 1) << 8);        \
    size += sizeof(uint16_t)
#endif

#define IES_DECODE_U8(buffer, decoded, value)            \
    DECODE_U8(buffer + decoded, value, decoded)

#define IES_DECODE_U16(buffer, decoded, value)           \
    DECODE_U16(buffer + decoded, value, decoded)

#define IES_DECODE_U24(buffer, decoded, value)           \
    DECODE_U24(buffer + decoded, value, decoded)

#define IES_DECODE_U32(buffer, decoded, value)           \
    DECODE_U32(buffer + decoded, value, decoded)

typedef enum {
  DECODE_ERROR_OK                     =  0,
  DECODE_UNEXPECTED_IEI               = -1,
  DECODE_MANDATORY_FIELD_NOT_PRESENT  = -2,
  DECODE_VALUE_DOESNT_MATCH           = -3,

  /* Fatal errors - received message should not be processed */
  DECODE_WRONG_MESSAGE_TYPE           = -10,
  DECODE_PROTOCOL_NOT_SUPPORTED       = -11,
  DECODE_BUFFER_TOO_SHORT             = -12,
  DECODE_BUFFER_NULL                  = -13,
  DECODE_MAC_MISMATCH                 = -14,
  /* issue #452: ciphered payload not decoded — non-null algorithm (EEA1-7),
   * or unknown algorithm and not a plausible plain NAS message */
  DECODE_CIPHERED_PAYLOAD             = -15,
} decoder_error_code_t;

/* Defines error code limit below which received message should be discarded
 * because it cannot be further processed */
#define DECODE_FATAL_ERROR  (DECODE_VALUE_DOESNT_MATCH)
/* Issue #545: NAS decode diagnostics go through the SDK logger (mmt_log.h):
 * off by default, stderr only, rate-limited, counted; it adds file:line. */
#define LOG(fmt, args...) mmt_log_warn("[NAS] " fmt, ##args)

/* Issue #507 (F-BUG-220): the decoders return their error code; there is no
 * process-global error variable, which every decoding thread used to write. */
#define RETURN(x, y)                                                           \
		if(unlikely( x<0 )) return x;   /*error*/                              \
		else                return (x+y);

/*
 * Issue #548: the input checks are functions, and each call site spells out
 * its own control flow: it stores the result of nas_check_pdu() or
 * nas_check_length() and returns it when it is negative, after
 * NAS_LOG_PDU_CHECK() for a nas_check_pdu() failure (a nas_check_length()
 * failure is not logged). No macro hides a return any more.
 *
 * The functions only check. The LOG() lines stay in macros expanded at the
 * call site: mmt_log_warn() records __FILE__/__LINE__ and keeps one
 * rate-limit state per expansion (mmt_log.h), so a diagnostic still names
 * the decoder that rejected the input, and each site is rate-limited on its
 * own. Each operand is evaluated in its own type, then converted to int64_t,
 * which holds every int/uint32_t value: the comparison gives the result the
 * operands' own types gave when the checks were macros.
 */

/* DECODE_BUFFER_NULL when buffer is NULL, DECODE_BUFFER_TOO_SHORT when
 * length < minimum_length, else 0. */
static inline int nas_check_pdu(const void *buffer, int64_t minimum_length, int64_t length)
{
	if (unlikely( buffer == NULL ))
		return DECODE_BUFFER_NULL;
	if (unlikely( length < minimum_length ))
		return DECODE_BUFFER_TOO_SHORT;
	return 0;
}

/* DECODE_BUFFER_TOO_SHORT when buffer_length < length, else 0. */
static inline int nas_check_length(int64_t buffer_length, int64_t length)
{
	if (unlikely( buffer_length < length ))
		return DECODE_BUFFER_TOO_SHORT;
	return 0;
}

/* The warning for a non-zero nas_check_pdu() result rc. */
#define NAS_LOG_PDU_CHECK(rc, minimum_length, length) do {                    \
		if ((rc) == DECODE_BUFFER_NULL)                                        \
			LOG("Got NULL pointer for the payload\n");                         \
		else                                                                   \
			LOG("Expecting at least %d bytes, got %d\n",                       \
				(int) (minimum_length), (int) (length));                       \
	} while (0)

/* Warns when the IEI read from the wire (got) is not the expected one; the
 * decoder goes on either way. */
#define NAS_LOG_IEI_MISMATCH(iei, got) do {                                   \
		if (unlikely( (iei) != (got) ))                                        \
			LOG("IEI is different than the one expected."                      \
				"(Got: 0x%x, expecting: 0x%x)\n", (got), (iei));               \
	} while (0)

#define CHECK_MESSAGE_TYPE(message_type, buffer)                               \
		while (unlikely( message_type != buffer ))                             \
		{                                                                      \
				return (DECODE_WRONG_MESSAGE_TYPE);                            \
		}


#endif /* SRC_MMT_5G_NAS_UTIL_DECODER_H_ */
