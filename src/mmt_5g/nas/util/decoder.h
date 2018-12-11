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
#include <arpa/inet.h>
#include "branch_optimization.h"

#define DECODE_U8(buffer, value, size)                   \
    value = *(uint8_t*)(buffer);                         \
    size += sizeof(uint8_t)

#define DECODE_U16(buffer, value, size)                  \
    value = ntohs(*(uint16_t*)(buffer));                 \
    size += sizeof(uint16_t)

#define DECODE_U24(buffer, value, size)                  \
    value = ntohl(*(uint32_t*)(buffer)) >> 8;            \
    size += sizeof(uint8_t) + sizeof(uint16_t)

#define DECODE_U32(buffer, value, size)                  \
    value = ntohl(*(uint32_t*)(buffer));                 \
    size += sizeof(uint32_t)

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
} decoder_error_code_t;

/* Defines error code limit below which received message should be discarded
 * because it cannot be further processed */
#define DECODE_FATAL_ERROR  (DECODE_VALUE_DOESNT_MATCH)
#define LOG(fmt, args...) fprintf(stderr, "%s:%d" fmt, __FILE__, __LINE__,##args)

extern int errorCodeDecoder;
#define CHECK_RESULT_DECODER( ret, decoded )                                   \
		if( unlikely( ret <0 )) return ret;                                    \
		else                    decoded += ret;

#define RETURN(x, y)                                                           \
		if(unlikely( x<0 )) return x;   /*error*/                              \
		else                return (x+y);
#define CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, minimumlength, length)    \
		while (unlikely( buffer == NULL ))                                     \
        {                                                                      \
                LOG("(%s:%d) Got NULL pointer for the payload\n",              \
                __FILE__, __LINE__);                                           \
                errorCodeDecoder = DECODE_BUFFER_NULL;                         \
                return (DECODE_BUFFER_NULL);                                   \
        }                                                                      \
		while (unlikely( length < minimumlength))                              \
        {                                                                      \
                LOG("(%s:%d) Expecting at least %d bytes, got %d\n",           \
                      __FILE__, __LINE__, minimumlength, length);              \
                errorCodeDecoder = DECODE_BUFFER_TOO_SHORT;                    \
                return (DECODE_BUFFER_TOO_SHORT);                              \
        }

#define CHECK_LENGTH_DECODER(bufferlength, length)                             \
        while (unlikely( bufferlength < length ))                              \
        {                                                                      \
                errorCodeDecoder = DECODE_BUFFER_TOO_SHORT;                    \
                return (DECODE_BUFFER_TOO_SHORT);                              \
        }

#define CHECK_MESSAGE_TYPE(message_type, buffer)                               \
		while (unlikely( message_type != buffer ))                             \
		{                                                                      \
				errorCodeDecoder = DECODE_WRONG_MESSAGE_TYPE;                  \
				return (errorCodeDecoder);                                     \
		}

#define CHECK_IEI_DECODER(iei, buffer)                                         \
        if( unlikely( iei != buffer ))                                         \
        {                                                                      \
                LOG("IEI is different than the one expected."                  \
                "(Got: 0x%x, expecting: 0x%x)\n", buffer, iei);                \
                errorCodeDecoder = DECODE_UNEXPECTED_IEI;                      \
        }


#endif /* SRC_MMT_5G_NAS_UTIL_DECODER_H_ */
