/*
 * nas_msg.h
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_NAS_MSG_H_
#define SRC_MMT_5G_NAS_NAS_MSG_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "util/common.h"
#include "emm/nas_emm_msg.h"
#include "esm/nas_esm_msg.h"


  /* Protocol discriminator identifier for EPS Mobility Management */
#define NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE 0b0111
  /* Protocol discriminator identifier for EPS Session Management */
#define NAS_EPS_SESSION_MANAGEMENT_MESSAGE  0b0010

#define SECURITY_HEADER_TYPE_NOT_PROTECTED                    0b0000
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED              0b0001
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED     0b0010
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW          0b0011
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW 0b0100
#define SECURITY_HEADER_TYPE_SERVICE_REQUEST                  0b0110



#define NAS_MESSAGE_SECURITY_HEADER_SIZE    6
/*
 * General message organization example for a security-protected NAS message:
 *
 *  --------------------------------------------------
 *   8     7      6      5     4      3      2      1
 *  +-----------------------+------------------------+
 *  | Security header type  | Protocol discriminator | octet 1
 *  +-----------------------+------------------------+
 *  |                                                | octet 2
 *  |                                                |
 *  |          Message authentication code           |
 *  |                                                | octet 5
 *  +-----------------------+------------------------+
 *  |                Sequence number                 | octet 6
 *  +-----------------------+------------------------+
 *  |                                                | octet 7
 *  |                  NAS message                   |
 *  ...                                            ...
 *  |                                                | octet n
 *  +-----------------------+------------------------+
 */

typedef struct __package__ {
#ifdef __LITTLE_ENDIAN__
  uint8_t protocol_discriminator: 4;
  uint8_t security_header_type  : 4;
#else
  uint8_t security_header_type  : 4;
  uint8_t protocol_discriminator: 4;
#endif
  uint32_t message_authentication_code;
  uint8_t  sequence_number;
} nas_msg_security_header_t ;

/* Plain NAS message */
typedef union{
	nas_emm_msg_t emm;
	nas_esm_msg_t esm;
} nas_msg_plain_t;

/* Security-protected NAS message */
typedef struct{
	nas_msg_security_header_t header;
	nas_msg_plain_t           msg;
}nas_msg_security_protected_t;

/* A NAS message is either a plain one or a security-protected one */
typedef union{
	nas_msg_security_protected_t protected_msg;
	nas_msg_plain_t              plain_msg;
}nas_msg_t;


/**
 * Decode layer 3 NAS message
 *
 * @inputs:
 * - buffer: Pointer to the buffer containing layer 3 NAS message data
 * - length: Number of bytes that should be decoded
 *
 * @outputs:
 * - msg: L3 NAS message structure to be filled
 *
 * @return:
 *  A positive number of bytes in the buffer if the buffer if the data have been successfully decoded
 *  Otherwise, a negative number representing code error
 */
int nas_decode_msg_header( nas_msg_t *msg, const uint8_t *buffer, int length );

#endif /* SRC_MMT_5G_NAS_NAS_MSG_H_ */
