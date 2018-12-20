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
#include <stdbool.h>

#include "util/common.h"
#include "emm/nas_emm_msg.h"
#include "esm/nas_esm_msg.h"


/* Protocol discriminator identifier for EPS Mobility Management */
#define NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE 0b0111
/* Protocol discriminator identifier for EPS Session Management */
#define NAS_EPS_SESSION_MANAGEMENT_MESSAGE  0b0010

#define NAS_SECURITY_HEADER_TYPE_NOT_PROTECTED                    0b0000
#define NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED              0b0001
#define NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED     0b0010
#define NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW          0b0011
#define NAS_SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW 0b0100
#define NAS_SECURITY_HEADER_TYPE_SERVICE_REQUEST                  0b1100



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


/*The first common byte of any NAS message*/
typedef struct __package__ {
	__NAS_MSG_FIRST_OCTET__
}nas_msg_header_t;

typedef struct __package__ {
	__NAS_MSG_FIRST_OCTET__
	uint32_t message_authentication_code;
	uint8_t  sequence_number;
} nas_msg_security_header_t ;

/* Plain NAS message */
typedef union{
	nas_msg_header_t  header;
	nas_emm_msg_t     emm;
	nas_esm_msg_t     esm;
} nas_msg_plain_t;

/* Security-protected NAS message */
typedef struct{
	nas_msg_security_header_t header;
	nas_msg_plain_t           msg;
}nas_msg_security_protected_t;

/* A NAS message is either a plain one or a security-protected one */
typedef union{
	nas_msg_header_t             header;
	nas_msg_security_protected_t protected_msg;
	nas_msg_plain_t              plain_msg;
}nas_msg_t;




static inline bool nas_is_plain_msg( const nas_msg_t *msg ){
	return (msg->header.security_header_type == NAS_SECURITY_HEADER_TYPE_NOT_PROTECTED);
}


static inline nas_msg_plain_t *nas_get_plain_msg( nas_msg_t *msg ){
	if( nas_is_plain_msg( msg) )
		return &msg->plain_msg;
	return &msg->protected_msg.msg;
}

static inline bool nas_is_security_protected_msg( const nas_msg_t *msg ){
	return (msg->header.protocol_discriminator == NAS_EPS_MOBILITY_MANAGEMENT_MESSAGE
		&&  msg->header.security_header_type   != NAS_SECURITY_HEADER_TYPE_SERVICE_REQUEST
		&&  msg->header.security_header_type   != NAS_SECURITY_HEADER_TYPE_NOT_PROTECTED);
}

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
int nas_decode( nas_msg_t *msg, const uint8_t *buffer, int length );

#endif /* SRC_MMT_5G_NAS_NAS_MSG_H_ */
