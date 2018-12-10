/*
 * nas_emm_msg_header.h
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_EMM_NAS_EMM_MSG_HEADER_H_
#define SRC_MMT_5G_NAS_EMM_NAS_EMM_MSG_HEADER_H_

#include <stdlib.h>
#include <stdint.h>
#include "../util/common.h"
/* EPS Mobility Management Security header type */

/* Message identifiers for EPS Mobility Management     */
#define NAS_EMM_ATTACH_REQUEST                0b01000001 /* 65 = 0x41 */
#define NAS_EMM_ATTACH_ACCEPT                 0b01000010 /* 66 = 0x42 */
#define NAS_EMM_ATTACH_COMPLETE               0b01000011 /* 67 = 0x43 */

/*
 * General message organization example for a normal EMM NAS message:
 *
 *  --------------------------------------------------
 *   8     7      6      5     4      3      2      1
 *  +-----------------------+------------------------+
 *  | Security header       | Protocol discriminator | octet 1
 *  +-----------------------+------------------------+
 *  |                 Message type                   | octet 2
 *  +-----------------------+------------------------+
 *  |                                                | octet 3
 *  |     Other information elements as required     |
 *  ...                                            ...
 *  |                                                | octet n
 *  +-----------------------+------------------------+
 */


/*
 * General message organization for a normal EMM NAS message
 */
typedef struct __package__ {
#ifdef __LITTLE_ENDIAN__
  uint8_t protocol_discriminator :4;
  uint8_t security_header_type   :4;
#else
  uint8_t security_header_type   :4;
  uint8_t protocol_discriminator :4;
#endif

  uint8_t message_type;

} nas_emm_msg_header_t;

#define MIN_LEN_NAS_EMM_MSG_HEADER 2
#define MAX_LEN_NAS_EMM_MSG_HEADER 2

int nas_decode_emm_msg_header(nas_emm_msg_header_t *msg, const uint8_t *buffer, uint32_t len);

#endif /* SRC_MMT_5G_NAS_EMM_NAS_EMM_MSG_HEADER_H_ */
