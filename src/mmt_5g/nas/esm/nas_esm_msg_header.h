/*
 * nas_esm_msg_header.h
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_ESM_NAS_ESM_MSG_HEADER_H_
#define SRC_MMT_5G_NAS_ESM_NAS_ESM_MSG_HEADER_H_

#include <stdlib.h>
#include <stdint.h>
#include "../util/common.h"



/*
 * General message organization example for an ESM NAS message:
 *
 *  --------------------------------------------------
 *   8     7      6      5     4      3      2      1
 *  +-----------------------+------------------------+
 *  | EPS bearer identity   | Protocol discriminator | octet 1
 *  +-----------------------+------------------------+
 *  |          Procedure transaction identity        | octet 2
 *  +-----------------------+------------------------+
 *  |                 Message type                   | octet 3
 *  +-----------------------+------------------------+
 *  |                                                | octet 4
 *  |     Other information elements as required     |
 *  ...                                            ...
 *  |                                                | octet n
 *  +-----------------------+------------------------+
 */
typedef struct __package__ {
#ifdef __LITTLE_ENDIAN__
  uint8_t protocol_discriminator :4;
  uint8_t eps_bearer_identity    :4;
#else
  uint8_t eps_bearer_identity    :4;
  uint8_t protocol_discriminator :4;
#endif

  uint8_t procedure_transaction_identity;
  uint8_t message_type;

} nas_esm_msg_header_t;


#endif /* SRC_MMT_5G_NAS_ESM_NAS_ESM_MSG_HEADER_H_ */
