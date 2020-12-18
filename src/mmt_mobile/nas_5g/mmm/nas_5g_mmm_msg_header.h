/*
 * nas_5g_mmm_msg_header.h
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#include <stdlib.h>
#include <stdint.h>
#ifndef SRC_MMT_MOBILE_NAS_5G_MMM_NAS_5G_MMM_MSG_HEADER_H_
#define SRC_MMT_MOBILE_NAS_5G_MMM_NAS_5G_MMM_MSG_HEADER_H_

/* 3GPP TS 24.501 version 15.0.0 Release 15
 * ETSI TS 124 501 V15.0.0 (2018-07)
 * 8.2 5GS mobility management messages
 * General message organization example for a normal MMM NAS message:
 *
 *  --------------------------------------------------
 *   8     7      6      5     4      3      2      1
 *  +-----------------------+------------------------+
 *  +-----------------------+------------------------+
 *  |       Extended protocol discriminator          | octet 1
 *  +-----------------------+------------------------+
 *  | Security header       |                        | octet 2
 *  +-----------------------+------------------------+
 *  |                 Message type                   | octet 3
 *  +-----------------------+------------------------+
 *  |                                                | octet 4
 *  |     Other information elements as required     |
 *  ...                                            ...
 *  |                                                | octet n
 *  +-----------------------+------------------------+
 */

typedef struct nas_5g_mmm_msg_header{
	uint8_t protocol_discriminator;
#ifdef __LITTLE_ENDIAN__
  uint8_t padding                :4;
  uint8_t security_header_type   :4;
#else
  uint8_t security_header_type   :4;
  uint8_t padding                :4;
#endif

  uint8_t message_type;

} nas_5g_mmm_msg_header_t;

#endif /* SRC_MMT_MOBILE_NAS_5G_MMM_NAS_5G_MMM_MSG_HEADER_H_ */
