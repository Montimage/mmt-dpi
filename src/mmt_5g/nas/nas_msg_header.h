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


  /* Protocol discriminator identifier for EPS Mobility Management */
#define EPS_MOBILITY_MANAGEMENT_MESSAGE 0x7
  /* Protocol discriminator identifier for EPS Session Management */
#define EPS_SESSION_MANAGEMENT_MESSAGE  0x2


/*
 * Header of EPS Mobility Management plain NAS message
 * ---------------------------------------------------
 *   8     7      6      5     4      3      2      1
 *  +-----------------------+------------------------+
 *  | Security header type  | Protocol discriminator |
 *  +-----------------------+------------------------+
 */
typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t protocol_discriminator:4;
  uint8_t security_header_type:4;
#else
  uint8_t security_header_type:4;
  uint8_t protocol_discriminator:4;
#endif
} nas_msg_header_t;

int nas_decode_msg_header( nas_msg_header_t *msg, const uint8_t *buffer, int length );

#endif /* SRC_MMT_5G_NAS_NAS_MSG_H_ */
