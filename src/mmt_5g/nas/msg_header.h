/*
 * msg_header.h
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_MSG_HEADER_H_
#define SRC_MMT_5G_NAS_MSG_HEADER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef enum eps_protocol_discriminator_e {
  /* Protocol discriminator identifier for EPS Mobility Management */
  EPS_MOBILITY_MANAGEMENT_MESSAGE =   0x7,

  /* Protocol discriminator identifier for EPS Session Management */
  EPS_SESSION_MANAGEMENT_MESSAGE =    0x2,
} eps_protocol_discriminator_t;


/*
 * Header of EPS Mobility Management plain NAS message
 * ---------------------------------------------------
 *   8     7      6      5     4      3      2      1
 *  +-----------------------+------------------------+
 *  | Security header type  | Protocol discriminator |
 *  +-----------------------+------------------------+
 *  |                 Message type                   |
 *  +-----------------------+------------------------+
 */
typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t protocol_discriminator:4;
  uint8_t security_header_type:4;
#endif
#if BYTE_ORDER == BIG_ENDIA
  uint8_t security_header_type:4;
  uint8_t protocol_discriminator:4;
#endif
  uint8_t message_type;
} __attribute__((__packed__)) msg_header_t;

#endif /* SRC_MMT_5G_NAS_MSG_HEADER_H_ */
