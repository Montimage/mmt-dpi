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

/* Message identifiers for EPS Session Management   */
# define NAS_ESM_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST   0b11000001 /* 193 = 0xc1 */
# define NAS_ESM_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT    0b11000010 /* 194 = 0xc2 */
# define NAS_ESM_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT    0b11000011 /* 195 = 0xc3 */
# define NAS_ESM_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST 0b11000101 /* 197 = 0xc5 */
# define NAS_ESM_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT  0b11000110 /* 198 = 0xc6 */
# define NAS_ESM_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT  0b11000111 /* 199 = 0xc7 */
# define NAS_ESM_MODIFY_EPS_BEARER_CONTEXT_REQUEST             0b11001001 /* 201 = 0xc9 */
# define NAS_ESM_MODIFY_EPS_BEARER_CONTEXT_ACCEPT              0b11001010 /* 202 = 0xca */
# define NAS_ESM_MODIFY_EPS_BEARER_CONTEXT_REJECT              0b11001011 /* 203 = 0xcb */
# define NAS_ESM_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST         0b11001101 /* 205 = 0xcd */
# define NAS_ESM_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT          0b11001110 /* 206 = 0xce */
# define NAS_ESM_PDN_CONNECTIVITY_REQUEST                      0b11010000 /* 208 = 0xd0 */
# define NAS_ESM_PDN_CONNECTIVITY_REJECT                       0b11010001 /* 209 = 0xd1 */
# define NAS_ESM_PDN_DISCONNECT_REQUEST                        0b11010010 /* 210 = 0xd2 */
# define NAS_ESM_PDN_DISCONNECT_REJECT                         0b11010011 /* 211 = 0xd3 */
# define NAS_ESM_BEARER_RESOURCE_ALLOCATION_REQUEST            0b11010100 /* 212 = 0xd4 */
# define NAS_ESM_BEARER_RESOURCE_ALLOCATION_REJECT             0b11010101 /* 213 = 0xd5 */
# define NAS_ESM_BEARER_RESOURCE_MODIFICATION_REQUEST          0b11010110 /* 214 = 0xd6 */
# define NAS_ESM_BEARER_RESOURCE_MODIFICATION_REJECT           0b11010111 /* 215 = 0xd7 */
# define NAS_ESM_ESM_INFORMATION_REQUEST                       0b11011001 /* 217 = 0xd9 */
# define NAS_ESM_ESM_INFORMATION_RESPONSE                      0b11011010 /* 218 = 0xda */
# define NAS_ESM_ESM_STATUS                                    0b11101000 /* 232 = 0xe8 */

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
