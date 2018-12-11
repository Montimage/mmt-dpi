/*
 * pdn_address.h
 *
 *  Created on: Dec 11, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_IES_PDN_ADDRESS_H_
#define SRC_MMT_5G_NAS_IES_PDN_ADDRESS_H_

#include <stdlib.h>
#include <stdint.h>


#include "../util/octet_string.h"

#define PDN_ADDRESS_MINIMUM_LENGTH 7
#define PDN_ADDRESS_MAXIMUM_LENGTH 15

#define NAS_PDN_VALUE_TYPE_IPV4      0b001
#define NAS_PDN_VALUE_TYPE_IPV6      0b010
#define NAS_PDN_VALUE_TYPE_IPV4V6    0b011

typedef struct {
  uint8_t            pdn_type_value:3;
  nas_octet_string_t pdn_address_information;
} nas_pdn_address_t;

int nas_decode_pdn_address(nas_pdn_address_t *add, uint8_t iei, const uint8_t *buffer, uint32_t len);

#endif /* SRC_MMT_5G_NAS_IES_PDN_ADDRESS_H_ */
