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

/* the IPv6 interface identifier an IPv6 or IPv4v6 PDN address carries */
#define NAS_PDN_IPV6_IID_LENGTH      8

typedef struct {
  uint8_t            pdn_type_value;
  nas_octet_string_t pdn_address_information;
} nas_pdn_address_t;

int nas_decode_pdn_address(nas_pdn_address_t *add, uint8_t iei, const uint8_t *buffer, uint32_t len);

/* Copy the IPv4 address of a decoded PDN address of type IPv4 or IPv4v6
 * into *ipv4, in network byte order. Returns 1 when copied, 0 for any other
 * PDN type or a value too short to hold it (*ipv4 is then left unchanged). */
int nas_pdn_address_get_ipv4(const nas_pdn_address_t *addr, uint32_t *ipv4);

#endif /* SRC_MMT_5G_NAS_IES_PDN_ADDRESS_H_ */
