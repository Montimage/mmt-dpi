/*
 * ngap.h
 *
 *  Created on: Dec 14, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_NGAP_NGAP_H_
#define SRC_MMT_MOBILE_NGAP_NGAP_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Try decoding NGAP protocol
 * @param buffer
 * @param length
 * @return true if decode successfully, otherwise false
 */
bool try_decode_ngap( const uint8_t * buffer, const uint32_t length );

#endif /* SRC_MMT_MOBILE_NGAP_NGAP_H_ */
