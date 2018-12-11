/*
 * eps_quality_of_service.h
 *
 *  Created on: Dec 11, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_IES_EPS_QUALITY_OF_SERVICE_H_
#define SRC_MMT_5G_NAS_IES_EPS_QUALITY_OF_SERVICE_H_

#include <stdlib.h>
#include <stdint.h>


#define EPS_QUALITY_OF_SERVICE_MINIMUM_LENGTH  2
#define EPS_QUALITY_OF_SERVICE_MAXIMUM_LENGTH 10

typedef struct {
  uint8_t max_bit_rate_for_ul;
  uint8_t max_bit_rate_for_dl;
  uint8_t guar_bit_rate_for_ul;
  uint8_t guar_bit_rate_for_dl;
} nas_eps_qos_bit_rates_t;

typedef struct {
  uint8_t bit_rates_present:1;
  uint8_t bit_rates_ext_present:1;
  uint8_t qci;
  nas_eps_qos_bit_rates_t bit_rates;
  nas_eps_qos_bit_rates_t bit_rates_ext;
} nas_eps_quality_of_service_t;

//typedef uint8_t EpsQualityOfService;

int nas_decode_eps_quality_of_service(nas_eps_quality_of_service_t *m, uint8_t iei, const uint8_t *buffer, uint32_t len);

#endif /* SRC_MMT_5G_NAS_IES_EPS_QUALITY_OF_SERVICE_H_ */
