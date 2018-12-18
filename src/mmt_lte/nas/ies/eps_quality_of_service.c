#include "../util/decoder.h"
#include "eps_quality_of_service.h"

static inline int _decode_eps_qos_bit_rates(nas_eps_qos_bit_rates_t* m, const uint8_t *buffer)
{
  int decoded = 0;
  DECODE_U8( buffer, m->max_bit_rate_for_ul, decoded);
  DECODE_U8( buffer, m->max_bit_rate_for_dl, decoded);
  DECODE_U8( buffer, m->guar_bit_rate_for_ul, decoded);
  DECODE_U8( buffer, m->guar_bit_rate_for_dl, decoded);
  return decoded;
}

int nas_decode_eps_quality_of_service(nas_eps_quality_of_service_t *m, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
  int decoded = 0;
  uint8_t ielen = 0;

  if (iei > 0) {
    CHECK_IEI_DECODER(iei, *buffer);
    decoded++;
  }

  ielen = *(buffer + decoded);
  decoded++;
  CHECK_LENGTH_DECODER(len - decoded, ielen);

  DECODE_U8( buffer, m->qci, decoded );

  if ( ielen > 2 + (iei > 0) ? 1 : 0 ) {
    /* bitRates is present */
    m->bit_rates_present = 1;
    decoded += _decode_eps_qos_bit_rates(&m->bit_rates,
                                        buffer + decoded);
  } else {
    /* bitRates is not present */
    m->bit_rates_present = 0;
  }

  if ( ielen > 6 + (iei > 0) ? 1 : 0 ) {
    /* bitRatesExt is present */
    m->bit_rates_ext_present = 1;
    decoded += _decode_eps_qos_bit_rates(&m->bit_rates_ext,
                                        buffer + decoded);
  } else {
    /* bitRatesExt is not present */
    m->bit_rates_ext_present = 0;
  }

  return decoded;
}
