#include "../util/decoder.h"
#include "eps_quality_of_service.h"

static inline int _decode_eps_qos_bit_rates(nas_eps_qos_bit_rates_t* m, const uint8_t *buffer)
{
  int decoded = 0;
  /* F-BUG-088: read at buffer + decoded — the bare buffer returned the
   * same first byte for all four bit rates. */
  DECODE_U8( buffer + decoded, m->max_bit_rate_for_ul, decoded);
  DECODE_U8( buffer + decoded, m->max_bit_rate_for_dl, decoded);
  DECODE_U8( buffer + decoded, m->guar_bit_rate_for_ul, decoded);
  DECODE_U8( buffer + decoded, m->guar_bit_rate_for_dl, decoded);
  return decoded;
}

int nas_decode_eps_quality_of_service(nas_eps_quality_of_service_t *m, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
  int decoded = 0;
  uint8_t ielen = 0;
  int rc;

  /* F-BUG-083: validate pointer and length before the first read;
   * remainders are computed in a checked signed form. */
  if (iei > 0) {
    rc = nas_check_pdu(buffer, 1, len);
    if (unlikely(rc < 0)) {
      NAS_LOG_PDU_CHECK(rc, 1, len);
      return rc;
    }
    NAS_LOG_IEI_MISMATCH(iei, *buffer);
    decoded++;
  }

  rc = nas_check_pdu(buffer, decoded + 1, len);
  if (unlikely(rc < 0)) {
    NAS_LOG_PDU_CHECK(rc, decoded + 1, len);
    return rc;
  }
  IES_DECODE_U8(buffer, decoded, ielen);
  rc = nas_check_length((int32_t)len - decoded, ielen);
  if (unlikely(rc < 0))
    return rc;

  // F-BUG-205: bound QCI by ielen and fix buffer offset
  rc = nas_check_length(ielen, 1);
  if (unlikely(rc < 0))
    return rc;
  rc = nas_check_length((int32_t)len - decoded, 1);
  if (unlikely(rc < 0))
    return rc;
  IES_DECODE_U8(buffer, decoded, m->qci);

  // F-BUG-205: fix operator-precedence guards
  if ( ielen > (2 + (iei > 0 ? 1 : 0)) ) {
    /* bitRates is present */
    rc = nas_check_length(ielen, 1 + 4);
    if (unlikely(rc < 0))
      return rc;
    rc = nas_check_length((int32_t)len - decoded, 4);
    if (unlikely(rc < 0))
      return rc;
    m->bit_rates_present = 1;
    decoded += _decode_eps_qos_bit_rates(&m->bit_rates,
                                        buffer + decoded);
  } else {
    /* bitRates is not present */
    m->bit_rates_present = 0;
  }

  if ( ielen > (6 + (iei > 0 ? 1 : 0)) ) {
    /* bitRatesExt is present */
    rc = nas_check_length(ielen, 1 + 8);
    if (unlikely(rc < 0))
      return rc;
    rc = nas_check_length((int32_t)len - decoded, 4);
    if (unlikely(rc < 0))
      return rc;
    m->bit_rates_ext_present = 1;
    decoded += _decode_eps_qos_bit_rates(&m->bit_rates_ext,
                                        buffer + decoded);
  } else {
    /* bitRatesExt is not present */
    m->bit_rates_ext_present = 0;
  }

  return decoded;
}
