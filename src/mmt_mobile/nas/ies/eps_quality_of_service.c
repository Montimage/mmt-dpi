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

/* TS 24.301 §9.9.4.3: ielen counts the contents only (never the IEI): the
 * QCI, then up to three optional groups of four rate octets — the bit rates
 * (octets 4-7), the extended bit rates (octets 8-11) and the Rel-11 extended-2
 * bit rates (octets 12-15), so ielen is 1, 5, 9 or 13. Issue #573: a group is
 * decoded when ielen holds it whole; octets past the last whole group are
 * skipped, never read as the next IE. The caller checked ielen octets are
 * readable at contents and ielen >= 1. */
static void _decode_eps_qos_contents(nas_eps_quality_of_service_t *m, const uint8_t *contents, uint8_t ielen)
{
  m->qci = contents[0];
  m->bit_rates_present = ielen >= 5;
  if (m->bit_rates_present)
    _decode_eps_qos_bit_rates(&m->bit_rates, contents + 1);
  m->bit_rates_ext_present = ielen >= 9;
  if (m->bit_rates_ext_present)
    _decode_eps_qos_bit_rates(&m->bit_rates_ext, contents + 5);
  m->bit_rates_ext2_present = ielen >= 13;
  if (m->bit_rates_ext2_present)
    _decode_eps_qos_bit_rates(&m->bit_rates_ext2, contents + 9);
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
  _decode_eps_qos_contents(m, buffer + decoded, ielen);

  /* issue #573: the whole IE is consumed, so the caller resumes at the next
   * IE whatever groups ielen held */
  return decoded + ielen;
}
