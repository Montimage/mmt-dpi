#include <string.h>
#include "../util/decoder.h"
#include "pdn_address.h"

int nas_decode_pdn_address(nas_pdn_address_t *addr, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
  int decoded = 0;
  uint8_t ielen = 0;
  int decode_result;
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
  IES_DECODE_U8( buffer, decoded, ielen );

  rc = nas_check_length((int32_t)len - decoded, ielen);
  if (unlikely(rc < 0))
    return rc;

  // F-BUG-206: reject ielen=0 before reading pdn_type byte (enabler for 202)
  if (ielen == 0) {
    return DECODE_BUFFER_TOO_SHORT;
  }
  rc = nas_check_length((int32_t)len - decoded, 1);
  if (unlikely(rc < 0))
    return rc;

  DECODE_U8( buffer+decoded, addr->pdn_type_value, decoded );
  //get 4 high bits
  addr->pdn_type_value &= 0b111;

  // ielen includes the pdn_type byte; address payload is the remainder
  addr->pdn_address_information.len  = ielen - 1;
  addr->pdn_address_information.data = buffer + decoded;

  // F-BUG-202: bound address read by pdn_type-implied minimum
  if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4) {
    rc = nas_check_length(addr->pdn_address_information.len, 4);
    if (unlikely(rc < 0))
      return rc;
  } else if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV6) {
    rc = nas_check_length(addr->pdn_address_information.len, 8);
    if (unlikely(rc < 0))
      return rc;
  } else if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4V6) {
    rc = nas_check_length(addr->pdn_address_information.len, 12);
    if (unlikely(rc < 0))
      return rc;
  }

  decoded += addr->pdn_address_information.len;

  return decoded;
}


/* TS 24.301 §9.9.4.9: the PDN address information is the IPv4 address for
 * PDN type IPv4, the 8-octet IPv6 interface identifier for IPv6, and the
 * interface identifier followed by the IPv4 address for IPv4v6. Issue #573:
 * the IPv4 of an IPv4v6 address is read after the interface identifier. */
int nas_pdn_address_get_ipv4(const nas_pdn_address_t *addr, uint32_t *ipv4)
{
  uint32_t offset;

  if (addr == NULL || ipv4 == NULL || addr->pdn_address_information.data == NULL)
    return 0;
  if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4)
    offset = 0;
  else if (addr->pdn_type_value == NAS_PDN_VALUE_TYPE_IPV4V6)
    offset = NAS_PDN_IPV6_IID_LENGTH;
  else
    return 0;
  if (addr->pdn_address_information.len < offset + sizeof(*ipv4))
    return 0;
  memcpy(ipv4, addr->pdn_address_information.data + offset, sizeof(*ipv4));
  return 1;
}
