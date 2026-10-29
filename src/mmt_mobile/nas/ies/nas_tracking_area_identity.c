#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#include "tracking_area_identity.h"
#include "../util/decoder.h"

int nas_decode_tracking_area_identity(nas_tracking_area_identity_t *trackingareaidentity, uint8_t iei, uint8_t *buffer, uint32_t len)
{
  int decoded = 0;
  int rc;

  /* F-BUG-084: honour len — validate pointer and length before the first
   * read. The TAI content is 5 bytes (3 MCC/MNC + 2 TAC). */
  if (iei > 0) {
    rc = nas_check_pdu(buffer, 1, len);
    if (unlikely(rc < 0)) {
      NAS_LOG_PDU_CHECK(rc, 1, len);
      return rc;
    }
    NAS_LOG_IEI_MISMATCH(iei, *buffer);
    decoded++;
  }

  rc = nas_check_pdu(buffer, decoded + 5, len);
  if (unlikely(rc < 0)) {
    NAS_LOG_PDU_CHECK(rc, decoded + 5, len);
    return rc;
  }

  trackingareaidentity->mccdigit2 = (*(buffer + decoded) >> 4) & 0xf;
  trackingareaidentity->mccdigit1 = *(buffer + decoded) & 0xf;
  decoded++;
  trackingareaidentity->mncdigit3 = (*(buffer + decoded) >> 4) & 0xf;
  trackingareaidentity->mccdigit3 = *(buffer + decoded) & 0xf;
  decoded++;
  trackingareaidentity->mncdigit2 = (*(buffer + decoded) >> 4) & 0xf;
  trackingareaidentity->mncdigit1 = *(buffer + decoded) & 0xf;
  decoded++;
  //IES_DECODE_U16(trackingareaidentity->tac, *(buffer + decoded));
  IES_DECODE_U16(buffer, decoded, trackingareaidentity->tac);
#if defined (NAS_DEBUG)
  dump_tracking_area_identity_xml(trackingareaidentity, iei);
#endif
  return decoded;
}

