#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#include "tracking_area_identity.h"
#include "../util/decoder.h"

int nas_decode_tracking_area_identity(nas_tracking_area_identity_t *trackingareaidentity, uint8_t iei, uint8_t *buffer, uint32_t len)
{
  int decoded = 0;

  /* F-BUG-084: honour len — validate pointer and length before the first
   * read. The TAI content is 5 bytes (3 MCC/MNC + 2 TAC). */
  if (iei > 0) {
    CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, 1, len);
    CHECK_IEI_DECODER(iei, *buffer);
    decoded++;
  }

  CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, decoded + 5, len);

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

