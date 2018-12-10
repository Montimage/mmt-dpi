#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracking_area_identity_list.h"
#include "../util/decoder.h"

int decode_tracking_area_identity_list(tracking_area_identity_list_t *trackingareaidentitylist, uint8_t iei, const uint8_t *buffer, uint32_t len)
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
  trackingareaidentitylist->typeoflist = (*(buffer + decoded) >> 5) & 0x3;
  trackingareaidentitylist->numberofelements = *(buffer + decoded) & 0x1f;
  decoded++;
  trackingareaidentitylist->mccdigit2 = (*(buffer + decoded) >> 4) & 0xf;
  trackingareaidentitylist->mccdigit1 = *(buffer + decoded) & 0xf;
  decoded++;
  trackingareaidentitylist->mncdigit3 = (*(buffer + decoded) >> 4) & 0xf;
  trackingareaidentitylist->mccdigit3 = *(buffer + decoded) & 0xf;
  decoded++;
  trackingareaidentitylist->mncdigit2 = (*(buffer + decoded) >> 4) & 0xf;
  trackingareaidentitylist->mncdigit1 = *(buffer + decoded) & 0xf;
  decoded++;

  //IES_DECODE_U16(trackingareaidentitylist->tac, *(buffer + decoded));
  IES_DECODE_U16(buffer, decoded, trackingareaidentitylist->tac);
#if defined (NAS_DEBUG)
  dump_tracking_area_identity_list_xml(trackingareaidentitylist, iei);
#endif
  return decoded;
}
