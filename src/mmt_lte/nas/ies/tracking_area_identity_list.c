#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracking_area_identity_list.h"
#include "../util/decoder.h"

int nas_decode_tracking_area_identity_list(nas_tracking_area_identity_list_t *lst, uint8_t iei, const uint8_t *buffer, uint32_t len)
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
  lst->typeoflist = (*(buffer + decoded) >> 5) & 0x3;
  lst->numberofelements = *(buffer + decoded) & 0x1f;
  decoded++;
  lst->mccdigit2 = (*(buffer + decoded) >> 4) & 0xf;
  lst->mccdigit1 = *(buffer + decoded) & 0xf;
  decoded++;
  lst->mncdigit3 = (*(buffer + decoded) >> 4) & 0xf;
  lst->mccdigit3 = *(buffer + decoded) & 0xf;
  decoded++;
  lst->mncdigit2 = (*(buffer + decoded) >> 4) & 0xf;
  lst->mncdigit1 = *(buffer + decoded) & 0xf;
  decoded++;

  //IES_DECODE_U16(trackingareaidentitylist->tac, *(buffer + decoded));
  IES_DECODE_U16(buffer, decoded, lst->tac);
#if defined (NAS_DEBUG)
  dump_tracking_area_identity_list_xml(lst, iei);
#endif
  return decoded;
}
