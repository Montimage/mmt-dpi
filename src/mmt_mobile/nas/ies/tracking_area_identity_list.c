#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracking_area_identity_list.h"
#include "../util/decoder.h"

int nas_decode_tracking_area_identity_list(nas_tracking_area_identity_list_t *lst, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
  int decoded = 0;
  uint8_t ielen = 0;

  /* F-BUG-083: validate pointer and length before the first read;
   * remainders are computed in a checked signed form. */
  if (iei > 0) {
    CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, 1, len);
    CHECK_IEI_DECODER(iei, *buffer);
    decoded++;
  }

  CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, decoded + 1, len);
  ielen = *(buffer + decoded);
  decoded++;
  CHECK_LENGTH_DECODER((int32_t)len - decoded, ielen);
  // F-BUG-204: validate ielen>=6 (+IEI) for TAI lists (legal 0..5)
  CHECK_LENGTH_DECODER(ielen, 6);
  CHECK_LENGTH_DECODER((int32_t)len - decoded, 6);
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
