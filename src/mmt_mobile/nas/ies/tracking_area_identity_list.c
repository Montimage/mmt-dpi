#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "tracking_area_identity_list.h"
#include "../util/decoder.h"

/* PLMN identity: 3 octets of BCD digits (TS 24.301 §9.9.3.32) */
static void _decode_plmn(nas_tracking_area_identity_t *tai, const uint8_t *p)
{
  tai->mccdigit2 = (p[0] >> 4) & 0xf;
  tai->mccdigit1 = p[0] & 0xf;
  tai->mncdigit3 = (p[1] >> 4) & 0xf;
  tai->mccdigit3 = p[1] & 0xf;
  tai->mncdigit2 = (p[2] >> 4) & 0xf;
  tai->mncdigit1 = p[2] & 0xf;
}

static uint16_t _decode_tac(const uint8_t *p)
{
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Append one TAI; returns 0 once the 16-TAI limit is reached */
static int _add_tai(nas_tracking_area_identity_list_t *lst,
    const nas_tracking_area_identity_t *plmn, uint16_t tac)
{
  if (lst->tai_count >= TRACKING_AREA_IDENTITY_LIST_MAX_TAIS)
    return 0;
  lst->tai[lst->tai_count] = *plmn;
  lst->tai[lst->tai_count].tac = tac;
  lst->tai_count++;
  return 1;
}

/*
 * Decode the partial lists of a TAI list value (TS 24.301 §9.9.3.33).
 * Every read is bounded by the IE length: a partial list that overruns
 * it, the reserved type 11, or more than 16 TAIs stop decoding and set
 * lst->malformed; the caller still consumes the whole IE.
 */
static void _decode_partial_lists(nas_tracking_area_identity_list_t *lst,
    const uint8_t *p, uint32_t ielen)
{
  uint32_t off = 0;

  while (off < ielen) {
    uint8_t  type  = (p[off] >> 5) & 0x3;
    uint32_t count = (uint32_t)(p[off] & 0x1f) + 1;
    uint32_t need;

    /* number of elements above 01111 is unused and interpreted as 16 */
    if (count > TRACKING_AREA_IDENTITY_LIST_MAX_TAIS)
      count = TRACKING_AREA_IDENTITY_LIST_MAX_TAIS;
    nas_tracking_area_identity_t plmn = {0};

    switch (type) {
    case TRACKING_AREA_IDENTITY_LIST_ONE_PLMN_NON_CONSECUTIVE_TACS:
      need = 1 + 3 + 2 * count;
      break;
    case TRACKING_AREA_IDENTITY_LIST_ONE_PLMN_CONSECUTIVE_TACS:
      need = 1 + 3 + 2;
      break;
    case TRACKING_AREA_IDENTITY_LIST_MANY_PLMNS:
      need = 1 + 5 * count;
      break;
    default:
      lst->malformed = 1;
      return;
    }
    if (need > ielen - off) {
      lst->malformed = 1;
      return;
    }

    if (lst->partial_lists == 0) {
      lst->typeoflist       = type;
      lst->numberofelements = p[off] & 0x1f;
    }

    for (uint32_t i = 0; i < count; i++) {
      uint16_t tac;
      switch (type) {
      case TRACKING_AREA_IDENTITY_LIST_ONE_PLMN_NON_CONSECUTIVE_TACS:
        _decode_plmn(&plmn, p + off + 1);
        tac = _decode_tac(p + off + 4 + 2 * i);
        break;
      case TRACKING_AREA_IDENTITY_LIST_ONE_PLMN_CONSECUTIVE_TACS:
        _decode_plmn(&plmn, p + off + 1);
        tac = (uint16_t)(_decode_tac(p + off + 4) + i);
        break;
      default: /* MANY_PLMNS */
        _decode_plmn(&plmn, p + off + 1 + 5 * i);
        tac = _decode_tac(p + off + 4 + 5 * i);
        break;
      }
      if (!_add_tai(lst, &plmn, tac)) {
        lst->malformed = 1;
        return;
      }
    }
    lst->partial_lists++;
    off += need;
  }
}

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

  /* no stale header or first TAI survives a malformed first partial list */
  memset(lst, 0, sizeof(*lst));
  _decode_partial_lists(lst, buffer + decoded, ielen);

  /* The first TAI stays mirrored in the flat fields for existing callers */
  if (lst->tai_count > 0) {
    lst->mccdigit2 = lst->tai[0].mccdigit2;
    lst->mccdigit1 = lst->tai[0].mccdigit1;
    lst->mncdigit3 = lst->tai[0].mncdigit3;
    lst->mccdigit3 = lst->tai[0].mccdigit3;
    lst->mncdigit2 = lst->tai[0].mncdigit2;
    lst->mncdigit1 = lst->tai[0].mncdigit1;
    lst->tac       = lst->tai[0].tac;
  }

  /* issue #335: consume the whole IE, not only the first partial list,
   * so the next IE of the message is read from its real offset */
  decoded += ielen;
#if defined (NAS_DEBUG)
  dump_tracking_area_identity_list_xml(lst, iei);
#endif
  return decoded;
}
