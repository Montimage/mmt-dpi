#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracking_area_identity.h"

#ifndef TRACKING_AREA_IDENTITY_LIST_H_
#define TRACKING_AREA_IDENTITY_LIST_H_

#define TRACKING_AREA_IDENTITY_LIST_MINIMUM_LENGTH 8
#define TRACKING_AREA_IDENTITY_LIST_MAXIMUM_LENGTH 98

/* Type of list, TS 24.301 §9.9.3.33 (issue #335: all three are decoded) */
#define TRACKING_AREA_IDENTITY_LIST_ONE_PLMN_NON_CONSECUTIVE_TACS 0b00
#define TRACKING_AREA_IDENTITY_LIST_ONE_PLMN_CONSECUTIVE_TACS     0b01
#define TRACKING_AREA_IDENTITY_LIST_MANY_PLMNS                    0b10

/* A TAI list holds at most 16 TAIs across all its partial lists */
#define TRACKING_AREA_IDENTITY_LIST_MAX_TAIS 16

typedef struct TrackingAreaIdentityList_tag {
  /* Header and first TAI of the first partial list. numberofelements is
   * the raw 5-bit field: the partial list holds numberofelements + 1 TAIs
   * (raw values above 15 are read as 16). */
  uint8_t  typeoflist:2;
  uint8_t  numberofelements:5;
  uint8_t  mccdigit2:4;
  uint8_t  mccdigit1:4;
  uint8_t  mncdigit3:4;
  uint8_t  mccdigit3:4;
  uint8_t  mncdigit2:4;
  uint8_t  mncdigit1:4;
  uint16_t tac;
  /* Every partial list, flattened (consecutive-TAC lists are expanded) */
  uint8_t  partial_lists;  /* partial lists decoded */
  uint8_t  tai_count;      /* TAIs stored in tai[] */
  uint8_t  malformed;      /* 1: a partial list was truncated, of the reserved
                            * type 11, or the list held more than 16 TAIs;
                            * decoding stopped there, tai[] keeps the prefix.
                            * A number of elements above 01111 is read as 16
                            * (TS 24.301 §9.9.3.33). All fields are zeroed
                            * before decoding. */
  nas_tracking_area_identity_t tai[TRACKING_AREA_IDENTITY_LIST_MAX_TAIS];
} nas_tracking_area_identity_list_t;

int nas_decode_tracking_area_identity_list(nas_tracking_area_identity_list_t *trackingareaidentitylist, uint8_t iei, const  uint8_t *buffer, uint32_t len);

#endif /* TRACKING AREA IDENTITY LIST_H_ */
