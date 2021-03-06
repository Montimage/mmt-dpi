#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef TRACKING_AREA_IDENTITY_H_
#define TRACKING_AREA_IDENTITY_H_

#define TRACKING_AREA_IDENTITY_MINIMUM_LENGTH 6
#define TRACKING_AREA_IDENTITY_MAXIMUM_LENGTH 6

typedef struct {
  uint8_t  mccdigit2:4;
  uint8_t  mccdigit1:4;
  uint8_t  mncdigit3:4;
  uint8_t  mccdigit3:4;
  uint8_t  mncdigit2:4;
  uint8_t  mncdigit1:4;
  uint16_t tac;
} nas_tracking_area_identity_t;

int nas_decode_tracking_area_identity(nas_tracking_area_identity_t *trackingareaidentity, uint8_t iei, uint8_t *buffer, uint32_t len);

#endif /* TRACKING AREA IDENTITY_H_ */

