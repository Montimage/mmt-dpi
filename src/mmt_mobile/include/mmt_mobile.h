/*
 * mmt_lte.h
 *
 *  Created on: Dec 18, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_MOBILE_INCLUDE_MMT_MOBILE_H_
#define SRC_MMT_MOBILE_INCLUDE_MMT_MOBILE_H_

#include <stdlib.h>
#include <stdint.h>

#include "proto_s1ap.h"
#include "proto_diameter.h"
#include "proto_gtpv2.h"
#include "proto_ngap.h"
#include "proto_nas_5g.h"

#define PROTO_S1AP 900
#define PROTO_S1AP_ALIAS "s1ap"

#define PROTO_DIAMETER 901
#define PROTO_DIAMETER_ALIAS "diameter"

#define PROTO_GTPV2 902
#define PROTO_GTPV2_ALIAS "gtpv2"

#define PROTO_NGAP 903
#define PROTO_NGAP_ALIAS "ngap"

#define PROTO_NAS5G 904
#define PROTO_NAS5G_ALIAS "nas_5g"
#endif /* SRC_MMT_MOBILE_INCLUDE_MMT_MOBILE_H_ */
