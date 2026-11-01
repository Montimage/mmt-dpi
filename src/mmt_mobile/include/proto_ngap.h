/*
 * proto_ngap.h
 *
 *  Created on: Dec 11, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_INCLUDE_PROTO_NGAP_H_
#define SRC_MMT_MOBILE_INCLUDE_PROTO_NGAP_H_

#include <stdint.h>
#include "mmt_exports.h"

enum {
	NGAP_ATT_PROCEDURE_CODE = 1,
	NGAP_ATT_PDU_PRESENT,
	NGAP_ATT_AMF_UE_ID,
	NGAP_ATT_RAN_UE_ID,
	/* Issue #574, appended: the Rel-16 IE SRVCCOperationPossible (id 177)
	 * of a DownlinkNASTransport or PathSwitchRequestAcknowledge --
	 * 0 possible, 1 notPossible; not extracted when the IE is absent */
	NGAP_ATT_SRVCC_OPERATION_POSSIBLE,
};

#define NGAP_PROCEDURE_CODE_ALIAS "procedure_code"
#define NGAP_PDU_PRESENT_ALIAS    "pdu_present"
#define NGAP_AMF_UE_ID_ALIAS      "amf_ue_id"
#define NGAP_RAN_UE_ID_ALIAS      "ran_ue_id"
#define NGAP_SRVCC_OPERATION_POSSIBLE_ALIAS "srvcc_operation_possible"

/* update_ngap_data() re-encodes the NGAP message of ipacket into data
 * (data_size bytes) with attribute att_id set to new_val, and returns the
 * number of bytes written at the NGAP offset (0 when nothing was written).
 * libmmt_tmobile is built -fvisibility=hidden (issue #534); this MMTAPI
 * declaration keeps it exported for 5Greplay, which calls it. */
struct ipacket_struct;
MMTAPI uint32_t update_ngap_data( unsigned char *data, uint32_t data_size, const struct ipacket_struct *ipacket, uint32_t proto_id, uint32_t att_id, uint64_t new_val );

#endif /* SRC_MMT_MOBILE_INCLUDE_PROTO_NGAP_H_ */
