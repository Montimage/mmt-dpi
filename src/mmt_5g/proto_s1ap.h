/*
 * proto_s1ap.h
 *
 *  Created on: Nov 2, 2018
 *          by: nhnghia
 */

#ifndef SRC_MMT_5G_PROTO_S1AP_H_
#define SRC_MMT_5G_PROTO_S1AP_H_

#define PROTO_S1AP 900
#define PROTO_S1AP_ALIAS     "s1ap"

#define S1AP_PROCEDURE_CODE_ALIAS "procedure_code"
#define S1AP_IMSI_ALIAS     "imsi"
#define S1AP_TEID_ALIAS     "gtp_teid"
#define S1AP_UE_IP_ALIAS    "ue_ipv4"
#define S1AP_MME_IP_ALIAS   "mme_ipv4"
#define S1AP_MME_NAME_ALIAS "mme_name"
#define S1AP_ENB_IP_ALIAS   "enb_ipv4"
#define S1AP_ENB_NAME_ALIAS "enb_name"

//protocol attributes
enum{
	S1AP_PROCEDURE_CODE = 1,
	S1AP_IMSI,
	S1AP_TEID,
	S1AP_UE_IP,
	S1AP_ENB_NAME,
	S1AP_ENB_IP,
	S1AP_MME_NAME,
	S1AP_MME_IP
};



#endif /* SRC_MMT_5G_PROTO_S1AP_H_ */
