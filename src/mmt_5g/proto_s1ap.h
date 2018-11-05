/*
 * proto_s1ap.h
 *
 *  Created on: Nov 2, 2018
 *      Author: nhnghia
 */

#ifndef SRC_MMT_5G_PROTO_S1AP_H_
#define SRC_MMT_5G_PROTO_S1AP_H_

#define PROTO_S1AP  900
#define PROTO_S1AP_ALIAS "s1ap"

#define S1AP_IMSI_ALIAS "imsi"
#define S1AP_TEID_ALIAS "gtp_teid"
#define S1AP_IP_ALIAS   "pdn_ipv4"

//protocol attributes
enum{
	S1AP_IMSI = 1,
	S1AP_TEID,
	S1AP_IP
};



#endif /* SRC_MMT_5G_PROTO_S1AP_H_ */
