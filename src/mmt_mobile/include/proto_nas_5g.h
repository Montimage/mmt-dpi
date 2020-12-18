/*
 * proto_nas_5g.h
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_INCLUDE_PROTO_NAS_5G_H_
#define SRC_MMT_MOBILE_INCLUDE_PROTO_NAS_5G_H_

enum{
	NAS5G_ATT_PROTOCOL_DISCRIMINATOR = 1,
	NAS5G_ATT_MESSAGE_TYPE,
	NAS5G_ATT_SECURITY_TYPE,
	NAS5G_ATT_PROCEDURE_TRANSACTION_ID
};

#define NAS5G_PROTOCOL_DISCRIMINATOR_ALIAS   "protocol_discriminator"
#define NAS5G_MESSAGE_TYPE_ALIAS             "message_type"
#define NAS5G_SECURITY_TYPE_ALIAS            "security_type"
#define NAS5G_PROCEDURE_TRANSACTION_ID_ALIAS "procedure_transaction_id"

#endif /* SRC_MMT_MOBILE_INCLUDE_PROTO_NAS_5G_H_ */
