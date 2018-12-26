/*
 * proto_s1ap.h
 *
 *  Created on: Nov 2, 2018
 *          by: nhnghia
 */

#ifndef SRC_MMT_LTE_PROTO_S1AP_H_
#define SRC_MMT_LTE_PROTO_S1AP_H_

#define PROTO_S1AP 900
#define PROTO_S1AP_ALIAS          "s1ap"

#define S1AP_PROCEDURE_CODE_ALIAS "procedure_code"
#define S1AP_PDU_PRESENT_ALIAS    "pdu_present"

//ue
#define S1AP_UE_ID_ALIAS          "ue_id"
#define S1AP_IMSI_ALIAS           "imsi"
#define S1AP_M_TMSI_ALIAS         "m_tmsi"
#define S1AP_TEID_ALIAS           "gtp_teid"
#define S1AP_UE_IP_ALIAS          "ue_ipv4"
#define S1AP_UE_STATUS_ALIAS      "ue_status"

//mme
#define S1AP_MME_ID_ALIAS         "mme_id"
#define S1AP_MME_IP_ALIAS         "mme_ipv4"
#define S1AP_MME_NAME_ALIAS       "mme_name"
#define S1AP_MME_UE_ID_ALIAS      "mme_ue_id"
#define S1AP_MME_STATUS_ALIAS     "mme_status"

//enb
#define S1AP_ENB_ID_ALIAS         "enb_id"
#define S1AP_ENB_IP_ALIAS         "enb_ipv4"
#define S1AP_ENB_NAME_ALIAS       "enb_name"
#define S1AP_ENB_UE_ID_ALIAS      "enb_ue_id"
#define S1AP_ENB_STATUS_ALIAS     "enb_status"

#define S1AP_ENTITY_UE_ALIAS      "ue_entity"  //current entity concerning the packet
#define S1AP_ENTITY_ENODEB_ALIAS  "enb_entity"  //current entity concerning the packet
#define S1AP_ENTITY_MME_ALIAS     "mme_entity"  //current entity concerning the packet

//protocol attributes
enum{
	S1AP_ATT_PROCEDURE_CODE = 1,
	S1AP_ATT_PDU_PRESENT,

	S1AP_ATT_IMSI,
	S1AP_ATT_TEID,
	S1AP_ATT_M_TMSI,
	/**
	 * An unique ID of UE.
	 * This is generated by MMT by correlating different identifiers of UE,
	 * such as MME-UE-S1AP_ATT-ID, ENB-UE-S1AP_ATT-ID, ...
	 */
	S1AP_ATT_UE_ID,
	S1AP_ATT_UE_IP,
	S1AP_ATT_UE_STATUS,

	S1AP_ATT_ENB_ID,
	S1AP_ATT_ENB_NAME,
	S1AP_ATT_ENB_IP,
	S1AP_ATT_ENB_UE_ID,
	S1AP_ATT_ENB_STATUS,

	S1AP_ATT_MME_ID,
	S1AP_ATT_MME_NAME,
	S1AP_ATT_MME_IP,
	S1AP_ATT_MME_UE_ID,
	S1AP_ATT_MME_STATUS,

	S1AP_ATT_ENTITY_UE,  //full information of UE represented by an s1ap_entity_t object
	S1AP_ATT_ENTITY_ENODEB, //full information of eNodeB represented by an s1ap_entity_t object
	S1AP_ATT_ENTITY_MME //full information of MME represented by an s1ap_entity_t object
};

//status of an entity in EPC/LTE network
typedef enum{
	S1AP_ENTITY_STATUS_UNKNOWN = 0,
	S1AP_ENTITY_STATUS_ATTACHING,
	S1AP_ENTITY_STATUS_ATTACHED,
	S1AP_ENTITY_STATUS_DETACHING,
	S1AP_ENTITY_STATUS_DETACHED,
	//special status for UEs
	S1AP_ENTITY_STATUS_LOST_SIGNAL,
}s1ap_entity_status_t;


typedef enum{
	S1AP_ENTITY_TYPE_UNKNOWN = 0,
	S1AP_ENTITY_TYPE_UE,
	S1AP_ENTITY_TYPE_ENODEB,
	S1AP_ENTITY_TYPE_MME,
	S1AP_ENTITY_TYPE_GW
}s1ap_entity_type_t;

//Maximum 150 characters (See ETSI TS 136 413 V15.3.0/9.1.8.4 S1 SETUP REQUEST), the last one is for '\0'
#define S1AP_ENTITY_NAME_LENGTH (150 + 1)
/**
 * Definition of any entities in a LTE network
 */
typedef struct {
	//common data
	s1ap_entity_type_t type;

	uint32_t id; //id is given by MMT
	uint32_t ipv4;

	s1ap_entity_status_t status;

	uint32_t parent; //id of entity it attached to. Zero if nothing.

	//private data of each kind of element
	union{

		struct{
			uint32_t enb_ue_s1ap_id;
			uint32_t mme_ue_s1ap_id;
			uint32_t m_tmsi;
			char imsi[15];
		}ue;

		struct{
			char name[S1AP_ENTITY_NAME_LENGTH];
		}enb;

		struct{
			char name[S1AP_ENTITY_NAME_LENGTH];
		}mme;

		struct{

		}gw;
	}data;
}s1ap_entity_t;

enum S1AP_ProcedureCode {
	S1AP_ProcedureCode_id_HandoverPreparation	= 0,
	S1AP_ProcedureCode_id_HandoverResourceAllocation	= 1,
	S1AP_ProcedureCode_id_HandoverNotification	= 2,
	S1AP_ProcedureCode_id_PathSwitchRequest	= 3,
	S1AP_ProcedureCode_id_HandoverCancel	= 4,
	S1AP_ProcedureCode_id_E_RABSetup	= 5,
	S1AP_ProcedureCode_id_E_RABModify	= 6,
	S1AP_ProcedureCode_id_E_RABRelease	= 7,
	S1AP_ProcedureCode_id_E_RABReleaseIndication	= 8,
	S1AP_ProcedureCode_id_InitialContextSetup	= 9,
	S1AP_ProcedureCode_id_Paging	= 10,
	S1AP_ProcedureCode_id_downlinkNASTransport	= 11,
	S1AP_ProcedureCode_id_initialUEMessage	= 12,
	S1AP_ProcedureCode_id_uplinkNASTransport	= 13,
	S1AP_ProcedureCode_id_Reset	= 14,
	S1AP_ProcedureCode_id_ErrorIndication	= 15,
	S1AP_ProcedureCode_id_NASNonDeliveryIndication	= 16,
	S1AP_ProcedureCode_id_S1Setup	= 17,
	S1AP_ProcedureCode_id_UEContextReleaseRequest	= 18,
	S1AP_ProcedureCode_id_DownlinkS1cdma2000tunneling	= 19,
	S1AP_ProcedureCode_id_UplinkS1cdma2000tunneling	= 20,
	S1AP_ProcedureCode_id_UEContextModification	= 21,
	S1AP_ProcedureCode_id_UECapabilityInfoIndication	= 22,
	S1AP_ProcedureCode_id_UEContextRelease	= 23,
	S1AP_ProcedureCode_id_eNBStatusTransfer	= 24,
	S1AP_ProcedureCode_id_MMEStatusTransfer	= 25,
	S1AP_ProcedureCode_id_DeactivateTrace	= 26,
	S1AP_ProcedureCode_id_TraceStart	= 27,
	S1AP_ProcedureCode_id_TraceFailureIndication	= 28,
	S1AP_ProcedureCode_id_ENBConfigurationUpdate	= 29,
	S1AP_ProcedureCode_id_MMEConfigurationUpdate	= 30,
	S1AP_ProcedureCode_id_LocationReportingControl	= 31,
	S1AP_ProcedureCode_id_LocationReportingFailureIndication	= 32,
	S1AP_ProcedureCode_id_LocationReport	= 33,
	S1AP_ProcedureCode_id_OverloadStart	= 34,
	S1AP_ProcedureCode_id_OverloadStop	= 35,
	S1AP_ProcedureCode_id_WriteReplaceWarning	= 36,
	S1AP_ProcedureCode_id_eNBDirectInformationTransfer	= 37,
	S1AP_ProcedureCode_id_MMEDirectInformationTransfer	= 38,
	S1AP_ProcedureCode_id_PrivateMessage	= 39,
	S1AP_ProcedureCode_id_eNBConfigurationTransfer	= 40,
	S1AP_ProcedureCode_id_MMEConfigurationTransfer	= 41,
	S1AP_ProcedureCode_id_CellTrafficTrace	= 42,
	S1AP_ProcedureCode_id_Kill	= 43,
	S1AP_ProcedureCode_id_downlinkUEAssociatedLPPaTransport	= 44,
	S1AP_ProcedureCode_id_uplinkUEAssociatedLPPaTransport	= 45,
	S1AP_ProcedureCode_id_downlinkNonUEAssociatedLPPaTransport	= 46,
	S1AP_ProcedureCode_id_uplinkNonUEAssociatedLPPaTransport	= 47
};



enum S1ap_PDU_Present {
	S1AP_PDU_Present_nothing,	/* No components present */
	S1AP_PDU_Present_initiatingMessage,
	S1AP_PDU_Present_successfulOutcome,
	S1AP_PDU_Present_unsuccessfulOutcome,
};

#endif /* SRC_MMT_LTE_PROTO_S1AP_H_ */
