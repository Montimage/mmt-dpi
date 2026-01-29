/* Generated with MMT Plugin Generator */

#ifndef DICOM_H
#define DICOM_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "../../mmt_core/public_include/plugin_defs.h"
#include "../../mmt_core/public_include/mmt_core.h"

#define PROTO_DICOM 701
#define PROTO_DICOM_ALIAS "dicom"

#define PROTO_DICOM_HDRLEN 6
#define DICOM_PAYLOAD_MIN_LEN 4

// DICOM Command Field Values
#define DICOM_C_STORE_RQ          0x0001
#define DICOM_C_STORE_RSP         0x8001
#define DICOM_C_GET_RQ            0x0010
#define DICOM_C_GET_RSP           0x8010
#define DICOM_C_FIND_RQ           0x0020
#define DICOM_C_FIND_RSP          0x8020
#define DICOM_C_MOVE_RQ           0x0021
#define DICOM_C_MOVE_RSP          0x8021
#define DICOM_C_ECHO_RQ           0x0030
#define DICOM_C_ECHO_RSP          0x8030
#define DICOM_N_EVENT_REPORT_RQ   0x0100
#define DICOM_N_EVENT_REPORT_RSP  0x8100
#define DICOM_N_GET_RQ            0x0110
#define DICOM_N_GET_RSP           0x8110
#define DICOM_N_SET_RQ            0x0120
#define DICOM_N_SET_RSP           0x8120
#define DICOM_N_ACTION_RQ         0x0130
#define DICOM_N_ACTION_RSP        0x8130
#define DICOM_N_CREATE_RQ         0x0140
#define DICOM_N_CREATE_RSP        0x8140
#define DICOM_N_DELETE_RQ         0x0150
#define DICOM_N_DELETE_RSP        0x8150
#define DICOM_C_CANCEL_RQ         0x0FFF

// DICOM PDU Types
enum dicom_pdu_type {
    A_ASSOCIATE_RQ = 1,
    A_ASSOCIATE_AC = 2,
    A_ASSOCIATE_RJ = 3,
    P_DATA_TF = 4,
    A_RELEASE_RQ = 5,
    A_RELEASE_RP = 6,
    A_ABORT = 7
};

enum dicom_attributes {
    DICOM_PDU_TYPE = 1,
    DICOM_PDU_LEN,
    DICOM_PROTO_VERSION,
    DICOM_CALLED_AE_TITLE,
    DICOM_CALLING_AE_TITLE,
    DICOM_APPLICATION_CONTEXT,
    DICOM_PRESENTATION_CONTEXT,
    DICOM_MAX_PDU_LENGTH,
    DICOM_IMPLEMENTATION_CLASS_UID,
    // P-DATA-TF attributes
    DICOM_PDV_LENGTH,
    DICOM_PDV_CONTEXT,
    DICOM_PDV_FLAGS,
    DICOM_COMMAND_GROUP_LENGTH,
    DICOM_COMMAND_FIELD,
    DICOM_PATIENT_NAME,
    // New attributes
    DICOM_STATUS,
    DICOM_AFFECTED_SOP_CLASS_UID,
    DICOM_MESSAGE_ID,
    DICOM_ABSTRACT_SYNTAX,
    DICOM_TRANSFER_SYNTAX,
    DICOM_DATA_SET_TYPE,
    DICOM_ATTRIBUTES_NB = DICOM_DATA_SET_TYPE,
};

#define DICOM_PDU_TYPE_ALIAS "pdu_type"
#define DICOM_PDU_LEN_ALIAS "pdu_len"
#define DICOM_PROTO_VERSION_ALIAS "proto_version"
#define DICOM_CALLED_AE_TITLE_ALIAS "called_ae_title"
#define DICOM_CALLING_AE_TITLE_ALIAS "calling_ae_title"
#define DICOM_APPLICATION_CONTEXT_ALIAS "application_context"
#define DICOM_PRESENTATION_CONTEXT_ALIAS "presentation_context"
#define DICOM_MAX_PDU_LENGTH_ALIAS "max_pdu_length"
#define DICOM_IMPLEMENTATION_CLASS_UID_ALIAS "implementation_class_uid"
// P-DATA-TF aliases
#define DICOM_PDV_LENGTH_ALIAS "pdv_length"
#define DICOM_PDV_CONTEXT_ALIAS "pdv_context"
#define DICOM_PDV_FLAGS_ALIAS "pdv_flags"
#define DICOM_COMMAND_GROUP_LENGTH_ALIAS "command_group_length"
#define DICOM_COMMAND_FIELD_ALIAS "command_field"
#define DICOM_PATIENT_NAME_ALIAS "patient_name"
// New attribute aliases
#define DICOM_STATUS_ALIAS "status"
#define DICOM_AFFECTED_SOP_CLASS_UID_ALIAS "affected_sop_class_uid"
#define DICOM_MESSAGE_ID_ALIAS "message_id"
#define DICOM_ABSTRACT_SYNTAX_ALIAS "abstract_syntax"
#define DICOM_TRANSFER_SYNTAX_ALIAS "transfer_syntax"
#define DICOM_DATA_SET_TYPE_ALIAS "data_set_type"

struct __attribute__((packed)) dicomhdr {
    uint8_t pdu_type ;
    uint8_t reserved ;
    uint32_t pdu_len ;
};

int init_dicom_proto_struct();
classified_proto_t dicom_stack_classification(ipacket_t * ipacket);
int mmt_check_dicom_hdr(struct dicomhdr* header);
int mmt_check_dicom_payload(struct dicomhdr* header, unsigned int packet_len);
int mmt_check_dicom(struct dicomhdr * header, int offset, int packet_len);
int mmt_check_dicom_tcp(ipacket_t * ipacket, unsigned index);
static int _extraction_att(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data);

#ifndef CORE
	int init_proto();
	int cleanup_proto();
#endif //CORE

#ifdef	__cplusplus
}
#endif
#endif	/* DICOM_H */