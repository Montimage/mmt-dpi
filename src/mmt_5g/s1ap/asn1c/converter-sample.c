/*
 * Generic converter template for a selected ASN.1 type.
 * Copyright (c) 2005, 2006, 2007 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * 
 * To compile with your own ASN.1 type, please redefine the PDU as shown:
 * 
 * cc -DPDU=MyCustomType -o myDecoder.o -c converter-sample.c
 */
#ifdef	HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>	/* for atoi(3) */
#include <unistd.h>	/* for getopt(3) */
#include <string.h>	/* for strerror(3) */
#include <sysexits.h>	/* for EX_* exit codes */
#include <errno.h>	/* for errno */

#include <asn_application.h>
#include <asn_internal.h>	/* for _ASN_DEFAULT_STACK_MAX */


#include "S1ap-Criticality.h"
#include "S1ap-Presence.h"
#include "S1ap-PrivateIE-ID.h"
#include "S1ap-ProcedureCode.h"
#include "S1ap-ProtocolExtensionID.h"
#include "S1ap-ProtocolIE-ID.h"
#include "S1ap-TriggeringMessage.h"
#include "S1ap-AllocationAndRetentionPriority.h"
#include "S1ap-Bearers-SubjectToStatusTransfer-List.h"
#include "S1ap-Bearers-SubjectToStatusTransfer-Item.h"
#include "S1ap-BitRate.h"
#include "S1ap-BPLMNs.h"
#include "S1ap-BroadcastCompletedAreaList.h"
#include "S1ap-Cause.h"
#include "S1ap-CauseMisc.h"
#include "S1ap-CauseProtocol.h"
#include "S1ap-CauseRadioNetwork.h"
#include "S1ap-CauseTransport.h"
#include "S1ap-CauseNas.h"
#include "S1ap-CellIdentity.h"
#include "S1ap-CellID-Broadcast.h"
#include "S1ap-CellID-Broadcast-Item.h"
#include "S1ap-Cdma2000PDU.h"
#include "S1ap-Cdma2000RATType.h"
#include "S1ap-Cdma2000SectorID.h"
#include "S1ap-Cdma2000HOStatus.h"
#include "S1ap-Cdma2000HORequiredIndication.h"
#include "S1ap-Cdma2000OneXSRVCCInfo.h"
#include "S1ap-Cdma2000OneXMEID.h"
#include "S1ap-Cdma2000OneXMSI.h"
#include "S1ap-Cdma2000OneXPilot.h"
#include "S1ap-Cdma2000OneXRAND.h"
#include "S1ap-Cell-Size.h"
#include "S1ap-CellType.h"
#include "S1ap-CGI.h"
#include "S1ap-CI.h"
#include "S1ap-CNDomain.h"
#include "S1ap-CSFallbackIndicator.h"
#include "S1ap-CSG-Id.h"
#include "S1ap-CSG-IdList.h"
#include "S1ap-CSG-IdList-Item.h"
#include "S1ap-COUNTvalue.h"
#include "S1ap-DataCodingScheme.h"
#include "S1ap-DL-Forwarding.h"
#include "S1ap-Direct-Forwarding-Path-Availability.h"
#include "S1ap-ECGIList.h"
#include "S1ap-EmergencyAreaIDList.h"
#include "S1ap-EmergencyAreaID.h"
#include "S1ap-EmergencyAreaID-Broadcast.h"
#include "S1ap-EmergencyAreaID-Broadcast-Item.h"
#include "S1ap-CompletedCellinEAI.h"
#include "S1ap-CompletedCellinEAI-Item.h"
#include "S1ap-ENB-ID.h"
#include "S1ap-GERAN-Cell-ID.h"
#include "S1ap-Global-ENB-ID.h"
#include "S1ap-ENB-StatusTransfer-TransparentContainer.h"
#include "S1ap-ENBname.h"
#include "S1ap-ENBX2TLAs.h"
#include "S1ap-EncryptionAlgorithms.h"
#include "S1ap-EPLMNs.h"
#include "S1ap-EventType.h"
#include "S1ap-E-RAB-ID.h"
#include "S1ap-E-RABInformationList.h"
#include "S1ap-E-RABInformationListItem.h"
#include "S1ap-E-RABList.h"
#include "S1ap-E-RABItem.h"
#include "S1ap-E-RABLevelQoSParameters.h"
#include "S1ap-EUTRAN-CGI.h"
#include "S1ap-ExtendedRNC-ID.h"
#include "S1ap-ForbiddenInterRATs.h"
#include "S1ap-ForbiddenTAs.h"
#include "S1ap-ForbiddenTAs-Item.h"
#include "S1ap-ForbiddenTACs.h"
#include "S1ap-ForbiddenLAs.h"
#include "S1ap-ForbiddenLAs-Item.h"
#include "S1ap-ForbiddenLACs.h"
#include "S1ap-GBR-QosInformation.h"
#include "S1ap-GTP-TEID.h"
#include "S1ap-GUMMEI.h"
#include "S1ap-HandoverRestrictionList.h"
#include "S1ap-HandoverType.h"
#include "S1ap-HFN.h"
#include "S1ap-IMSI.h"
#include "S1ap-IntegrityProtectionAlgorithms.h"
#include "S1ap-InterfacesToTrace.h"
#include "S1ap-LAC.h"
#include "S1ap-LAI.h"
#include "S1ap-LastVisitedCell-Item.h"
#include "S1ap-LastVisitedEUTRANCellInformation.h"
#include "S1ap-LastVisitedUTRANCellInformation.h"
#include "S1ap-LastVisitedGERANCellInformation.h"
#include "S1ap-L3-Information.h"
#include "S1ap-MessageIdentifier.h"
#include "S1ap-MMEname.h"
#include "S1ap-MME-Group-ID.h"
#include "S1ap-MME-Code.h"
#include "S1ap-M-TMSI.h"
#include "S1ap-MSClassmark2.h"
#include "S1ap-MSClassmark3.h"
#include "S1ap-NAS-PDU.h"
#include "S1ap-NASSecurityParametersfromE-UTRAN.h"
#include "S1ap-NASSecurityParameterstoE-UTRAN.h"
#include "S1ap-NumberofBroadcastRequest.h"
#include "S1ap-NumberOfBroadcasts.h"
#include "S1ap-OldBSS-ToNewBSS-Information.h"
#include "S1ap-OverloadAction.h"
#include "S1ap-OverloadResponse.h"
#include "S1ap-PagingDRX.h"
#include "S1ap-PDCP-SN.h"
#include "S1ap-PLMNidentity.h"
#include "S1ap-Pre-emptionCapability.h"
#include "S1ap-Pre-emptionVulnerability.h"
#include "S1ap-PriorityLevel.h"
#include "S1ap-QCI.h"
#include "S1ap-ReceiveStatusofULPDCPSDUs.h"
#include "S1ap-RelativeMMECapacity.h"
#include "S1ap-RAC.h"
#include "S1ap-RequestType.h"
#include "S1ap-RIMTransfer.h"
#include "S1ap-RIMInformation.h"
#include "S1ap-RIMRoutingAddress.h"
#include "S1ap-ReportArea.h"
#include "S1ap-RepetitionPeriod.h"
#include "S1ap-RNC-ID.h"
#include "S1ap-RRC-Container.h"
#include "S1ap-RRC-Establishment-Cause.h"
#include "S1ap-SecurityKey.h"
#include "S1ap-SecurityContext.h"
#include "S1ap-SerialNumber.h"
#include "S1ap-SONInformation.h"
#include "S1ap-SONInformationRequest.h"
#include "S1ap-SONInformationReply.h"
#include "S1ap-SONConfigurationTransfer.h"
#include "S1ap-Source-ToTarget-TransparentContainer.h"
#include "S1ap-SourceBSS-ToTargetBSS-TransparentContainer.h"
#include "S1ap-SourceeNB-ID.h"
#include "S1ap-SRVCCOperationPossible.h"
#include "S1ap-SRVCCHOIndication.h"
#include "S1ap-SourceeNB-ToTargeteNB-TransparentContainer.h"
#include "S1ap-SourceRNC-ToTargetRNC-TransparentContainer.h"
#include "S1ap-ServedGUMMEIs.h"
#include "S1ap-ServedGUMMEIsItem.h"
#include "S1ap-ServedGroupIDs.h"
#include "S1ap-ServedMMECs.h"
#include "S1ap-ServedPLMNs.h"
#include "S1ap-SubscriberProfileIDforRFP.h"
#include "S1ap-SupportedTAs.h"
#include "S1ap-SupportedTAs-Item.h"
#include "S1ap-S-TMSI.h"
#include "S1ap-TAC.h"
#include "S1ap-TAIItem.h"
#include "S1ap-TAIList.h"
#include "S1ap-TAIListforWarning.h"
#include "S1ap-TAI.h"
#include "S1ap-TAI-Broadcast.h"
#include "S1ap-TAI-Broadcast-Item.h"
#include "S1ap-CompletedCellinTAI.h"
#include "S1ap-CompletedCellinTAI-Item.h"
#include "S1ap-TargetID.h"
#include "S1ap-TargeteNB-ID.h"
#include "S1ap-TargetRNC-ID.h"
#include "S1ap-TargeteNB-ToSourceeNB-TransparentContainer.h"
#include "S1ap-Target-ToSource-TransparentContainer.h"
#include "S1ap-TargetRNC-ToSourceRNC-TransparentContainer.h"
#include "S1ap-TargetBSS-ToSourceBSS-TransparentContainer.h"
#include "S1ap-TimeToWait.h"
#include "S1ap-Time-UE-StayedInCell.h"
#include "S1ap-TransportLayerAddress.h"
#include "S1ap-TraceActivation.h"
#include "S1ap-TraceDepth.h"
#include "S1ap-E-UTRAN-Trace-ID.h"
#include "S1ap-TypeOfError.h"
#include "S1ap-UEAggregateMaximumBitrate.h"
#include "S1ap-UE-associatedLogicalS1-ConnectionItem.h"
#include "S1ap-UEIdentityIndexValue.h"
#include "S1ap-UE-HistoryInformation.h"
#include "S1ap-UEPagingID.h"
#include "S1ap-UERadioCapability.h"
#include "S1ap-UESecurityCapabilities.h"
#include "S1ap-WarningAreaList.h"
#include "S1ap-WarningType.h"
#include "S1ap-WarningSecurityInfo.h"
#include "S1ap-WarningMessageContents.h"
#include "S1ap-X2TNLConfigurationInfo.h"
#include "S1ap-CriticalityDiagnostics.h"
#include "S1ap-CriticalityDiagnostics-IE-List.h"
#include "S1ap-CriticalityDiagnostics-IE-Item.h"
#include "S1ap-ResetType.h"
#include "S1ap-Inter-SystemInformationTransferType.h"
#include "S1ap-UE-S1AP-IDs.h"
#include "S1ap-UE-S1AP-ID-pair.h"
#include "S1ap-MME-UE-S1AP-ID.h"
#include "S1ap-ENB-UE-S1AP-ID.h"
#include "S1ap-TBCD-STRING.h"
#include "S1ap-InitiatingMessage.h"
#include "S1ap-SuccessfulOutcome.h"
#include "S1ap-UnsuccessfulOutcome.h"
#include "S1ap-HandoverRequired.h"
#include "S1ap-HandoverCommand.h"
#include "S1ap-HandoverNotify.h"
#include "S1ap-HandoverPreparationFailure.h"
#include "S1ap-HandoverRequest.h"
#include "S1ap-HandoverRequestAcknowledge.h"
#include "S1ap-HandoverFailure.h"
#include "S1ap-PathSwitchRequest.h"
#include "S1ap-PathSwitchRequestAcknowledge.h"
#include "S1ap-PathSwitchRequestFailure.h"
#include "S1ap-E-RABSetupRequest.h"
#include "S1ap-E-RABSetupResponse.h"
#include "S1ap-E-RABModifyRequest.h"
#include "S1ap-E-RABModifyResponse.h"
#include "S1ap-E-RABReleaseIndication.h"
#include "S1ap-E-RABReleaseCommand.h"
#include "S1ap-E-RABReleaseResponse.h"
#include "S1ap-InitialContextSetupRequest.h"
#include "S1ap-InitialContextSetupResponse.h"
#include "S1ap-InitialContextSetupFailure.h"
#include "S1ap-UEContextReleaseRequest.h"
#include "S1ap-Paging.h"
#include "S1ap-DownlinkNASTransport.h"
#include "S1ap-InitialUEMessage.h"
#include "S1ap-UplinkNASTransport.h"
#include "S1ap-NASNonDeliveryIndication.h"
#include "S1ap-HandoverCancel.h"
#include "S1ap-HandoverCancelAcknowledge.h"
#include "S1ap-Reset.h"
#include "S1ap-ResetAcknowledge.h"
#include "S1ap-S1SetupResponse.h"
#include "S1ap-S1SetupRequest.h"
#include "S1ap-S1SetupFailure.h"
#include "S1ap-ErrorIndication.h"
#include "S1ap-ENBConfigurationUpdate.h"
#include "S1ap-ENBConfigurationUpdateAcknowledge.h"
#include "S1ap-ENBConfigurationUpdateFailure.h"
#include "S1ap-MMEConfigurationUpdate.h"
#include "S1ap-MMEConfigurationUpdateAcknowledge.h"
#include "S1ap-MMEConfigurationUpdateFailure.h"
#include "S1ap-DownlinkS1cdma2000tunneling.h"
#include "S1ap-UplinkS1cdma2000tunneling.h"
#include "S1ap-UEContextModificationRequest.h"
#include "S1ap-UEContextModificationResponse.h"
#include "S1ap-UEContextModificationFailure.h"
#include "S1ap-UECapabilityInfoIndication.h"
#include "S1ap-UEContextReleaseCommand.h"
#include "S1ap-UEContextReleaseComplete.h"
#include "S1ap-ENBStatusTransfer.h"
#include "S1ap-MMEStatusTransfer.h"
#include "S1ap-DeactivateTrace.h"
#include "S1ap-TraceStart.h"
#include "S1ap-TraceFailureIndication.h"
#include "S1ap-CellTrafficTrace.h"
#include "S1ap-LocationReportingControl.h"
#include "S1ap-LocationReportingFailureIndication.h"
#include "S1ap-LocationReport.h"
#include "S1ap-OverloadStart.h"
#include "S1ap-OverloadStop.h"
#include "S1ap-WriteReplaceWarningRequest.h"
#include "S1ap-WriteReplaceWarningResponse.h"
#include "S1ap-ENBDirectInformationTransfer.h"
#include "S1ap-MMEDirectInformationTransfer.h"
#include "S1ap-ENBConfigurationTransfer.h"
#include "S1ap-MMEConfigurationTransfer.h"
#include "S1ap-PrivateMessage.h"
#include "S1ap-E-RABReleaseItemBearerRelComp.h"
#include "S1ap-E-RABToBeSwitchedDLList.h"
#include "S1ap-E-RABToBeSwitchedDLItem.h"
#include "S1ap-E-RABToBeSwitchedULList.h"
#include "S1ap-E-RABToBeSwitchedULItem.h"
#include "S1ap-E-RABToBeSetupListBearerSUReq.h"
#include "S1ap-E-RABToBeSetupItemBearerSUReq.h"
#include "S1ap-E-RABDataForwardingList.h"
#include "S1ap-E-RABDataForwardingItem.h"
#include "S1ap-E-RABToBeSetupListHOReq.h"
#include "S1ap-E-RABToBeSetupItemHOReq.h"
#include "S1ap-E-RABAdmittedList.h"
#include "S1ap-E-RABAdmittedItem.h"
#include "S1ap-E-RABFailedToSetupListHOReqAck.h"
#include "S1ap-E-RABToBeSetupItemCtxtSUReq.h"
#include "S1ap-E-RABToBeSetupListCtxtSUReq.h"
#include "S1ap-E-RABSetupItemBearerSURes.h"
#include "S1ap-E-RABSetupListBearerSURes.h"
#include "S1ap-E-RABSetupItemCtxtSURes.h"
#include "S1ap-E-RABSetupListCtxtSURes.h"
#include "S1ap-E-RABReleaseListBearerRelComp.h"
#include "S1ap-E-RABModifyItemBearerModRes.h"
#include "S1ap-E-RABModifyListBearerModRes.h"
#include "S1ap-E-RABFailedToSetupItemHOReqAck.h"
#include "S1ap-E-RABFailedToSetupListHOReqAck.h"
#include "S1ap-E-RABToBeModifiedItemBearerModReq.h"
#include "S1ap-E-RABToBeModifiedListBearerModReq.h"
#include "S1ap-UE-associatedLogicalS1-ConnectionListResAck.h"
#include "S1ap-IE.h"
#include "S1AP-PDU.h"

#define PDU S1AP_PDU
/* Convert "Type" defined by -DPDU into "asn_DEF_Type" */
#define	ASN_DEF_PDU(t)	asn_DEF_ ## t
#define	DEF_PDU_Type(t)	ASN_DEF_PDU(t)
#define	PDU_Type	DEF_PDU_Type(PDU)

extern asn_TYPE_descriptor_t PDU_Type;	/* ASN.1 type to be decoded */
#ifdef	ASN_PDU_COLLECTION		/* Generated by asn1c: -pdu=... */
extern asn_TYPE_descriptor_t *asn_pdu_collection[];
#endif

/*
 * Open file and parse its contens.
 */
static void *data_decode_from_file(asn_TYPE_descriptor_t *asnTypeOfPDU,
	FILE *file, const char *name, ssize_t suggested_bufsize, int first_pdu);
static int write_out(const void *buffer, size_t size, void *key);
static FILE *argument_to_file(char *av[], int idx);
static char *argument_to_name(char *av[], int idx);

       int opt_debug;	/* -d (or -dd) */
static int opt_check;	/* -c (constraints checking) */
static int opt_stack;	/* -s (maximum stack size) */
static int opt_nopad;	/* -per-nopad (PER input is not padded) */
static int opt_onepdu;	/* -1 (decode single PDU) */

/* Input data format selector */
static enum input_format {
	INP_BER,	/* -iber: BER input */
	INP_XER,	/* -ixer: XER input */
	INP_PER		/* -iper: Unaligned PER input */
} iform;	/* -i<format> */

/* Output data format selector */
static enum output_format {
	OUT_XER,	/* -oxer: XER (XML) output */
	OUT_DER,	/* -oder: DER (BER) output */
	OUT_PER,	/* -oper: Unaligned PER output */
	OUT_TEXT,	/* -otext: semi-structured text */
	OUT_NULL	/* -onull: No pretty-printing */
} oform;	/* -o<format> */

#ifdef	JUNKTEST		/* Enable -J <probability> */
#define	JUNKOPT	"J:"
static double opt_jprob;	/* Junk bit probability */
static int    junk_failures;
static void   junk_bytes_with_probability(uint8_t *, size_t, double prob);
#else
#define	JUNKOPT
#endif

/* Debug output function */
static inline void
DEBUG(const char *fmt, ...) {
	va_list ap;
	if(!opt_debug) return;
	fprintf(stderr, "AD: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

int
main(int ac, char *av[]) {
	static asn_TYPE_descriptor_t *pduType = &PDU_Type;
	ssize_t suggested_bufsize = 8192;  /* close or equal to stdio buffer */
	int number_of_iterations = 1;
	int num;
	int ch;

	  S1AP_PDU_t  pdu;
	  S1AP_PDU_t *pdu_p = &pdu;
	  asn_dec_rval_t dec_ret;

	  const char buffer[]= "qfdjmqkdfjqmdkfjqmdf";
	  const int length = strlen(buffer);

	  memset((void *)pdu_p, 0, sizeof(S1AP_PDU_t));

	  dec_ret = aper_decode(NULL,
	                        &asn_DEF_S1AP_PDU,
	                        (void **)&pdu_p,
	                        buffer,
	                        length,
	                        0,
	                        0);

	  if (dec_ret.code != RC_OK) {
	    printf("Failed to decode pdu\n");
	    return -1;
	  }

	/* Figure out if Unaligned PER needs to be default */
	if(pduType->uper_decoder)
		iform = INP_PER;

	/*
	 * Pocess the command-line argments.
	 */
	while((ch = getopt(ac, av, "i:o:1b:cdn:p:hs:" JUNKOPT)) != -1)
	switch(ch) {
	case 'i':
		if(optarg[0] == 'b') { iform = INP_BER; break; }
		if(optarg[0] == 'x') { iform = INP_XER; break; }
		if(pduType->uper_decoder
		&& optarg[0] == 'p') { iform = INP_PER; break; }
		fprintf(stderr, "-i<format>: '%s': improper format selector\n",
			optarg);
		exit(EX_UNAVAILABLE);
	case 'o':
		if(optarg[0] == 'd') { oform = OUT_DER; break; }
		if(pduType->uper_encoder
		&& optarg[0] == 'p') { oform = OUT_PER; break; }
		if(optarg[0] == 'x') { oform = OUT_XER; break; }
		if(optarg[0] == 't') { oform = OUT_TEXT; break; }
		if(optarg[0] == 'n') { oform = OUT_NULL; break; }
		fprintf(stderr, "-o<format>: '%s': improper format selector\n",
			optarg);
		exit(EX_UNAVAILABLE);
	case '1':
		opt_onepdu = 1;
		break;
	case 'b':
		suggested_bufsize = atoi(optarg);
		if(suggested_bufsize < 1
			|| suggested_bufsize > 16 * 1024 * 1024) {
			fprintf(stderr,
				"-b %s: Improper buffer size (1..16M)\n",
				optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
	case 'c':
		opt_check = 1;
		break;
	case 'd':
		opt_debug++;	/* Double -dd means ASN.1 debug */
		break;
	case 'n':
		number_of_iterations = atoi(optarg);
		if(number_of_iterations < 1) {
			fprintf(stderr,
				"-n %s: Improper iterations count\n", optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
	case 'p':
		if(strcmp(optarg, "er-nopad") == 0) {
			opt_nopad = 1;
			break;
		}
#ifdef	ASN_PDU_COLLECTION
		if(strcmp(optarg, "list") == 0) {
			asn_TYPE_descriptor_t **pdu = asn_pdu_collection;
			fprintf(stderr, "Available PDU types:\n");
			for(; *pdu; pdu++) printf("%s\n", (*pdu)->name);
			exit(0);
		} else if(optarg[0] >= 'A' && optarg[0] <= 'Z') {
			asn_TYPE_descriptor_t **pdu = asn_pdu_collection;
			while(*pdu && strcmp((*pdu)->name, optarg)) pdu++;
			if(*pdu) { pduType = *pdu; break; }
			fprintf(stderr, "-p %s: Unrecognized PDU\n", optarg);
		}
#endif	/* ASN_PDU_COLLECTION */
		fprintf(stderr, "-p %s: Unrecognized option\n", optarg);
		exit(EX_UNAVAILABLE);
	case 's':
		opt_stack = atoi(optarg);
		if(opt_stack < 0) {
			fprintf(stderr,
				"-s %s: Non-negative value expected\n",
				optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
#ifdef	JUNKTEST
	case 'J':
		opt_jprob = strtod(optarg, 0);
		if(opt_jprob <= 0.0 || opt_jprob > 1.0) {
			fprintf(stderr,
				"-J %s: Probability range 0..1 expected \n",
				optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
#endif	/* JUNKTEST */
	case 'h':
	default:
#ifdef	ASN_CONVERTER_TITLE
#define	_AXS(x)	#x
#define	_ASX(x)	_AXS(x)
		fprintf(stderr, "%s\n", _ASX(ASN_CONVERTER_TITLE));
#endif
		fprintf(stderr, "Usage: %s [options] <data.ber> ...\n", av[0]);
		fprintf(stderr, "Where options are:\n");
		if(pduType->uper_decoder)
		fprintf(stderr,
		"  -iper        Input is in Unaligned PER (Packed Encoding Rules) (DEFAULT)\n");
		fprintf(stderr,
		"  -iber        Input is in BER (Basic Encoding Rules)%s\n",
			iform == INP_PER ? "" : " (DEFAULT)");
		fprintf(stderr,
		"  -ixer        Input is in XER (XML Encoding Rules)\n");
		if(pduType->uper_encoder)
		fprintf(stderr,
		"  -oper        Output in Unaligned PER (Packed Encoding Rules)\n");
		fprintf(stderr,
		"  -oder        Output in DER (Distinguished Encoding Rules)\n"
		"  -oxer        Output in XER (XML Encoding Rules) (DEFAULT)\n"
		"  -otext       Output in plain semi-structured text (dump)\n"
		"  -onull       Verify (decode) input, but do not output\n");
		if(pduType->uper_decoder)
		fprintf(stderr,
		"  -per-nopad   Assume PER PDUs are not padded (-iper)\n");
#ifdef	ASN_PDU_COLLECTION
		fprintf(stderr,
		"  -p <PDU>     Specify PDU type to decode\n"
		"  -p list      List available PDUs\n");
#endif	/* ASN_PDU_COLLECTION */
		fprintf(stderr,
		"  -1           Decode only the first PDU in file\n"
		"  -b <size>    Set the i/o buffer size (default is %ld)\n"
		"  -c           Check ASN.1 constraints after decoding\n"
		"  -d           Enable debugging (-dd is even better)\n"
		"  -n <num>     Process files <num> times\n"
		"  -s <size>    Set the stack usage limit (default is %d)\n"
#ifdef	JUNKTEST
		"  -J <prob>    Set random junk test bit garbaging probability\n"
#endif
		, (long)suggested_bufsize, _ASN_DEFAULT_STACK_MAX);
		exit(EX_USAGE);
	}

	ac -= optind;
	av += optind;

	if(ac < 1) {
		fprintf(stderr, "%s: No input files specified. "
				"Try '-h' for more information\n",
				av[-optind]);
		exit(EX_USAGE);
	}

	setvbuf(stdout, 0, _IOLBF, 0);

	for(num = 0; num < number_of_iterations; num++) {
	  int ac_i;
	  /*
	   * Process all files in turn.
	   */
	  for(ac_i = 0; ac_i < ac; ac_i++) {
	    asn_enc_rval_t erv;
	    void *structure;	/* Decoded structure */
	    FILE *file = argument_to_file(av, ac_i);
	    char *name = argument_to_name(av, ac_i);
	    int first_pdu;

	    for(first_pdu = 1; first_pdu || !opt_onepdu; first_pdu = 0) {
		/*
		 * Decode the encoded structure from file.
		 */
		structure = data_decode_from_file(pduType,
				file, name, suggested_bufsize, first_pdu);
		if(!structure) {
			if(errno) {
				/* Error message is already printed */
				exit(EX_DATAERR);
			} else {
				/* EOF */
				break;
			}
		}

		/* Check ASN.1 constraints */
		if(opt_check) {
			char errbuf[128];
			size_t errlen = sizeof(errbuf);
			if(asn_check_constraints(pduType, structure,
				errbuf, &errlen)) {
				fprintf(stderr, "%s: ASN.1 constraint "
					"check failed: %s\n", name, errbuf);
				exit(EX_DATAERR);
			}
		}

		switch(oform) {
		case OUT_NULL:
#ifdef	JUNKTEST
		    if(opt_jprob == 0.0)
#endif
			fprintf(stderr, "%s: decoded successfully\n", name);
			break;
		case OUT_TEXT:	/* -otext */
			asn_fprint(stdout, pduType, structure);
			break;
		case OUT_XER:	/* -oxer */
			if(xer_fprint(stdout, pduType, structure)) {
				fprintf(stderr,
					"%s: Cannot convert %s into XML\n",
					name, pduType->name);
				exit(EX_UNAVAILABLE);
			}
			break;
		case OUT_DER:
			erv = der_encode(pduType, structure, write_out, stdout);
			if(erv.encoded < 0) {
				fprintf(stderr,
					"%s: Cannot convert %s into DER\n",
					name, pduType->name);
				exit(EX_UNAVAILABLE);
			}
			DEBUG("Encoded in %ld bytes of DER", (long)erv.encoded);
			break;
		case OUT_PER:
			erv = uper_encode(pduType, structure, write_out, stdout);
			if(erv.encoded < 0) {
				fprintf(stderr,
				"%s: Cannot convert %s into Unaligned PER\n",
					name, pduType->name);
				exit(EX_UNAVAILABLE);
			}
			DEBUG("Encoded in %ld bits of UPER", (long)erv.encoded);
			break;
		}

		ASN_STRUCT_FREE(*pduType, structure);
	    }

	    if(file && file != stdin)
		fclose(file);
	  }
	}

#ifdef	JUNKTEST
	if(opt_jprob > 0.0) {
		fprintf(stderr, "Junked %f OK (%d/%d)\n",
			opt_jprob, junk_failures, number_of_iterations);
	}
#endif	/* JUNKTEST */

	return 0;
}

static struct dynamic_buffer {
	uint8_t *data;		/* Pointer to the data bytes */
	size_t offset;		/* Offset from the start */
	size_t length;		/* Length of meaningful contents */
	size_t unbits;		/* Unused bits in the last byte */
	size_t allocated;	/* Allocated memory for data */
	int    nreallocs;	/* Number of data reallocations */
	off_t  bytes_shifted;	/* Number of bytes ever shifted */
} DynamicBuffer;

static void
buffer_dump() {
	uint8_t *p = DynamicBuffer.data + DynamicBuffer.offset;
	uint8_t *e = p + DynamicBuffer.length - (DynamicBuffer.unbits ? 1 : 0);
	if(!opt_debug) return;
	DEBUG("Buffer: { d=%p, o=%ld, l=%ld, u=%ld, a=%ld, s=%ld }",
		DynamicBuffer.data,
		(long)DynamicBuffer.offset,
		(long)DynamicBuffer.length,
		(long)DynamicBuffer.unbits,
		(long)DynamicBuffer.allocated,
		(long)DynamicBuffer.bytes_shifted);
	for(; p < e; p++) {
		fprintf(stderr, " %c%c%c%c%c%c%c%c",
			((*p >> 7) & 1) ? '1' : '0',
			((*p >> 6) & 1) ? '1' : '0',
			((*p >> 5) & 1) ? '1' : '0',
			((*p >> 4) & 1) ? '1' : '0',
			((*p >> 3) & 1) ? '1' : '0',
			((*p >> 2) & 1) ? '1' : '0',
			((*p >> 1) & 1) ? '1' : '0',
			((*p >> 0) & 1) ? '1' : '0');
	}
	if(DynamicBuffer.unbits) {
		unsigned int shift;
		fprintf(stderr, " ");
		for(shift = 7; shift >= DynamicBuffer.unbits; shift--)
			fprintf(stderr, "%c", ((*p >> shift) & 1) ? '1' : '0');
		fprintf(stderr, " %ld:%ld\n",
			(long)DynamicBuffer.length - 1,
			(long)8 - DynamicBuffer.unbits);
	} else {
		fprintf(stderr, " %ld\n", (long)DynamicBuffer.length);
	}
}

/*
 * Move the buffer content left N bits, possibly joining it with
 * preceeding content.
 */
static void
buffer_shift_left(size_t offset, int bits) {
	uint8_t *ptr = DynamicBuffer.data + DynamicBuffer.offset + offset;
	uint8_t *end = DynamicBuffer.data + DynamicBuffer.offset
			+ DynamicBuffer.length - 1;
	
	if(!bits) return;

	DEBUG("Shifting left %d bits off %ld (o=%ld, u=%ld, l=%ld)",
		bits, (long)offset,
		(long)DynamicBuffer.offset,
		(long)DynamicBuffer.unbits,
		(long)DynamicBuffer.length);

	if(offset) {
		int right;
		right = ptr[0] >> (8 - bits);

		DEBUG("oleft: %c%c%c%c%c%c%c%c",
			((ptr[-1] >> 7) & 1) ? '1' : '0',
			((ptr[-1] >> 6) & 1) ? '1' : '0',
			((ptr[-1] >> 5) & 1) ? '1' : '0',
			((ptr[-1] >> 4) & 1) ? '1' : '0',
			((ptr[-1] >> 3) & 1) ? '1' : '0',
			((ptr[-1] >> 2) & 1) ? '1' : '0',
			((ptr[-1] >> 1) & 1) ? '1' : '0',
			((ptr[-1] >> 0) & 1) ? '1' : '0');

		DEBUG("oriht: %c%c%c%c%c%c%c%c",
			((ptr[0] >> 7) & 1) ? '1' : '0',
			((ptr[0] >> 6) & 1) ? '1' : '0',
			((ptr[0] >> 5) & 1) ? '1' : '0',
			((ptr[0] >> 4) & 1) ? '1' : '0',
			((ptr[0] >> 3) & 1) ? '1' : '0',
			((ptr[0] >> 2) & 1) ? '1' : '0',
			((ptr[0] >> 1) & 1) ? '1' : '0',
			((ptr[0] >> 0) & 1) ? '1' : '0');

		DEBUG("mriht: %c%c%c%c%c%c%c%c",
			((right >> 7) & 1) ? '1' : '0',
			((right >> 6) & 1) ? '1' : '0',
			((right >> 5) & 1) ? '1' : '0',
			((right >> 4) & 1) ? '1' : '0',
			((right >> 3) & 1) ? '1' : '0',
			((right >> 2) & 1) ? '1' : '0',
			((right >> 1) & 1) ? '1' : '0',
			((right >> 0) & 1) ? '1' : '0');

		ptr[-1] = (ptr[-1] & (0xff << bits)) | right;

		DEBUG("after: %c%c%c%c%c%c%c%c",
			((ptr[-1] >> 7) & 1) ? '1' : '0',
			((ptr[-1] >> 6) & 1) ? '1' : '0',
			((ptr[-1] >> 5) & 1) ? '1' : '0',
			((ptr[-1] >> 4) & 1) ? '1' : '0',
			((ptr[-1] >> 3) & 1) ? '1' : '0',
			((ptr[-1] >> 2) & 1) ? '1' : '0',
			((ptr[-1] >> 1) & 1) ? '1' : '0',
			((ptr[-1] >> 0) & 1) ? '1' : '0');
	}

	buffer_dump();

	for(; ptr < end; ptr++) {
		int right = ptr[1] >> (8 - bits);
		*ptr = (*ptr << bits) | right;
	}
	*ptr <<= bits;

	DEBUG("Unbits [%d=>", (int)DynamicBuffer.unbits);
	if(DynamicBuffer.unbits == 0) {
		DynamicBuffer.unbits += bits;
	} else {
		DynamicBuffer.unbits += bits;
		if(DynamicBuffer.unbits > 7) {
			DynamicBuffer.unbits -= 8;
			DynamicBuffer.length--;
			DynamicBuffer.bytes_shifted++;
		}
	}
	DEBUG("Unbits =>%d]", (int)DynamicBuffer.unbits);

	buffer_dump();

	DEBUG("Shifted. Now (o=%ld, u=%ld l=%ld)",
		(long)DynamicBuffer.offset,
		(long)DynamicBuffer.unbits,
		(long)DynamicBuffer.length);
	

}

/*
 * Ensure that the buffer contains at least this amount of free space.
 */
static void add_bytes_to_buffer(const void *data2add, size_t bytes) {

	if(bytes == 0) return;

	DEBUG("=> add_bytes(%ld) { o=%ld l=%ld u=%ld, s=%ld }",
		(long)bytes,
		(long)DynamicBuffer.offset,
		(long)DynamicBuffer.length,
		(long)DynamicBuffer.unbits,
		(long)DynamicBuffer.allocated);

	if(DynamicBuffer.allocated
	>= (DynamicBuffer.offset + DynamicBuffer.length + bytes)) {
		DEBUG("\tNo buffer reallocation is necessary");
	} else if(bytes <= DynamicBuffer.offset) {
		DEBUG("\tContents shifted by %ld", DynamicBuffer.offset);

		/* Shift the buffer contents */
		memmove(DynamicBuffer.data,
		        DynamicBuffer.data + DynamicBuffer.offset,
			DynamicBuffer.length);
		DynamicBuffer.bytes_shifted += DynamicBuffer.offset;
		DynamicBuffer.offset = 0;
	} else {
		size_t newsize = (DynamicBuffer.allocated << 2) + bytes;
		void *p = MALLOC(newsize);
		if(!p) {
			perror("malloc()");
			exit(EX_OSERR);
		}
		memcpy(p,
			DynamicBuffer.data + DynamicBuffer.offset,
			DynamicBuffer.length);
		FREEMEM(DynamicBuffer.data);
		DynamicBuffer.data = (uint8_t *)p;
		DynamicBuffer.offset = 0;
		DynamicBuffer.allocated = newsize;
		DynamicBuffer.nreallocs++;
		DEBUG("\tBuffer reallocated to %ld (%d time)",
			newsize, DynamicBuffer.nreallocs);
	}

	memcpy(DynamicBuffer.data
		+ DynamicBuffer.offset + DynamicBuffer.length,
		data2add, bytes);
	DynamicBuffer.length += bytes;
	if(DynamicBuffer.unbits) {
		int bits = DynamicBuffer.unbits;
		DynamicBuffer.unbits = 0;
		buffer_shift_left(DynamicBuffer.length - bytes, bits);
	}

	DEBUG("<= add_bytes(%ld) { o=%ld l=%ld u=%ld, s=%ld }",
		(long)bytes,
		(long)DynamicBuffer.offset,
		(long)DynamicBuffer.length,
		(long)DynamicBuffer.unbits,
		(long)DynamicBuffer.allocated);
}

static void *
data_decode_from_file(asn_TYPE_descriptor_t *pduType, FILE *file, const char *name, ssize_t suggested_bufsize, int on_first_pdu) {
	static uint8_t *fbuf;
	static ssize_t fbuf_size;
	static asn_codec_ctx_t s_codec_ctx;
	asn_codec_ctx_t *opt_codec_ctx = 0;
	void *structure = 0;
	asn_dec_rval_t rval;
	size_t old_offset;	
	size_t new_offset;
	int tolerate_eof;
	size_t rd;

	if(!file) {
		fprintf(stderr, "%s: %s\n", name, strerror(errno));
		errno = EINVAL;
		return 0;
	}

	if(opt_stack) {
		s_codec_ctx.max_stack_size = opt_stack;
		opt_codec_ctx = &s_codec_ctx;
	}

	DEBUG("Processing %s", name);

	/* prepare the file buffer */
	if(fbuf_size != suggested_bufsize) {
		fbuf = (uint8_t *)REALLOC(fbuf, suggested_bufsize);
		if(!fbuf) {
			perror("realloc()");
			exit(EX_OSERR);
		}
		fbuf_size = suggested_bufsize;
	}

	if(on_first_pdu) {
		DynamicBuffer.offset = 0;
		DynamicBuffer.length = 0;
		DynamicBuffer.unbits = 0;
		DynamicBuffer.allocated = 0;
		DynamicBuffer.bytes_shifted = 0;
		DynamicBuffer.nreallocs = 0;
	}

	old_offset = DynamicBuffer.bytes_shifted + DynamicBuffer.offset;

	/* Pretend immediate EOF */
	rval.code = RC_WMORE;
	rval.consumed = 0;

	for(tolerate_eof = 1;	/* Allow EOF first time buffer is non-empty */
	    (rd = fread(fbuf, 1, fbuf_size, file))
		|| feof(file) == 0
		|| (tolerate_eof && DynamicBuffer.length)
	    ;) {
		int      ecbits = 0;	/* Extra consumed bits in case of PER */
		uint8_t *i_bptr;
		size_t   i_size;

		/*
		 * Copy the data over, or use the original buffer.
		 */
		if(DynamicBuffer.allocated) {
			/* Append new data into the existing dynamic buffer */
			add_bytes_to_buffer(fbuf, rd);
			i_bptr = DynamicBuffer.data + DynamicBuffer.offset;
			i_size = DynamicBuffer.length;
		} else {
			i_bptr = fbuf;
			i_size = rd;
		}

		DEBUG("Decoding %ld bytes", (long)i_size);

#ifdef	JUNKTEST
		junk_bytes_with_probability(i_bptr, i_size, opt_jprob);
#endif

		switch(iform) {
		case INP_BER:
			rval = ber_decode(opt_codec_ctx, pduType,
				(void **)&structure, i_bptr, i_size);
			break;
		case INP_XER:
			rval = xer_decode(opt_codec_ctx, pduType,
				(void **)&structure, i_bptr, i_size);
			break;
		case INP_PER:
			if(opt_nopad)
			rval = uper_decode(opt_codec_ctx, pduType,
				(void **)&structure, i_bptr, i_size, 0,
				DynamicBuffer.unbits);
			else
			rval = uper_decode_complete(opt_codec_ctx, pduType,
				(void **)&structure, i_bptr, i_size);
			switch(rval.code) {
			case RC_OK:
				/* Fall through */
			case RC_FAIL:
				if(opt_nopad) {
					/* uper_decode() returns bits! */
					/* Extra bits */
					ecbits = rval.consumed % 8;
					/* Convert into bytes! */
					rval.consumed /= 8;
				}
				break;
			case RC_WMORE:
				/* PER does not support restartability */
				ASN_STRUCT_FREE(*pduType, structure);
				structure = 0;
				rval.consumed = 0;
				/* Continue accumulating data */
				break;
			}
			break;
		}
		DEBUG("decode(%ld) consumed %ld+%db (%ld), code %d",
			(long)DynamicBuffer.length,
			(long)rval.consumed, ecbits, (long)i_size,
			rval.code);

		if(DynamicBuffer.allocated == 0) {
			/*
			 * Flush remainder into the intermediate buffer.
			 */
			if(rval.code != RC_FAIL && rval.consumed < rd) {
				add_bytes_to_buffer(fbuf + rval.consumed,
					rd - rval.consumed);
				buffer_shift_left(0, ecbits);
				DynamicBuffer.bytes_shifted = rval.consumed;
				rval.consumed = 0;
				ecbits = 0;
			}
		}

		/*
		 * Adjust position inside the source buffer.
		 */
		if(DynamicBuffer.allocated) {
			DynamicBuffer.offset += rval.consumed;
			DynamicBuffer.length -= rval.consumed;
		} else {
			DynamicBuffer.bytes_shifted += rval.consumed;
		}

		switch(rval.code) {
		case RC_OK:
			if(ecbits) buffer_shift_left(0, ecbits);
			DEBUG("RC_OK, finishing up with %ld+%d",
				(long)rval.consumed, ecbits);
			return structure;
		case RC_WMORE:
			DEBUG("RC_WMORE, continuing read=%ld, cons=%ld "
				" with %ld..%ld-%ld..%ld",
				(long)rd,
				(long)rval.consumed,
				(long)DynamicBuffer.offset,
				(long)DynamicBuffer.length,
				(long)DynamicBuffer.unbits,
				(long)DynamicBuffer.allocated);
			if(!rd) tolerate_eof--;
			continue;
		case RC_FAIL:
			break;
		}
		break;
	}

	DEBUG("Clean up partially decoded structure");
	ASN_STRUCT_FREE(*pduType, structure);

	new_offset = DynamicBuffer.bytes_shifted + DynamicBuffer.offset;

	/*
	 * Print a message and return failure only if not EOF,
	 * unless this is our first PDU (empty file).
	 */
	if(on_first_pdu
	|| DynamicBuffer.length
	|| new_offset - old_offset > ((iform == INP_XER)?sizeof("\r\n")-1:0)
	) {

#ifdef	JUNKTEST
		/*
		 * Nothing's wrong with being unable to decode junk.
		 * Simulate EOF.
		 */
		if(opt_jprob != 0.0) {
			junk_failures++;
			errno = 0;
			return 0;
		}
#endif

		DEBUG("ofp %d, no=%ld, oo=%ld, dbl=%ld",
			on_first_pdu, (long)new_offset, (long)old_offset,
			(long)DynamicBuffer.length);
		fprintf(stderr, "%s: "
			"Decode failed past byte %ld: %s\n",
			name, (long)new_offset,
			(rval.code == RC_WMORE)
				? "Unexpected end of input"
				: "Input processing error");
#ifndef	ENOMSG
#define	ENOMSG EINVAL
#endif
#ifndef	EBADMSG
#define	EBADMSG EINVAL
#endif
		errno = (rval.code == RC_WMORE) ? ENOMSG : EBADMSG;
	} else {
		/* Got EOF after a few successful PDUs */
		errno = 0;
	}

	return 0;
}

/* Dump the buffer out to the specified FILE */
static int write_out(const void *buffer, size_t size, void *key) {
	FILE *fp = (FILE *)key;
	return (fwrite(buffer, 1, size, fp) == size) ? 0 : -1;
}

static int argument_is_stdin(char *av[], int idx) {
	if(strcmp(av[idx], "-")) {
		return 0;	/* Certainly not <stdin> */
	} else {
		/* This might be <stdin>, unless `./program -- -` */
		if(strcmp(av[-1], "--"))
			return 1;
		else
			return 0;
	}
}

static FILE *argument_to_file(char *av[], int idx) {
	return argument_is_stdin(av, idx)
		? stdin
		: fopen(av[idx], "rb");
}

static char *argument_to_name(char *av[], int idx) {
	return argument_is_stdin(av, idx)
		? "standard input"
		: av[idx];
}

#ifdef	JUNKTEST
/*
 * Fill bytes with some garbage with specified probability (more or less).
 */
static void
junk_bytes_with_probability(uint8_t *buf, size_t size, double prob) {
	static int junkmode;
	uint8_t *ptr;
	uint8_t *end;
	if(opt_jprob <= 0.0) return;
	for(ptr = buf, end = ptr + size; ptr < end; ptr++) {
		int byte = *ptr;
		if(junkmode++ & 1) {
			if((((double)random() / RAND_MAX) < prob))
				byte = random() & 0xff;
		} else {
#define	BPROB(b)	((((double)random() / RAND_MAX) < prob) ? b : 0)
			byte ^= BPROB(0x80);
			byte ^= BPROB(0x40);
			byte ^= BPROB(0x20);
			byte ^= BPROB(0x10);
			byte ^= BPROB(0x08);
			byte ^= BPROB(0x04);
			byte ^= BPROB(0x02);
			byte ^= BPROB(0x01);
		}
		if(byte != *ptr) {
			DEBUG("Junk buf[%d] %02x -> %02x",
				ptr - buf, *ptr, byte);
			*ptr = byte;
		}
	}
}
#endif	/* JUNKTEST */

