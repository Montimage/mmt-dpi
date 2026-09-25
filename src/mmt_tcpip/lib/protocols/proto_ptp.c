#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

static int _classify_ptp_from_udp( ipacket_t * ipacket, unsigned index ){

	//check udp ports
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	const mmt_una_udphdr_t *udp = packet->udp; /* issue #57: alignment-safe view */
	//should not happen since we enter here from UDP, but check anyway
	if (udp == NULL)
		return 0;
	u_int32_t ptp_u  = htons(320);
	u_int32_t ptp_c  = htons(319);
	//we expect UDP ports should be one of 319 or 320
	if (!((udp->source == ptp_u) || (udp->dest == ptp_u)
	   || (udp->source == ptp_c) || (udp->dest == ptp_c)))
		return 0;

	int offset = get_packet_offset_at_index(ipacket, index);
	int udp_header_size = sizeof( struct udphdr );
	int next_offset = offset + udp_header_size;

	//not enough room for other data ?
	if( next_offset + 44  > ipacket->p_hdr->caplen )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_PTP;
	retval.offset   = udp_header_size; //PTP is inside UDP payload
	retval.status   = Classified;
	return set_classified_proto(ipacket, index + 1, retval);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ptp_struct() {
	protocol_t *protocol_struct = init_protocol_struct_for_registration(
			PROTO_PTP, PROTO_PTP_ALIAS);
	if (protocol_struct == NULL)
		return PROTO_NOT_REGISTERED;

	int ret = register_classification_function_with_parent_protocol( PROTO_UDP, _classify_ptp_from_udp, 100);
	if (ret == 0) {
		//no SCTP (need to do if diameter can work with TCP)
		mmt_stderr_log( "Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}
	return register_protocol(protocol_struct, PROTO_PTP);
}

