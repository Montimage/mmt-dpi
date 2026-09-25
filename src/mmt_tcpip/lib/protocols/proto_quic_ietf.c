/*
 * proto_quic_ietf.c
 *
 *  Created on: Feb 16, 2023
 *      Author: nhnghia
 */

#include "proto_quic_ietf.h"
#include "mmt_tcpip_protocols.h"
#include "../mmt_common_internal_include.h"
#include <arpa/inet.h>

#define NOT_FOUND 0
#define FOUND     1

#define QUIC_IETF_VERSION_1 0x00000001 /* RFC 9000 */
#define QUIC_IETF_VERSION_2 0x6b3343cf /* RFC 9369 */

/* RFC 9000 §17.2: a v1/v2 connection ID is at most 20 bytes. */
#define QUIC_IETF_MAX_CID_LENGTH 20
/* Short-header DCID length used when the flow's long headers did not announce
 * one (e.g. capture started mid-connection): the historical fixed 8 bytes. */
#define QUIC_IETF_DEFAULT_SHORT_HEADER_DCID_LENGTH 8
/* INT shim + metadata header offset probed when the INT shim Length is
 * unusable (the historical fixed INT header size). */
#define QUIC_IETF_INT_DEFAULT_LENGTH 56

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/* Parse the long header at data[0..len) into the LOCAL descriptor `hdr`.
 * Returns !=0 only when the whole variable-length section (dcid_len, dcid,
 * scid_len, scid) fits inside `len`: each cursor step is validated against
 * the captured length before it is taken (issue #203, F-BUG-063). A header
 * whose declared spans overrun the capture is malformed — nothing is
 * extracted from it. */
static int _quic_ietf_parse_long_header(const uint8_t *data, size_t len,
		quic_ietf_long_header_t *hdr) {
	//flags octet + version + dcid_len must all be present
	if( len < 6 )
		return 0;
	hdr->flags = data[0];
	{
		uint32_t v;
		memcpy(&v, data + 1, sizeof(v));
		hdr->version = ntohl(v);
	}
	hdr->destination_connection_id_length = data[5];
	size_t cursor = 6;
	if( cursor + hdr->destination_connection_id_length > len )
		return 0;
	hdr->destination_connection_id_offset = cursor;
	cursor += hdr->destination_connection_id_length;
	if( cursor + 1 > len )
		return 0;
	hdr->source_connection_id_length = data[cursor];
	cursor += 1;
	if( cursor + hdr->source_connection_id_length > len )
		return 0;
	hdr->source_connection_id_offset = cursor;
	cursor += hdr->source_connection_id_length;
	hdr->types_pecific_payload_offset = cursor;
	return 1;
}

static inline int _quic_ietf_is_supported_version(uint32_t version) {
	return version == QUIC_IETF_VERSION_1 || version == QUIC_IETF_VERSION_2;
}

/* Long packet type in RFC 9000 terms (enum quic_ietf_long_packet_types).
 * RFC 9369 §3.2 rotates the v2 codepoints: Initial=0b01, 0-RTT=0b10,
 * Handshake=0b11, Retry=0b00 — map them back so every consumer (attribute,
 * session analysis, coalesced-packet walk) reasons about one numbering. */
static inline uint8_t _quic_ietf_long_packet_type(uint8_t flags, uint32_t version) {
	uint8_t type = (flags >> 4) & 3;
	if( version == QUIC_IETF_VERSION_2 )
		type = (uint8_t)((type + 3) & 3);
	return type;
}

/* RFC 9000 §16 variable-length integer at data[*cursor..len). Advances the
 * cursor only when the whole encoding is inside len. */
static int _quic_ietf_read_varint(const uint8_t *data, size_t len, size_t *cursor,
		uint64_t *value) {
	if( *cursor >= len )
		return 0;
	size_t n = (size_t)1 << (data[*cursor] >> 6);
	if( n > len - *cursor )
		return 0;
	uint64_t v = data[*cursor] & 0x3f;
	for( size_t i = 1; i < n; i++ )
		v = (v << 8) | data[*cursor + i];
	*cursor += n;
	*value = v;
	return 1;
}

/* Size of the first QUIC packet of the datagram at data[0..len) when it is a
 * supported-version long header carrying a Length field (Initial, 0-RTT,
 * Handshake — RFC 9000 §17.2); 0 otherwise (short header and Retry packets
 * run to the end of the datagram, RFC 9000 §12.2), or when the declared spans
 * do not fit inside len. */
static size_t _quic_ietf_long_packet_size(const uint8_t *data, size_t len) {
	quic_ietf_long_header_t hdr;
	uint64_t v;
	if( len == 0 || !(data[0] & 0x80) )
		return 0;
	if( ! _quic_ietf_parse_long_header(data, len, &hdr) )
		return 0;
	if( ! _quic_ietf_is_supported_version(hdr.version) )
		return 0;
	size_t cursor = hdr.types_pecific_payload_offset;
	switch( _quic_ietf_long_packet_type(hdr.flags, hdr.version) ){
	case QUIC_IETF_INITIAL_PACKET_TYPE:
		//Token Length (i) + Token precede the Length field
		if( ! _quic_ietf_read_varint(data, len, &cursor, &v) || v > len - cursor )
			return 0;
		cursor += (size_t)v;
		/* fall through */
	case QUIC_IETF_0RTT_PACKET_TYPE:
	case QUIC_IETF_HANDSHAKE_PACKET_TYPE:
		//Length (i): Packet Number + Packet Payload
		if( ! _quic_ietf_read_varint(data, len, &cursor, &v) || v > len - cursor )
			return 0;
		return cursor + (size_t)v;
	default:
		return 0;
	}
}

/* Session lookup: a chained (coalesced) QUIC layer belongs to the connection
 * of the first QUIC layer of its datagram, whose session_data holds the
 * per-flow state. */
static quic_ietf_session_t *_quic_ietf_session_lookup(const ipacket_t *ipacket, unsigned index) {
	if( ipacket->session == NULL || index >= PROTO_PATH_SIZE )
		return NULL;
	const proto_hierarchy_t *path = ipacket->proto_hierarchy;
	while( path != NULL && index > 0 && (int)index < path->len
			&& path->proto_path[index - 1] == PROTO_QUIC_IETF )
		index--;
	return ipacket->session->session_data[index];
}

/* Length of the destination connection ID of a short-header packet. Short
 * headers omit it (RFC 9000 §5.1, §17.3): it is the source connection ID the
 * receiving endpoint announced in its own long headers, remembered per
 * endpoint by _quic_ietf_learn_cid_length(). Falls back to the historical 8
 * bytes when the flow's long headers were not seen. */
static uint8_t _quic_ietf_short_header_dcid_length(const ipacket_t *ipacket,
		const quic_ietf_session_t *session) {
	if( session != NULL && ipacket->internal_packet != NULL
			&& ipacket->internal_packet->dst != NULL ){
		for( int i = 0; i < 2; i++ )
			if( session->announced_cid[i].endpoint == ipacket->internal_packet->dst )
				return session->announced_cid[i].length;
	}
	return QUIC_IETF_DEFAULT_SHORT_HEADER_DCID_LENGTH;
}

/* non-static: driven directly by tools/phase0/tests/quic_dtls_extractor_test.c
   (declared in internal_decls.h — internal seam, not a public API) */
int _extraction_quic_ietf_att(const ipacket_t *ipacket, unsigned index,
		attribute_t * extracted_data) {
	int ioff = get_packet_offset_at_index(ipacket, index);
	if( ioff < 0 || (size_t)ioff >= ipacket->p_hdr->caplen )
		return ATTRIBUTE_UNSET;
	size_t offset = (size_t)ioff;
	size_t avail  = ipacket->p_hdr->caplen - offset;
	const uint8_t *data = ipacket->data;
	// first octet: header_form bit7
	uint8_t flags = data[ offset ];
	uint32_t u32;
	quic_ietf_session_t * session_data = _quic_ietf_session_lookup(ipacket, index);
	//extract session's attributes
	if( session_data != NULL ){
		int dir = (ipacket->internal_packet->src == session_data->quic_client ? CLIENT_TO_SERVER : SERVER_TO_CLIENT );
		spinbit_edge_t *edge = &session_data->spinbit_edge[dir];
		switch( extracted_data->field_id ){
		case QUIC_IETF_RTT:
			//return RTT only when we got 2 halfs of RTT
			if( edge->rtt_us ){
				(*(uint64_t *) extracted_data->data) = edge->rtt_us;
				return ATTRIBUTE_SET;
			} else
				return ATTRIBUTE_UNSET;
		}
	}

	if( flags & 0x80 ){
		//Long header — parse into a local descriptor, never onto the packet
		quic_ietf_long_header_t hdr;
		if( ! _quic_ietf_parse_long_header(data + offset, avail, &hdr) )
			return ATTRIBUTE_UNSET;

		switch( extracted_data->field_id ){
		case QUIC_IETF_HEADER_FORM:
			(*(uint8_t *) extracted_data->data) = (hdr.flags >> 7) & 1;
			return ATTRIBUTE_SET;
		case QUIC_IETF_LONG_PACKET_TYPE:
			//RFC 9000 numbering for every supported version (RFC 9369 §3.2)
			(*(uint8_t *) extracted_data->data) = _quic_ietf_long_packet_type(hdr.flags, hdr.version);
			return ATTRIBUTE_SET;
		case QUIC_IETF_VERSION:
			(*(uint32_t *) extracted_data->data) = hdr.version;
			return ATTRIBUTE_SET;
		case QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH:
			(*(uint16_t *) extracted_data->data) = hdr.destination_connection_id_length;
			return ATTRIBUTE_SET;
		case QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH:
			(*(uint16_t *) extracted_data->data) = hdr.source_connection_id_length;
			return ATTRIBUTE_SET;
		}

		//for each type of packet
		switch( _quic_ietf_long_packet_type(hdr.flags, hdr.version) ){
		//Initial: https://datatracker.ietf.org/doc/html/rfc9000#packet-initial
		case QUIC_IETF_INITIAL_PACKET_TYPE:
			switch( extracted_data->field_id ){
			case QUIC_IETF_TOKEN_LENGTH:
				//token_length is the first byte of the type-specific payload
				if( hdr.types_pecific_payload_offset >= avail )
					return ATTRIBUTE_UNSET;
				(*(uint16_t *) extracted_data->data) = data[ offset + hdr.types_pecific_payload_offset ];
				return ATTRIBUTE_SET;
			}
			break;
		//0-RTT: https://datatracker.ietf.org/doc/html/rfc9000#packet-0rtt
		case QUIC_IETF_0RTT_PACKET_TYPE:
			break;

		//Handshake: https://datatracker.ietf.org/doc/html/rfc9000#packet-handshake
		case QUIC_IETF_HANDSHAKE_PACKET_TYPE:
			break;
		//Retry: https://datatracker.ietf.org/doc/html/rfc9000#packet-retry
		case QUIC_IETF_RETRY_PACKET_TYPE:
			break;
		}
	} else {
		//Short header — flag bits are in data[offset], the destination
		//connection id at offset+1 (its length learned from the flow's long
		//headers), then the packet number (RFC 9000 §17.3).
		size_t dcid_len = _quic_ietf_short_header_dcid_length(ipacket, session_data);
		size_t pn_len   = (size_t)(flags & 3) + 1;
		switch( extracted_data->field_id ){
		case QUIC_IETF_HEADER_FORM:
			(*(uint8_t *) extracted_data->data) = (flags >> 7) & 1;
			return ATTRIBUTE_SET;
		case QUIC_IETF_SPIN_BIT:
			(*(uint8_t *) extracted_data->data) = (flags >> 5) & 1;
			return ATTRIBUTE_SET;
		case QUIC_IETF_PACKET_NUMBER_LENGTH:
			(*(uint8_t *) extracted_data->data) = flags & 3;
			return ATTRIBUTE_SET;
		case QUIC_IETF_DESTINATION_CONNECTION_ID:
			if( avail < 1 + dcid_len )
				return ATTRIBUTE_UNSET;
			{
				mmt_string_data_t *string = (mmt_string_data_t *) extracted_data->data;
				string->len = (uint32_t) dcid_len;
				memcpy( string->data, &data[ offset + 1 ], dcid_len );
				string->data[dcid_len] = '\0';
			}
			return ATTRIBUTE_SET;
		case QUIC_IETF_PACKET_NUMBER:
			//the Packet Number field is QUIC_IETF_PACKET_NUMBER_LENGTH + 1
			//bytes, big-endian
			if( avail < 1 + dcid_len + pn_len )
				return ATTRIBUTE_UNSET;
			u32 = 0;
			for( size_t i = 0; i < pn_len; i++ )
				u32 = (u32 << 8) | data[ offset + 1 + dcid_len + i ];
			(*(uint32_t *) extracted_data->data) = u32;
			return ATTRIBUTE_SET;
		}
	}
	return ATTRIBUTE_UNSET;
}

/* Wire minimums preserved from the old packed-overlay size gates so the
 * classification boundary is byte-identical: the old code required
 * sizeof(quic_ietf_long_header_t)=31 payload bytes for a long header and
 * sizeof(quic_ietf_1_rtt_packet_t)=21 for a short header. */
#define QUIC_IETF_LONG_HEADER_WIRE_MIN  31
#define QUIC_IETF_SHORT_HEADER_WIRE_MIN 21

static void _quic_ietf_session_data_init(ipacket_t * ipacket, unsigned index);
static int _quic_ietf_session_data_analysis(ipacket_t * ipacket, unsigned index);
static void _quic_ietf_learn_cid_length(ipacket_t * ipacket, unsigned index,
		quic_ietf_session_t * session);

/* session_index: protocol index whose QUIC session proves this flow already
 * showed a long header — the new QUIC layer's own index for a datagram
 * payload, the enclosing QUIC layer's index for a coalesced packet. */
static int _classify_quic_ietf_from_data_offset(ipacket_t *ipacket, unsigned session_index, size_t offset) {
	if( offset >= ipacket->p_hdr->caplen )
		return NOT_FOUND;
	size_t payload_len = ipacket->p_hdr->caplen - offset;
	// get the first octet of the UDP payload: header_form bit7, fixed_bit bit6
	uint8_t flags = ipacket->data[ offset ];
	if( flags & 0x80 ){
		// Long Header — must have enough room
		if( payload_len < QUIC_IETF_LONG_HEADER_WIRE_MIN )
			goto _not_found_quic_ietf;

		//fixed_bit (bit6) is set to 1.
		// Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded
		// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
		if( !(flags & 0x40) )
			goto _not_found_quic_ietf;
		//versions 1 (RFC 9000) and 2 (RFC 9369) share this wire image
		{
			uint32_t version;
			memcpy(&version, &ipacket->data[offset + 1], sizeof(version));
			if( ! _quic_ietf_is_supported_version( ntohl(version) ) )
				goto _not_found_quic_ietf;
		}

	} else {
		//Short Header

		//must have enough room to contain QUIC
		if( session_index >= PROTO_PATH_SIZE || ipacket->session == NULL )
			goto _not_found_quic_ietf;

		//QUIC session must be initialized (must be seen long header first)
		if( ipacket->session->session_data[session_index] == NULL )
			goto _not_found_quic_ietf;

		// must have enough room
		if( payload_len < QUIC_IETF_SHORT_HEADER_WIRE_MIN )
			goto _not_found_quic_ietf;

		if( !(flags & 0x40) ) //fixed_bit is set to 1
			goto _not_found_quic_ietf;

		//The reserved bits (0x18) are NOT checked: they are zero only
		//"prior to protection" — header protection (RFC 9001 §5.4.1) masks
		//them together with the packet number length, so on the wire they
		//carry arbitrary values until the header protection key removes the
		//mask, which a passive observer does not have.

		//check correct packet length
	}

	//if we can reach here => all signatures are valid => got QUIC
	//mmt_internal_add_connection(ipacket, PROTO_QUIC_IETF, MMT_REAL_PROTOCOL);
	//debug("classified QUIC");
	return FOUND;

	_not_found_quic_ietf:
	//checked but not found
	//=> exclude from the next check
	//MMT_ADD_PROTOCOL_TO_BITMASK(ipacket->internal_packet->flow->excluded_protocol_bitmask, PROTO_QUIC_IETF);
	return NOT_FOUND;
}

/* The protocol path is session-backed, so a QUIC-after-QUIC layer detected
 * on one datagram would stick to every later datagram of the flow. When the
 * current datagram carries no further coalesced packet, drop the trailing
 * chained QUIC layers (and any session data the core attached to them, which
 * the timeout cleanup — walking the path — would no longer reach). Only a
 * tail made purely of QUIC layers is ever touched. */
static void _quic_ietf_drop_chained_layers(ipacket_t *ipacket, unsigned index) {
	proto_hierarchy_t *path = ipacket->proto_hierarchy;
	if( path == NULL || path->len <= (int)index + 1 )
		return;
	int len = path->len > PROTO_PATH_SIZE ? PROTO_PATH_SIZE : path->len;
	for( int i = (int)index + 1; i < len; i++ )
		if( path->proto_path[i] != PROTO_QUIC_IETF )
			return;
	if( ipacket->session != NULL ){
		for( int i = (int)index + 1; i < len; i++ ){
			mmt_free( ipacket->session->session_data[i] );
			ipacket->session->session_data[i] = NULL;
		}
	}
	path->len = (int)index + 1;
	if( ipacket->proto_headers_offset != NULL )
		ipacket->proto_headers_offset->len = path->len;
	if( ipacket->proto_classif_status != NULL )
		ipacket->proto_classif_status->len = path->len;
	ipacket->internal_cumulative_offset_valid = 0;
}

/* Coalesced packets (RFC 9000 §12.2): a UDP datagram may carry several QUIC
 * packets back to back — every one but the last is a long header whose
 * Length field delimits it. Each valid QUIC packet after the one at
 * quic_index is classified as QUIC after QUIC (bounded by the protocol path
 * and the handler's classification depth); zero padding after the last
 * packet fails the fixed-bit check and is left alone. The chained layers
 * share the connection's session (the first QUIC layer's), which learns
 * their announced connection IDs. */
static void _quic_ietf_classify_coalesced(ipacket_t *ipacket, unsigned quic_index,
		quic_ietf_session_t *session) {
	unsigned index = quic_index;
	while( index + 1 < PROTO_PATH_SIZE ){
		int base = get_packet_offset_at_index(ipacket, index);
		if( base < 0 || (size_t)base >= ipacket->p_hdr->caplen )
			break;
		size_t avail = ipacket->p_hdr->caplen - (size_t)base;
		size_t first = _quic_ietf_long_packet_size( ipacket->data + base, avail );
		if( first == 0 || first >= avail )
			break;
		if( _classify_quic_ietf_from_data_offset( ipacket, quic_index, (size_t)base + first ) != FOUND )
			break;
		classified_proto_t retval;
		retval.offset = first;
		retval.proto_id = PROTO_QUIC_IETF;
		retval.status = Classified;
		if( ! set_classified_proto(ipacket, index + 1, retval) )
			break;
		index++;
		if( session != NULL )
			_quic_ietf_learn_cid_length( ipacket, index, session );
	}
	_quic_ietf_drop_chained_layers( ipacket, index );
}

/* Session init and analysis run from here, the classification entry point:
 * the UDP post-classification (udp_post_classification_function) ends the
 * pipeline walk at UDP for a layer it did not detect through the tcpip
 * protocol stack, so the core does not process this QUIC layer — its
 * registered session_data_init/analysis hooks would not run. The UDP checker
 * is dispatched on every packet of the flow, so this is the per-packet
 * analysis point; the registered hooks cover paths where the core does
 * process the layer (both are idempotent for one packet). */
static int _classified_quic_ietf(ipacket_t *ipacket, unsigned index, size_t offset){
	classified_proto_t retval;
	retval.offset = offset;
	retval.proto_id = PROTO_QUIC_IETF;
	retval.status = Classified;

	int ret = set_classified_proto(ipacket, index+1, retval);
	if( ! ret )
		return ret;
	_quic_ietf_session_data_init( ipacket, index+1 );
	_quic_ietf_session_data_analysis( ipacket, index+1 );
	_quic_ietf_classify_coalesced( ipacket, index+1,
			ipacket->session ? ipacket->session->session_data[index+1] : NULL );
	return ret;
}
static int _classify_quic_ietf_from_udp(ipacket_t *ipacket, unsigned index) {
	int base = get_packet_offset_at_index(ipacket, index);
	if( base < 0 || (size_t)base + 8 > ipacket->p_hdr->caplen )
		return NOT_FOUND;
	size_t offset = (size_t)base + 8; //8 bytes of UDP header
	if( _classify_quic_ietf_from_data_offset( ipacket, index + 1, offset ) == FOUND )
		return _classified_quic_ietf( ipacket, index, 8 );
	return NOT_FOUND;
}

static int _classify_quic_ietf_from_int(ipacket_t *ipacket, unsigned index) {
	//it is evident
	if( ipacket->proto_hierarchy->proto_path[index] != PROTO_INT )
		return NOT_FOUND;
	//classify only if we got UDP
	if( index >=1 && ipacket->proto_hierarchy->proto_path[index-1] != PROTO_UDP )
		return NOT_FOUND;

	int base = get_packet_offset_at_index(ipacket, index);
	if( base < 0 || (size_t)base >= ipacket->p_hdr->caplen )
		return NOT_FOUND;
	//the INT shim Length (byte 2) counts the shim, metadata header and
	//metadata stack in 4-byte words (INT v1.0 §4.6.1); fall back to the
	//historical fixed size when the shim is absent, of a type the INT
	//dissector does not parse (> 1) or smaller than shim + header — the
	//same rule as _int_header_length() in proto_int.c, so both agree on
	//where the layer after INT starts
	size_t int_len = QUIC_IETF_INT_DEFAULT_LENGTH;
	if( (size_t)base + 4 <= ipacket->p_hdr->caplen
			&& ipacket->data[ base ] <= 1 && ipacket->data[ base + 2 ] >= 3 )
		int_len = (size_t)ipacket->data[ base + 2 ] * 4;
	size_t offset = (size_t)base + int_len;
	if( offset >= ipacket->p_hdr->caplen )
		return NOT_FOUND;

	if( _classify_quic_ietf_from_data_offset( ipacket, index + 1, offset ) == FOUND )
		return _classified_quic_ietf( ipacket, index, int_len );
	return NOT_FOUND;
}

static void _quic_ietf_session_data_init(ipacket_t * ipacket, unsigned index) {
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

	quic_ietf_session_t * session_data = ipacket->session->session_data[index];
	if( session_data == NULL ){
		session_data = (quic_ietf_session_t *) mmt_malloc(sizeof (*session_data));
		debug("QUIC session init");
		memset(session_data, 0, sizeof(*session_data));
		ipacket->session->session_data[index] = session_data;

		session_data->quic_client = packet->src;
	}
}

/* Remember the source connection ID length an endpoint announces in its long
 * headers: its peer uses that connection ID as the DCID of the short-header
 * packets it sends to the endpoint (RFC 9000 §7.2). */
static void _quic_ietf_learn_cid_length(ipacket_t * ipacket, unsigned index,
		quic_ietf_session_t * session) {
	int ioff = get_packet_offset_at_index(ipacket, index);
	const void *src = ipacket->internal_packet ? ipacket->internal_packet->src : NULL;
	if( src == NULL || ioff < 0 || (size_t)ioff >= ipacket->p_hdr->caplen )
		return;
	const uint8_t *data = ipacket->data + ioff;
	size_t avail = ipacket->p_hdr->caplen - (size_t)ioff;
	quic_ietf_long_header_t hdr;
	if( !(data[0] & 0x80) || ! _quic_ietf_parse_long_header(data, avail, &hdr) )
		return;
	if( ! _quic_ietf_is_supported_version(hdr.version)
			|| hdr.source_connection_id_length > QUIC_IETF_MAX_CID_LENGTH )
		return;
	int slot = -1;
	for( int i = 0; i < 2 && slot < 0; i++ )
		if( session->announced_cid[i].endpoint == src )
			slot = i;
	for( int i = 0; i < 2 && slot < 0; i++ )
		if( session->announced_cid[i].endpoint == NULL )
			slot = i;
	if( slot < 0 )
		slot = 1;
	session->announced_cid[slot].endpoint = src;
	session->announced_cid[slot].length   = hdr.source_connection_id_length;
}


static void _quic_ietf_session_data_cleanup(mmt_session_t * session, unsigned index) {
	debug("QUIC session clean");
	if (session->session_data[index] != NULL) {
		mmt_free(session->session_data[index]);
	}
}



static void _quic_ietf_calculate_rtts(ipacket_t * ipacket, unsigned index, quic_ietf_session_t * session){
	attribute_t extracted_data;
	uint8_t spinbit = 0;
	//prepare to extract spinbit
	extracted_data.proto_id = PROTO_QUIC_IETF;
	extracted_data.field_id = QUIC_IETF_SPIN_BIT;
	extracted_data.data     = &spinbit;
	//get spinbit
	if( _extraction_quic_ietf_att( ipacket, index, &extracted_data ) == ATTRIBUTE_UNSET ){
		//no spinbit => long header
		//=> reset rtt
		memset(& session->spinbit_edge[0], 0, sizeof(spinbit_edge_t));
		memset(& session->spinbit_edge[1], 0, sizeof(spinbit_edge_t));
		debug("QUIC reset spinbit edge");

		//extract long packet type
		uint8_t long_packet_type = 0;
		extracted_data.field_id = QUIC_IETF_LONG_PACKET_TYPE;
		extracted_data.data     = &long_packet_type;

		//update quic client depending on the type of packet
		if( _extraction_quic_ietf_att( ipacket, index, &extracted_data ) == ATTRIBUTE_SET ){
			if( long_packet_type == QUIC_IETF_INITIAL_PACKET_TYPE )
				session->quic_client = ipacket->internal_packet->src;
			else if( long_packet_type == QUIC_IETF_HANDSHAKE_PACKET_TYPE )
				session->quic_client = ipacket->internal_packet->dst;
		}
		return;
	}

	int dir = (ipacket->internal_packet->src == session->quic_client ? CLIENT_TO_SERVER : SERVER_TO_CLIENT );
	spinbit_edge_t *edge = &session->spinbit_edge[dir];
	//we do not see see any modification of spinbit
	if( spinbit == edge->last_pkt_spinbit )
		return;
	edge->last_pkt_spinbit = spinbit;

	// avoid 2 consecutive edge in the same direction
	//if( session->spinbit_edge.pkt_src == ipacket->internal_packet->src )
	//	return;

	//timestamp of the current packet in microsecond
	size_t us = ipacket->p_hdr->ts.tv_sec * 1000000 + ipacket->p_hdr->ts.tv_usec;
	//avoid unordered packets
	if( us <= edge->pkt_us)
		return;

	//we got the spinbit edge here
	debug("QUIC spinbit edge %s at packet_id=%zu", dir == CLIENT_TO_SERVER? "c->s":"s->c", ipacket->packet_id);

	//get RTT ( pkt_us==0 for the first time )
	if( edge->pkt_us > 0 )
		edge->rtt_us = us - edge->pkt_us;

	//remember the last values
	edge->pkt_us  = us;
}

static int _quic_ietf_session_data_analysis(ipacket_t * ipacket, unsigned index) {
	//debug("QUIC session analysis");
	quic_ietf_session_t * session_data = ipacket->session->session_data[index];
	if( session_data == NULL )
		return MMT_CONTINUE;

	_quic_ietf_learn_cid_length( ipacket, index, session_data );
	_quic_ietf_calculate_rtts( ipacket, index, session_data );
	return MMT_CONTINUE;
}


#define def_att(id, data_type, data_len ) { id, id##_ALIAS, data_type, data_len, POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_quic_ietf_att}
static attribute_metadata_t _attributes_metadata[] = {
	def_att( QUIC_IETF_HEADER_FORM,      MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_LONG_PACKET_TYPE, MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_SPIN_BIT,         MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_VERSION,          MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH, MMT_U16_DATA,            sizeof(uint16_t) ),
	def_att( QUIC_IETF_DESTINATION_CONNECTION_ID,        MMT_STRING_LONG_DATA, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH,      MMT_U16_DATA,            sizeof(uint16_t) ),
	def_att( QUIC_IETF_SOURCE_CONNECTION_ID,             MMT_STRING_LONG_DATA, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_LENGTH,               MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_PACKET_NUMBER_LENGTH, MMT_U8_DATA,  sizeof(uint8_t) ),
	def_att( QUIC_IETF_PACKET_NUMBER,        MMT_U32_DATA, sizeof(uint32_t) ),
	def_att( QUIC_IETF_TOKEN_LENGTH,         MMT_U16_DATA, sizeof(uint16_t) ),
	def_att( QUIC_IETF_TOKEN,                MMT_STRING_LONG_DATA, sizeof(mmt_string_data_t) ),
	def_att( QUIC_IETF_RTT,                  MMT_U64_DATA, sizeof(uint64_t) )
};


int init_proto_quic_ietf_struct() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_QUIC_IETF, PROTO_QUIC_IETF_ALIAS);
	if( protocol_struct == NULL ){
		log_err("Cannot initialize PROTO_QUIC_IETF having id=%d", PROTO_QUIC_IETF);
		return PROTO_NOT_REGISTERED;
	}

	int i, len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ ){
		if( ! register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i]) ){
			log_err("Cannot register attribute %s.%s", PROTO_QUIC_IETF_ALIAS,  _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	}

	//QUIC is after UDP, so we classify it once we got UDP; coalesced
	//QUIC-after-QUIC packets are classified by the same checker
	//(_quic_ietf_classify_coalesced)
	if( !register_classification_function_with_parent_protocol( PROTO_UDP, _classify_quic_ietf_from_udp, 100 ) ){
		log_err("Need mmt_tcpip library containing PROTO_UDP having id = %d", PROTO_UDP);
		return PROTO_NOT_REGISTERED;
	}

	if( !register_classification_function_with_parent_protocol( PROTO_INT, _classify_quic_ietf_from_int, 100 ) ){
		log_err("Need mmt_tcpip library containing PROTO_INT having id = %d", PROTO_INT);
		return PROTO_NOT_REGISTERED;
	}

	mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
			&excluded_protocol_bitmask,
			MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
			PROTO_INT, PROTO_QUIC_IETF);

	//per-flow QUIC session (index-keyed session_data of the owning layer):
	//client endpoint, announced connection-ID lengths, spin-bit RTT
	register_session_data_initialization_function(protocol_struct, _quic_ietf_session_data_init);
	register_session_data_cleanup_function(protocol_struct, _quic_ietf_session_data_cleanup);
	register_session_data_analysis_function(protocol_struct, _quic_ietf_session_data_analysis);

	return register_protocol(protocol_struct, PROTO_QUIC_IETF);
}
