/*
 * proto_quic_ietf.c
 *
 *  Created on: Feb 16, 2023
 *      Author: nhnghia
 */

#include "proto_quic_ietf.h"
#include "proto_int.h"
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
#define QUIC_IETF_UDP_HEADER_LEN 8
/* Issue #571: a capture that starts mid-connection shows only 1-RTT
 * packets. The flow is QUIC once QUIC_IETF_SH_MIN_PACKETS client packets to
 * UDP/QUIC_IETF_SH_PORT in a row carried the same first
 * QUIC_IETF_SH_DCID_PREFIX bytes of DCID; QUIC_IETF_SH_REJECTED marks a flow
 * shown not to be QUIC. */
#define QUIC_IETF_SH_PORT 443
#define QUIC_IETF_SH_MIN_PACKETS 4
#define QUIC_IETF_SH_DCID_PREFIX 8
#define QUIC_IETF_SH_REJECTED 0xff
/* TURN ChannelData (RFC 8656 §12.4) on UDP: channel numbers 0x4000-0x4fff,
 * a 16-bit length after them, the data padded to 4 bytes at most. */
#define QUIC_IETF_TURN_CHANNEL_MASK 0xf0
#define QUIC_IETF_TURN_CHANNEL_HIGH 0x40
#define QUIC_IETF_TURN_HEADER_LEN 4
#define QUIC_IETF_TURN_MAX_PADDING 3

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

static inline int _quic_ietf_is_chained(const ipacket_t *ipacket, unsigned index);

/* Issue #571: the SNI, ALPN and JA4 of the client's ClientHello, reported on
 * the packet whose Initial completed it, for the flow's first QUIC layer. */
static int _quic_ietf_hello_attribute(const ipacket_t *ipacket, unsigned index,
		const quic_ietf_session_t *session, attribute_t *extracted_data) {
	static __thread mmt_int_one_line_struct_t lines[QUIC_IETF_TLS_JA4 - QUIC_IETF_SERVER_NAME + 1];
	const quic_hello_facts_t *hello = session->crypto.hello;
	if( hello == NULL || session->hello_packet_id != ipacket->packet_id
			|| _quic_ietf_is_chained( ipacket, index ) )
		return ATTRIBUTE_UNSET;
	mmt_int_one_line_struct_t *line = &lines[extracted_data->field_id - QUIC_IETF_SERVER_NAME];
	switch( extracted_data->field_id ){
	case QUIC_IETF_SERVER_NAME:
		line->ptr = (const uint8_t *) hello->sni;
		line->len = hello->sni_len;
		break;
	case QUIC_IETF_TLS_ALPN:
		line->ptr = (const uint8_t *) hello->alpn;
		line->len = hello->alpn_len;
		break;
	default:
		line->ptr = (const uint8_t *) hello->ja4;
		line->len = hello->has_ja4 ? TLS_JA4_LEN : 0;
		break;
	}
	if( line->len == 0 )
		return ATTRIBUTE_UNSET;
	extracted_data->data = line;
	return ATTRIBUTE_SET;
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
		case QUIC_IETF_SERVER_NAME:
		case QUIC_IETF_TLS_ALPN:
		case QUIC_IETF_TLS_JA4:
			return _quic_ietf_hello_attribute( ipacket, index, session_data, extracted_data );
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

/* Bytes the IP header declares from the UDP header at data offset udp_off
 * on: the IPv4 total length (proto_ip.c keeps the captured length when it
 * is 0) or the IPv6 payload length, less what precedes the UDP header. The
 * captured length only for an IPv6 jumbogram, whose length the header does
 * not carry. Unlike packet->l4_packet_len, a snap length does not cut it. */
static size_t _quic_ietf_ip_declared_len(const ipacket_t *ipacket, size_t udp_off) {
	const struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	if( packet->iph != NULL ){
		size_t ip_off = (size_t) ((uintptr_t) packet->iph - (uintptr_t) ipacket->data);
		if( ip_off > udp_off || udp_off - ip_off > packet->l3_packet_len )
			return 0;
		return packet->l3_packet_len - (udp_off - ip_off);
	}
	if( packet->iphv6 != NULL ){
		const uint8_t *ip6 = (const uint8_t *) packet->iphv6;
		size_t ip_off = (size_t) ((uintptr_t) ip6 - (uintptr_t) ipacket->data);
		size_t plen = ((size_t) ip6[4] << 8) | ip6[5];
		if( plen == 0 )
			return ipacket->p_hdr->caplen - udp_off;
		if( udp_off < ip_off + sizeof(struct mmt_ipv6hdr)
				|| udp_off - ip_off - sizeof(struct mmt_ipv6hdr) > plen )
			return 0;
		return plen - (udp_off - ip_off - sizeof(struct mmt_ipv6hdr));
	}
	return ipacket->p_hdr->caplen - udp_off;
}

/* Bytes of the UDP datagram from data offset `offset` on, as the UDP header
 * bounds the datagram inside the IP payload — the derivation of
 * udp_pre_classification_function before its caplen clamp: udp->len, at
 * most what the IP header declares, 0 meaning all of it (issue #571). Never
 * the captured length, which an FCS trailer or a snap length changes. 0
 * without a UDP header or when `offset` is not inside the datagram. */
static size_t _quic_ietf_udp_datagram_len(const ipacket_t *ipacket, size_t offset) {
	const struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	if( packet == NULL || packet->udp == NULL )
		return 0;
	uintptr_t udp_off = (uintptr_t) packet->udp - (uintptr_t) ipacket->data;
	if( udp_off >= ipacket->p_hdr->caplen
			|| ipacket->p_hdr->caplen - udp_off < QUIC_IETF_UDP_HEADER_LEN )
		return 0;
	size_t bound = _quic_ietf_ip_declared_len( ipacket, (size_t) udp_off );
	size_t udp_len = ntohs( packet->udp->len );
	if( udp_len != 0 && udp_len < bound )
		bound = udp_len;
	size_t start = (size_t) udp_off + QUIC_IETF_UDP_HEADER_LEN;
	if( bound <= QUIC_IETF_UDP_HEADER_LEN || offset < start
			|| offset - start >= bound - QUIC_IETF_UDP_HEADER_LEN )
		return 0;
	return bound - QUIC_IETF_UDP_HEADER_LEN - (offset - start);
}

/* TURN ChannelData framing (RFC 8656 §12.4): a channel number 0x4000-0x4fff
 * whose length field + 4 is the datagram length, up to 3 bytes of padding
 * aside. It looks like a QUIC 1-RTT first byte, and with constant-size data
 * its next 8 bytes repeat like a DCID (issue #571). */
static int _quic_ietf_is_turn_channel_data(const uint8_t *data, size_t avail, size_t datagram_len) {
	if( avail < QUIC_IETF_TURN_HEADER_LEN
			|| (data[0] & QUIC_IETF_TURN_CHANNEL_MASK) != QUIC_IETF_TURN_CHANNEL_HIGH )
		return 0;
	size_t framed = QUIC_IETF_TURN_HEADER_LEN + (((size_t) data[2] << 8) | data[3]);
	return datagram_len >= framed && datagram_len - framed <= QUIC_IETF_TURN_MAX_PADDING;
}

/* Issue #571: a short header on a flow with no QUIC session (the capture
 * started mid-connection). Client packets to UDP/443 count when they repeat
 * the first 8 bytes after the first one — the DCID of a 1-RTT packet, which
 * a connection keeps; other bytes restart the count. Packets from port 443
 * neither count nor reset (the client's DCID is often empty). A packet with
 * the fixed bit clear, or TURN ChannelData framing, in either direction shows
 * the flow is not QUIC: it is never counted again. The state lives in the
 * UDP flow's l4 bytes, so the flow record does not grow. Returns 1 when this
 * packet makes the verdict. */
static int _quic_ietf_short_header_candidate(ipacket_t *ipacket, size_t offset) {
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	if( packet == NULL || packet->flow == NULL || packet->udp == NULL
			|| offset >= ipacket->p_hdr->caplen )
		return 0;
	//right after the UDP header only (not behind INT)
	if( offset != (size_t) ((uintptr_t) packet->udp - (uintptr_t) ipacket->data) + QUIC_IETF_UDP_HEADER_LEN )
		return 0;
	struct mmt_internal_udp_session_struct *udp = &packet->flow->l4.udp;
	uint16_t dport = ntohs( packet->udp->dest );
	if( udp->quic_sh_count == QUIC_IETF_SH_REJECTED
			|| (dport != QUIC_IETF_SH_PORT && ntohs( packet->udp->source ) != QUIC_IETF_SH_PORT) )
		return 0;
	const uint8_t *data = ipacket->data + offset;
	size_t avail = ipacket->p_hdr->caplen - offset;
	if( !(data[0] & 0x40)
			|| _quic_ietf_is_turn_channel_data( data, avail, _quic_ietf_udp_datagram_len( ipacket, offset ) ) ){
		udp->quic_sh_count = QUIC_IETF_SH_REJECTED;
		return 0;
	}
	if( dport != QUIC_IETF_SH_PORT || avail < QUIC_IETF_SHORT_HEADER_WIRE_MIN )
		return 0;
	if( udp->quic_sh_count == 0
			|| memcmp( udp->quic_sh_dcid, data + 1, QUIC_IETF_SH_DCID_PREFIX ) != 0 ){
		memcpy( udp->quic_sh_dcid, data + 1, QUIC_IETF_SH_DCID_PREFIX );
		udp->quic_sh_count = 1;
		return 0;
	}
	if( udp->quic_sh_count < QUIC_IETF_SH_MIN_PACKETS )
		udp->quic_sh_count++;
	return udp->quic_sh_count >= QUIC_IETF_SH_MIN_PACKETS;
}

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
		//a v1/v2 connection ID is at most 20 bytes (RFC 9000 §17.2, issue
		//#570); with DCID length <= 20 the SCID length byte at 6 + DCID
		//length lies inside the QUIC_IETF_LONG_HEADER_WIRE_MIN bytes checked
		//above
		{
			uint8_t dcid_len = ipacket->data[offset + 5];
			if( dcid_len > QUIC_IETF_MAX_CID_LENGTH
					|| ipacket->data[offset + 6 + dcid_len] > QUIC_IETF_MAX_CID_LENGTH )
				goto _not_found_quic_ietf;
		}

	} else {
		//Short Header

		//must have enough room to contain QUIC
		if( session_index >= PROTO_PATH_SIZE || ipacket->session == NULL )
			goto _not_found_quic_ietf;

		//QUIC session must be initialized (must be seen long header first),
		//or the flow must look like QUIC from mid-connection (issue #571)
		if( ipacket->session->session_data[session_index] == NULL
				&& ! _quic_ietf_short_header_candidate( ipacket, offset ) )
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
	//MMT_EXCLUDE_PROTOCOL(ipacket->internal_packet->flow, PROTO_QUIC_IETF);
	return NOT_FOUND;
}

/* Issue #571: `proto`, last in the path, is the application layer the flow's
 * QUIC session appended (_quic_ietf_append_app_layer). */
static int _quic_ietf_is_app_layer(const ipacket_t *ipacket, unsigned index, uint32_t proto) {
	const quic_ietf_session_t *session = _quic_ietf_session_lookup( ipacket, index );
	return session != NULL && proto != PROTO_UNKNOWN && proto != PROTO_QUIC_IETF
			&& (proto == session->app_layer || proto == session->app_proto);
}

/* The protocol path is session-backed, so a QUIC-after-QUIC layer detected
 * on one datagram would stick to every later datagram of the flow. When the
 * current datagram carries no further coalesced packet, drop the trailing
 * chained QUIC layers (and any session data the core attached to them, which
 * the timeout cleanup — walking the path — would no longer reach). Only a
 * tail made purely of QUIC layers, possibly followed by the flow's
 * application layer (issue #571), is ever touched. */
static void _quic_ietf_drop_chained_layers(ipacket_t *ipacket, unsigned index) {
	proto_hierarchy_t *path = ipacket->proto_hierarchy;
	if( path == NULL || path->len <= (int)index + 1 )
		return;
	int len = path->len > PROTO_PATH_SIZE ? PROTO_PATH_SIZE : path->len;
	//the flow's application layer after the chained tail goes with it: it is
	//appended again after the datagram's last QUIC layer (issue #571)
	int quic_end = len;
	if( _quic_ietf_is_app_layer( ipacket, index, path->proto_path[len - 1] ) )
		quic_end = len - 1;
	for( int i = (int)index + 1; i < quic_end; i++ )
		if( path->proto_path[i] != PROTO_QUIC_IETF )
			return;
	if( ipacket->session != NULL ){
		for( int i = (int)index + 1; i < quic_end; i++ ){
			mmt_free( ipacket->session->session_data[i] );
			ipacket->session->session_data[i] = NULL;
		}
	}
	path->len = (int)index + 1;
	if( ipacket->proto_headers_offset != NULL )
		ipacket->proto_headers_offset->len = path->len;
	if( ipacket->proto_classif_status != NULL )
		ipacket->proto_classif_status->len = path->len;
	ipacket_internal(ipacket)->internal_cumulative_offset_valid = 0;
}

/* Issue #571: the application the flow's SNI names — or the IP-range guess
 * a mid-flow QUIC verdict took the place of — follows the datagram's last
 * QUIC layer `last`, with its own classification method (set_classified_proto
 * records DPI for a checker's write). */
static void _quic_ietf_append_app_layer(ipacket_t *ipacket, unsigned last) {
	quic_ietf_session_t *session = _quic_ietf_session_lookup( ipacket, last );
	if( session == NULL || session->app_proto == PROTO_UNKNOWN || last + 1 >= PROTO_PATH_SIZE )
		return;
	classified_proto_t retval;
	retval.offset = 0; //the application shares the QUIC payload
	retval.proto_id = session->app_proto;
	retval.status = Classified;
	if( set_classified_proto(ipacket, last + 1, retval) ){
		session->app_layer = session->app_proto;
		if( ipacket->session != NULL )
			ipacket->session->classification_method = session->app_method;
	}
}

/* The datagram's last QUIC layer is `last`: drop what an earlier datagram
 * chained after it, then append the flow's application layer. */
static void _quic_ietf_settle_tail(ipacket_t *ipacket, unsigned last) {
	_quic_ietf_drop_chained_layers( ipacket, last );
	_quic_ietf_append_app_layer( ipacket, last );
}

/* A QUIC checker that found no QUIC on a flow already classified as QUIC
 * (path[quic_index] is QUIC): this datagram carries no coalesced packet, so
 * the chained tail left by an earlier datagram must not stick to it. */
static void _quic_ietf_drop_stale_chain(ipacket_t *ipacket, unsigned quic_index) {
	const proto_hierarchy_t *path = ipacket->proto_hierarchy;
	if( path != NULL && quic_index < PROTO_PATH_SIZE && (int)quic_index < path->len
			&& path->proto_path[quic_index] == PROTO_QUIC_IETF )
		_quic_ietf_settle_tail( ipacket, quic_index );
}

/* RFC 9000 §12.2: senders never coalesce packets with different connection
 * IDs, and receivers ignore a later packet whose destination connection ID
 * differs from the first packet's. A short header carries no DCID length:
 * it is the first packet's (same connection ID). With a zero-length
 * connection ID there is nothing to compare. */
static int _quic_ietf_same_dcid(const uint8_t *pkt, size_t avail,
		const uint8_t *dcid, size_t dcid_len) {
	if( pkt[0] & 0x80 ){
		quic_ietf_long_header_t hdr;
		if( ! _quic_ietf_parse_long_header(pkt, avail, &hdr)
				|| hdr.destination_connection_id_length != dcid_len )
			return 0;
		return memcmp( pkt + hdr.destination_connection_id_offset, dcid, dcid_len ) == 0;
	}
	if( avail < 1 + dcid_len )
		return 0;
	return memcmp( pkt + 1, dcid, dcid_len ) == 0;
}

/* Coalesced packets (RFC 9000 §12.2): a UDP datagram may carry several QUIC
 * packets back to back — every one but the last is a long header whose
 * Length field delimits it. Each valid QUIC packet after the one at
 * quic_index is classified as QUIC after QUIC (bounded by the protocol path
 * and the handler's classification depth) when it carries the first
 * packet's destination connection ID; zero padding after the last packet
 * fails the fixed-bit check, and trailing bytes with another DCID fail the
 * DCID match — both are left alone. The chained layers share the
 * connection's session (the first QUIC layer's), which learns their
 * announced connection IDs. */
static void _quic_ietf_classify_coalesced(ipacket_t *ipacket, unsigned quic_index,
		quic_ietf_session_t *session) {
	unsigned index = quic_index;
	const uint8_t *dcid = NULL;
	size_t dcid_len = 0;
	{
		int qoff = get_packet_offset_at_index(ipacket, quic_index);
		quic_ietf_long_header_t hdr;
		if( qoff >= 0 && (size_t)qoff < ipacket->p_hdr->caplen
				&& (ipacket->data[qoff] & 0x80)
				&& _quic_ietf_parse_long_header( ipacket->data + qoff,
						ipacket->p_hdr->caplen - (size_t)qoff, &hdr ) ){
			dcid = ipacket->data + qoff + hdr.destination_connection_id_offset;
			dcid_len = hdr.destination_connection_id_length;
		}
	}
	while( dcid != NULL && index + 1 < PROTO_PATH_SIZE ){
		int base = get_packet_offset_at_index(ipacket, index);
		if( base < 0 || (size_t)base >= ipacket->p_hdr->caplen )
			break;
		size_t avail = ipacket->p_hdr->caplen - (size_t)base;
		size_t first = _quic_ietf_long_packet_size( ipacket->data + base, avail );
		if( first == 0 || first >= avail )
			break;
		if( ! _quic_ietf_same_dcid( ipacket->data + base + first, avail - first, dcid, dcid_len ) )
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
	_quic_ietf_settle_tail( ipacket, index );
}

/* Issue #571: the IP-range application guess the UDP fallback left at the
 * QUIC layer's place (a flow first seen from mid-connection), else
 * PROTO_UNKNOWN. */
static uint32_t _quic_ietf_ip_range_guess(const ipacket_t *ipacket, unsigned index) {
	const proto_hierarchy_t *path = ipacket->proto_hierarchy;
	if( path == NULL || ipacket->session == NULL || index >= PROTO_PATH_SIZE || (int)index >= path->len
			|| ipacket->session->classification_method != MMT_CLASSIFICATION_METHOD_IP
			|| path->proto_path[index] == PROTO_QUIC_IETF )
		return PROTO_UNKNOWN;
	return path->proto_path[index];
}

/* Session init and analysis run from here, the classification entry point:
 * the UDP post-classification (udp_post_classification_function) ends the
 * pipeline walk at UDP for a layer it did not detect through the tcpip
 * protocol stack, so the core does not process this QUIC layer — its
 * registered session_data_init/analysis hooks would not run. The UDP checker
 * is dispatched on every packet of the flow up to the classification
 * threshold, so this is the per-packet analysis point; past the threshold
 * the core processes the layer and the registered hooks take over (both are
 * idempotent for one packet). The analysis also walks the coalesced
 * packets of the datagram. */
static int _classified_quic_ietf(ipacket_t *ipacket, unsigned index, size_t offset){
	classified_proto_t retval;
	retval.offset = offset;
	retval.proto_id = PROTO_QUIC_IETF;
	retval.status = Classified;

	uint32_t guess = _quic_ietf_ip_range_guess( ipacket, index+1 );
	int ret = set_classified_proto(ipacket, index+1, retval);
	if( ! ret )
		return ret;
	_quic_ietf_session_data_init( ipacket, index+1 );
	//keep the guess as the application after QUIC (issue #571)
	quic_ietf_session_t *session = ipacket->session->session_data[index+1];
	if( guess != PROTO_UNKNOWN && session != NULL && session->app_proto == PROTO_UNKNOWN ){
		session->app_proto  = guess;
		session->app_method = MMT_CLASSIFICATION_METHOD_IP;
	}
	_quic_ietf_session_data_analysis( ipacket, index+1 );
	return ret;
}
static int _classify_quic_ietf_from_udp(ipacket_t *ipacket, unsigned index) {
	int base = get_packet_offset_at_index(ipacket, index);
	if( base < 0 || (size_t)base + 8 > ipacket->p_hdr->caplen )
		return NOT_FOUND;
	size_t offset = (size_t)base + 8; //8 bytes of UDP header
	if( _classify_quic_ietf_from_data_offset( ipacket, index + 1, offset ) == FOUND )
		return _classified_quic_ietf( ipacket, index, 8 );
	_quic_ietf_drop_stale_chain( ipacket, index + 1 );
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
	//historical fixed size when the captured bytes are not a valid shim —
	//the same validator as _int_header_length() in proto_int.c, so both
	//agree on where the layer after INT starts
	size_t int_len = proto_int_valid_shim_length( &ipacket->data[ base ],
			ipacket->p_hdr->caplen - (uint32_t)base );
	if( int_len == 0 )
		int_len = QUIC_IETF_INT_DEFAULT_LENGTH;
	size_t offset = (size_t)base + int_len;
	if( offset < ipacket->p_hdr->caplen
			&& _classify_quic_ietf_from_data_offset( ipacket, index + 1, offset ) == FOUND )
		return _classified_quic_ietf( ipacket, index, int_len );
	_quic_ietf_drop_stale_chain( ipacket, index + 1 );
	return NOT_FOUND;
}

/* A chained (coalesced) QUIC layer: the QUIC layer before it owns the
 * connection's session (_quic_ietf_session_lookup). */
static inline int _quic_ietf_is_chained(const ipacket_t *ipacket, unsigned index) {
	const proto_hierarchy_t *path = ipacket->proto_hierarchy;
	return path != NULL && index > 0 && index < PROTO_PATH_SIZE && (int)index < path->len
			&& path->proto_path[index - 1] == PROTO_QUIC_IETF;
}

static void _quic_ietf_session_data_init(ipacket_t * ipacket, unsigned index) {
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

	//a chained layer shares the owning layer's session: allocating one here
	//would leave an orphan the owning layer never updates
	if( _quic_ietf_is_chained( ipacket, index ) )
		return;

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
	quic_ietf_session_t *session_data = session->session_data[index];
	if (session_data != NULL) {
		//the CRYPTO reassembly and the ClientHello facts (issue #571)
		quic_crypto_release( &session_data->crypto );
		mmt_free(session_data);
	}
}

/* Issue #571: the client's Initials carry its TLS ClientHello in CRYPTO
 * frames, under keys every observer derives (quic_ietf_crypto.h). Once it is
 * whole, its SNI, ALPN and JA4 are reported on this packet and the SNI names
 * the flow's application through the hostname table (hostname_classify),
 * like a TLS SNI (proto_ssl.c). */
static void _quic_ietf_read_crypto(ipacket_t * ipacket, unsigned index, quic_ietf_session_t * session){
	if( session->crypto.state != QUIC_CRYPTO_ACTIVE || session->crypto_packet_id == ipacket->packet_id
			|| ipacket->internal_packet == NULL )
		return;
	session->crypto_packet_id = ipacket->packet_id; //once per packet
	int ioff = get_packet_offset_at_index(ipacket, index);
	if( ioff < 0 || (size_t)ioff >= ipacket->p_hdr->caplen )
		return;
	size_t datagram_len = _quic_ietf_udp_datagram_len( ipacket, (size_t)ioff );
	size_t avail = ipacket->p_hdr->caplen - (size_t)ioff;
	if( avail > datagram_len )
		avail = datagram_len;
	if( quic_crypto_consume( &session->crypto, ipacket->internal_packet->src,
			ipacket->data + ioff, avail, datagram_len ) != QUIC_CRYPTO_HELLO )
		return;
	session->hello_packet_id = ipacket->packet_id;
	quic_hello_facts_t *hello = session->crypto.hello;
	if( hello->sni_len == 0 || ipacket->mmt_handler == NULL || ipacket->mmt_handler->hostname_classify != 1 )
		return;
	uint32_t app = get_proto_id_by_hostname( ipacket, hello->sni, hello->sni_len );
	if( app != PROTO_UNKNOWN ){
		session->app_proto  = app;
		session->app_method = MMT_CLASSIFICATION_METHOD_HOSTNAME;
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

/* Per-packet analysis of the owning QUIC layer; chained layers are analysed
 * by the owning layer's coalesced-packet walk. The walk re-derives the
 * chain from the current datagram on every packet — including past the
 * classification threshold, when the checker no longer runs and the core
 * calls this hook — so a chain classified on an earlier datagram never
 * persists on a later one. */
static int _quic_ietf_session_data_analysis(ipacket_t * ipacket, unsigned index) {
	//debug("QUIC session analysis");
	if( _quic_ietf_is_chained( ipacket, index ) )
		return MMT_CONTINUE;
	quic_ietf_session_t * session_data = ipacket->session->session_data[index];
	if( session_data != NULL ){
		_quic_ietf_learn_cid_length( ipacket, index, session_data );
		_quic_ietf_calculate_rtts( ipacket, index, session_data );
		_quic_ietf_read_crypto( ipacket, index, session_data );
	}
	_quic_ietf_classify_coalesced( ipacket, index, session_data );
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
	def_att( QUIC_IETF_RTT,                  MMT_U64_DATA, sizeof(uint64_t) ),
	def_att( QUIC_IETF_SERVER_NAME,          MMT_HEADER_LINE, sizeof(void *) ),
	def_att( QUIC_IETF_TLS_ALPN,             MMT_HEADER_LINE, sizeof(void *) ),
	def_att( QUIC_IETF_TLS_JA4,              MMT_HEADER_LINE, sizeof(void *) )
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
