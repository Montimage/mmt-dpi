#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "mmt_common_internal_include.h"
#include "../../include/http2.h"
#include "../mmt_tcpip_plugin_structs.h" /* mmt_tcpip_internal_packet_t */
#include "../mmt_tcpip_plugin_structs.h" /* mmt_tcpip_internal_packet_t */

/*
 * HTTP/2 frame parser hardening (issue #4, H1).
 *
 * The parser reads multi-byte fields (2-4 bytes) at offsets derived from
 * attacker-controlled length fields, and in several places steps back one byte
 * (`proto_offset - 1`) before a 4-byte read. http2_can_read() bounds every such
 * access against the captured length: it returns 1 only when the n-byte window
 * starting at `offset` lies fully inside [0, caplen). A negative offset (e.g. an
 * underflowed `proto_offset - 1`) fails the check, and the (offset + n) sum is
 * computed in 64-bit so it cannot overflow for the small values involved.
 */
static inline int http2_can_read(int offset, unsigned int n, unsigned int caplen) {
	if (offset < 0)
		return 0;
	return ((uint64_t) offset + (uint64_t) n) <= (uint64_t) caplen;
}

/* issue #204 (F-BUG-057): mirror of http2_can_read() for the mutation side.
 * Every helper that writes into data_out must prove the whole n-byte window
 * starting at `offset` lies inside [0, data_out_size) before touching the
 * buffer — offsets and lengths below are attacker controlled (the HTTP/2
 * 24-bit frame length and the packet-derived proto_offset). */
static inline int http2_can_write(int offset, unsigned int n, unsigned int caplen) {
	if (offset < 0)
		return 0;
	return ((uint64_t) offset + (uint64_t) n) <= (uint64_t) caplen;
}

/* ---- HTTP/2 frame-type classification (RFC 7540 §6.1) ---- */

/* Forward declarations. */
static int http2_find_frame_offset(const ipacket_t *packet, unsigned proto_index,
		int frame_index, int *frame_offset, uint8_t *frame_type);
static int http2_walk_frames(const ipacket_t *packet, unsigned proto_index,
		uint8_t *frame_types, int *count, int out_size);

/* Walk all HTTP/2 frames in the TCP segment payload. Returns the number of
 * frames found. Skips the 24-byte connection preface if present. Each frame
 * is a 9-byte header (3-byte length + 1-byte type + 1-byte flags + 4-byte
 * stream ID) followed by a 24-bit-length payload. The walk is bounded by
 * the TCP segment's payload length (internal_packet->payload_packet_len).
 *
 * frame_types[out] receives the type byte of each frame; *count is set to
 * the number of frames found (capped at out_size). Returns 0 on success,
 * -1 if the segment is too short for even a header. */
static int http2_walk_frames(const ipacket_t *packet, unsigned proto_index,
		uint8_t *frame_types, int *count, int out_size) {
	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	unsigned int caplen = packet->p_hdr->caplen;
	int n_frames = 0;

	/* We need at least 9 bytes for a frame header. */
	if (!http2_can_read(proto_offset, 9, caplen))
		return -1;

	/* Get the TCP payload length to bound the walk. */
	struct mmt_tcpip_internal_packet_struct *internal =
		(struct mmt_tcpip_internal_packet_struct *) packet->internal_packet;
	unsigned int h2_end;
	if (internal && internal->payload_packet_len > 0
		&& (unsigned int)proto_offset + internal->payload_packet_len >= (unsigned int)proto_offset
		&& internal->payload_packet_len <= caplen) {
		/* Use the TCP payload length as the boundary. */
		h2_end = (unsigned int)proto_offset + internal->payload_packet_len;
	} else {
		/* Fall back to caplen — payload_packet_len may be incorrect
		 * (e.g. non-standard pcap link type causes misparse). */
		h2_end = caplen;
	}

	/* Skip the 24-byte connection preface if present. */
	int pos = proto_offset;
	if (h2_end - (unsigned int)pos >= 24
		&& strncmp((const char*)&packet->data[pos],
			"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
		pos += 24;
	}

	/* Walk frames. */
	while (pos + 9 <= (int)h2_end && n_frames < out_size) {
		/* Read the 3-byte length field. */
		if (!http2_can_read(pos, 3, caplen))
			break;
		uint32_t payload_len = 0;
		payload_len = (uint32_t)packet->data[pos] << 16
			| (uint32_t)packet->data[pos + 1] << 8
			| (uint32_t)packet->data[pos + 2];

		/* Read the type byte. */
		uint8_t frame_type = packet->data[pos + 3];
		frame_types[n_frames++] = frame_type;

		/* Advance past this frame: 9-byte header + payload. */
		uint64_t frame_total = (uint64_t)pos + 9 + (uint64_t)payload_len;
		if (frame_total > (uint64_t)h2_end)
			break; /* truncated frame — stop walking */
		pos = (int)frame_total;
	}

	*count = n_frames;
	return 0;
}

/* Find the byte offset of the Nth HTTP/2 frame (0-indexed) after skipping
 * the connection preface. Returns -1 if the frame index is out of range.
 * frame_offset[out] receives the base offset of that frame's 9-byte header.
 * frame_type[out] (if non-NULL) receives the frame's type byte. */
static int http2_find_frame_offset(const ipacket_t *packet, unsigned proto_index,
		int frame_index, int *frame_offset, uint8_t *frame_type) {
	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	unsigned int caplen = packet->p_hdr->caplen;

	if (!http2_can_read(proto_offset, 9, caplen))
		return -1;

	struct mmt_tcpip_internal_packet_struct *internal =
		(struct mmt_tcpip_internal_packet_struct *) packet->internal_packet;
	unsigned int h2_end;
	if (internal && internal->payload_packet_len > 0
		&& (unsigned int)proto_offset + internal->payload_packet_len >= (unsigned int)proto_offset
		&& internal->payload_packet_len <= caplen) {
		h2_end = (unsigned int)proto_offset + internal->payload_packet_len;
	} else {
		h2_end = caplen;
	}

	int pos = proto_offset;
	if (h2_end - (unsigned int)pos >= 24
		&& strncmp((const char*)&packet->data[pos],
			"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
		pos += 24;
	}

	int i;
	for (i = 0; i <= frame_index; i++) {
		if (pos + 9 > (int)h2_end)
			return -1;
		if (!http2_can_read(pos, 9, caplen))
			return -1;

		uint32_t payload_len = (uint32_t)packet->data[pos] << 16
			| (uint32_t)packet->data[pos + 1] << 8
			| (uint32_t)packet->data[pos + 2];

		if (i == frame_index) {
			if (frame_offset) *frame_offset = pos;
			if (frame_type) *frame_type = packet->data[pos + 3];
			return 0;
		}

		uint64_t frame_total = (uint64_t)pos + 9 + (uint64_t)payload_len;
		if (frame_total > (uint64_t)h2_end)
			return -1; /* truncated */
		pos = (int)frame_total;
	}

	return -1;
}

static const char *http2_frame_type_name(uint8_t type) {
	switch (type) {
		case HTTP2_FRAME_DATA:                return "DATA";
		case HTTP2_FRAME_HEADERS:             return "HEADERS";
		case HTTP2_FRAME_PRIORITY:            return "PRIORITY";
		case HTTP2_FRAME_RST_STREAM:          return "RST_STREAM";
		case HTTP2_FRAME_SETTINGS:            return "SETTINGS";
		case HTTP2_FRAME_PUSH_PROMISE:        return "PUSH_PROMISE";
		case HTTP2_FRAME_PING:                return "PING";
		case HTTP2_FRAME_GOAWAY:              return "GOAWAY";
		case HTTP2_FRAME_WINDOW_UPDATE:       return "WINDOW_UPDATE";
		case HTTP2_FRAME_CONTINUATION:        return "CONTINUATION";
		default:                              return "UNKNOWN";
	}
}

/* Extract ALL frame types found in the TCP segment.
 * Writes a comma-separated list like "DATA,HEADERS,RST_STREAM" into the
 * attribute buffer. */
static int http2_frame_type_name_extraction(const ipacket_t *packet,
		unsigned proto_index, attribute_t *extracted_data) {
	uint8_t frame_types[64];
	int n_frames = 0;

	if (http2_walk_frames(packet, proto_index, frame_types, &n_frames, 64) < 0)
		return 0;

	if (n_frames == 0)
		return 0;

	/* Build a comma-separated list. */
	char *buf = (char *)extracted_data->data;
	int pos = 0;
	int i;
	for (i = 0; i < n_frames; i++) {
		const char *name = http2_frame_type_name(frame_types[i]);
		int len = (int)strlen(name);
		if (pos + len + 1 >= 16) {
			/* Truncate — we have enough. */
			break;
		}
		if (i > 0) {
			buf[pos++] = ',';
		}
		memcpy(buf + pos, name, len);
		pos += len;
	}
	buf[pos] = '\0';
	return 1;
}

classified_proto_t http2_stack_classification(ipacket_t *ipacket) {

	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_HTTP2;
	retval.status = Classified;
	return retval;
}

int http2_header_method_extraction(const ipacket_t *packet,
		unsigned proto_index, attribute_t *extracted_data) {
	/* Report ALL frame types in the segment as a comma-separated list.
	 * This replaces the old single-byte type with a multi-frame list so
	 * security rules can detect RST_STREAM, HEADERS, etc. regardless of
	 * their position in the TCP segment. */
	uint8_t frame_types[64];
	int n_frames = 0;

	if (http2_walk_frames(packet, proto_index, frame_types, &n_frames, 64) < 0)
		return 0;

	if (n_frames == 0)
		return 0;

	char *buf = (char *)extracted_data->data;
	int pos = 0;
	int i;
	for (i = 0; i < n_frames; i++) {
		const char *name = http2_frame_type_name(frame_types[i]);
		int len = (int)strlen(name);
		if (pos + len + 1 >= 16)
			break;
		if (i > 0)
			buf[pos++] = ',';
		memcpy(buf + pos, name, len);
		pos += len;
	}
	buf[pos] = '\0';
	return 1;
}

int http2_header_length_extraction(const ipacket_t *packet,
		unsigned proto_index, attribute_t *extracted_data) {
	int proto_offset = get_packet_offset_at_index(packet, proto_index);

	/* Find the first real frame (skip the connection preface). */
	int frame_offset = 0;
	uint8_t frame_type = 0;
	if (http2_find_frame_offset(packet, proto_index, 0, &frame_offset, &frame_type) < 0)
		return 0;

	int attribute_offset = extracted_data->position_in_packet - 1;
	int read_offset = frame_offset + attribute_offset;
	//ensure the 4-byte length field is fully inside the packet; this also
	//guards the position-1 step-back from underflowing to a negative offset
	if (!http2_can_read(read_offset, sizeof(unsigned int), packet->p_hdr->caplen))
		return 0;

	*((unsigned int*) extracted_data->data) = ntohl(get_u32(packet->data, read_offset));
	*((unsigned int*) extracted_data->data) &= 0x00FFFFFF;
	if ((*((unsigned int*) extracted_data->data)) > 2000) {
		*((unsigned int*) extracted_data->data) = 0;
		return 0;
	}
	return 1;
}

int http2_payload_stream_id_extraction(const ipacket_t *packet,
		unsigned proto_index, attribute_t *extracted_data) {
	//Go to http2
	// [ETH][IP][TCP][HTTP2-HDR PAYLOAD][xxx]
	//===============^
	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	//Go to method field
	//9 header characters: 
	// - 3 bytes for length
	// - 1 byte for type
	// - 1 byte for flag
	// - 4 bytes for reserve
	int method_offset = proto_offset + 9;

	//not enough room to read the 1-byte method/type field
	if (!http2_can_read(method_offset, 1, packet->p_hdr->caplen))
		return 0;

	uint8_t method_value = *((uint8_t*) &packet->data[method_offset]);
	/* Handle all frame types that carry payload data with a stream ID.
	 * DATA (0x00), HEADERS (0x01), PUSH_PROMISE (0x05), PRIORITY (0x02),
	 * SETTINGS (0x04), PING (0x06), GOAWAY (0x07) all have payloads.
	 * RST_STREAM (0x03) and WINDOW_UPDATE (0x08) have fixed 4-byte payloads. */
	if ((method_value & 0x0F) == HTTP2_FRAME_DATA
		|| (method_value & 0x0F) == HTTP2_FRAME_HEADERS
		|| (method_value & 0x0F) == HTTP2_FRAME_PUSH_PROMISE
		|| (method_value & 0x0F) == HTTP2_FRAME_PRIORITY
		|| (method_value & 0x0F) == HTTP2_FRAME_SETTINGS
		|| (method_value & 0x0F) == HTTP2_FRAME_PING
		|| (method_value & 0x0F) == HTTP2_FRAME_GOAWAY
		|| (method_value & 0x0F) == HTTP2_FRAME_RST_STREAM
		|| (method_value & 0x0F) == HTTP2_FRAME_WINDOW_UPDATE) {

		// 3 bytes for payload length
		// we go back 1 byte to extract an integer of 4 bytes
		// we then later remove the latest byte
		// Get http2 protocol offset
		int offset_header_length = proto_offset - 1;
		//bounds-check the 4-byte length read; also rejects proto_offset == 0
		//(offset_header_length underflow)
		if (!http2_can_read(offset_header_length, sizeof(unsigned int), packet->p_hdr->caplen))
			return 0;
		int header_length = ntohl(get_u32(packet->data, offset_header_length));
		header_length = header_length & 0x00FFFFFF;
		// printf("header_length %d\n",header_length );
		int payload_offset = header_length + 9 + proto_offset;
		int stream_id_payload_offset = payload_offset + 5;

		//ensure the whole 4-byte stream id is inside the packet
		if( !http2_can_read(stream_id_payload_offset, sizeof(unsigned int), packet->p_hdr->caplen) )
			return 0;

		*((unsigned int*) extracted_data->data) = ntohl(get_u32(packet->data, stream_id_payload_offset));
		//printf("payload stream id %d\n",  *((unsigned int*) extracted_data->data));
		return 1;
	}
	return 0;
}

int http2_payload_length_extraction(const ipacket_t *packet,
		unsigned proto_index, attribute_t *extracted_data) {

	//Go to http2
	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	//Go to method field
	int method_offset = proto_offset + 9;


	//not enough room to read the 1-byte method/type field
	if (!http2_can_read(method_offset, 1, packet->p_hdr->caplen))
		return 0;

	uint8_t method_value = *((uint8_t*) &packet->data[method_offset]);
	/* Handle all frame types that carry payload data with a stream ID.
	 * DATA (0x00), HEADERS (0x01), PUSH_PROMISE (0x05), PRIORITY (0x02),
	 * SETTINGS (0x04), PING (0x06), GOAWAY (0x07) all have payloads.
	 * RST_STREAM (0x03) and WINDOW_UPDATE (0x08) have fixed 4-byte payloads. */
	if ((method_value & 0x0F) == HTTP2_FRAME_DATA
		|| (method_value & 0x0F) == HTTP2_FRAME_HEADERS
		|| (method_value & 0x0F) == HTTP2_FRAME_PUSH_PROMISE
		|| (method_value & 0x0F) == HTTP2_FRAME_PRIORITY
		|| (method_value & 0x0F) == HTTP2_FRAME_SETTINGS
		|| (method_value & 0x0F) == HTTP2_FRAME_PING
		|| (method_value & 0x0F) == HTTP2_FRAME_GOAWAY
		|| (method_value & 0x0F) == HTTP2_FRAME_RST_STREAM
		|| (method_value & 0x0F) == HTTP2_FRAME_WINDOW_UPDATE) {

		// Get http2 protocol offset
		int offset_header_length = proto_offset - 1;
		//bounds-check the 4-byte length read; also rejects proto_offset == 0
		//(offset_header_length underflow)
		if (!http2_can_read(offset_header_length, sizeof(unsigned int), packet->p_hdr->caplen))
			return 0;
		int header_length = ntohl(get_u32(packet->data, offset_header_length));
		header_length = header_length & 0x00FFFFFF;
		// printf("header_length %d\n",header_length );
		int payload_offset = header_length + 9 + proto_offset - 1;//In order to get to http2 payload you need to get the header length, adding the 9 bytes of the header.

		//ensure the whole 4-byte payload length is inside the packet
		if( !http2_can_read(payload_offset, sizeof(unsigned int), packet->p_hdr->caplen) )
			return 0;

		//Payload length is three bytes, while an integer is 4 bytes, so here we start from one byte before and and bitwise with 0x00FFFFFF that integer to remove last byte.
		*((unsigned int*) extracted_data->data) = ntohl(get_u32(packet->data, payload_offset));
		*((unsigned int*) extracted_data->data) &= 0x00FFFFFF;
		//printf("payload stream id %d\n",  *((unsigned int*) extracted_data->data));
		return 1;

	}
	return 0;
}

int http2_payload_data_extraction(const ipacket_t *packet, unsigned proto_index,
		attribute_t *extracted_data) {
	//Go to http2
	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	//Go to method field
	int method_offset = proto_offset + 9;

	//not enough room to read the 1-byte method/type field
	if (!http2_can_read(method_offset, 1, packet->p_hdr->caplen))
		return 0;

	uint8_t method_value = *((uint8_t*) &packet->data[method_offset]);
	/* Handle all frame types that carry payload data with a stream ID.
	 * DATA (0x00), HEADERS (0x01), PUSH_PROMISE (0x05), PRIORITY (0x02),
	 * SETTINGS (0x04), PING (0x06), GOAWAY (0x07) all have payloads.
	 * RST_STREAM (0x03) and WINDOW_UPDATE (0x08) have fixed 4-byte payloads. */
	if ((method_value & 0x0F) == HTTP2_FRAME_DATA
		|| (method_value & 0x0F) == HTTP2_FRAME_HEADERS
		|| (method_value & 0x0F) == HTTP2_FRAME_PUSH_PROMISE
		|| (method_value & 0x0F) == HTTP2_FRAME_PRIORITY
		|| (method_value & 0x0F) == HTTP2_FRAME_SETTINGS
		|| (method_value & 0x0F) == HTTP2_FRAME_PING
		|| (method_value & 0x0F) == HTTP2_FRAME_GOAWAY
		|| (method_value & 0x0F) == HTTP2_FRAME_RST_STREAM
		|| (method_value & 0x0F) == HTTP2_FRAME_WINDOW_UPDATE) {

		// Get http2 protocol offset
		int offset_header_length = proto_offset - 1;
		//bounds-check the 4-byte length read; also rejects proto_offset == 0
		//(offset_header_length underflow)
		if (!http2_can_read(offset_header_length, sizeof(unsigned int), packet->p_hdr->caplen))
			return 0;
		int header_length = ntohl(get_u32(packet->data, offset_header_length));
		header_length = header_length & 0x00FFFFFF;
		// printf("header_length %d\n",header_length );
		int payload_offset = header_length + 9 + proto_offset - 1;//In order to get to http2 payload you need to get the header length, adding the 9 bytes of the header.
		//Payload length is three bytes, while an integer is 4 bytes, so here we start from one byte before and and bitwise with 0x00FFFFFF that integer to remove last byte.
		//bounds-check the 4-byte payload-length read
		if (!http2_can_read(payload_offset, sizeof(unsigned int), packet->p_hdr->caplen))
			return 0;
		int payload_length = ntohl(get_u32(packet->data, payload_offset));
		payload_length &= 0x00FFFFFF;

		payload_offset += 9 + 1; //why?
		//use '<' so the data pointer addresses a byte still inside the packet
		if( http2_can_read(payload_offset, 1, packet->p_hdr->caplen) ){
			extracted_data->data = (char*) &packet->data[payload_offset];
			//printf("payload stream id %d\n",  *((unsigned int*) extracted_data->data));
			return 1;
		}

	}
	*((unsigned int*) extracted_data->data) = 0;

	return 0;
}
int http2_stream_id_extraction(const ipacket_t *packet, unsigned proto_index,
		attribute_t *extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);

	/* Find the first real frame (skip the connection preface). */
	int frame_offset = 0;
	uint8_t frame_type = 0;
	if (http2_find_frame_offset(packet, proto_index, 0, &frame_offset, &frame_type) < 0)
		return 0;

	int attribute_offset = extracted_data->position_in_packet;
	int read_offset = frame_offset + attribute_offset;
	//ensure the whole 4-byte stream id is inside the packet
	if (!http2_can_read(read_offset, sizeof(unsigned int), packet->p_hdr->caplen))
		return 0;
	*((unsigned int*) extracted_data->data) = (ntohl(get_u32(packet->data, read_offset)));
	return 1;
}

int _http2_classify_next_proto(ipacket_t * ipacket, unsigned index) {
	//packet offset of http2 header
	int proto_offset = get_packet_offset_at_index(ipacket, index);
	int http2_header_size = 0;
	const char *signature_http2 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";	//PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
	//only compare the preface when it is fully captured at this offset
	if (http2_can_read(proto_offset, strlen(signature_http2), ipacket->p_hdr->caplen)
			&& strncmp((char*) &ipacket->data[proto_offset], signature_http2, strlen(signature_http2)) == 0) {
		return 0;
	} else {

		//extract http2 length
		//extracted_data.position_in_packet = 1;
		//extracted_data.data = &http2_header_size;
		// Get http2 protocol offset: step back one byte to read a 4-byte int.
		//Bounds-check that read; this also rejects proto_offset == 0 underflow.
		if (!http2_can_read(proto_offset - 1, sizeof(unsigned int), ipacket->p_hdr->caplen))
			return 0;
		const char *payload = (char*) &ipacket->data[proto_offset - 1];
		http2_header_size = ntohl(get_u32(payload, 0));
		http2_header_size &= 0x00FFFFFF;
		http2_header_size = http2_header_size + 9;


		//ensure that we do not go out of the packet
		if( proto_offset + http2_header_size >= ipacket->p_hdr->caplen )
			return 0;

		//classify the next protocol that is after HTTP2
		// the next protocol resides inside the payload of HTTP2. The HTTP2 payload is the memory segment after the HTTP2 header
		// so we need to calculate the length of HTTP2 header
		classified_proto_t unknown_proto;
		unknown_proto.offset = http2_header_size;
		unknown_proto.proto_id = 0; //unknown protocol id
		unknown_proto.status = Classified;
		return set_classified_proto(ipacket, index+1, unknown_proto);
	}
}

static attribute_metadata_t http2_attributes_metadata[HTTP2_ATTRIBUTES_NB] = {

	{HTTP2_HEADER_LENGTH,     HTTP2_HEADER_LENGTH_ALIAS,    MMT_U32_DATA, sizeof(uint32_t),  0 , SCOPE_PACKET, http2_header_length_extraction},
	{HTTP2_TYPE,              HTTP2_TYPE_ALIAS,             MMT_STRING_DATA,  16, 3, SCOPE_PACKET, http2_header_method_extraction},//put here all extract function
	{HTTP2_HEADER_STREAM_ID,  HTTP2_HEADER_STREAM_ID_ALIAS, MMT_U32_DATA, sizeof(uint32_t),   5, SCOPE_PACKET, http2_stream_id_extraction},
	{HTTP2_HEADER_METHOD,     HTTP2_HEADER_METHOD_ALIAS,    MMT_U8_DATA, sizeof(char), 9, 	SCOPE_PACKET, http2_header_method_extraction},
	{HTTP2_PAYLOAD_LENGTH,    HTTP2_PAYLOAD_LENGTH_ALIAS,   MMT_U32_DATA, sizeof(uint32_t),POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_length_extraction},
	{HTTP2_PAYLOAD_STREAM_ID, HTTP2_PAYLOAD_STREAM_ID_ALIAS,MMT_U32_DATA, sizeof(uint32_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_stream_id_extraction},
	{HTTP2_PAYLOAD_DATA,      HTTP2_PAYLOAD_DATA_ALIAS,     MMT_DATA_POINTER,    sizeof (char*),    POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_data_extraction},

};

/* Extra attributes beyond the base set — registered separately so the
 * base array stays stable for existing consumers. */
static attribute_metadata_t http2_extra_metadata[] = {
	{HTTP2_FRAME_TYPE_NAME,   HTTP2_FRAME_TYPE_NAME_ALIAS,  MMT_STRING_DATA,  16, 3, SCOPE_PACKET, http2_frame_type_name_extraction},
};

int init_http2_proto_struct() {
	//printf("I am inside init_http2_proto_struct \n");
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_HTTP2, PROTO_HTTP2_ALIAS);
	//printf("Attribute_NB %d \n",HTTP2_ATTRIBUTES_NB);
	if (protocol_struct != NULL) {

		int i = 0;
		for (; i < HTTP2_ATTRIBUTES_NB; i++) {
			register_attribute_with_protocol(protocol_struct,
					&http2_attributes_metadata[i]);
		}

		if (!register_classification_function_with_parent_protocol(PROTO_TCP,
				mmt_check_http2, 9)) {
			mmt_stderr_log(
					"[err] init_http2_proto_struct - cannot register_classification_function_with_parent_protocol\n");
		};

		register_classification_function(protocol_struct, _http2_classify_next_proto);

		register_protocol_stack(PROTO_HTTP2, PROTO_HTTP2_ALIAS,
				http2_stack_classification);
		return register_protocol(protocol_struct, PROTO_HTTP2);
	} else
		return -1;
}

/*
 * HTTP2 data extraction routines
 */
int mmt_check_http2(ipacket_t *ipacket, unsigned proto_index) {

	// Get the offset for the packet to be classified at next protocol
	int proto_offset_tcp = get_packet_offset_at_index(ipacket, proto_index);
	int proto_offset = get_packet_offset_at_index(ipacket, proto_index + 1);
	//size of TCP header
	int tcp_header_size = proto_offset - proto_offset_tcp;
	//this attribute data is to use to extract http2 length
	//attribute_t extracted_data;
	//printf("Proto_offset  %d\n",proto_offset);

	//not enough room
	if (proto_offset >= ipacket->p_hdr->caplen || tcp_header_size < 0)
		return 0;

	//second way to calculate the offset
	const char *signature_http2 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";	//PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
	//only compare the preface when it is fully captured at this offset
	if (http2_can_read(proto_offset, strlen(signature_http2), ipacket->p_hdr->caplen)
			&& strncmp((char*) &ipacket->data[proto_offset], signature_http2, strlen(signature_http2)) == 0) {
		classified_proto_t http2_proto = http2_stack_classification(ipacket);
		http2_proto.offset = tcp_header_size;
		return set_classified_proto(ipacket, proto_index + 1, http2_proto);
	}
	return 0;
}

int restore_http2_packet(uint8_t*data_out,const ipacket_t * packet,int proto_offset,uint32_t data_out_size){
	uint32_t header_length = 0;
	int offset_header_length = proto_offset -1;
	/* issue #204 (F-BUG-057): bound the length-field reads before touching
	 * either buffer — proto_offset is packet-derived and may be negative. */
	if (!http2_can_read(offset_header_length, 4, data_out_size)
			|| !http2_can_read(offset_header_length, 4, packet->p_hdr->caplen))
		return 0;
	for (int i = offset_header_length; i < offset_header_length+4; i++) {
		header_length = (header_length << 8) | data_out[i];
	}
	header_length=header_length & 0x00FFFFFF;
	uint32_t new_length = 0;
	for (int i = offset_header_length; i < offset_header_length+4; i++) {
		new_length = (new_length << 8) | packet->data[i];
	}
	new_length = new_length & 0x00FFFFFF;
	// printf("new_length %d, header_length %d\n",new_length,header_length);
	// printf("data_out %02X packet_data %02X \n",data_out[proto_offset],packet->data[proto_offset]);
	/* The old check `new_length+9>data_out_size || proto_offset>data_out_size`
	 * forgot the proto_offset term entirely and used `>` where `>=` was
	 * required: the copy must satisfy proto_offset + new_length + 9 <= size
	 * on the write side and <= caplen on the read side. */
	if (!http2_can_write(proto_offset, (unsigned int)(new_length + 9), data_out_size)
			|| !http2_can_read(proto_offset, (unsigned int)(new_length + 9), packet->p_hdr->caplen))
		return 0;
	memcpy((uint8_t*)data_out+proto_offset,packet->data+proto_offset,new_length+9);
	return new_length-header_length;
}
int modify_get(uint8_t*data_out,int proto_offset,uint32_t data_out_size){
	//Go to method field
	uint32_t header_length = 0;
	// Get http2 protocol offset
	int offset_header_length = proto_offset -1;
	/* issue #204 (F-BUG-057): guard the 4-byte length read (offset may be
	 * negative) — the same window is later rewritten, so it must also be
	 * writable. */
	if (!http2_can_write(offset_header_length, 4, data_out_size))
		return 0;
	for (int i = offset_header_length; i < offset_header_length+4; i++) {
		header_length = (header_length << 8) | data_out[i];
	}
	header_length = header_length & 0x00FFFFFF;
	uint8_t authority_amf[] = {0x41,0x8d,0x0b,0xa2,0x5c,0x2e,0x2e,0xdb,0xeb,0xba,0xcd,0xc7,0x80,0xf0,0x3f,0x7a,0x03,0x61,0x6d,0x66};
	int authority_amf_length = sizeof(authority_amf) ;
	//printf("[modify_get]authority_amf_length %d\n",authority_amf_length);
	/* The old check `proto_offset+9+header_length-2 > data_out_size` verified
	 * only the write *start* (and with `>` instead of `>=`): bound the whole
	 * authority_amf window instead. */
	if (!http2_can_write(proto_offset + 9 + header_length - 2, authority_amf_length, data_out_size))
		return 0;
	memcpy(data_out+proto_offset+9+header_length-2,authority_amf,authority_amf_length);
	//printf("modify get after update:\n");
	//for(int i=proto_offset+9+header_length-2;i<proto_offset+9+header_length-2+authority_amf_length;i++)
	//	printf("%02hhX ",data_out[i]);
	header_length += authority_amf_length-2;//Http2 buffers the authority and amf with 2 bytes(0xc0 0xc1)from the first packet.The code restore the first authority_amf value.
	//The new header lenght will be the sizeof authority and amf minus 2
	data_out[offset_header_length+1] = header_length>>16; //I update the last 24 bites
	data_out[offset_header_length+2] = header_length>>8; //I update the last 16 bites
	data_out[offset_header_length+3] = header_length ;//I update the last 8 bites
	//printf("[modify_get]offset_header_length %02hhX %02hhX %02hhX \n",data_out[offset_header_length+1],data_out[offset_header_length+2],data_out[offset_header_length+3]);
	return (int)(sizeof(authority_amf)-2);
}
uint32_t update_window_update(char *data_out,int proto_offset,uint32_t modify,uint32_t data_out_size){
	int window_size_offset = proto_offset+9;
	//int offset_header_length = proto_offset -1;
	if(modify == 1){
		/* issue #204 (F-BUG-057): the 4-byte window-size write had no bound. */
		if (!http2_can_write(window_size_offset, 4, data_out_size))
			return 0;
		data_out[window_size_offset] = 0x00;
		data_out[window_size_offset+1] = 0x00;
		data_out[window_size_offset+2] = 0x00;
		data_out[window_size_offset+3] = 0xFF;	
		int difference_size = -9;
		return difference_size;
	}
	//int header_length=0;
	//int header_length =ntohl( *((unsigned int *) & packet->data[offset_header_length]));
	return 0;
}

int inject_http2_packet(uint8_t*data_out, uint8_t*data_to_inject,int proto_offset,int data_to_inject_len, uint32_t data_out_size){
	int offset_header_length = proto_offset -1;
	uint32_t header_length = 0;
	/* issue #204 (F-BUG-057): guard the length-field read and bound the
	 * injected copy against the space actually remaining at proto_offset. */
	if (!http2_can_read(offset_header_length, 4, data_out_size))
		return 0;
	for (int i = offset_header_length; i < offset_header_length+4; i++) {
		header_length = (header_length << 8) | data_out[i];
	}
	header_length = header_length & 0x00FFFFFF;
	// printf("inject_http2_packet Header_length %d",header_length);
	if (data_to_inject_len <= 0
			|| !http2_can_write(proto_offset, (unsigned int) data_to_inject_len, data_out_size))
		return 0;
	memcpy(data_out + proto_offset,data_to_inject,data_to_inject_len);
	return (data_to_inject_len - header_length-9);
}

int update_stream_id(char *data_out,int proto_offset,uint32_t new_val,uint32_t data_out_size){

	int stream_id_offset = proto_offset+5;
	/* issue #204 (F-BUG-057): this helper took no buffer size at all; every
	 * write/read window below is now checked against data_out_size. */
	if (!http2_can_write(stream_id_offset, 4, data_out_size))
		return 0;
	data_out[stream_id_offset] = new_val>> 24;
	data_out[stream_id_offset+1] = new_val>> 16;
	data_out[stream_id_offset+2] = new_val>> 8;
	data_out[stream_id_offset+3] = new_val;
	//printf("update_stream_id  data_out[stream_id_offset] after the modification %02hhX %02hhX %02hhX %02hhX  \n",data_out[stream_id_offset],data_out[stream_id_offset+1],data_out[stream_id_offset+2],data_out[stream_id_offset+3]);
	int offset_header_length = proto_offset -1;
	int method_offset = proto_offset+9;
	if (!http2_can_read(method_offset, 1, data_out_size))
		return 0;
	uint8_t method_value = ((uint8_t )  data_out[method_offset]);
	/* Handle all frame types that carry payload data with a stream ID.
	 * DATA (0x00), HEADERS (0x01), PUSH_PROMISE (0x05), PRIORITY (0x02),
	 * SETTINGS (0x04), PING (0x06), GOAWAY (0x07) all have payloads.
	 * RST_STREAM (0x03) and WINDOW_UPDATE (0x08) have fixed 4-byte payloads. */
	if ((method_value & 0x0F) == HTTP2_FRAME_DATA
		|| (method_value & 0x0F) == HTTP2_FRAME_HEADERS
		|| (method_value & 0x0F) == HTTP2_FRAME_PUSH_PROMISE
		|| (method_value & 0x0F) == HTTP2_FRAME_PRIORITY
		|| (method_value & 0x0F) == HTTP2_FRAME_SETTINGS
		|| (method_value & 0x0F) == HTTP2_FRAME_PING
		|| (method_value & 0x0F) == HTTP2_FRAME_GOAWAY
		|| (method_value & 0x0F) == HTTP2_FRAME_RST_STREAM
		|| (method_value & 0x0F) == HTTP2_FRAME_WINDOW_UPDATE) {
		uint32_t header_length = 0;
		if (!http2_can_read(offset_header_length, 4, data_out_size))
			return 0;
		//int header_length =ntohl( *((unsigned int *) & packet->data[offset_header_length]));
		for (int i = offset_header_length; i < offset_header_length+4; i++) {
			header_length = (header_length << 8) | data_out[i];
		}
		header_length = header_length & 0x00FFFFFF;
		//printf("update_stream_id header_length %d\n",header_length );
		int payload_offset = header_length+9+proto_offset;
		int stream_id_payload_offset = payload_offset+5;
		if (!http2_can_write(stream_id_payload_offset, 4, data_out_size))
			return 0;
		data_out[stream_id_payload_offset]   = new_val >> 24;
		data_out[stream_id_payload_offset+1] = new_val >> 16;
		data_out[stream_id_payload_offset+2] = new_val >> 8;
		data_out[stream_id_payload_offset+3] = new_val;
		//printf("update_stream_id  data_out[stream_id_payload_offset] after the modification %02hhX \n",data_out[stream_id_payload_offset]);
	}
	return 1;
}

int fuzz_payload(uint8_t*data_out,const ipacket_t*packet,int proto_offset,uint32_t data_out_size){
	//Go to method field
	uint32_t header_length = 0;
	uint32_t payload_length = 0;
	// Get http2 protocol offset
	int offset_header_length = proto_offset -1;

	const char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;\'///:,.<>/?\\";
	/* issue #204 (F-BUG-057): both length fields are attacker controlled —
	 * guard every read and bound the fuzzed write window. */
	if (!http2_can_read(offset_header_length, 4, data_out_size))
		return 0;
	for (int i = offset_header_length; i < offset_header_length+4; i++) {
		header_length = (header_length << 8) | data_out[i];
	}
	header_length = header_length & 0x00FFFFFF;
	//printf("fuzz_payload header_length %d\n",header_length );
	int payload_offset = header_length+9+proto_offset-1;
	//printf("fuzz payload payload_pffset %d\n",payload_offset);
	if (!http2_can_read(payload_offset, 4, data_out_size))
		return 0;
	for (int i = payload_offset; i < payload_offset+4; i++) {
		payload_length = (payload_length << 8) | data_out[i];
		//        printf(" data_out[payload_offset]%02hhX  ", data_out[i]);
	}
	int mask = 0x00FFFFFF; // mask to set last 2 bytes to 0
	payload_length = payload_length & mask; // put to 0 last byte
	//printf("fuzz_payload payload_length %d\n",payload_length );
	payload_offset = payload_offset+ 9+1;
	/* The loop writes data_out[i] for i in (payload_offset+payload_length/2,
	 * payload_offset+payload_length] — bound the whole window. */
	if (!http2_can_write(payload_offset, (unsigned int) payload_length + 1, data_out_size))
		return 0;
	//printf("%d \n",data_out[payload_offset]);
	for(int i = payload_offset+payload_length;i > (int)((payload_offset+(payload_length/2)));i--){
		int r = rand() % (sizeof(characters)-1);
		data_out[i] = characters[r];
	}
	// printf("fuzz_payload data_out after modification");
	//for(int i=payload_offset;i<payload_offset+payload_length;i++)
	//	printf("%c",data_out[i]);
	return 0;
}


int update_http2_data( char *data_out, uint32_t data_size, const ipacket_t *packet, uint32_t proto_id, uint32_t att_id, uint32_t new_val ){
	//Go to http2
	//printf("update_http2_data Id of packet is   ");
	//printf(" %lu \n",packet->packet_id);
	int difference_size = 0;
	uint32_t ret = 0;
	if( proto_id != PROTO_HTTP2 )
		return ret;
	int proto_http2 = get_protocol_index_by_id(packet, proto_id);

	const int proto_offset = get_packet_offset_at_index(packet,proto_http2);
	uint8_t window_update_frame[] = {0x00,0x00,0x04,0x08,0x00,0x00,0x00,0x00,0x00,
		0x0f,0xff,0x00,0x01//window size increment:set to a small value
	};
	int win_len = (int)sizeof(window_update_frame);

	//printf("Proto offset %d and proto_id %u",proto_offset,proto_id);
	//Go to method field
	//data_out  = (char*) &packet->data[proto_offset ];
	switch(att_id){

		case(HTTP2_HEADER_STREAM_ID):
			update_stream_id(data_out,proto_offset,new_val,data_size);
			break;
		
		case(HTTP2_WINDOW_UPDATE):
			difference_size = update_window_update(data_out,proto_offset,new_val,data_size);
			return difference_size; 
			break;
			
		case(HTTP2_DISCARD_SETTINGS):
			difference_size = -9;
			return difference_size; 

		case(HTTP2_PAYLOAD_FUZZ):
			fuzz_payload((uint8_t*)data_out,packet,proto_offset,data_size);
			//printf("[update_http2_data]data_size %d\n",data_size);
			update_stream_id(data_out,proto_offset,new_val,data_size);
			break;
			
		case(HTTP2_GET_MODIFY):
			update_stream_id(data_out,proto_offset,new_val,data_size);
			difference_size = modify_get((uint8_t*)data_out, proto_offset,data_size);
			return difference_size;
			break;
			
		case(HTTP2_INJECT_WIN_UPDATE):
			difference_size = inject_http2_packet((uint8_t*)data_out,window_update_frame,proto_offset,win_len,data_size);
			return difference_size;
			break;
			
		case (HTTP2_RESTORE_PACKET):
			difference_size = restore_http2_packet((uint8_t*)data_out,packet,proto_offset,data_size);
			return difference_size;
			break;

		default:
			//printf("update_http2_data  INSERT A VALID ATT_ID  \n");
			break;
	
	}

	return 0;
	

}

