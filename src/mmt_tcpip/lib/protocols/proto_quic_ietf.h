/*
 * proto_quic_ietf.h
 *
 *  Created on: Feb 16, 2023
 *      Author: nhnghia
 */

#ifndef SRC_MMT_TCPIP_LIB_PROTOCOLS_PROTO_QUIC_IETF_H_
#define SRC_MMT_TCPIP_LIB_PROTOCOLS_PROTO_QUIC_IETF_H_


#include "plugin_defs.h"
#include "mmt_core.h"


/**
https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
Long Header Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2),
  Type-Specific Bits (4),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Type-Specific Payload (..),
}
*/
typedef struct quic_ietf_long_header {
#ifdef __BIG_ENDIAN_BITFIELD
	uint8_t header_form       : 1; //is set to 1 for long headers
	uint8_t fixed_bit         : 1; //is set to 1, unless the packet is a Version Negotiation packet.
	                               //Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded
	uint8_t long_packet_type  : 2; //
	uint8_t types_pecific_bits: 4; // being determined by the packet type
#else
	uint8_t types_pecific_bits: 4; // being determined by the packet type
	uint8_t long_packet_type  : 2; //
	uint8_t fixed_bit         : 1; //is set to 1, unless the packet is a Version Negotiation packet.
	                               //Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded
	uint8_t header_form       : 1; //is set to 1 for long headers
#endif

	uint32_t version;

	uint8_t destination_connection_id_length;
	const uint8_t *destination_connection_id; //0 up to 160 bytes.
	                                     // In QUIC version 1, this MUST NOT exceed 20 bytes, MUST drop the packet if so
	uint8_t source_connection_id_length;
	const uint8_t *source_connection_id;  //0 up to 160 bytes

	const uint8_t *types_pecific_payload; //The remainder of the packet, if any, is type specific.
}  __attribute__((packed))
quic_ietf_long_header_t;

//https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
typedef struct quic_ietf_initial_packet {
	uint8_t token_length;
	const uint8_t *token;
	uint16_t length;
	uint32_t packet_number; //8..32bits
	const uint8_t *packet_payload;
}quic_ietf_initial_packet_t;

//https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.3
typedef struct quic_ietf_0_rtt_packet {
	uint16_t length;
	uint32_t packet_number; //8..32bits
	const uint8_t *packet_payload;
}quic_ietf_0_rtt_packet_t;

//https://datatracker.ietf.org/doc/html/rfc9000#packet-handshake
typedef struct quic_ietf_handshake_packet {
	uint16_t length;
	uint32_t packet_number; //8..32bits
	const uint8_t *packet_payload;
}quic_ietf_hanshake_packet_t;

//https://datatracker.ietf.org/doc/html/rfc9000#name-retry-packet
typedef struct quic_ietf_retry_packet {
	const uint8_t *retry_token;
	uint8_t retry_integrity_tag[16];
}quic_ietf_retry_packet_t;

//https://datatracker.ietf.org/doc/html/rfc9000#name-short-header-packets
typedef struct quic_ietf_1_rtt_packet {
#ifdef __BIG_ENDIAN_BITFIELD
	uint8_t header_form         : 1; //is set to 0
	uint8_t fixed_bit           : 1; //is set to 1. Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded
	uint8_t spin_bit            : 1;
	uint8_t reserved_bits       : 2; //MUST be set to 0
	uint8_t key_phase           : 1;
	uint8_t packet_number_length: 2; //the length of the Packet Number field is the value of this field plus one
#else
	uint8_t packet_number_length: 2; //the length of the Packet Number field is the value of this field plus one
	uint8_t key_phase           : 1;
	uint8_t reserved_bits       : 2; //MUST be set to 0
	uint8_t spin_bit            : 1;
	uint8_t fixed_bit           : 1; //is set to 1. Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded
	uint8_t header_form         : 1; //is set to 0
#endif
	uint8_t destination_connection_id[8]; //0..160, TODO: fixed 8 bytes for now
	uint8_t packet_number[4]; // (8..32),
	const uint8_t *packet_payload;
} __attribute__((packed))
quic_ietf_1_rtt_packet_t;

typedef quic_ietf_1_rtt_packet_t quic_ietf_short_packet_t;


typedef struct quic_ietf_session {
	//we need to remember the length of connection ID so that we can get them in packets of short header form
	uint16_t destination_connection_id_length;
	uint16_t source_connection_id_length;
	uint8_t packet_number_length;
} quic_ietf_session_t;


#define PROTO_QUIC_IETF_ALIAS "quic_ietf"
enum quic_ietf_attributes {
	QUIC_IETF_HEADER_FORM = 1,
	QUIC_IETF_LONG_PACKET_TYPE,
	QUIC_IETF_SPIN_BIT,
	QUIC_IETF_VERSION,
	QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH,
	QUIC_IETF_DESTINATION_CONNECTION_ID,
	QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH,
	QUIC_IETF_SOURCE_CONNECTION_ID,
	QUIC_IETF_LENGTH,
	QUIC_IETF_PACKET_NUMBER_LENGTH,
	QUIC_IETF_PACKET_NUMBER,
	QUIC_IETF_TOKEN_LENGTH,
	QUIC_IETF_TOKEN
};


#define QUIC_IETF_HEADER_FORM_ALIAS                      "header_form"
#define QUIC_IETF_LONG_PACKET_TYPE_ALIAS                 "long_packet_type"
#define QUIC_IETF_SPIN_BIT_ALIAS                         "spin_bit"
#define QUIC_IETF_VERSION_ALIAS                          "version"
#define QUIC_IETF_DESTINATION_CONNECTION_ID_LENGTH_ALIAS "dst_conn_id_len"
#define QUIC_IETF_DESTINATION_CONNECTION_ID_ALIAS        "dst_conn_id"
#define QUIC_IETF_SOURCE_CONNECTION_ID_LENGTH_ALIAS      "src_conn_id_len"
#define QUIC_IETF_SOURCE_CONNECTION_ID_ALIAS             "src_conn_id"
#define QUIC_IETF_LENGTH_ALIAS                           "length"
#define QUIC_IETF_PACKET_NUMBER_LENGTH_ALIAS             "packet_number_len"
#define QUIC_IETF_PACKET_NUMBER_ALIAS                    "packet_number"
#define QUIC_IETF_TOKEN_LENGTH_ALIAS                     "token_len"
#define QUIC_IETF_TOKEN_ALIAS                            "token"

#endif /* SRC_MMT_TCPIP_LIB_PROTOCOLS_PROTO_QUIC_IETF_H_ */
