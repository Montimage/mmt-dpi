/*
 * inband_telemetry.h
 *
 *  Created on: Dec 21, 2021
 *      Author: nhnghia
 */

#ifndef SRC_MMT_TCPIP_LIB_PROTOCOLS_INBAND_TELEMETRY_H_
#define SRC_MMT_TCPIP_LIB_PROTOCOLS_INBAND_TELEMETRY_H_

#include "plugin_defs.h"
#include "mmt_core.h"


/**
 * INT shim header for TCP/UDP:
 *   the INT metadata header and INT metadata stack will be encapsulated
 *   between the shim header and the TCP/UDP payload
 *
 * [1] The P4.org Working Group, “In-band Network Telemetry (INT) Dataplane Specification V1.0,” P4.org Appl. Work. Gr., pp. 1–42, 2020.
 * Section 4.6.1. INT over TCP/UDP

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Type           |   Reserved    |  Length       | DSCP      |R R|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct int_shim_tcpudp_v10_struct {
	uint8_t type;
	uint8_t reserved_1;
	uint8_t length; //total length of INT metadata header, INT stack and the shim header in 4-byte words.

#ifdef __BIG_ENDIAN_BITFIELD
	uint8_t
	DSCP       :6, //If IP DSCP is used to indicate INT, this field optionally stores the original DSCP value. Otherwise, this field is reserved
	reserved_2 :2; //2 reserved bits for future use
#else
	uint8_t
	reserved_2 :2,
	DSCP       :6;
#endif
} __attribute__((packed))
int_shim_tcpudp_v10_t;


/**
 * Section 4.7. INT Hop-by-Hop Metadata Header Format
 * [1] The P4.org Working Group, “In-band Network Telemetry (INT) Dataplane Specification V1.0,” P4.org Appl. Work. Gr., pp. 1–42, 2020.
 * Section 4.6.1. INT over TCP/UDP

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver   |Rep|C|E|M|     Reserved      |  Hop ML |RemainingHopCnt|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Instruction Bitmap         |          Reserved             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| INT Metadata Stack (Each hop inserts Hop ML * 4B of metadata) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Last INT metadata                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
typedef struct int_hop_by_hop_v10_struct {
#ifdef __BIG_ENDIAN_BITFIELD
	uint8_t
	ver :4, //version: should be 1
	rep :2, //Replication requested.
	c   :1, //copy
	e   :1; //Max Hop Count exceeded.

	uint8_t
	m      :1, //MTU exceeded
	reserved_1 :7;

	uint8_t
	reserved_2  :3,
	hop_ml :5, //
#else
	uint8_t
	e    :1,
	c    :1,
	rep  :2,
	ver  :4;

	uint8_t
	reserved_1 :7,
	m      :1;

	uint8_t
	hop_ml :5, //Per-hop Metadata Length, the length of metadata in 4-Byte words
	reserved_2 :3;
#endif

	uint8_t  remain_hop_count; //The remaining number of hops that are allowed to add their metadata to the packet
	uint16_t instructions; //INT instructions are encoded as a bitmap in the 16-bit INT Instruction field
	uint16_t reserved_3;
} __attribute__((packed))
int_hop_by_hop_v10_t;


#endif /* SRC_MMT_TCPIP_LIB_PROTOCOLS_INBAND_TELEMETRY_H_ */
