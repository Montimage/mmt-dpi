/* Generated with MMT Plugin Generator */

#ifndef GEO_NETWORKING_H
#define GEO_NETWORKING_H
#ifdef __cplusplus
extern "C"
{
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

	struct gn_basic_header
	{
		uint8_t nex_header : 4, version : 4;
		uint8_t reserved;
		uint8_t life_time;
		uint8_t remaining_hop_limit;
	};
	struct gn_secured_packet
	{
		uint8_t version;
		uint8_t head_var_length : 7, head_var_length_determination : 1;
	};

	// struct gn_secured_packet_payload
	// {
	// 	uint8_t type;
	// 	uint8_t payload_var_length : 7, payload_var_length_determination : 1;
	// };

	struct gn_common_header
	{
		uint8_t reserved0 : 4, next_header : 4;
		uint8_t header_type;
		uint8_t traffic_class;
		uint8_t flags;
		uint16_t payload_length;
		uint8_t max_hop_limit;
		uint8_t reserved;
	};

	enum geo_networking_attributes
	{
		GN_BASIC_HEADER_NEXT_HEADER = 1,
		GN_SECURED_PACKET_LENGTH,
		GN_COMMON_HEADER_NEXT_HEADER,
		GN_COMMON_HEADER_HEADER_TYPE,
		GN_COMMON_HEADER_PAYLOAD_LENGTH,
		GN_ATTRIBUTES_NB = GN_COMMON_HEADER_PAYLOAD_LENGTH,
	};

#define GN_BASIC_HEADER_NEXT_HEADER_ALIAS "basic_header_next_header"
#define GN_SECURED_PACKET_LENGTH_ALIAS "secured_packet_length"
#define GN_COMMON_HEADER_NEXT_HEADER_ALIAS "common_header_next_header"
#define GN_COMMON_HEADER_HEADER_TYPE_ALIAS "common_header_header_type"
#define GN_COMMON_HEADER_PAYLOAD_LENGTH_ALIAS "common_header_payload_length"

#ifdef __cplusplus
}
#endif
#endif /* ARP_H */
