/*
 * proto_ips_data.c
 *
 *  Created on: Jun 3, 2021
 *      Author: nhnghia
 */


#include "mmt_business_app_internal.h"
#include <time.h>
#include <sys/time.h>

/*
TrolleyPos: 32.981, Hoistpos: 38.042, NoOfMarkers: 3, m1: (58901,70912) , m2: (72175,70950) , m3: (65803,71939) , m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)
TrolleyPos: 32.978, Hoistpos: 38.124, NoOfMarkers: 3, m1: (58843,70948) , m2: (72122,70987) , m3: (65767,71983) , m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)
T:2023-08-03 15:21:25.108736, PVAct: 1 , MhPos: 35.000, TrPos: -12.000, GaPos: 0.000, MhSpdRef: 0.0, TrSpdRef: 0.0, GaSpdRef: 0.0, MhSpdAct: 0.0, TrSpdAct: 0.0, GaSpdAct: 0.0, MhStopOk: False, TrStopOk: False, GaStopOk: False


 */

#define HAS_STR( x ) (x[0] != '\0') //check if string is not empty
#define ASSIGN_STR( x, y, len ) while( HAS_STR(y) ){ memcpy(x, y, len); break; }

static int _ips_data_classify_next_proto(ipacket_t *packet, unsigned index) {
	int offset = get_packet_offset_at_index(packet, index);
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	if( data_len <= 0 )
		return 0;
	//started by "TrolleyPos" ??
	if( strncmp("TrolleyPos", data, 10) != 0 )
		return 0;

	classified_proto_t retval;
	retval.proto_id = PROTO_IPS_DATA;
	retval.offset = 0;
	retval.status = Classified;
	return set_classified_proto(packet, index + 1, retval);
	return 0;
}

static inline const char *_get_pos( int main_length, const char *main, const char *sub ){
	int i, j;
	if( main == NULL || sub == NULL || main_length == 0 )
		return NULL;

	const size_t sub_length = strlen( sub );
	for( i=0; i<main_length; i++ ){
		for( j=0; j<sub_length; j++ )
			if( i + j >= main_length || main[i+j] != sub[j] )
				break;
		//find a full sub
		if( j == sub_length )
			return & main[i+j];
	}
	return NULL;
}

static inline void _assign_uint32_t(const char* ptr, attribute_t * extracted_data){
	if( ptr )
		*((uint32_t *) extracted_data->data) = (uint32_t)atol( ptr );
	else
		*((uint32_t *) extracted_data->data) = 0;
}

static inline void _assign_float(const char* ptr, attribute_t * extracted_data){
	if( ptr ){
		*((float *) extracted_data->data) = atof( ptr );
	}
		
	else
		*((float *) extracted_data->data) = 0;
}

static inline void _assign_date(const char* ptr, attribute_t * extracted_data){
	if( ptr ){

		struct tm timestamp; // structure to store info about date and hour
		memset(&timestamp, 0, sizeof(struct tm)); 
		strptime(ptr, "%Y-%m-%d %H:%M:%S", &timestamp); // analyse memory locaction and store it in the struct
		double decimal_seconds = strtod(strchr(ptr, '.') + 1, NULL) / 1000000.0;
		struct timeval tv;
		tv.tv_sec = mktime(&timestamp);
		tv.tv_usec = (long)(decimal_seconds * 1000000.0);
		memcpy(extracted_data->data, &tv, sizeof(struct timeval));
	}
	else
		printf("Problems while reading pointer location, %s", &ptr);

}

static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {

	int offset = get_packet_offset_at_index(packet, proto_index);
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	const char* ptr;
	if( data_len <= 0 )
		return 0;
	switch( extracted_data->field_id ){
	case IPS_DATA_TROLLEY_POS:
		ptr = _get_pos( data_len, data, "TrPos:" );
		_assign_float( ptr, extracted_data );
		// printf("STO PRENDENDO: %f\n", atof( ptr ));

		break;

	case IPS_DATA_HOIST_POS:
		ptr = _get_pos( data_len, data, "MhPos:" );
		_assign_float( ptr, extracted_data );
		break;
	case IPS_DATA_GANTRY_POS:
		ptr = _get_pos( data_len, data, "GaPos:" );
		_assign_float( ptr, extracted_data );
		break;
	
	case IPS_DATA_NO_OF_MARKERS:
		ptr = _get_pos( data_len, data, "NoOfMarkers:" );
		if( ptr )
			*((uint16_t *) extracted_data->data) = atoi( ptr );
		break;
	case IPS_DATA_PVACT:
		ptr = _get_pos( data_len, data, "PVAct:" );
		if( ptr )
			*((uint16_t *) extracted_data->data) = atoi( ptr );
		break;

	case IPS_DATA_M1_X:
		ptr = _get_pos( data_len, data, "m1: (" );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M1_Y:
		//goto x
		ptr = _get_pos( data_len, data, "m1: (" );
		ptr = _get_pos( data_len - (ptr-data), ptr, "," );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M2_X:
		ptr = _get_pos( data_len, data, "m2: (" );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M2_Y:
		ptr = _get_pos( data_len, data, "m2: (" );
		ptr = _get_pos( data_len - (ptr-data), ptr, "," );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M3_X:
		ptr = _get_pos( data_len, data, "m3: (" );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M3_Y:
		ptr = _get_pos( data_len, data, "m3: (" );
		ptr = _get_pos( data_len - (ptr-data), ptr, "," );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M4_X:
		ptr = _get_pos( data_len, data, "m4: (" );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M4_Y:
		ptr = _get_pos( data_len, data, "m4: (" );
		ptr = _get_pos( data_len - (ptr-data), ptr, "," );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M5_X:
		ptr = _get_pos( data_len, data, "m5: (" );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M5_Y:
		ptr = _get_pos( data_len, data, "m5: (" );
		ptr = _get_pos( data_len - (ptr-data), ptr, "," );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M6_X:
		ptr = _get_pos( data_len, data, "m6: (" );
		_assign_uint32_t( ptr, extracted_data );
		break;

	case IPS_DATA_M6_Y:
		ptr = _get_pos( data_len, data, "m6: (" );
		ptr = _get_pos( data_len - (ptr-data), ptr, "," );
		_assign_uint32_t( ptr, extracted_data );
		break;
	case IPS_DATA_ORDER:
		*((uint64_t *) extracted_data->data) = packet->packet_id;
		break;
	case IPS_DATA_GASPD:
		ptr = _get_pos( data_len, data, "GaSpd: " );
		_assign_float( ptr, extracted_data );
		break;
	case IPS_DATA_TRSPD:
		ptr = _get_pos( data_len, data, "TrSpd: " );
		_assign_float( ptr, extracted_data );
		break;
	case IPS_DATA_MHSPD:
		ptr = _get_pos( data_len, data, "MhSpd: " );
		_assign_float( ptr, extracted_data );
		break;	
	case IPS_DATA_TIMESTAMP:
		ptr = _get_pos( data_len, data, "T:" );
		_assign_date( ptr, extracted_data );
		break;		
	
	

	case IPS_DATA_TROLLEY_SPD_REF:
		ptr = _get_pos( data_len, data, "TrSpdRef:" );
		_assign_float( ptr, extracted_data );
		break;

	case IPS_DATA_HOIST_SPD_REF:
		ptr = _get_pos( data_len, data, "MhSpdRef:" );
		_assign_float( ptr, extracted_data );
		break;
	case IPS_DATA_GANTRY_SPD_REF:
		ptr = _get_pos( data_len, data, "GaSpdRef:" );
		_assign_float( ptr, extracted_data );
		break;
	case IPS_DATA_TROLLEY_SPD_ACT:
		ptr = _get_pos( data_len, data, "TrSpdAct:" );
		_assign_float( ptr, extracted_data );
		break;

	case IPS_DATA_HOIST_SPD_ACT:
		ptr = _get_pos( data_len, data, "MhSpdAct:" );
		_assign_float( ptr, extracted_data );
		break;
	case IPS_DATA_GANTRY_SPD_ACT:
		ptr = _get_pos( data_len, data, "GaSpdAct:" );
		_assign_float( ptr, extracted_data );
		break;
	case IPS_DATA_TROLLEY_STOP:
		ptr = _get_pos( data_len, data, "TrStopOk: " );
		memcpy(extracted_data->data, ptr, 5);
		break;

	case IPS_DATA_HOIST_STOP:
		ptr = _get_pos( data_len, data, "MhStopOk: " );
		memcpy(extracted_data->data, ptr, 5);
		break;
	case IPS_DATA_GANTRY_STOP:
		ptr = _get_pos( data_len, data, "GaStopOk: " );
		memcpy(extracted_data->data, ptr, 5);
		break;
	}
	return 1;
}

static attribute_metadata_t _attributes_metadata[] = {
		{IPS_DATA_TROLLEY_POS,  IPS_DATA_TROLLEY_POS_ALIAS,  MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_HOIST_POS,    IPS_DATA_HOIST_POS_ALIAS,    MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_GANTRY_POS,    IPS_DATA_GANTRY_POS_ALIAS,    MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		//Normally 6 markers are logged but during the scenario up to 25 markers were detected. => uint16_t is larger enough
		{IPS_DATA_NO_OF_MARKERS,IPS_DATA_NO_OF_MARKERS_ALIAS,MMT_U16_DATA,  sizeof( uint16_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		//Markers [m1 … m6] (x,y)-coordinates in pixels in a coordinate system 0-131072 in both x and y-axis
		{IPS_DATA_M1_X,         IPS_DATA_M1_X_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_M1_Y,         IPS_DATA_M1_Y_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{IPS_DATA_M2_X,         IPS_DATA_M2_X_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_M2_Y,         IPS_DATA_M2_Y_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{IPS_DATA_M3_X,         IPS_DATA_M3_X_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_M3_Y,         IPS_DATA_M3_Y_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{IPS_DATA_M4_X,         IPS_DATA_M4_X_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_M4_Y,         IPS_DATA_M4_Y_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{IPS_DATA_M5_X,         IPS_DATA_M5_X_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_M5_Y,         IPS_DATA_M5_Y_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{IPS_DATA_M6_X,         IPS_DATA_M6_X_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_M6_Y,         IPS_DATA_M6_Y_ALIAS,         MMT_U32_DATA,  sizeof( uint32_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{IPS_DATA_ORDER,        IPS_DATA_ORDER_ALIAS,        MMT_U64_DATA,  sizeof( uint64_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{IPS_DATA_GASPD,        IPS_DATA_GASPD_ALIAS,        MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_TRSPD,        IPS_DATA_TRSPD_ALIAS,        MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_MHSPD,        IPS_DATA_MHSPD_ALIAS,        MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		//change 											 type of data,	  sizeof timestamp
		{IPS_DATA_TIMESTAMP,    IPS_DATA_TIMESTAMP_ALIAS,    MMT_DATA_TIMEVAL,  sizeof (struct timeval),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_TROLLEY_SPD_REF,  IPS_DATA_TROLLEY_SPD_REF_ALIAS,  MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_HOIST_SPD_REF,    IPS_DATA_HOIST_SPD_REF_ALIAS,    MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_GANTRY_SPD_REF,    IPS_DATA_GANTRY_SPD_REF_ALIAS,    MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_TROLLEY_SPD_ACT,  IPS_DATA_TROLLEY_SPD_ACT_ALIAS,  MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_HOIST_SPD_ACT,    IPS_DATA_HOIST_SPD_ACT_ALIAS,    MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_GANTRY_SPD_ACT,    IPS_DATA_GANTRY_SPD_ACT_ALIAS,    MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_TROLLEY_STOP,  IPS_DATA_TROLLEY_STOP_ALIAS,  MMT_BINARY_DATA,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_HOIST_STOP,    IPS_DATA_HOIST_STOP_ALIAS,    MMT_BINARY_DATA,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_GANTRY_STOP,    IPS_DATA_GANTRY_STOP_ALIAS,    MMT_BINARY_DATA,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_PVACT,  IPS_DATA_PVACT_ALIAS,  MMT_U16_DATA,  sizeof( uint16_t ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

};

static classified_proto_t _ips_data_stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_IPS_DATA;
	retval.status = Classified;
	return retval;
}

int init_proto_ips_data(){
	protocol_t *protocol_struct = init_protocol_struct_for_registration(PROTO_IPS_DATA, PROTO_IPS_DATA_ALIAS);
	if (protocol_struct == NULL)
		return 0;
	//register attributes
	int i;
	int len = sizeof( _attributes_metadata ) / sizeof( attribute_metadata_t);
	for( i=0; i<len; i++ )
		if( !register_attribute_with_protocol(protocol_struct, &_attributes_metadata[i])){
			log_err("Cannot register attribute %s.%s", PROTO_IPS_DATA_ALIAS, _attributes_metadata[i].alias);
			return PROTO_NOT_REGISTERED;
		}
	if( register_classification_function(protocol_struct, _ips_data_classify_next_proto) == 0 )
		return 0;

	// IPS_DATA is a single, independent protocol, register it as a stack
	if( register_protocol_stack(PROTO_IPS_DATA, PROTO_IPS_DATA_ALIAS, _ips_data_stack_classification) == 0 ){
		fprintf(stderr, "Cannot register protocol stack %s", PROTO_IPS_DATA_ALIAS );
		return 0;
	}
	return register_protocol(protocol_struct, PROTO_IPS_DATA);
}
