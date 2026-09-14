/*
 * proto_ips_data.c
 *
 *  Created on: Jun 3, 2021
 *      Author: nhnghia
 */


#include "mmt_business_app_internal.h"


/*
TrolleyPos: 32.981, Hoistpos: 38.042, NoOfMarkers: 3, m1: (58901,70912) , m2: (72175,70950) , m3: (65803,71939) , m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)
TrolleyPos: 32.978, Hoistpos: 38.124, NoOfMarkers: 3, m1: (58843,70948) , m2: (72122,70987) , m3: (65767,71983) , m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)
 */
static int _ips_data_classify_next_proto(ipacket_t *packet, unsigned index) {
	int offset = get_packet_offset_at_index(packet, index);
	if( offset < 0 || (size_t)offset >= packet->p_hdr->caplen )
		return 0;
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	/* strncmp(n=10) reads up to 10 bytes: a shorter capture would be
	 * over-read even though the buffer is not NUL-terminated (#195). */
	if( data_len < 10 )
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

/* Number of packet bytes readable at `ptr` — ptr points into
 * [data, data+data_len). Returns 0 for NULL so the numeric converters see an
 * empty token instead of dereferencing a wild pointer (#195, F-BUG-098). */
static inline size_t _avail_at( const char *data, int data_len, const char *ptr ){
	if( ptr == NULL )
		return 0;
	long r = (long)data_len - (long)( ptr - data );
	return ( r > 0 ) ? (size_t)r : 0;
}

/* Bound + NUL-terminate the raw packet bytes into a stack copy before calling
 * the libc numeric converters: atol/atof/atoi require a C string and would
 * otherwise scan past the end of the captured buffer (F-BUG-098). 63 bytes is
 * far wider than any numeric token this protocol emits, so well-formed values
 * convert exactly as before. */
static inline size_t _copy_num_token( char *buf, size_t buf_len, const char *ptr, size_t avail ){
	size_t n = avail < buf_len - 1 ? avail : buf_len - 1;
	memcpy( buf, ptr, n );
	buf[n] = '\0';
	return n;
}

static inline void _assign_uint32_t(const char* ptr, size_t avail, attribute_t * extracted_data){
	char buf[64];
	if( ptr != NULL && avail > 0 ){
		_copy_num_token( buf, sizeof(buf), ptr, avail );
		*((uint32_t *) extracted_data->data) = (uint32_t)atol( buf );
	}else
		*((uint32_t *) extracted_data->data) = 0;
}

static inline void _assign_float(const char* ptr, size_t avail, attribute_t * extracted_data){
	char buf[64];
	if( ptr != NULL && avail > 0 ){
		_copy_num_token( buf, sizeof(buf), ptr, avail );
		*((float *) extracted_data->data) = atof( buf );
	}else
		*((float *) extracted_data->data) = 0;
}

static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	int offset = get_packet_offset_at_index(packet, proto_index);
	if( offset < 0 || (size_t)offset > packet->p_hdr->caplen )
		return 0;
	const int data_len = packet->p_hdr->caplen - offset;
	const char* data = (char *)&packet->data[offset];
	const char* ptr;
	if( data_len <= 0 )
		return 0;
	switch( extracted_data->field_id ){
	case IPS_DATA_TROLLEY_POS:
		ptr = _get_pos( data_len, data, "TrolleyPos:" );
		_assign_float( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_HOIST_POS:
		ptr = _get_pos( data_len, data, "Hoistpos:" );
		_assign_float( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_NO_OF_MARKERS:
		ptr = _get_pos( data_len, data, "NoOfMarkers:" );
		if( ptr && _avail_at(data, data_len, ptr) > 0 ){
			char buf[64];
			_copy_num_token( buf, sizeof(buf), ptr, _avail_at(data, data_len, ptr) );
			*((uint16_t *) extracted_data->data) = atoi( buf );
		}
		break;

	case IPS_DATA_M1_X:
		ptr = _get_pos( data_len, data, "m1: (" );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M1_Y:
		//goto x
		ptr = _get_pos( data_len, data, "m1: (" );
		/* ptr may be NULL (key absent): the subtraction would then be a wild
		 * length — guard before the second search (#195, F-BUG-107). */
		if( ptr )
			ptr = _get_pos( (int)_avail_at(data, data_len, ptr), ptr, "," );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M2_X:
		ptr = _get_pos( data_len, data, "m2: (" );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M2_Y:
		ptr = _get_pos( data_len, data, "m2: (" );
		/* ptr may be NULL (key absent): the subtraction would then be a wild
		 * length — guard before the second search (#195, F-BUG-107). */
		if( ptr )
			ptr = _get_pos( (int)_avail_at(data, data_len, ptr), ptr, "," );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M3_X:
		ptr = _get_pos( data_len, data, "m3: (" );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M3_Y:
		ptr = _get_pos( data_len, data, "m3: (" );
		/* ptr may be NULL (key absent): the subtraction would then be a wild
		 * length — guard before the second search (#195, F-BUG-107). */
		if( ptr )
			ptr = _get_pos( (int)_avail_at(data, data_len, ptr), ptr, "," );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M4_X:
		ptr = _get_pos( data_len, data, "m4: (" );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M4_Y:
		ptr = _get_pos( data_len, data, "m4: (" );
		/* ptr may be NULL (key absent): the subtraction would then be a wild
		 * length — guard before the second search (#195, F-BUG-107). */
		if( ptr )
			ptr = _get_pos( (int)_avail_at(data, data_len, ptr), ptr, "," );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M5_X:
		ptr = _get_pos( data_len, data, "m5: (" );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M5_Y:
		ptr = _get_pos( data_len, data, "m5: (" );
		/* ptr may be NULL (key absent): the subtraction would then be a wild
		 * length — guard before the second search (#195, F-BUG-107). */
		if( ptr )
			ptr = _get_pos( (int)_avail_at(data, data_len, ptr), ptr, "," );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M6_X:
		ptr = _get_pos( data_len, data, "m6: (" );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;

	case IPS_DATA_M6_Y:
		ptr = _get_pos( data_len, data, "m6: (" );
		/* ptr may be NULL (key absent): the subtraction would then be a wild
		 * length — guard before the second search (#195, F-BUG-107). */
		if( ptr )
			ptr = _get_pos( (int)_avail_at(data, data_len, ptr), ptr, "," );
		_assign_uint32_t( ptr, _avail_at(data, data_len, ptr), extracted_data );
		break;
	case IPS_DATA_ORDER:
		*((uint64_t *) extracted_data->data) = packet->packet_id;
		break;
	}
	return 1;
}

static attribute_metadata_t _attributes_metadata[] = {
		{IPS_DATA_TROLLEY_POS,  IPS_DATA_TROLLEY_POS_ALIAS,  MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{IPS_DATA_HOIST_POS,    IPS_DATA_HOIST_POS_ALIAS,    MMT_DATA_FLOAT,  sizeof( float ),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
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
