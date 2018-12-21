/*
 * proto_s1ap.c
 *
 *  Created on: Nov 2, 2018
 *          by: nhnghia
 */
#include<pthread.h>
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"

#include "proto_s1ap.h"
#include "mmt_tcpip.h"
#include "s1ap_common.h"

#define __PACKED __attribute__((packed))

struct sctp_datahdr {
	uint8_t type;
	uint8_t flags;
	uint16_t length;
	uint32_t tsn;
	uint16_t stream;
	uint16_t ssn;
	uint32_t ppid;
} __PACKED;


//global variables
static s1ap_entities_t *list_head = NULL;
static pthread_mutex_t      mutex = PTHREAD_MUTEX_INITIALIZER;

//this is called when mmt_dpi releasing to free memory
static inline void _free_entities_list(){
	pthread_mutex_lock( &mutex );
	while( list_head != NULL ){
		s1ap_entities_t *p = list_head;
		list_head = list_head->next;

		mmt_free( p );
	}
	pthread_mutex_unlock( &mutex );
}

#define HAS_STR( x ) (x[0] != '\0')
#define HAS_VAL( x ) (x    != 0)

#define ASSIGN_STR( x, y, len ) while( !HAS_STR(x) && HAS_STR(y) ){ memcpy(x, y, len); break; }
#define ASSIGN_VAL( x, y )      while( HAS_VAL(y) ){ x = y; break; }

#define IS_CONTAIN_ENB( msg ) (HAS_VAL( msg->enb_plmn_id )       || HAS_STR( msg->enb_name ) || HAS_VAL( msg->enb_ipv4 ))
#define IS_CONTAIN_MME( msg ) (HAS_VAL( msg->mme_group_code_id ) || HAS_STR( msg->mme_name ) || HAS_VAL( msg->mme_ipv4 ))
#define IS_CONTAIN_UE(  msg ) (HAS_STR( msg->imsi )    \
							   || HAS_VAL( msg->m_tmsi )  \
							   || HAS_VAL( msg->ue_ipv4 ) \
							   || HAS_VAL( msg->enb_ue_id ) || HAS_VAL( msg->mme_ue_id) )



/**
 * Find an entity based on information given by a msg.
 * A msg represents information of only one entity
 */
static inline s1ap_entities_t* _find_entity( s1ap_entity_type_t type, const s1ap_message_t *msg ){
	s1ap_entities_t *p = list_head;

	//find eNodeB
	if( type == S1AP_ENTITY_TYPE_ENODEB && IS_CONTAIN_ENB( msg ) ){
		for( p = list_head; p != NULL; p = p->next ){
			if( p->entity.type != S1AP_ENTITY_TYPE_ENODEB )
				continue;

			//same ipv4
			if( HAS_VAL( msg->enb_ipv4 ) && p->entity.ipv4 == msg->enb_ipv4 )
				return p;
			//same name
			if( HAS_STR( msg->enb_name ) && memcmp( msg->enb_name, p->entity.data.enb.name, S1AP_ENTITY_NAME_LENGTH ) == 0)
				return p;
		}
		return NULL;
	}

	//find mme
	if( type == S1AP_ENTITY_TYPE_MME && IS_CONTAIN_MME( msg ) ){
		for( p = list_head; p != NULL; p = p->next ){
			if( p->entity.type != S1AP_ENTITY_TYPE_MME )
				continue;

			//same ipv4
			if( HAS_VAL( msg->mme_ipv4 ) && p->entity.ipv4 == msg->mme_ipv4 )
				return p;
			//same name
			if( HAS_STR( msg->mme_name ) && memcmp( msg->mme_name, p->entity.data.mme.name, S1AP_ENTITY_NAME_LENGTH ) == 0)
				return p;
		}
		return NULL;
	}

	//find ue
	if( type == S1AP_ENTITY_TYPE_UE && IS_CONTAIN_UE( msg )){

		for( p = list_head; p != NULL; p = p->next ){
			if( p->entity.type != S1AP_ENTITY_TYPE_UE )
				continue;
			//same m_tmsi
			if( HAS_VAL( msg->m_tmsi) && msg->m_tmsi == p->entity.data.ue.m_tmsi )
				return p;
			//same ENB_UE_ID
			if( HAS_VAL( msg->enb_ue_id ) && msg->enb_ue_id == p->entity.data.ue.enb_ue_s1ap_id )
				return p;
			//same MME_UE_ID
			if( HAS_VAL( msg->mme_ue_id ) && msg->mme_ue_id == p->entity.data.ue.mme_ue_s1ap_id )
				return p;
			//same ip
			if( HAS_VAL( msg->ue_ipv4) && msg->ue_ipv4 == p->entity.ipv4 )
				return p;
			//same imsi
			if( HAS_STR( msg->imsi ) && memcmp( msg->imsi, p->entity.data.ue.imsi, sizeof( msg->imsi)) == 0 )
				return p;
		}
		return NULL;
	}

	return NULL;
}

static inline void _update_entity( s1ap_entity_type_t type, s1ap_entities_t *p, const s1ap_message_t *msg ){
	if( type == S1AP_ENTITY_TYPE_ENODEB && IS_CONTAIN_ENB( msg ) ){
		p->entity.type = S1AP_ENTITY_TYPE_ENODEB;
		ASSIGN_VAL( p->entity.status, msg->enb_status );
		ASSIGN_VAL( p->entity.ipv4, msg->enb_ipv4 );
		ASSIGN_STR( p->entity.data.enb.name, msg->enb_name, S1AP_ENTITY_NAME_LENGTH );
		return;
	}

	//find mme
	if( type == S1AP_ENTITY_TYPE_MME && IS_CONTAIN_MME( msg ) ){
		p->entity.type = S1AP_ENTITY_TYPE_MME;
		ASSIGN_VAL( p->entity.status, msg->mme_status );
		ASSIGN_VAL( p->entity.ipv4, msg->mme_ipv4 );
		ASSIGN_STR( p->entity.data.mme.name, msg->mme_name, S1AP_ENTITY_NAME_LENGTH );
		return;
	}

	//find ue
	if( type == S1AP_ENTITY_TYPE_UE && IS_CONTAIN_UE( msg )){
		p->entity.type = S1AP_ENTITY_TYPE_UE;
		ASSIGN_VAL( p->entity.status, msg->ue_status );
		ASSIGN_VAL( p->entity.ipv4, msg->ue_ipv4 );
		ASSIGN_VAL( p->entity.data.ue.m_tmsi, msg->m_tmsi );
		ASSIGN_VAL( p->entity.data.ue.enb_ue_s1ap_id, msg->enb_ue_id );
		ASSIGN_VAL( p->entity.data.ue.mme_ue_s1ap_id, msg->mme_ue_id );
		ASSIGN_STR( p->entity.data.ue.imsi, msg->imsi, sizeof( msg->imsi) );
	}
}

static inline s1ap_entities_t* _update_entities_list( s1ap_entity_type_t type, const s1ap_message_t *msg ){

	//msg does not contain any information
	//normally this comes from the lack of S1AP extraction, i.e., ignoring some S1AP packet
	if( !((    type == S1AP_ENTITY_TYPE_ENODEB && IS_CONTAIN_ENB(msg))
			|| (type == S1AP_ENTITY_TYPE_MME   &&  IS_CONTAIN_MME(msg))
			|| (type == S1AP_ENTITY_TYPE_UE    && IS_CONTAIN_UE(msg)) ))
		return NULL;

	s1ap_entities_t *entity = NULL;

	//in case of multi-threading
	pthread_mutex_lock( &mutex );

	int entities_type[3] = {S1AP_ENTITY_TYPE_ENODEB, S1AP_ENTITY_TYPE_MME, S1AP_ENTITY_TYPE_UE};

	entity = _find_entity( type, msg );

	//not found any entity
	if( entity == NULL ){

		entity = mmt_malloc( sizeof(s1ap_entities_t) );
		memset( entity, 0, sizeof(s1ap_entities_t) );

		//the first entity
		if( list_head == NULL ){
			entity->entity.id = 1;
			list_head = entity;
		} else {
			entity->entity.id   = list_head->entity.id + 1;

			//append to the head
			entity->next = list_head;
			list_head  = entity;
		}
	}

	//
	_update_entity( type, entity, msg );

	//in case of multi-threading
	pthread_mutex_unlock( &mutex );

	return entity;
}

static inline int _parse_s1ap_packet( s1ap_message_t *msg, const ipacket_t * packet, unsigned proto_index ){

	memset(msg, 0, sizeof(s1ap_message_t));
//	char string[1000];
//	proto_hierarchy_to_str( packet->proto_hierarchy, string );
//	printf("    %s\n", string );

	int offset = get_packet_offset_at_index(packet, proto_index);

//	printf("ipacket id %lu, proto_index: %d, offset: %d\n", packet->packet_id, proto_index, offset );

	if( unlikely( packet->p_hdr->caplen <= offset ))
		return 0;

	const uint16_t data_len = packet->p_hdr->caplen - offset;

//	printf("ipacket id %lu, proto_index: %d, offset: %d, data_len: %d\n", packet->packet_id, proto_index, offset, data_len );


	int ret = s1ap_decode( msg, & packet->data[offset], data_len );

	/*
	//This block will never be called as we are processing S1AP protocol
	// and SCTP_SHUTDOWN and SCTP_SHUTDOWN_COMPLETE do not contain S1AP.
	//
	//if we got SCTP_SHUTDOWN => eNodeB in detaching
	if( get_protocol_index_by_id( packet, PROTO_SCTP_SHUTDOWN ) != -1 )
		msg->enb_status = S1AP_S1AP_ENTITY_TYPE_STATUS_DETACHING;
	else if( get_protocol_index_by_id( packet, PROTO_SCTP_SHUTDOWN_COMPLETE ) != -1 )
		msg->enb_status = S1AP_S1AP_ENTITY_TYPE_STATUS_DETACHED;
	*/
	return ret;
}


static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
	if (packet->session == NULL)
		return 0;

	//static variables for each thread
	static __thread s1ap_message_t msg;
	static __thread uint64_t packet_id = 0;
	static __thread s1ap_entities_t *node_ue = NULL, *node_mme = NULL, *node_enb = NULL;

	//to increase performance, we parse S1AP only once for a packet
	if( packet_id != packet->packet_id ){
		packet_id = packet->packet_id;

		int ret = _parse_s1ap_packet( &msg, packet, proto_index );

		if( ret < 0 )
			return 0;

		node_enb = _update_entities_list( S1AP_ENTITY_TYPE_ENODEB, &msg );
		node_mme = _update_entities_list( S1AP_ENTITY_TYPE_MME,    &msg );
		node_ue  = _update_entities_list( S1AP_ENTITY_TYPE_UE,     &msg );
	}

	mmt_binary_data_t *b;
	switch( extracted_data->field_id ){
	case S1AP_ATT_PROCEDURE_CODE:
		*((uint16_t *) extracted_data->data) = msg.procedure_code;
		break;
	case S1AP_ATT_PDU_PRESENT:
		*((uint8_t *) extracted_data->data) = msg.pdu_present;
		break;
	case S1AP_ATT_UE_IP:
		if( msg.ue_ipv4 == 0 )
			return 0;
		*((uint32_t *) extracted_data->data) = msg.ue_ipv4;
		break;
	case S1AP_ATT_ENB_IP:
		if( msg.enb_ipv4 == 0 )
			return 0;
		*((uint32_t *) extracted_data->data) = msg.enb_ipv4;
		break;
	case S1AP_ATT_MME_IP:
		if( msg.mme_ipv4 == 0 )
			return 0;
		*((uint32_t *) extracted_data->data) = msg.mme_ipv4;
		break;
	case S1AP_ATT_TEID:
		if( msg.gtp_teid == 0 )
			return 0;
		*((uint32_t *) extracted_data->data) = msg.gtp_teid;
		break;
	case S1AP_ATT_ENB_NAME:
		b = (mmt_binary_data_t *)extracted_data->data;
		b->len = strlen( msg.enb_name );
		if( b->len == 0 )
			return 0;
		memcpy( b->data, msg.enb_name, b->len + 1);
		break;
	case S1AP_ATT_MME_NAME:
		b = (mmt_binary_data_t *)extracted_data->data;
		b->len = strlen( msg.mme_name );
		if( b->len == 0 )
			return 0;
		memcpy( b->data, msg.mme_name, b->len + 1);
		break;
	case S1AP_ATT_IMSI:
		if( msg.imsi[0] == 0 )
			return 0;

		b = (mmt_binary_data_t *) extracted_data->data;
		b->len = sizeof( msg.imsi );
		memcpy( b->data, msg.imsi, b->len);
		b->data[ b->len + 1 ] = '\0';
		break;
	case S1AP_ATT_ENB_UE_ID:
		if( msg.enb_ue_id == 0 )
			return 0;
		*((uint32_t *) extracted_data->data) = msg.enb_ue_id;
		break;
	case S1AP_ATT_MME_UE_ID:
		if( msg.mme_ue_id == 0 )
			return 0;
		*((uint32_t *) extracted_data->data) = msg.mme_ue_id;
		break;

	case S1AP_ATT_UE_STATUS:
		if( msg.ue_status == 0 )
			return 0;
		*((uint8_t *) extracted_data->data) = msg.ue_status;
		break;

	case S1AP_ATT_ENB_STATUS:
		if( msg.enb_status == 0 )
			return 0;
		*((uint8_t *) extracted_data->data) = msg.enb_status;
		break;
	case S1AP_ATT_MME_STATUS:
		if( msg.mme_status == 0 )
			return 0;
		*((uint8_t *) extracted_data->data) = msg.mme_status;
		break;

	case S1AP_ATT_ENB_ID:
		if( !node_enb  )
			return 0;
		*((uint32_t *) extracted_data->data) = node_enb->entity.id;
		break;
	case S1AP_ATT_MME_ID:
		if( !node_mme )
			return 0;
		*((uint32_t *) extracted_data->data) = node_mme->entity.id;
		break;
	case S1AP_ATT_UE_ID:
		if( !node_ue )
			return 0;
		*((uint32_t *) extracted_data->data) = node_ue->entity.id;
		break;
	case S1AP_ATT_M_TMSI:
		if( msg.m_tmsi == 0 )
			return 0;
		*((uint32_t *) extracted_data->data) = msg.m_tmsi;
		break;
	case S1AP_ATT_ENTITY_UE:
		if( !node_ue )
			return 0;
		extracted_data->data = &node_ue->entity;
		break;
	case S1AP_ATT_ENTITY_ENODEB:
		if( !node_enb )
			return 0;
		extracted_data->data = &node_enb->entity;
		break;
	case S1AP_ATT_ENTITY_MME:
		if( !node_mme )
			return 0;
		extracted_data->data = &node_mme->entity;
		break;
	case S1AP_ATT_ENTITIES:
		if( !list_head )
			return 0;
		extracted_data->data = list_head;
		break;
	}//end of switch

	return 1;
}


static attribute_metadata_t s1ap_attributes_metadata[] = {
		{S1AP_ATT_PROCEDURE_CODE, S1AP_PROCEDURE_CODE_ALIAS, MMT_U16_DATA,     sizeof( uint16_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_PDU_PRESENT,    S1AP_PDU_PRESENT_ALIAS,    MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_UE_ID,          S1AP_UE_ID_ALIAS,          MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_IMSI,           S1AP_IMSI_ALIAS,           MMT_STRING_DATA,  sizeof( mmt_binary_data_t), POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_TEID,           S1AP_TEID_ALIAS,           MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_M_TMSI,         S1AP_M_TMSI_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_UE_IP,          S1AP_UE_IP_ALIAS,          MMT_DATA_IP_ADDR, sizeof( MMT_DATA_IP_ADDR),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_UE_STATUS,      S1AP_UE_STATUS_ALIAS,      MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_ENB_ID,         S1AP_ENB_ID_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_NAME,       S1AP_ENB_NAME_ALIAS,       MMT_STRING_DATA,  sizeof (MMT_STRING_DATA),   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_IP,         S1AP_ENB_IP_ALIAS,         MMT_DATA_IP_ADDR, sizeof (MMT_DATA_IP_ADDR),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_UE_ID,      S1AP_ENB_UE_ID_ALIAS,      MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_STATUS,     S1AP_ENB_STATUS_ALIAS,     MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_MME_ID,         S1AP_MME_ID_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_NAME,       S1AP_MME_NAME_ALIAS,       MMT_STRING_DATA,  sizeof (MMT_STRING_DATA),   POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_IP,         S1AP_MME_IP_ALIAS,         MMT_DATA_IP_ADDR, sizeof (MMT_DATA_IP_ADDR),  POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_UE_ID,      S1AP_MME_UE_ID_ALIAS,      MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_STATUS,     S1AP_MME_STATUS_ALIAS,     MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_ENTITY_UE,      S1AP_ENTITY_UE_ALIAS,      MMT_DATA_POINTER, sizeof( void *),            POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENTITY_ENODEB,  S1AP_ENTITY_ENODEB_ALIAS,  MMT_DATA_POINTER, sizeof( void *),            POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENTITY_MME,     S1AP_ENTITY_MME_ALIAS,     MMT_DATA_POINTER, sizeof( void *),            POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENTITIES,       S1AP_ENTITIES_ALIAS,       MMT_DATA_POINTER, sizeof( void *),            POSITION_NOT_KNOWN, SCOPE_SESSION,_extraction_att}
};
/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

static int _classify_s1ap_from_sctp_data( ipacket_t * ipacket, unsigned index ){
	int offset = get_packet_offset_at_index(ipacket, index);
	//not enough room
	if( offset > ipacket->p_hdr->caplen + sizeof(struct sctp_datahdr) )
		return 0;

	classified_proto_t retval;

	struct sctp_datahdr *hdr = (struct sctp_datahdr *) &ipacket->data[ offset ];
	switch( ntohl( hdr->ppid )){
	case 18: //S1AP
		retval.proto_id = PROTO_S1AP;
		retval.offset = sizeof( struct sctp_datahdr );
		retval.status = Classified;

		//fix length
		ipacket->proto_hierarchy->len =      (index + 1) + 1;
		return set_classified_proto(ipacket, (index + 1), retval);
	default:
		return 0;
	}

	return 0;
}


static void * _on_init_protocol(void * protocol_context, void * args){
	return NULL;
}
static void _on_clean_protocol(void * protocol_context, void * args){
	_free_entities_list();
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////
int init_proto_s1ap() {
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_S1AP, PROTO_S1AP_ALIAS);

	if( protocol_struct == NULL ){
		fprintf(stderr, "Cannot initialize S1AP protocol");
		return 0;
	}

	int i = 0;
	int len = sizeof( s1ap_attributes_metadata ) / sizeof( attribute_metadata_t );
	for (; i < len; i++)
		register_attribute_with_protocol(protocol_struct, &s1ap_attributes_metadata[i]);

	register_classification_function_with_parent_protocol( PROTO_SCTP_DATA, _classify_s1ap_from_sctp_data, 100 );

	//register_classification_function(protocol_struct, sctp_classify_next_chunk);
	register_proto_context_init_cleanup_function( protocol_struct, _on_init_protocol, _on_clean_protocol, NULL );

	return register_protocol(protocol_struct, PROTO_S1AP);
}


int init_proto() {
	return init_proto_s1ap();
}
int cleanup_proto(){
	//printf("close s1ap protocol");
	return 0;
}
