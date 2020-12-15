/*
 * proto_s1ap.c
 *
 *  Created on: Nov 2, 2018
 *          by: nhnghia
 */
#include<pthread.h>
#include "mmt_mobile_internal.h"
#include "s1ap/s1ap_common.h"

//A linked-list containing all entities (UE, eNodeB, MME, gw) of the current LTE network being monitored
typedef struct s1ap_entities_struct{
	s1ap_entity_t entity;
	struct s1ap_entities_struct *next;
}s1ap_entities_t;


//global variables
static s1ap_entities_t *list_head = NULL;
//the access to list_head variable must be synchronized by this mutex
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


#define HAS_STR( x ) (x[0] != '\0') //check if string is not empty
#define HAS_VAL( x ) (x    != 0)    //check if a number is not zero

#define IS_CONTAIN_ENB( msg ) (HAS_VAL( msg->enb_plmn_id )       || HAS_STR( msg->enb_name ) || HAS_VAL( msg->enb_ipv4 ))
#define IS_CONTAIN_MME( msg ) (HAS_VAL( msg->mme_group_code_id ) || HAS_STR( msg->mme_name ) || HAS_VAL( msg->mme_ipv4 ))
#define IS_CONTAIN_UE(  msg ) (HAS_STR( msg->imsi )       \
							   || HAS_VAL( msg->m_tmsi )  \
							   || HAS_VAL( msg->ue_ipv4 ) \
							   || HAS_VAL( msg->enb_ue_id ) || HAS_VAL( msg->mme_ue_id) )



/**
 * Find an entity based on information given by a msg.
 * A msg represents information of only one entity
 */
static inline s1ap_entities_t* _find_entity_node( s1ap_entity_type_t type, const s1ap_message_t *msg ){
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
			//same imsi
			if( HAS_STR( msg->imsi ) && memcmp( msg->imsi, p->entity.data.ue.imsi, sizeof( msg->imsi)) == 0 )
				return p;

			//same ip
			//if( HAS_VAL( msg->ue_ipv4) && msg->ue_ipv4 == p->entity.ipv4 )
			//	return p;
		}
		return NULL;
	}

	return NULL;
}

/**
 * Update information of an entity from a given s1ap_message_t
 */
static inline void _update_entity( s1ap_entity_type_t type, s1ap_entity_t *p, const s1ap_message_t *msg ){

	//"local" macros they are used only in this function
	#define ASSIGN_STR( x, y, len ) while( HAS_STR(y) ){ memcpy(x, y, len); break; }
	#define ASSIGN_VAL( x, y )      while( HAS_VAL(y) ){ x = y;             break; }


	switch( type ){
	case S1AP_ENTITY_TYPE_ENODEB:
		if( IS_CONTAIN_ENB( msg ) ){
			p->type = S1AP_ENTITY_TYPE_ENODEB;
			ASSIGN_VAL( p->status, msg->enb_status );
			ASSIGN_VAL( p->ipv4, msg->enb_ipv4 );
			ASSIGN_STR( p->data.enb.name, msg->enb_name, S1AP_ENTITY_NAME_LENGTH );
			return;
		}
		break;

	//find mme
	case S1AP_ENTITY_TYPE_MME:
		if( IS_CONTAIN_MME( msg ) ){
			p->type = S1AP_ENTITY_TYPE_MME;
			ASSIGN_VAL( p->status, msg->mme_status );
			ASSIGN_VAL( p->ipv4, msg->mme_ipv4 );
			ASSIGN_STR( p->data.mme.name, msg->mme_name, S1AP_ENTITY_NAME_LENGTH );
			return;
		}
		break;

	//find ue
	case S1AP_ENTITY_TYPE_UE:
		if( IS_CONTAIN_UE( msg )){
			p->type = S1AP_ENTITY_TYPE_UE;
			ASSIGN_VAL( p->status, msg->ue_status );
			ASSIGN_VAL( p->ipv4, msg->ue_ipv4 );
			ASSIGN_VAL( p->data.ue.m_tmsi, msg->m_tmsi );
			ASSIGN_VAL( p->data.ue.enb_ue_s1ap_id, msg->enb_ue_id );
			ASSIGN_VAL( p->data.ue.mme_ue_s1ap_id, msg->mme_ue_id );
			ASSIGN_VAL( p->data.ue.gtp_teid,       msg->gtp_teid );
			ASSIGN_STR( p->data.ue.imsi, msg->imsi, sizeof( msg->imsi) );
		}
		break;
	default:
		break;
	}
}

/**
 * Update information of a node in the linked-list of an entity given by the s1ap_message_t
 * If the linked-list does not contain the entity,
 *  then a new node will be created and append to the head of the linked-list.
 */
static inline s1ap_entities_t* _update_entities_list( s1ap_entity_type_t type, const s1ap_message_t *msg ){

	//msg does not contain any information
	//normally this comes from the lack of S1AP extraction, i.e., ignoring some S1AP packet
	if( !((    type == S1AP_ENTITY_TYPE_ENODEB && IS_CONTAIN_ENB(msg))
			|| (type == S1AP_ENTITY_TYPE_MME   && IS_CONTAIN_MME(msg))
			|| (type == S1AP_ENTITY_TYPE_UE    && IS_CONTAIN_UE(msg)) ))
		return NULL;

	s1ap_entities_t *node = _find_entity_node( type, msg );

	//not found any entity
	if( node == NULL ){

		//create a new empty node
		node = mmt_malloc( sizeof(s1ap_entities_t) );
		memset( node, 0, sizeof(s1ap_entities_t) );

		//if this is the first node of the linked-list
		if( list_head == NULL ){
			node->entity.id = 1;
			list_head = node;
		} else {
			node->entity.id   = list_head->entity.id + 1;

			//append to the head
			node->next = list_head;
			list_head  = node;
		}
	}

	//update information of the node in the linked-list with the information in msg
	_update_entity( type, &node->entity, msg );

	return node;
}

//header of IPv4 packet
struct ipv4_hdr{
	uint8_t ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
};

/**
 * In some case, e.g., eNodeB detaches MME, no message of S1AP protocol is sent but the one of SCTP_SHUTDOWN,
 * we need to get IP src/dst of the current packet.
 * If the packet is IP-in-IP, we need to get the IP packet the SCTP belongs to.
 */
static inline bool _get_ip_src_dst( const ipacket_t *packet, uint32_t *ip_src, uint32_t *ip_dst ){

    if (packet->session == NULL)
    	return false;

    //the index in the protocol hierarchy of the protocol session belongs to
    const uint32_t proto_session_index  = get_session_protocol_index( packet->session );
    // Flow extraction
    const uint32_t proto_session_id = get_protocol_id_at_index(packet, proto_session_index);

    //must be either PROTO_IP or PROTO_IPV6
    //currently we support IPv4
    if( unlikely( proto_session_id != PROTO_IP )){
    	S1AP_WARN("Does not support IPv6 yet. Packet id = %lu", packet->packet_id );
    	return false;
    }

	int offset = get_packet_offset_at_index(packet, proto_session_index );
	const struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) &packet->data[offset];

	*ip_src = ip_hdr->saddr;
	*ip_dst = ip_hdr->daddr;

    return true;
}

/**
 * Assign IP for eNodeB and MME based on ip src/dst of the packet
 */
static inline void _assign_enb_mme_ip( s1ap_message_t *msg, const ipacket_t * packet, bool is_from_enb_to_mme ){
	uint32_t ip_src, ip_dst;
	if( ! _get_ip_src_dst( packet, &ip_src, &ip_dst ))
		return;

	if( is_from_enb_to_mme ){
		msg->enb_ipv4 = ip_src;
		msg->mme_ipv4 = ip_dst;
	}else{
		msg->enb_ipv4 = ip_dst;
		msg->mme_ipv4 = ip_src;
	}
}

static inline int _parse_s1ap_packet( s1ap_message_t *msg, const ipacket_t * packet, unsigned proto_index ){

	memset(msg, 0, sizeof(s1ap_message_t));
//	char string[1000];
//	proto_hierarchy_to_str( packet->proto_hierarchy, string );
//	printf("    %s\n", string );

	int offset = get_packet_offset_at_index(packet, proto_index);

//	printf("ipacket id %lu, proto_index: %d, offset: %d\n", packet->packet_id, proto_index, offset );

	//if body of S1AP packet is empty
	//=> this is the case of PROTO_SCTP_SHUTDOWN and  PROTO_SCTP_SHUTDOWN_COMPLETE protocols
	//   that are used to add a dummy S1AP protocol after them.
	//   The reason is these two protocols are used to detach eNodeB
	if( unlikely( packet->p_hdr->caplen <= offset + 1 )){
		//This block will be called as we are processing S1AP protocol and
		//_classify_s1ap_from_sctp_shutdown will attach S1AP after SCTP_SHUTDOWN and SCTP_SHUTDOWN_COMPLETE
		//
		//if we got SCTP_SHUTDOWN => eNodeB is detaching
		if( (proto_index = get_protocol_index_by_id( packet, PROTO_SCTP_SHUTDOWN )) != -1 ){
			msg->enb_status = S1AP_ENTITY_STATUS_DETACHING;

			//need to check shutdown or shutdown_ack
			//not enough room
			offset = get_packet_offset_at_index(packet, proto_index);
			if( offset > packet->p_hdr->caplen + sizeof(struct sctp_datahdr) )
				return 0;

			classified_proto_t retval;

			struct sctp_datahdr *hdr = (struct sctp_datahdr *) &packet->data[ offset ];
			switch( hdr->type ){
			case 7: //SHUTDOWN
				_assign_enb_mme_ip( msg, packet, true );
				break;
			case 8: //ACK
				_assign_enb_mme_ip( msg, packet, false );
				break;
			}


		}else if( get_protocol_index_by_id( packet, PROTO_SCTP_SHUTDOWN_COMPLETE ) != -1 ){
			msg->enb_status = S1AP_ENTITY_STATUS_DETACHED;
			//a confirm from eNodeB -> MME
			_assign_enb_mme_ip( msg, packet, true );
		}

		return 0;
	}

	const uint16_t data_len = packet->p_hdr->caplen - offset;

//	printf("ipacket id %lu, proto_index: %d, offset: %d, data_len: %d\n", packet->packet_id, proto_index, offset, data_len );


	//decode S1AP packet
	int ret = s1ap_decode( msg, & packet->data[offset], data_len );

	//we can use IP src-dst before SCTP as IP of eNodeB and MME
	//S1SetupRequest: a message from eNodeB --> MME
	if( msg->procedure_code == S1AP_ProcedureCode_id_S1Setup ) {
		if( msg->pdu_present == S1AP_PDU_Present_initiatingMessage )
			_assign_enb_mme_ip( msg, packet, true );
		else if( msg->pdu_present == S1AP_PDU_Present_successfulOutcome )
			_assign_enb_mme_ip( msg, packet, false );
	}

	return ret;
}

//assign s1ap_entity_t data to mmt_binary_var_data_t
static inline void _copy_binary_data_type( void *dst, const s1ap_entity_t *src ){
	mmt_binary_var_data_t *bin = (mmt_binary_var_data_t *) dst;
	bin->len = sizeof( s1ap_entity_t );

	//this happens only cause by programmer
	if( unlikely( bin->len > BINARY_1024DATA_LEN )){
		S1AP_ERROR("Structure s1ap_entities_t is too big");
		bin->len = 0;
		return;
	}

	memcpy( bin->data, src, bin->len );
}

#define IF_TRUE_UNLOCK_AND_RETURN( exp, ret_val ) \
	while( exp ){                                 \
		pthread_mutex_unlock( &mutex );           \
		return ret_val;                           \
	}

/**
 * Extract attribute
 */
static int _extraction_att(const ipacket_t * packet, unsigned proto_index,
		attribute_t * extracted_data) {
//printf("packet_id: %"PRIu64"\n", packet->packet_id );
	//static variables for each thread
	//these variables are used to keep information between extracting different attributes of a packet
	//they must be updated for each packet
	static __thread s1ap_message_t msg;
	static __thread uint64_t packet_id = 0;
	static __thread s1ap_entities_t *node_ue = NULL, *node_mme = NULL, *node_enb = NULL;

	//in case of multi-threading
	pthread_mutex_lock( &mutex );

	//to increase performance, we parse S1AP only once for a packet
	//thus when this function is called again to extract other attribute,
	// we can get information from the static __thread variables above.
	if( packet_id != packet->packet_id ){
		//remember the id of packet being parsed
		packet_id = packet->packet_id;

		int ret = _parse_s1ap_packet( &msg, packet, proto_index );

		//clear the current value of the caches, if the parsing is fail
		node_ue = node_mme = node_enb = NULL;

		IF_TRUE_UNLOCK_AND_RETURN( ret < 0, 0 );

		node_enb = _update_entities_list( S1AP_ENTITY_TYPE_ENODEB, &msg );
		node_mme = _update_entities_list( S1AP_ENTITY_TYPE_MME,    &msg );
		node_ue  = _update_entities_list( S1AP_ENTITY_TYPE_UE,     &msg );


		//once an entity is changed to ATTACHED => we need to indicate its parent (the entity it is attaching to)
		if( node_enb && node_mme && node_enb->entity.status == S1AP_ENTITY_STATUS_ATTACHED )
				node_enb->entity.parent = node_mme->entity.id;

		if( node_ue  && node_enb && node_ue->entity.status == S1AP_ENTITY_STATUS_ATTACHED )
				node_ue->entity.parent = node_enb->entity.id;
	}

	mmt_binary_data_t *b;

	//depending on id of attribute to be extracted
	switch( extracted_data->field_id ){
	case S1AP_ATT_PROCEDURE_CODE:
		*((uint16_t *) extracted_data->data) = msg.procedure_code;
		break;
	case S1AP_ATT_PDU_PRESENT:
		*((uint8_t *) extracted_data->data) = msg.pdu_present;
		break;
	case S1AP_ATT_UE_IP:
		IF_TRUE_UNLOCK_AND_RETURN( msg.ue_ipv4 == 0, 0 );
		*((uint32_t *) extracted_data->data) = msg.ue_ipv4;
		break;
	case S1AP_ATT_ENB_IP:
		IF_TRUE_UNLOCK_AND_RETURN( msg.enb_ipv4 == 0, 0 );
		*((uint32_t *) extracted_data->data) = msg.enb_ipv4;
		break;
	case S1AP_ATT_MME_IP:
		IF_TRUE_UNLOCK_AND_RETURN( msg.mme_ipv4 == 0, 0 );
		*((uint32_t *) extracted_data->data) = msg.mme_ipv4;
		break;
	case S1AP_ATT_TEID:
		IF_TRUE_UNLOCK_AND_RETURN( msg.gtp_teid == 0, 0 );
		*((uint32_t *) extracted_data->data) = msg.gtp_teid;
		break;


	case S1AP_ATT_ENB_NAME:
		b = (mmt_binary_data_t *)extracted_data->data;
		b->len = strlen( msg.enb_name );
		IF_TRUE_UNLOCK_AND_RETURN( b->len == 0, 0 );
		if( b->len > sizeof( b->data ) )
			b->len = sizeof( b->data );
		memcpy( b->data, msg.enb_name, b->len + 1);
		break;
	case S1AP_ATT_MME_NAME:
		b = (mmt_binary_data_t *)extracted_data->data;
		b->len = strlen( msg.mme_name );
		IF_TRUE_UNLOCK_AND_RETURN( b->len == 0, 0 );
		if( b->len > sizeof( b->data ) )
			b->len = sizeof( b->data );
		memcpy( b->data, msg.mme_name, b->len + 1);
		break;
	case S1AP_ATT_IMSI:
		IF_TRUE_UNLOCK_AND_RETURN( msg.imsi[0] == 0, 0 );

		b = (mmt_binary_data_t *) extracted_data->data;
		b->len = sizeof( msg.imsi );
		memcpy( b->data, msg.imsi, b->len);
		b->data[ b->len + 1 ] = '\0';
		break;

	case S1AP_ATT_QCI:
		IF_TRUE_UNLOCK_AND_RETURN( msg.qos_qci == 0, 0 );
		*((uint8_t *) extracted_data->data) = msg.qos_qci;
		break;

	case S1AP_ATT_PRIORITY_LEVEL:
		IF_TRUE_UNLOCK_AND_RETURN( msg.qos_priority_level == 0, 0 );
		*((uint8_t *) extracted_data->data) = msg.qos_priority_level;
		break;

	case S1AP_ATT_ENB_UE_ID:
		IF_TRUE_UNLOCK_AND_RETURN( msg.enb_ue_id == 0, 0 );
		*((uint32_t *) extracted_data->data) = msg.enb_ue_id;
		break;
	case S1AP_ATT_MME_UE_ID:
		IF_TRUE_UNLOCK_AND_RETURN( msg.mme_ue_id == 0, 0 );
		*((uint32_t *) extracted_data->data) = msg.mme_ue_id;
		break;


	case S1AP_ATT_UE_STATUS:
		IF_TRUE_UNLOCK_AND_RETURN( msg.ue_status == 0, 0 );
		*((uint8_t *) extracted_data->data) = msg.ue_status;
		break;
	case S1AP_ATT_ENB_STATUS:
		IF_TRUE_UNLOCK_AND_RETURN( msg.enb_status == 0, 0 );
		*((uint8_t *) extracted_data->data) = msg.enb_status;
		break;
	case S1AP_ATT_MME_STATUS:
		IF_TRUE_UNLOCK_AND_RETURN( msg.mme_status == 0, 0 );
		*((uint8_t *) extracted_data->data) = msg.mme_status;
		break;


	case S1AP_ATT_ENB_ID:
		IF_TRUE_UNLOCK_AND_RETURN( !node_enb, 0 );
		*((uint32_t *) extracted_data->data) = node_enb->entity.id;
		break;
	case S1AP_ATT_MME_ID:
		IF_TRUE_UNLOCK_AND_RETURN( !node_mme, 0 );
		*((uint32_t *) extracted_data->data) = node_mme->entity.id;
		break;
	case S1AP_ATT_UE_ID:
		IF_TRUE_UNLOCK_AND_RETURN( !node_ue, 0 );
		*((uint32_t *) extracted_data->data) = node_ue->entity.id;
		break;


	case S1AP_ATT_M_TMSI:
		IF_TRUE_UNLOCK_AND_RETURN( msg.m_tmsi == 0, 0 );
		*((uint32_t *) extracted_data->data) = msg.m_tmsi;
		break;


	case S1AP_ATT_ENTITY_UE:
		IF_TRUE_UNLOCK_AND_RETURN( !node_ue, 0 );
		_copy_binary_data_type( extracted_data->data, &node_ue->entity );
		break;
	case S1AP_ATT_ENTITY_ENODEB:
		IF_TRUE_UNLOCK_AND_RETURN( !node_enb, 0 );
		_copy_binary_data_type( extracted_data->data, &node_enb->entity );
		break;
	case S1AP_ATT_ENTITY_MME:
		IF_TRUE_UNLOCK_AND_RETURN( !node_mme, 0 );
		_copy_binary_data_type( extracted_data->data, &node_mme->entity );
		break;
	}//end of switch


	//in case of multi-threading
	pthread_mutex_unlock( &mutex );
	return 1;
}


static attribute_metadata_t s1ap_attributes_metadata[] = {
		{S1AP_ATT_PROCEDURE_CODE, S1AP_PROCEDURE_CODE_ALIAS, MMT_U16_DATA,     sizeof( uint16_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_PDU_PRESENT,    S1AP_PDU_PRESENT_ALIAS,    MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_UE_ID,          S1AP_UE_ID_ALIAS,          MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_IMSI,           S1AP_IMSI_ALIAS,           MMT_STRING_DATA,  BINARY_64DATA_LEN,          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_M_TMSI,         S1AP_M_TMSI_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_TEID,           S1AP_TEID_ALIAS,           MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_QCI,            S1AP_QCI_ALIAS,            MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_PRIORITY_LEVEL, S1AP_PRIORITY_LEVEL_ALIAS, MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_UE_IP,          S1AP_UE_IP_ALIAS,          MMT_DATA_IP_ADDR, sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_UE_STATUS,      S1AP_UE_STATUS_ALIAS,      MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},


		{S1AP_ATT_MME_ID,         S1AP_MME_ID_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_NAME,       S1AP_MME_NAME_ALIAS,       MMT_STRING_DATA,  BINARY_64DATA_LEN,          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_IP,         S1AP_MME_IP_ALIAS,         MMT_DATA_IP_ADDR, sizeof( uint32_t ),         POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_UE_ID,      S1AP_MME_UE_ID_ALIAS,      MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_MME_STATUS,     S1AP_MME_STATUS_ALIAS,     MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

		{S1AP_ATT_ENB_ID,         S1AP_ENB_ID_ALIAS,         MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_NAME,       S1AP_ENB_NAME_ALIAS,       MMT_STRING_DATA,  BINARY_64DATA_LEN,          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_IP,         S1AP_ENB_IP_ALIAS,         MMT_DATA_IP_ADDR, sizeof( uint32_t ),         POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_UE_ID,      S1AP_ENB_UE_ID_ALIAS,      MMT_U32_DATA,     sizeof( uint32_t),          POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENB_STATUS,     S1AP_ENB_STATUS_ALIAS,     MMT_U8_DATA,      sizeof( uint8_t),           POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},


		{S1AP_ATT_ENTITY_UE,      S1AP_ENTITY_UE_ALIAS,      MMT_BINARY_VAR_DATA, BINARY_1024DATA_TYPE_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENTITY_MME,     S1AP_ENTITY_MME_ALIAS,     MMT_BINARY_VAR_DATA, BINARY_1024DATA_TYPE_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},
		{S1AP_ATT_ENTITY_ENODEB,  S1AP_ENTITY_ENODEB_ALIAS,  MMT_BINARY_VAR_DATA, BINARY_1024DATA_TYPE_LEN,    POSITION_NOT_KNOWN, SCOPE_PACKET, _extraction_att},

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


static int _classify_s1ap_from_sctp_shutdown( ipacket_t * ipacket, unsigned index ){
	int offset = get_packet_offset_at_index(ipacket, index);
	if( offset > ipacket->p_hdr->caplen )
		return 0;

	classified_proto_t retval;

	retval.proto_id = PROTO_S1AP;
	//at the end of the packet: 0 bytes for S1AP
	//Reality, there is no S1AP protocol after SCTP_SHUTDOWN or SCTP_SHUTDOWN_COMPLETE
	//We add a dummy S1AP after these protocols as they are  related to detach eNodeB
	retval.offset = ipacket->p_hdr->caplen - offset - 1;
	retval.status = Classified;

	//fix length
	ipacket->proto_hierarchy->len =      (index + 1) + 1;
	return set_classified_proto(ipacket, (index + 1), retval);

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
		S1AP_ERROR("Cannot initialize S1AP protocol\n");
		return 0;
	}

	int i = 0;
	int len = sizeof( s1ap_attributes_metadata ) / sizeof( attribute_metadata_t );
	for (; i < len; i++)
		register_attribute_with_protocol(protocol_struct, &s1ap_attributes_metadata[i]);

	int ret = register_classification_function_with_parent_protocol( PROTO_SCTP_DATA, _classify_s1ap_from_sctp_data, 100 );
	if( ret == 0 ){
		S1AP_ERROR("Need mmt_tcpip library containing PROTO_SCTP_DATA having id = %d\n", PROTO_SCTP_DATA);
		return 0;
	}

	//We need to process S1AP after SCTP_SHUTDOWN and SCTP_SHUTDOWN_COPLETE
	register_classification_function_with_parent_protocol( PROTO_SCTP_SHUTDOWN, _classify_s1ap_from_sctp_shutdown, 100 );
	if( ret == 0 ){
		S1AP_ERROR("Need mmt_tcpip library containing PROTO_SCTP_SHUTDOWN having id = %d\n", PROTO_SCTP_SHUTDOWN);
		return 0;
	}

	register_classification_function_with_parent_protocol( PROTO_SCTP_SHUTDOWN_COMPLETE, _classify_s1ap_from_sctp_shutdown, 100 );
	if( ret == 0 ){
		S1AP_ERROR("Need mmt_tcpip library containing PROTO_SCTP_SHUTDOWN_COMPLETE having id = %d\n", PROTO_SCTP_SHUTDOWN_COMPLETE);
		return 0;
	}

	//register_classification_function(protocol_struct, sctp_classify_next_chunk);
	register_proto_context_init_cleanup_function( protocol_struct, _on_init_protocol, _on_clean_protocol, NULL );

	return register_protocol(protocol_struct, PROTO_S1AP);
}
