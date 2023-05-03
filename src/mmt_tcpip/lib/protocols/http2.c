#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include "../../include/http2.h"


classified_proto_t http2_stack_classification(ipacket_t * ipacket) {

	classified_proto_t retval;
	retval.offset = 0;
	retval.proto_id = PROTO_HTTP2;
	retval.status = Classified;
	return retval;
}

int http2_header_method_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    *((unsigned char *) extracted_data->data) = *((unsigned char *) & packet->data[proto_offset + attribute_offset]);
    return 1;
}
int http2_header_length_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {
	//int proto_http2 = get_protocol_index_by_id(packet, PROTO_HTTP2);
 // 	int proto_offset = get_packet_offset_at_index(packet,proto_http2);

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int http2_offset = get_packet_offset_at_index(packet, proto_index+1);
    
   // printf("http2_offset %d \n", http2_offset);
    char * payload= (char*) &packet->data[http2_offset ];

    
    char signature_http2[]={ 0x0D,  0x0A,  0x0D, 0x0A, 0x53, 0x4D, 0x0D,  0x0A,  0x0D,  0x0A };//PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n

    if(strncmp(payload+http2_offset,signature_http2,sizeof(signature_http2) / sizeof(signature_http2[0]))==0){

     	*((unsigned int*) extracted_data->data)=0;
    	return 1;
    
    }
    //char * payload= (char*) &packet->data[proto_offset ];
    int attribute_offset = extracted_data->position_in_packet-1;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    *((unsigned int*) extracted_data->data) =ntohl( *((unsigned int *) & packet->data[proto_offset + attribute_offset]));
    *((unsigned int*) extracted_data->data) =*((unsigned int*) extracted_data->data) &(0x00FFFFFF);
    return 1;
}


int http2_payload_stream_id_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data){
     //Go to http2
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //Go to method field
    int method_offset = proto_offset+9;
    uint8_t method_value= *((uint8_t *) & packet->data[method_offset]);


	
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);

	//printf("method_value %d\n",method_value);
	if(method_value==131){

      		// Get http2 protocol offset
   		 int offset_header_length = proto_offset -1;
   		 int header_length =ntohl( *((unsigned int *) & packet->data[offset_header_length]));
   		 header_length=header_length & 0x00FFFFFF;
  	        // printf("header_length %d\n",header_length );
  		 int payload_offset= header_length+9+proto_offset;
   		 int stream_id_payload_offset=payload_offset+5;
   		 
   	 

    		*((unsigned int*) extracted_data->data) =ntohl( *((unsigned int *) & packet->data[stream_id_payload_offset]));
    		 //printf("payload stream id %d\n",  *((unsigned int*) extracted_data->data));
		return 1;
 }
	return 0;
}

int http2_payload_length_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data){
     //Go to http2
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //Go to method field
    int method_offset = proto_offset+9;
    uint8_t method_value= *((uint8_t *) & packet->data[method_offset]);


	
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);

	//printf("method_value %d\n",method_value);
	if(method_value==131){

      		// Get http2 protocol offset
   		 int offset_header_length = proto_offset -1;
   		 int header_length =ntohl( *((unsigned int *) & packet->data[offset_header_length]));
   		 header_length=header_length & 0x00FFFFFF;

  	        // printf("header_length %d\n",header_length );
  		 int payload_offset= header_length+9+proto_offset-1;

   	 

    		*((unsigned int*) extracted_data->data) =ntohl( *((unsigned int *) & packet->data[payload_offset]));

    		*((unsigned int*) extracted_data->data) &= 0x00FFFFFF;
    		 //printf("payload stream id %d\n",  *((unsigned int*) extracted_data->data));
		return 1;
 }
	return 0;
}
int http2_payload_data_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data){
     //Go to http2
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    //Go to method field
    int method_offset = proto_offset+9;
    uint8_t method_value= *((uint8_t *) & packet->data[method_offset]);


	
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);

	//printf("method_value %d\n",method_value);
	if(method_value==131){

      		// Get http2 protocol offset
   		 int offset_header_length = proto_offset -1;
   		 int header_length =ntohl( *((unsigned int *) & packet->data[offset_header_length]));
   		 header_length=header_length & 0x00FFFFFF;

  	        // printf("header_length %d\n",header_length );
  		 int payload_offset= header_length+9+proto_offset-1;

   	 

    		int payload_length =ntohl( *((unsigned int *) & packet->data[payload_offset]));

    		payload_length &= 0x00FFFFFF;
    		
    		extracted_data->data = (char*) &packet->data[payload_offset + 9+1];

    		 //printf("payload stream id %d\n",  *((unsigned int*) extracted_data->data));
		return 1;
 }
 	else
     	*((unsigned int*) extracted_data->data)=0;
	return 0;
}
int http2_stream_id_extraction(const ipacket_t * packet, unsigned proto_index,
    attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = (extracted_data->position_in_packet);

    *((unsigned int *) extracted_data->data) = (ntohl(*((unsigned int *) & packet->data[proto_offset + attribute_offset])));
  
    

    return 1;
}

static attribute_metadata_t http2_attributes_metadata[HTTP2_ATTRIBUTES_NB] = {

	{HTTP2_HEADER_LENGTH,     HTTP2_HEADER_LENGTH_ALIAS,      MMT_U32_DATA, sizeof(uint32_t),  0 , SCOPE_PACKET, http2_header_length_extraction},
	{HTTP2_TYPE,                HTTP2_TYPE_ALIAS,             MMT_U8_DATA	, sizeof(char), 3, SCOPE_PACKET, http2_header_method_extraction},//put here all extract function
	{HTTP2_HEADER_STREAM_ID,     HTTP2_HEADER_STREAM_ID_ALIAS, MMT_U32_DATA, sizeof(uint32_t),   5, SCOPE_PACKET, http2_stream_id_extraction},
	{HTTP2_HEADER_METHOD,      HTTP2_HEADER_METHOD_ALIAS,      MMT_U8_DATA, sizeof(char), 9, 	SCOPE_PACKET, http2_header_method_extraction},
	{HTTP2_PAYLOAD_LENGTH,    HTTP2_PAYLOAD_LENGTH_ALIAS,      MMT_U32_DATA, sizeof(uint32_t),POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_length_extraction},
	{HTTP2_PAYLOAD_STREAM_ID, HTTP2_PAYLOAD_STREAM_ID_ALIAS,       MMT_U32_DATA, sizeof(uint32_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_stream_id_extraction},

        {HTTP2_PAYLOAD_DATA,         HTTP2_PAYLOAD_DATA_ALIAS,      MMT_DATA_POINTER,    sizeof (char*),    POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_data_extraction},

};

int init_http2_proto_struct() {
	//printf("I am inside init_http2_proto_struct \n");
	protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_HTTP2, PROTO_HTTP2_ALIAS);
	//printf("Attribute_NB %d \n",HTTP2_ATTRIBUTES_NB);
	if (protocol_struct != NULL) {

		int i = 0;
		for(; i < HTTP2_ATTRIBUTES_NB; i ++) {
			register_attribute_with_protocol(protocol_struct, &http2_attributes_metadata[i]);
		}

	if (!register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http2, 9)) {
    		  fprintf(stderr, "[err] init_http2_proto_struct - cannot register_classification_function_with_parent_protocol\n");
    };

		register_protocol_stack(PROTO_HTTP2, PROTO_HTTP2_ALIAS, http2_stack_classification);
		return register_protocol(protocol_struct, PROTO_HTTP2);
	} else {
		return -1;
	}
}

/*
* HTTP2 data extraction routines
 */
 int mmt_check_http2(ipacket_t * ipacket, unsigned proto_index) {
              srand(time(NULL));   // Initialization, should only be called once.

	//printf("I am inside mmt_check_http2 \n");
	// Get the offset for the packet to be classified at next protocol
	int proto_offset = get_packet_offset_at_index(ipacket, proto_index+1);
	
  	

  	
	//printf("Proto_offset  %d\n",proto_offset);
	
	 //second way to calculate the offset

	char * payload= (char*) &ipacket->data[proto_offset ];
/*
	printf("Len payload %zu\n",strlen(payload));
		printf("Payload1  is   ");
		for (int i = 0; i < strlen(payload); i++){
  		printf(" %02hhX ",payload[i]);

	}
*/
		//printf("\n Payload[9] and [10]");
  		//printf(" %02hhX ",payload[9]);
  		//printf(" %02hhX ",payload[10]);
  		

	char* signature_http2="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";//PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n

	if(strncmp(payload,signature_http2,strlen(signature_http2))==0){
		//printf("Id of packet is   ");
  		//printf(" %lu ",ipacket->packet_id);
  	
//		printf("\n Signature:%.*s",(int) strlen(signature_http2), payload);

		//printf("\nHTTP2 recognized");
		classified_proto_t http2_proto = http2_stack_classification(ipacket);
		return set_classified_proto(ipacket, proto_index + 1, http2_proto);
	}
	else
		return 0;

}

