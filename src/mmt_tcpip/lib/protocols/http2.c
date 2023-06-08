#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "mmt_common_internal_include.h"
#include "../../include/http2.h"
#include <nghttp2/nghttp2.h>

#define HEADER_MAX_LENGTH 400


//Function to decompress header and adding character to increase the size of the packet
int inflate_header_increase(nghttp2_hd_inflater *inflater, nghttp2_nv* nv,
                         uint8_t *in, size_t inlen,  nghttp2_nv* nv_out,int *dim_out)
{
    ssize_t rv;
   // int final=0;
    int j=0;//Dimension of array nv_out
    
    for(;;) {
	//printf("Iterazione %d  \n",j);
        int inflate_flags = 0;
	//printf("Inlen %lu \n",inlen);
        rv = nghttp2_hd_inflate_hd2(inflater, nv, &inflate_flags,
                                    in, inlen, 0);
        if(rv < 0) {
            fprintf(stderr, "inflate failed with error code %zd\n", rv);
            return 0;
        }
        in += rv;
        inlen -= rv;
        //char c[30];
  	//printf("Input Inflate\n");
        if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
           // fwrite(nv->name, nv->namelen, 1, stderr);
           // fprintf(stderr, ": ");
           // fwrite(nv->value, nv->valuelen, 1, stderr);
          //  fprintf(stderr, "\n ");
            
            nv_out[j].name=malloc(sizeof(uint8_t)*(nv->namelen));
            memcpy((uint8_t*)nv_out[j].name,(uint8_t*)nv->name,nv->namelen);
            nv_out[j].namelen=nv->namelen;
            
            nv_out[j].flags=NGHTTP2_NV_FLAG_NONE;
            if( j==1){// 0x2F is ASCII code for /
            	//printf("inflate_header_increase allocation of the value in output");
           	nv_out[j].value=malloc(sizeof(uint8_t)*((nv->valuelen)+HEADER_MAX_LENGTH));
           	nv_out[j].valuelen=(nv->valuelen+HEADER_MAX_LENGTH);
            	memcpy((uint8_t*)nv_out[j].value,(uint8_t*)nv->value,nv->valuelen);
           	for(int i =nv->valuelen;i<nv->valuelen+HEADER_MAX_LENGTH;i++){ 

			nv_out[j].value[i]=(uint8_t)'A';
          	}
              }
              else{
                  nv_out[j].value=malloc(sizeof(uint8_t)*(nv->valuelen));
         	  memcpy((uint8_t*)nv_out[j].value,(uint8_t*)nv->value,nv->valuelen);
          	  nv_out[j].valuelen=nv->valuelen;    
              }
          //  printf("\n");
            j=j+1;
          //printf("Next Method\n");
        }
        if((inflate_flags & NGHTTP2_HD_INFLATE_FINAL)) {
            nghttp2_hd_inflate_end_headers(inflater);
            break;
        }
        if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&  inlen == 0) {
           break;
          }
       }
	*dim_out=j;
    return 0;
}

int inflate_header_fuzz(nghttp2_hd_inflater *inflater, nghttp2_nv* nv,
                         uint8_t *in, size_t inlen,  nghttp2_nv* nv_out,int *dim_out)
{
    ssize_t rv;
   // int final=0;
    int j=0;//Dimension of array nv_out
    for(;;) {
        int inflate_flags = 0;
	//printf("Inlen %lu \n",inlen);
        rv = nghttp2_hd_inflate_hd2(inflater, nv, &inflate_flags,
                                    in, inlen, 0);
        if(rv < 0) {
            fprintf(stderr, "inflate failed with error code %zd\n", rv);
            return 0;
        }
        in += rv;
        inlen -= rv;
  	//printf("Input Inflate\n");
        if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            //fwrite(nv->name, nv->namelen, 1, stderr);
          //  fprintf(stderr, ": ");
           // fwrite(nv->value, nv->valuelen, 1, stderr);
           // fprintf(stderr, "\n ");
            if(nv->value[0]==0x2F&& j==1){
                char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;\'///:,.<>/?\\";
          //      printf("Random char generated\n");
                for(int i=(int)nv->valuelen;i>(int)(nv->valuelen/3);i--){
                            int r = rand() % (sizeof(characters)-1);
                            nv->value[i]=characters[r];
                }
              }
             //remove this code 
            nv_out[j].name=malloc(sizeof(uint8_t)*(nv->namelen));
            memcpy((uint8_t*)nv_out[j].name,(uint8_t*)nv->name,nv->namelen);
            nv_out[j].namelen=nv->namelen;
            nv_out[j].value=malloc(sizeof(uint8_t)*(nv->valuelen));
            memcpy((uint8_t*)nv_out[j].value,(uint8_t*)nv->value,nv->valuelen);
            nv_out[j].valuelen=nv->valuelen;
            nv_out[j].flags=NGHTTP2_NV_FLAG_NONE;
           // for(int x=0;x<(int)nv->valuelen;x++)
           //    printf(" %02hhX  ", nv_out[j].value[x]);
           // printf("\n");
            j=j+1;
        //  printf("Next Method\n");
        }
        if((inflate_flags & NGHTTP2_HD_INFLATE_FINAL)) {
            nghttp2_hd_inflate_end_headers(inflater);
            break;
        }
        if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&  inlen == 0) {
           break;
          }
       }
	*dim_out=j;
    return 0;
}


static void deflate(nghttp2_hd_deflater *deflater,//nghttp2_hd_inflater *inflater, 
                     const nghttp2_nv *const nva, uint8_t*buf,
                    size_t nvlen,size_t *len_out) {
	ssize_t rv;
	size_t buflen;
	size_t outlen;
	size_t i;
	size_t sum;
	// printf("Input deflate   \n\n");
	//printf("nvlen %lu \n",nvlen);
	/*
	for(int j=0;j<(int)nvlen;j++){
		for(int x=0;x<(int)nva[j].valuelen;x++)
					printf(" %02hhX  ", nva[j].value[x]);
		printf("\n");
	}
	*/
	sum = 0;
	for (i = 0; i < nvlen; ++i) {
		sum += nva[i].namelen + nva[i].valuelen;
	}
	//  printf("Input deflate (%zu byte(s)):\n\n", sum);
	//for (i = 0; i < nvlen; ++i) {
	// fwrite(nva[i].name, 1, nva[i].namelen, stdout);
	//printf("Name %s Namelen %lu  \n",(char*)nva[i].name,nva[i].namelen);
	// printf(": ");
	// printf("Value %s value %lu\n",(char*)nva[i].value,nva[i].valuelen);
		//fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
		//printf("\n");
	//}
	buflen = nghttp2_hd_deflate_bound(deflater, nva, nvlen);
	//printf("Name   %lu\n",buflen);
	rv = nghttp2_hd_deflate_hd(deflater, buf, buflen, nva, nvlen);

	if (rv < 0) {
		fprintf(stderr, "nghttp2_hd_deflate_hd() failed with error: %s\n",
				nghttp2_strerror((int)rv));

		//free(buf);

		exit(EXIT_FAILURE);
		}
		outlen = (size_t)rv;
	//printf("\nDeflate (%zu byte(s), ratio %.02f):\n\n", outlen,
	// sum == 0 ? 0 : (double)outlen / (double)sum );
	//printf("outlen %lu\n",outlen);
	//for (i = 0; i < outlen; ++i) {
	//  if ((i & 0x0fu) == 0) {
	//   printf("%08zX: ", i);
	//  }

	// printf("%02X ", buf[i]);

	//  if (((i + 1) & 0x0fu) == 0) {
	//   printf("\n");
	//   }
	//}
	//printf("\nnvlen %lu-----buflen %lu -----outlen %lu------sum %lu \n", nvlen, buflen, outlen, sum);
	*len_out=outlen;
	//printf("\n-------------------------------------------------------------------------------\n");
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

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	int attribute_offset = extracted_data->position_in_packet;
	//int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
	*((unsigned char*) extracted_data->data) = *((unsigned char*) &packet->data[proto_offset + attribute_offset]);
	return 1;
}

int http2_header_length_extraction(const ipacket_t *packet,
		unsigned proto_index, attribute_t *extracted_data) {
	// [ETH][IP][TCP][HTTP2][xxx]
	//=================^
	
	int http2_offset = get_packet_offset_at_index(packet, proto_index );
	//not enough room
	//if (http2_offset >= packet->p_hdr->caplen)
	//	return 0;
	// printf("http2_offset %d \n", http2_offset);

	
	char *payload = (char*) &packet->data[http2_offset];
	char signature_http2[] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A }; 	//PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
	if (strncmp(payload , signature_http2,
			sizeof(signature_http2) / sizeof(signature_http2[0])) == 0) { //The first packet must be ignored

		*((unsigned int*) extracted_data->data) = 0;
		return 1;
	}

	//char * payload= (char*) &packet->data[proto_offset ];
	int attribute_offset = extracted_data->position_in_packet - 1;
	//int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
	*((unsigned int*) extracted_data->data) = ntohl(
			*((unsigned int* ) &packet->data[http2_offset + attribute_offset]));
	*((unsigned int*) extracted_data->data) =
			*((unsigned int*) extracted_data->data) & (0x00FFFFFF);
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

	//not enough room
	if (method_offset >= packet->p_hdr->caplen)
		return 0;

	uint8_t method_value = *((uint8_t*) &packet->data[method_offset]);
	//int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
	//printf("method_value %d\n",method_value);
	if (method_value == 131) {

		// 3 bytes for payload length
		// we go back 1 byte to extract an integer of 4 bytes
		// we then later remove the latest byte
		// Get http2 protocol offset
		int offset_header_length = proto_offset - 1;
		int header_length = ntohl(
				*((unsigned int* ) &packet->data[offset_header_length]));
		header_length = header_length & 0x00FFFFFF;
		// printf("header_length %d\n",header_length );
		int payload_offset = header_length + 9 + proto_offset;
		int stream_id_payload_offset = payload_offset + 5;
		*((unsigned int*) extracted_data->data) = ntohl(
				*((unsigned int* ) &packet->data[stream_id_payload_offset]));
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


	//not enough room
	//if (method_offset >= packet->p_hdr->caplen)
	//	return 0;

	uint8_t method_value = *((uint8_t*) &packet->data[method_offset]);
	//int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
	//printf("method_value %d\n",method_value);
	if (method_value == 131) {

		// Get http2 protocol offset
		int offset_header_length = proto_offset - 1;
		int header_length = ntohl(
				*((unsigned int* ) &packet->data[offset_header_length]));
		header_length = header_length & 0x00FFFFFF;
		// printf("header_length %d\n",header_length );
		int payload_offset = header_length + 9 + proto_offset - 1;//In order to get to http2 payload you need to get the header length, adding the 9 bytes of the header. 
		//Payload length is three bytes, while an integer is 4 bytes, so here we start from one byte before and and bitwise with 0x00FFFFFF that integer to remove last byte.
		*((unsigned int*) extracted_data->data) = ntohl(
				*((unsigned int* ) &packet->data[payload_offset]));
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

	//not enough room
	if (method_offset >= packet->p_hdr->caplen)
		return 0;

	uint8_t method_value = *((uint8_t*) &packet->data[method_offset]);
	//int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
	if (method_value == 131) {

		// Get http2 protocol offset
		int offset_header_length = proto_offset - 1;
		int header_length = ntohl(
				*((unsigned int* ) &packet->data[offset_header_length]));
		header_length = header_length & 0x00FFFFFF;
		// printf("header_length %d\n",header_length );
		int payload_offset = header_length + 9 + proto_offset - 1;//In order to get to http2 payload you need to get the header length, adding the 9 bytes of the header. 
		//Payload length is three bytes, while an integer is 4 bytes, so here we start from one byte before and and bitwise with 0x00FFFFFF that integer to remove last byte.
		int payload_length = ntohl(
				*((unsigned int* ) &packet->data[payload_offset]));
		payload_length &= 0x00FFFFFF;
		extracted_data->data = (char*) &packet->data[payload_offset + 9 + 1];
		//printf("payload stream id %d\n",  *((unsigned int*) extracted_data->data));
		return 1;

	}
	*((unsigned int*) extracted_data->data) = 0;

	return 0;
}
int http2_stream_id_extraction(const ipacket_t *packet, unsigned proto_index,
		attribute_t *extracted_data) {

	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	int attribute_offset = (extracted_data->position_in_packet);
	*((unsigned int*) extracted_data->data) = (ntohl( *((unsigned int* ) &packet->data[proto_offset + attribute_offset])));
	return 1;
}

static attribute_metadata_t http2_attributes_metadata[HTTP2_ATTRIBUTES_NB] = {

	{HTTP2_HEADER_LENGTH,     HTTP2_HEADER_LENGTH_ALIAS,    MMT_U32_DATA, sizeof(uint32_t),  0 , SCOPE_PACKET, http2_header_length_extraction},
	{HTTP2_TYPE,              HTTP2_TYPE_ALIAS,             MMT_U8_DATA	, sizeof(char), 3, SCOPE_PACKET, http2_header_method_extraction},//put here all extract function
	{HTTP2_HEADER_STREAM_ID,  HTTP2_HEADER_STREAM_ID_ALIAS, MMT_U32_DATA, sizeof(uint32_t),   5, SCOPE_PACKET, http2_stream_id_extraction},
	{HTTP2_HEADER_METHOD,     HTTP2_HEADER_METHOD_ALIAS,    MMT_U8_DATA, sizeof(char), 9, 	SCOPE_PACKET, http2_header_method_extraction},
	{HTTP2_PAYLOAD_LENGTH,    HTTP2_PAYLOAD_LENGTH_ALIAS,   MMT_U32_DATA, sizeof(uint32_t),POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_length_extraction},
	{HTTP2_PAYLOAD_STREAM_ID, HTTP2_PAYLOAD_STREAM_ID_ALIAS,MMT_U32_DATA, sizeof(uint32_t),  POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_stream_id_extraction},
	{HTTP2_PAYLOAD_DATA,      HTTP2_PAYLOAD_DATA_ALIAS,     MMT_DATA_POINTER,    sizeof (char*),    POSITION_NOT_KNOWN, SCOPE_PACKET, http2_payload_data_extraction},

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
			fprintf(stderr,
					"[err] init_http2_proto_struct - cannot register_classification_function_with_parent_protocol\n");
		};

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
	int http2_header_size = 0;
	//this attribute data is to use to extract http2 length
	//attribute_t extracted_data;
	//printf("Proto_offset  %d\n",proto_offset);
	//not enough room
	if (proto_offset >= ipacket->p_hdr->caplen)
		return 0;

	//second way to calculate the offset
	char *payload = (char*) &ipacket->data[proto_offset];
	char *signature_http2 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";	//PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
	if (strncmp(payload, signature_http2, strlen(signature_http2)) == 0) {
		classified_proto_t http2_proto = http2_stack_classification(ipacket);
		http2_proto.offset = tcp_header_size;
		return set_classified_proto(ipacket, proto_index + 1, http2_proto);

	} else if (ipacket->proto_hierarchy->proto_path[proto_index + 1] == PROTO_HTTP2) {
		//extract http2 length
		//extracted_data.position_in_packet = 1;
		//extracted_data.data = &http2_header_size;
		// Get http2 protocol offset
		payload--;
		http2_header_size = ntohl(*((unsigned int* ) payload));
		http2_header_size &= 0x00FFFFFF;
		http2_header_size = http2_header_size + 9;
		//classify the next protocol that is after HTTP2
		// the next protocol resides inside the payload of HTTP2. The HTTP2 payload is the memory segment after the HTTP2 header
		// so we need to calculate the length of HTTP2 header 
		classified_proto_t unknown_proto;
		unknown_proto.offset = http2_header_size;
		unknown_proto.proto_id = 1; //unknown protocol id
		unknown_proto.status = Classified;
		return set_classified_proto(ipacket, proto_index + 2, unknown_proto);

	} else
		return 0;
}

int restore_http2_packet(uint8_t*data_out,const ipacket_t * packet,int proto_offset,uint32_t data_out_size){
 	int header_length = 0;
 	int offset_header_length = proto_offset -1;
   	for (int i = offset_header_length; i < offset_header_length+4; i++) {
      		  header_length = (header_length << 8) | (data_out[i] & 0xFF);
   	 }
   	 header_length=header_length & 0x00FFFFFF;
 	int new_length = 0;
   	 for (int i = offset_header_length; i < offset_header_length+4; i++) {
      		  new_length = (new_length << 8) | (packet->data[i] & 0xFF);
   	 }
   	 new_length = new_length & 0x00FFFFFF;
   	// printf("new_length %d, header_length %d\n",new_length,header_length);
   	// printf("data_out %02X packet_data %02X \n",data_out[proto_offset],packet->data[proto_offset]);
   	if(new_length+9>data_out_size || proto_offset>(data_out_size))
   		return 0;
 	memcpy((uint8_t*)data_out+proto_offset,packet->data+proto_offset,new_length+9);
 	return new_length-header_length;
}

int modify_get(uint8_t*data_out,int proto_offset,uint32_t data_out_size){
    	//Go to method field
   	int header_length = 0;
      	// Get http2 protocol offset
   	int offset_header_length = proto_offset -1;
   	for (int i = offset_header_length; i < offset_header_length+4; i++) {
      		  header_length = (header_length << 8) |(data_out[i] & 0xFF);
   	 }
   	header_length = header_length & 0x00FFFFFF;
	uint8_t authority_amf[] = {0x41,0x8d,0x0b,0xa2,0x5c,0x2e,0x2e,0xdb,0xeb,0xba,0xcd,0xc7,0x80,0xf0,0x3f,0x7a,0x03,0x61,0x6d,0x66};
	int authority_amf_length = sizeof(authority_amf) ;
	//printf("[modify_get]authority_amf_length %d\n",authority_amf_length);
	if(authority_amf_length > data_out_size || proto_offset+9+header_length-2 > data_out_size)
		return 0;
	memcpy(data_out+proto_offset+9+header_length-2,authority_amf,authority_amf_length);
	//printf("modify get after update:\n");
	//for(int i=proto_offset+9+header_length-2;i<proto_offset+9+header_length-2+authority_amf_length;i++)
	//	printf("%02hhX ",data_out[i]);
	header_length += authority_amf_length-2;//Http2 buffers the authority and amf with 2 bytes(0xc0 0xc1)from the first packet.The code restore the first authority_amf value.
	//The new header lenght will be the sizeof authority and amf minus 2
	data_out[offset_header_length+1] = header_length>>16; //I update the last 24 bites
	data_out[offset_header_length+2] = header_length>>9; //I update the last 16 bites
	data_out[offset_header_length+3] = header_length ;//I update the last 8 bites
	//printf("[modify_get]offset_header_length %02hhX %02hhX %02hhX \n",data_out[offset_header_length+1],data_out[offset_header_length+2],data_out[offset_header_length+3]);
	return (int)(sizeof(authority_amf)-2);
}

uint32_t update_window_update(char *data_out,int proto_offset,uint32_t modify){
	int window_size_offset = proto_offset+9;
	//int offset_header_length = proto_offset -1;
	if(modify == 1){
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
   	int header_length = 0;
   	for (int i = offset_header_length; i < offset_header_length+4; i++) {
      		  header_length = (header_length << 8) | (data_out[i] & 0xFF);
   	 }
   	// printf("inject_http2_packet Header_length %d",header_length);
   	if(data_to_inject_len > data_out_size || proto_offset > data_out_size)
   		return 0;
 	memcpy(data_out + proto_offset,data_to_inject,data_to_inject_len);
 	return (data_to_inject_len - header_length-9); 
}

int update_stream_id(char *data_out,int proto_offset,uint32_t new_val){
	
  	int stream_id_offset = proto_offset+5;
	//printf("update_stream_id  data_out[stream_id_offset] %02hhX \n",data_out[stream_id_offset]);
	data_out[stream_id_offset] = (new_val>> 24) & 0xFF;
	data_out[stream_id_offset+1] = (new_val>> 16) & 0xFF;
	data_out[stream_id_offset+2] = (new_val>> 8) & 0xFF;
	data_out[stream_id_offset+3] = (new_val) & 0xFF;
	//printf("update_stream_id  data_out[stream_id_offset] after the modification %02hhX %02hhX %02hhX %02hhX  \n",data_out[stream_id_offset],data_out[stream_id_offset+1],data_out[stream_id_offset+2],data_out[stream_id_offset+3]);
	int offset_header_length = proto_offset -1;
	int method_offset = proto_offset+9;
	uint8_t method_value = ((uint8_t )  data_out[method_offset]);
   	//int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
	if(method_value == 131){
		int header_length = 0;
	   	//int header_length =ntohl( *((unsigned int *) & packet->data[offset_header_length]));
	   	 for (int i = offset_header_length; i < offset_header_length+4; i++) {
	      		  header_length = (header_length << 8) | (data_out[i] & 0xFF);
	   	 }
	  	//printf("update_stream_id header_length %d\n",header_length );
	  	int payload_offset = header_length+9+proto_offset;
	   	int stream_id_payload_offset = payload_offset+5;
		data_out[stream_id_payload_offset] = (new_val>> 24) & 0xFF;
		data_out[stream_id_payload_offset+1] = (new_val>> 16) & 0xFF;
		data_out[stream_id_payload_offset+2] = (new_val>> 8) & 0xFF;
		data_out[stream_id_payload_offset+3] = (new_val) & 0xFF;
		//printf("update_stream_id  data_out[stream_id_payload_offset] after the modification %02hhX \n",data_out[stream_id_payload_offset]);
	}
	return 1;
}

int update_path( uint8_t*data_out,  int proto_offset,int type, uint32_t data_size ){
	int   rv;
	int header_length = 0;
	int payload_length = 0;
	// Get http2 protocol offset
   	int offset_header_length = proto_offset -1;
	size_t len_out=0;
	for (int i = offset_header_length; i < offset_header_length+4; i++) {
      		  header_length = (header_length << 8) | (data_out[i] & 0xFF);
   	 }
   	header_length=header_length & 0x00FFFFFF;
   	//printf("Header length %d \n",header_length);
   	uint8_t data_to_modify[header_length]; //Compressed string
   	 
   	int payload_offset= proto_offset+header_length+9-1;
   	for (int i = payload_offset; i < payload_offset+4; i++) {
      		  payload_length = (payload_length << 8) | (data_out[i] & 0xFF);
   	 }
	int mask = 0x00FFFFFF; // mask to set last 2 bytes to 0
	payload_length = payload_length & mask; // put to 0 last byte
	if(sizeof(data_to_modify)>data_size)
		return 0;
   	memcpy(data_to_modify,data_out+9+proto_offset,sizeof(data_to_modify));
   	//printf("sizeof Data_to_modify %lu\n",sizeof(data_to_modify));
   	//printf("Data_to_modify ");
   	//for (size_t i = 0; i < sizeof(data_to_modify); i++) {
      	//	printf("%02hhX ", data_to_modify[i]);
    	//}
    	//printf("\n");
   	nghttp2_hd_inflater* inflater;
	nghttp2_hd_deflater *deflater;
	int dim_out=0;
	nghttp2_nv nv;
	nghttp2_nv  nv_decompressed[7];
	uint8_t buf_out[header_length+HEADER_MAX_LENGTH];
  	 rv = nghttp2_hd_inflate_new(&inflater);

  	if (rv != 0) {
  	  	fprintf(stderr, "nghttp2_hd_inflate_init failed with error: %s\n",
            	nghttp2_strerror(rv));
    		exit(EXIT_FAILURE);
 	}
 	 rv = nghttp2_hd_deflate_new(&deflater, 4096);

 	 if (rv != 0) {
  	  	fprintf(stderr, "nghttp2_hd_deflate_init failed with error: %s\n",
          	nghttp2_strerror(rv));
  		exit(EXIT_FAILURE);
  	}

  	if(type==HTTP2_PATH_FUZZ){
   		rv=inflate_header_fuzz(inflater, &nv, data_to_modify, sizeof(data_to_modify),nv_decompressed,&dim_out);
	 	if (rv != 0) {
  	  		fprintf(stderr, "inflate_header_fuzz failed with error \n");


  		}
  	}
  	else{
  	   	rv=inflate_header_increase(inflater, &nv, data_to_modify, sizeof(data_to_modify),nv_decompressed,&dim_out);
	 	if (rv != 0) {
  	  		fprintf(stderr, "inflate_header_increase failed with error \n");


  		}
  	
  	}
  	deflate(deflater ,nv_decompressed,buf_out,(size_t) dim_out,&len_out);
  	/*printf("Buf_out ");
	   for (size_t i = 0; i < (int)len_out; i++) {
      		printf("%02hhX ", buf_out[i]);
    	}
    	*/
	if((int)len_out!=header_length){
		//Go to http2
  		//printf("header_length %d\n",header_length );
  		//printf("Len_out %d\n",(int)len_out );
		//printf("payload_length %d\n",payload_length);
		uint8_t temp_payload[payload_length+9];	
		memcpy(temp_payload,data_out+payload_offset+1,(size_t) payload_length+9);//As the compressed header is usually bigger, I copy the payload in temp var
		//printf("Siezeof temp_payload %lu ",sizeof(temp_payload));
		//printf("temp \n");
		//for(int i=0;i<sizeof(temp);i++)
		// printf("%02X ",temp[i]);
		memcpy(data_out+9+proto_offset,buf_out,(size_t)len_out);//I copy the new  header compressed
		int shift_size=len_out-header_length;
		memcpy((uint8_t*)data_out+payload_offset+shift_size+1,(uint8_t*)temp_payload,sizeof(temp_payload));
		//printf("\nData_out after modifications: \n");
		//for(int i=payload_offset+shift_size+1;i<(int)sizeof(temp)+payload_offset+shift_size+1;i++)
		//printf("%02X ",data_out[i]);
		data_out[offset_header_length]=0x00; //I update the header size
		data_out[offset_header_length+1]=len_out>>16; //I update the header size
		data_out[offset_header_length+2]=len_out>>8; //I update the header size
		data_out[offset_header_length+3]=len_out ;//I update the header size
	}
	else
		memcpy(data_out+9+proto_offset,buf_out,(size_t)len_out);
	//printf("\nLen_out %lu ",len_out);

	
	//printf("New size %lu\n",len_out+payload_length+9+9);
	//printf("payload offset %d payload_length %d\n",payload_offset,payload_length);

    	//printf("\n");
    	
    	nghttp2_hd_inflate_del(inflater);
  	nghttp2_hd_deflate_del(deflater);
    	
    	for(int x=0;x<dim_out;x++){

           free(nv_decompressed[x].value);
           free(nv_decompressed[x].name);
      }
	return (len_out-(header_length));
}


int update_http2_payload(char *data_out, uint32_t data_size, const ipacket_t *packet, uint32_t proto_id, uint32_t att_id, char* new_data,uint32_t new_data_len){
	//1.Go to payload data
	int header_length = 0;
	uint32_t old_payload_length = 0;
	// Get http2 protocol offset
	int proto_http2 = get_protocol_index_by_id(packet, proto_id);
  	int proto_offset = get_packet_offset_at_index(packet,proto_http2);
	int offset_header_length = proto_offset -1;
	for (int i = offset_header_length; i < offset_header_length+4; i++) {
		header_length = (header_length << 8) | (data_out[i] & 0xFF);
	}
	//printf(" update_http2_payload header_length %d\n",header_length );
	int payload_offset = header_length+9+proto_offset-1;
	//printf("update_http2_payload payload_offset %d\n",payload_offset);
	//printf("Payload_length before %02hhX\n",old_payload_length);
	//This operation puts the 4 bytes in data_out in integer variable.
	for (int i = payload_offset; i < payload_offset+4; i++) {
		old_payload_length = (uint32_t)(old_payload_length << 8) | (data_out[i] & 0xFF);//By applying the bitwise AND operation array[i] & 0xFF, the 0xFF mask ensures that only the lower 8 bits are preserved, regardless of the signedness of char. This masking operation effectively clears the higher bits, preventing sign extension issue, so it converts signed char to unsigned char.
		       //printf(" data_out[payload_offset]%02hhX,\npayload_length  %02hhX\n", data_out[i],payload_length);
	}
	int mask = 0x00FFFFFF; // mask to set last 2 bytes to 0
	old_payload_length = old_payload_length & mask; // put to 0 last byte
	//printf("update_http2_payload payload_length %d\n",payload_length );
	//printf("%d \n",data_out[payload_offset]);
	// printf("update_http2_payload data_out after modification");
	//for(int i=payload_offset;i<payload_offset+payload_length;i++)
	//printf("%c",data_out[i]);
	//2.I update the length with the new_length
	data_out[payload_offset+1] = (new_data_len>>16) & 0xFF; //I update the last 24 bites
	data_out[payload_offset+2] = (new_data_len>>9) & 0xFF; //I update the last 16 bites
	data_out[payload_offset+3] = (new_data_len) & 0xFF ;//I update the last 8 bites
	//for(int i=payload_offset+1; i<payload_offset+4; i++)
	//	printf("data_out new_length  %02hhX",data_out[i]);
	//printf("update_http2_payload old_payload_length %d\n",old_payload_length );
	int payload_data_offset = payload_offset+ 9+1;
	//3. copy new payload characters
	if(new_data_len <= old_payload_length && payload_data_offset < data_size)
		 memcpy(data_out + payload_data_offset,new_data,new_data_len);
	return new_data_len - old_payload_length;
}

int update_http2_data( char *data_out, uint32_t data_size, const ipacket_t *packet, uint32_t proto_id, uint32_t att_id, uint32_t new_val ){
   	//Go to http2
	//printf("update_http2_data Id of packet is   ");
  	//printf(" %lu \n",packet->packet_id);
	int difference_size = 0;
	uint32_t ret = 0;
	if( proto_id != PROTO_HTTP2 )
		return ret;
	uint8_t window_update_frame[] = {0x00,0x00,0x04,0x08,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0xFF,0x01//window size increment:set to a small value
			};
  	int proto_http2 = get_protocol_index_by_id(packet, proto_id);
  	int proto_offset = get_packet_offset_at_index(packet,proto_http2);
  	//printf("Proto offset %d and proto_id %u\n",proto_offset,proto_id);
  	//Go to method field
  	//data_out  = (char*) &packet->data[proto_offset ];	
  	switch(att_id){
  		
  		case(HTTP2_HEADER_STREAM_ID):
  			update_stream_id(data_out,proto_offset,new_val);
			break;
		
		case(HTTP2_WINDOW_UPDATE):
			difference_size = update_window_update(data_out,proto_offset,new_val);
			return difference_size; 
			break;
	
		case(HTTP2_DISCARD_SETTINGS):
			difference_size = -9;
			return difference_size; 

		//case(HTTP2_PAYLOAD_FUZZ):
			//fuzz_payload((uint8_t*)data_out,packet,proto_offset);
			//printf("[update_http2_data]data_size %d\n",data_size);
			//update_stream_id(data_out,proto_offset,new_val);
			//break;
			
		case(HTTP2_GET_MODIFY):
			update_stream_id(data_out,proto_offset,new_val);
			difference_size = modify_get((uint8_t*)data_out, proto_offset,data_size);
			return difference_size;
			break;
			
		case(HTTP2_INJECT_WIN_UPDATE):
			int win_len = (int)sizeof(window_update_frame);
			difference_size = inject_http2_packet((uint8_t*)data_out,window_update_frame,proto_offset,win_len,data_size);
			return difference_size;
			break;
			
		case (HTTP2_RESTORE_PACKET):
			difference_size = restore_http2_packet((uint8_t*)data_out,packet,proto_offset,data_size);
			return difference_size;
			break;
			
		case(HTTP2_PATH_FUZZ):
			difference_size = update_path((uint8_t*)data_out,proto_offset,HTTP2_PATH_FUZZ,data_size);
			//printf("[update_http2_data]data_size %d\n",data_size);
			update_stream_id(data_out,proto_offset,new_val);
			return difference_size;
			break;
		case(HTTP2_HEADER_AMPLIFICATION):
			difference_size = update_path((uint8_t*)data_out,proto_offset,HTTP2_HEADER_AMPLIFICATION,data_size);
			//printf("[update_http2_data]data_size %d\n",data_size);
			return difference_size;
		default:
			  MMT_LOG(PROTO_HTTP2, MMT_LOG_ERROR, "NO VALID ATT ID FOR HTTP2.\n");
			//printf("update_http2_data  INSERT A VALID ATT_ID  \n");
			break;
	
	}

	return 0;
	

}

