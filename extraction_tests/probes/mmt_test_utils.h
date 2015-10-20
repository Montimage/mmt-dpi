#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "mmt/data_defs.h" 
/**
 * FTP command structure: CMD PARAMETER
 */
typedef struct ftp_command_struct{
    uint16_t cmd;
    char *str_cmd;
    char *param;
}ftp_command_t;

/**
 * FTP response structure
 */
typedef struct ftp_response_struct{
	uint16_t code;
    char *str_code;
    char *value;
}ftp_response_t;

/**
 * Print value
 */
void printValue(void* data,int dataType){
	if(data==NULL){
		printf("NULL,");
		return;
	}
	switch(dataType){
		// char*
		case 0:
			printf("%s,",(char*)data);
			break;
		// uint32_t
		case 1:
			printf("%u,", *((uint32_t * )data));
			break;
		// uint16_t
		case 2:
			printf("%u,", *((uint16_t * )data));
			break;
		// uint8_t
		case 3:
			printf("%u,", *((uint8_t * )data));
			break;
		// MMT_DATA_IP_ADDR
		case 5:
			printf("%s,",inet_ntoa(*(struct in_addr*)data));
			break;
		// Last command
		case 6:
			printf("%s | %s,", ((ftp_command_t*)data)->str_cmd,(((ftp_command_t*)data)->param==NULL?"NULL":((ftp_command_t*)data)->param));
			break;
		// Last response
		case 7:
			printf("%s | %s,", ((ftp_response_t*)data)->str_code, (((ftp_response_t*)data)->value==NULL?"NULL":((ftp_response_t*)data)->value));
			break;
		default:
			printf("unknown,");
	}
}
