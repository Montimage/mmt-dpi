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
 * Print value
 */
void printValue(int dataType,void* data){
	switch(dataType){
		// uint32_t
		case 1:
			if (data) {
				printf("%u,", *((uint32_t * )data));
			}else{
				printf("NULL,");
			}
			break;
		// uint16_t
		case 2:
			if (data) {
				printf("%u,", *((uint16_t * )data));
			}else{
				printf("NULL,");
			}
			break;
		// uint8_t
		case 3:
			if (data) {
				printf("%u,", *((uint8_t * )data));
			}else{
				printf("NULL,");
			}
			break;
		// struct timeval *tv
		case 4:
			if (data) {
				struct timeval* tv = (struct timeval*) data;
				printf("%ld,%ld,",(long)tv->tv_sec,(long)tv->tv_usec);
			}else{
				printf("NUL,NULL,");
			}
			break;
		// MMT_DATA_IP_ADDR
		case 5:
			if (data){
				struct in_addr * addr = (struct in_addr *)data;
				printf("%s,",inet_ntoa(*addr));
			}else{
				printf("NULL,");
			}
			break;
		default:
			printf("unknown,");
	}
}
