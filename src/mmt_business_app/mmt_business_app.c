/*
 * mmt_business_app.c
 *
 *  Created on: Jun 3, 2021
 *      Author: nhnghia
 */



#include <stdio.h>
#include "mmt_business_app_internal.h"

int init_proto() {
	if (!init_proto_ips_data()) {
		fprintf(stderr,	"Error initializing protocol PROTO_IPS_DATA\n Exiting\n");
		exit(0);
	}
	return 1;
}
int cleanup_proto() {
	//printf("close s1ap protocol");
	return 0;
}
