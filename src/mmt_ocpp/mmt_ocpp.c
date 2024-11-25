/*
 * mmt_business_app.c
 *
 *  Created on: Jun 3, 2021
 *      Author: nhnghia
 */



#include <stdio.h>
#include "mmt_ocpp_internal.h"

int init_proto() {
	if (!init_proto_ocpp_data()) {
		fprintf(stderr,	"Error initializing protocol PROTO_OCPP_DATA\n Exiting\n");
		exit(0);
	}
	return 1;
}
int cleanup_proto() {
	//printf("close s1ap protocol");
	return 0;
}
