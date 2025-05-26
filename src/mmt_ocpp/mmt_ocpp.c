/*
 * mmt_ocpp.c
 *
 *  Created on: Nov 20, 2024
 *      Author: vietpham
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
	//printf("close ocpp protocol");
	return 0;
}
