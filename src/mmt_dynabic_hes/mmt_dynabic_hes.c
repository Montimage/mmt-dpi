/*
 * mmt_dynabic_hes.c
 *
 *  Created on: Nov 20, 2024
 *      Author: vietpham
 */



#include <stdio.h>
#include "mmt_dynabic_hes_internal.h"

int init_proto() {
	if (!init_proto_dynabic_hes_data()) {
		fprintf(stderr,	"Error initializing protocol PROTO_DYNABIC_HES_DATA\n Exiting\n");
		exit(0);
	}
	return 1;
}
int cleanup_proto() {
	//printf("close s1ap protocol");
	return 0;
}