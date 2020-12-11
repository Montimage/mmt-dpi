/*
 * mmt_mobile_plugin.c
 *
 *  Created on: Dec 10, 2020
 *      Author: nhnghia
 */

#include "mmt_mobile_internal.h"

int init_proto() {
	if (!init_proto_diameter_struct()) {
		fprintf(stderr,	"Error initializing protocol PROTO_DIAMETER\n Exiting\n");
		exit(0);
	}
	if (!init_proto_gtpv2_struct()) {
		fprintf(stderr, "Error initializing protocol PROTO_GTPV2\n Exiting\n");
		exit(0);
	}
	if (!init_proto_ngap_struct()) {
		fprintf(stderr, "Error initializing protocol PROTO_NGAP\n Exiting\n");
		exit(0);
	}
	return init_proto_s1ap();
}
int cleanup_proto() {
	//printf("close s1ap protocol");
	return 0;
}
