/*
 * mmt_mobile_plugin.c
 *
 *  Created on: Dec 10, 2020
 *      Author: nhnghia
 */

#include "mmt_mobile_internal.h"

/**
 * Initialize protocols in mobile suite
 * @return
 *
 * This function can be called auto by init_proto when this plugin is loaded
 * or called directly when this plugin is linked as static
 */
int init_mobile_plugin() {
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
	if (!init_proto_nas_5g_struct()) {
		fprintf(stderr, "Error initializing protocol PROTO_NAS5G\n Exiting\n");
		exit(0);
	}
	return init_proto_s1ap();
}

int int_proto(){
	return init_mobile_plugin();
}
int cleanup_proto() {
	//printf("close s1ap protocol");
	return 0;
}
