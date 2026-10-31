/*
 * mmt_mobile_plugin.c
 *
 *  Created on: Dec 10, 2020
 *      Author: nhnghia
 */

#include "mmt_mobile_internal.h"

/**
 * Initialize protocols in mobile suite
 * @return 1 on success, 0 when a protocol fails to initialize (issue #503:
 * the failure reaches init_extraction() instead of terminating the host)
 *
 * This function can be called auto by init_proto when this plugin is loaded
 * or called directly when this plugin is linked as static
 */
int init_mobile_plugin() {
	if (!init_proto_diameter_struct()) {
		mmt_stderr_log("Error initializing protocol PROTO_DIAMETER\n");
		return 0;
	}
	if (!init_proto_gtpv2_struct()) {
		mmt_stderr_log("Error initializing protocol PROTO_GTPV2\n");
		return 0;
	}
	if (!init_proto_ngap_struct()) {
		mmt_stderr_log("Error initializing protocol PROTO_NGAP\n");
		return 0;
	}
	if (!init_proto_nas_5g_struct()) {
		mmt_stderr_log("Error initializing protocol PROTO_NAS5G\n");
		return 0;
	}
	return init_proto_s1ap();
}

int init_proto(){
	return init_mobile_plugin();
}
int cleanup_proto() {
	//printf("close s1ap protocol");
	return 0;
}
