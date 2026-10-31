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
		// Issue #503: report the failure to init_extraction() instead of
		// terminating the host process.
		mmt_stderr_log("Error initializing protocol PROTO_IPS_DATA\n");
		return 0;
	}
	return 1;
}
int cleanup_proto() {
	//printf("close s1ap protocol");
	return 0;
}
