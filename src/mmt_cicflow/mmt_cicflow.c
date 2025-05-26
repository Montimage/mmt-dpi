/*
 * mmt_cicflow.c
 *
 *  Created on: Nov 20, 2024
 *      Author: vietpham
 */



 #include <stdio.h>
 #include "mmt_cicflow_internal.h"
 
 int init_proto() {
     if (!init_proto_cicflow_data()) {
         fprintf(stderr,	"Error initializing protocol PROTO_CICFLOW_DATA\n Exiting\n");
         exit(0);
     }
     return 1;
 }
 int cleanup_proto() {
     //printf("close cicflow protocol");
     return 0;
 }
 