/*
 * ips_data.h
 *
 *  Created on: Jun 3, 2021
 *      Author: nhnghia
 */

/*
An example of a CSV file from VeriDevOps

TrolleyPos: 32.981, Hoistpos: 38.042, NoOfMarkers: 3, m1: (58901,70912) , m2: (72175,70950) , m3: (65803,71939) , m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)
TrolleyPos: 32.978, Hoistpos: 38.124, NoOfMarkers: 3, m1: (58843,70948) , m2: (72122,70987) , m3: (65767,71983) , m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)
TrolleyPos: 32.978, Hoistpos: 38.124, NoOfMarkers: 3, m1: (58843,70948) , m2: (72122,70987) , m3: (65767,71983) , m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)
 */
#ifndef SRC_MMT_BUSINESS_APP_INCLUDE_IPS_DATA_H_
#define SRC_MMT_BUSINESS_APP_INCLUDE_IPS_DATA_H_

#define IPS_DATA_TROLLEY_POS_ALIAS    "trolley_pos"
#define IPS_DATA_HOIST_POS_ALIAS      "hoist_pos"
#define IPS_DATA_NO_OF_MARKERS_ALIAS  "no_of_marker"
#define IPS_DATA_M1_X_ALIAS           "m1_x"
#define IPS_DATA_M1_Y_ALIAS           "m1_y"
#define IPS_DATA_M2_X_ALIAS           "m2_x"
#define IPS_DATA_M2_Y_ALIAS           "m2_y"
#define IPS_DATA_M3_X_ALIAS           "m3_x"
#define IPS_DATA_M3_Y_ALIAS           "m3_y"
#define IPS_DATA_M4_X_ALIAS           "m4_x"
#define IPS_DATA_M4_Y_ALIAS           "m4_y"
#define IPS_DATA_M5_X_ALIAS           "m5_x"
#define IPS_DATA_M5_Y_ALIAS           "m5_y"
#define IPS_DATA_M6_X_ALIAS           "m6_x"
#define IPS_DATA_M6_Y_ALIAS           "m6_y"
#define IPS_DATA_ORDER_ALIAS          "order" //order of the current data in the csv file (== packet_id)
#define IPS_DATA_GASPD_ALIAS          "ga_speed"
#define IPS_DATA_TRSPD_ALIAS          "tr_speed"
#define IPS_DATA_MHSPD_ALIAS          "mh_speed"
#define IPS_DATA_TIMESTAMP_ALIAS      "timestamp"


enum {
	IPS_DATA_TROLLEY_POS = 1,
	IPS_DATA_HOIST_POS,
	IPS_DATA_NO_OF_MARKERS,
	IPS_DATA_M1_X,
	IPS_DATA_M1_Y,
	IPS_DATA_M2_X,
	IPS_DATA_M2_Y,
	IPS_DATA_M3_X,
	IPS_DATA_M3_Y,
	IPS_DATA_M4_X,
	IPS_DATA_M4_Y,
	IPS_DATA_M5_X,
	IPS_DATA_M5_Y,
	IPS_DATA_M6_X,
	IPS_DATA_M6_Y,
	IPS_DATA_ORDER,
	IPS_DATA_GASPD,
	IPS_DATA_TRSPD,
	IPS_DATA_MHSPD,
	IPS_DATA_TIMESTAMP
};

#endif /* SRC_MMT_BUSINESS_APP_INCLUDE_IPS_DATA_H_ */
