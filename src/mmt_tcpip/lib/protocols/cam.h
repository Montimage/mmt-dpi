/* Generated with MMT Plugin Generator */

#ifndef CAM_H
#define CAM_H
#ifdef __cplusplus
extern "C"
{
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

  struct its_pdu_header
  {
    uint8_t protocol_version;
    uint8_t message_id;
    uint32_t station_id;
  };

  struct coop_awareness
  {
    uint16_t generation_delta_time;
    char *cam_parameters;
  };

  enum cam_attributes {
		CAM_PROTOCOLVERSION = 1,
		CAM_MESSAGEID,
		CAM_STATIONID,
		CAM_GENERATIONTIME,
		CAM_BASIC_STATION_TYPE,
		CAM_BASIC_RP_LATITUDE,
		CAM_BASIC_RP_LONGITUDE,
		CAM_BASIC_RP_PCE_MAJOR_CONF,
		CAM_BASIC_RP_PCE_MINOR_CONF,
		CAM_BASIC_RP_PCE_MAJOR_ORIE,
		CAM_BASIC_RP_ALTITUDE_VALUE,
		CAM_BASIC_RP_ALTITUDE_CONF,
		CAM_ATTRIBUTES_NB = CAM_BASIC_RP_ALTITUDE_CONF,
	};

#define CAM_PROTOCOLVERSION_ALIAS "protocolversion"
#define CAM_MESSAGEID_ALIAS "messageid"
#define CAM_STATIONID_ALIAS "stationid"
#define CAM_GENERATIONTIME_ALIAS "generationtime"
#define CAM_BASIC_STATION_TYPE_ALIAS "basic_station_type"
#define CAM_BASIC_RP_LATITUDE_ALIAS "basic_rp_latitude"
#define CAM_BASIC_RP_LONGITUDE_ALIAS "basic_rp_longitude"
#define CAM_BASIC_RP_PCE_MAJOR_CONF_ALIAS "basic_rp_pce_major_conf"
#define CAM_BASIC_RP_PCE_MINOR_CONF_ALIAS "basic_rp_pce_minor_conf"
#define CAM_BASIC_RP_PCE_MAJOR_ORIE_ALIAS "basic_rp_pce_major_orie"
#define CAM_BASIC_RP_ALTITUDE_VALUE_ALIAS "basic_rp_altitude_value"
#define CAM_BASIC_RP_ALTITUDE_CONF_ALIAS "basic_rp_altitude_conf"

#ifdef __cplusplus
}
#endif
#endif /* ARP_H */
