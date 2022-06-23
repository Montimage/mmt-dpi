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

  enum cam_networking_attributes
  {
    CAM_ITS_PDU_HEADER_PROTOCOL_VERSION = 1,
    CAM_ITS_PDU_HEADER_MESSAGE_ID,
    CAM_ITS_PDU_HEADER_STATION_ID,
    CAM_COOP_AWARENESS_GENERATION_DELTA_TIME,
    CAM_ATTRIBUTES_NB = CAM_COOP_AWARENESS_GENERATION_DELTA_TIME,
  };

#define CAM_ITS_PDU_HEADER_PROTOCOL_VERSION_ALIAS "its_pdu_header_protocol_version"
#define CAM_ITS_PDU_HEADER_MESSAGE_ID_ALIAS "its_pdu_header_message_id"
#define CAM_ITS_PDU_HEADER_STATION_ID_ALIAS "its_pdu_header_station_id"
#define CAM_COOP_AWARENESS_GENERATION_DELTA_TIME_ALIAS "coop_awareness_generation_delta_time"

#ifdef __cplusplus
}
#endif
#endif /* ARP_H */
