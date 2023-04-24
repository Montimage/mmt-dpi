/* Generated with MMT Plugin Generator */

#ifndef CPM_H
#define CPM_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"
  enum cpm_attributes {
    CPM_PROTOCOLVERSION = 1,
    CPM_MESSAGEID,
    CPM_STATIONID,
    CPM_GENERATIONTIME,
    CPM_ATTRIBUTES_NB = CPM_GENERATIONTIME,

  };


#define CPM_PROTOCOLVERSION_ALIAS "protocolversion"
#define CPM_MESSAGEID_ALIAS "messageid"
#define CPM_STATIONID_ALIAS "stationid"
#define CPM_GENERATIONTIME_ALIAS "generationtime"

#ifdef	__cplusplus
}
#endif
#endif	/* CPM_H */

