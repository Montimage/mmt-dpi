#ifndef LLC_H
#define LLC_H
#ifdef __cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"


enum{
	LLC_DSAP = 1,
	LLC_SSAP,
	LLC_CONTROL_FIELD
};

#define LLC_ATTRIBUTES_NB LLC_CONTROL_FIELD
#define LLC_DSAP_ALIAS	"dsap"
#define LLC_SSAP_ALIAS	"ssap"
#define LLC_CONTROL_FIELD_ALIAS	"control_field"

typedef struct llc_hdr_struct
{
	uint8_t dsap;
	uint8_t ssap;
	uint8_t cf;
	// uint16_t oc;
	// uint8_t oc2;
	// uint16_t pid;
} llc_hdr_t;

int init_llc_proto_struct();

#ifdef __cplusplus
}
#endif
#endif /* LLC_H */
