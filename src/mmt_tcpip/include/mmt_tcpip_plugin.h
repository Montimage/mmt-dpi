/*
 * File:   mmt_tcpip_plugin.h
 * Author: montimage
 *
 * Created on 23 mai 2011, 17:21
 */

#ifndef MMT_TCPIP_PLUGIN_H
#define MMT_TCPIP_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

//#include "mmt_tcpip.h"

/* init_proto/cleanup_proto are the entry points plugins_engine.c dlsym()s.
 * The plugin is built -fvisibility=hidden (issue #534): these MMTAPI
 * declarations are what libmmt_tcpip.so exports. */
MMTAPI int init_proto();
MMTAPI int init_tcpip_plugin();

MMTAPI int cleanup_proto();
MMTAPI int cleanup_tcpip_plugin();

#ifdef __cplusplus
}
#endif

#endif /* MMT_TCPIP_PLUGIN_H */
