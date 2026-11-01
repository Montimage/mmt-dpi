/**
 * @file
 * Identifiers of the META pseudo-protocol and of its attributes,
 * which describe the packet being processed (direction, time, length,
 * protocol hierarchy, session, classification status).
 *
 * Author: montimage
 *
 * Created on 20 mai 2011, 13:18
 */

#ifndef PROTO_META_H
#define	PROTO_META_H

#ifdef	__cplusplus
extern "C" {
#endif

#define PROTO_UNKNOWN 0 ///< Protocol identifier of the "unknown" pseudo-protocol.
#define PROTO_META    1 ///< Protocol identifier of the META pseudo-protocol, present in every packet.

/** Attribute identifiers of the META pseudo-protocol (registered in proto_meta.c). */
enum {
    META_PACKET_DIRECTION = 1, ///< Packet direction (MMT_U32_DATA): FROM_INITIATOR when the packet has no session, else the session's last packet direction.
    META_UARGS, ///< User arguments attached to the packet header (MMT_DATA_POINTER).
    META_UTIME, ///< Packet capture timestamp (MMT_DATA_TIMEVAL).
    META_P_LEN, ///< Packet length from the packet header (MMT_U32_DATA).
    META_PROTO_H, ///< Protocol hierarchy of the packet (MMT_DATA_PATH).
    META_SESSION, ///< Session the packet belongs to (MMT_DATA_POINTER); extracted only on the session's first packet.
    META_CLASSIFIED, ///< Session classification status (MMT_U8_DATA); extracted only once the session is classified.
    META_PROBE_ID, ///< Probe identifier from the packet header (MMT_U32_DATA).
    META_SOURCE_ID, ///< Source identifier from the packet header (MMT_U32_DATA).
	META_PACKET_INDEX, ///< Sequence number of the packet within its handler, counted from 1 (MMT_U64_DATA).
    META_CLASSIFICATION_METHOD, /**< How the session's application verdict was reached, an MMT_CLASSIFICATION_METHOD_* value (MMT_U8_DATA). Issue #567: appended — earlier ids keep their values. */
    META_ATTRIBUTES_NB = META_CLASSIFICATION_METHOD ///< Number of META attributes (ids start at 1).
};

// #define META_ATTRIBUTES_NB 7 /* To be updated with whenever necessary */

#define PROTO_META_ALIAS        "meta" ///< Name of the META pseudo-protocol.
#define PROTO_UNKNOWN_ALIAS     "unknown" ///< Name of the "unknown" pseudo-protocol.

#define META_UARGS_ALIAS        "args" ///< Name of the META_UARGS attribute.
#define META_UTIME_ALIAS        "utime" ///< Name of the META_UTIME attribute.
#define META_P_LEN_ALIAS        "packet_len" ///< Name of the META_P_LEN attribute.
#define META_PROTO_H_ALIAS      "proto_hierarchy" ///< Name of the META_PROTO_H attribute.
#define META_SESSION_ALIAS      "session" ///< Name of the META_SESSION attribute.
#define META_CLASSIFIED_ALIAS   "classified" ///< Name of the META_CLASSIFIED attribute.
#define META_PROBE_ID_ALIAS   "probe_id" ///< Name of the META_PROBE_ID attribute.
#define META_SOURCE_ID_ALIAS   "source_id" ///< Name of the META_SOURCE_ID attribute.
#define META_PACKET_DIRECTION_ALIAS "direction" ///< Name of the META_PACKET_DIRECTION attribute.
#define META_PACKET_INDEX_ALIAS "packet_index" ///< Name of the META_PACKET_INDEX attribute.
#define META_CLASSIFICATION_METHOD_ALIAS "classification_method" ///< Name of the META_CLASSIFICATION_METHOD attribute.

#ifdef	__cplusplus
}
#endif

#endif	/* PROTO_META_H */

