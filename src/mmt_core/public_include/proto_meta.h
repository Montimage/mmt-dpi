/*
 * File:   proto_meta.h
 * Author: montimage
 *
 * Created on 20 mai 2011, 13:18
 */

#ifndef PROTO_META_H
#define	PROTO_META_H

#ifdef	__cplusplus
extern "C" {
#endif

#define PROTO_UNKNOWN 0
#define PROTO_META    1

enum {
    META_PACKET_DIRECTION = 1,
    META_UARGS,
    META_UTIME,
    META_P_LEN,
    META_PROTO_H,
    META_SESSION,
    META_CLASSIFIED,
};

#define META_ATTRIBUTES_NB 7 /* To be updated with whenever necessary */

#define PROTO_META_ALIAS        "meta"
#define PROTO_UNKNOWN_ALIAS     "unknown"

#define META_UARGS_ALIAS        "args"
#define META_UTIME_ALIAS        "utime"
#define META_P_LEN_ALIAS        "packet_len"
#define META_PROTO_H_ALIAS      "proto_hierarchy"
#define META_SESSION_ALIAS      "session"
#define META_CLASSIFIED_ALIAS   "classified"
#define META_PACKET_DIRECTION_ALIAS "direction"

#ifdef	__cplusplus
}
#endif

#endif	/* PROTO_META_H */

