/* 
 * File:   batman.h
 * Author: montimage
 *
 * Created on 7 mai 2012, 09:38
 */

#ifndef BATMAN_H
#define	BATMAN_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "mmt_core.h"
#include "plugin_defs.h"

//#define BATMAN_PROTO        99
//#define BATMAN_PROTO_ALIAS  "batman"

#define BAT_PACKET       0x01
#define BAT_ICMP         0x02
#define BAT_UNICAST      0x03
#define BAT_BCAST        0x04
#define BAT_VIS          0x05
#define BAT_UNICAST_FRAG 0x06

#define BATMAN_PACKET                   100
#define BATMAN_PACKET_ALIAS             "batman_packet"

#define BATMAN_ICMP                     101
#define BATMAN_ICMP_ALIAS               "batman_icmp"

#define BATMAN_UNICAST                  102
#define BATMAN_UNICAST_ALIAS            "batman_unit"

#define BATMAN_BCAST			103
#define BATMAN_BCAST_ALIAS		"batman_bcast"

#define BATMAN_VIS			104
#define BATMAN_VIS_ALIAS		"batman_vis"

#define BATMAN_UNICAST_FRAG		105
#define BATMAN_UNICAST_FRAG_ALIAS	"batman_uni_frag"

#define ETH_P_BATMAN  0x4305	/* unofficial/not registered Ethertype */

    enum {
        BATMAN_PACKET_TYPE = 1,
        BATMAN_VERSION,
        BATMAN_FLAGS,
        BATMAN_TQ,
        BATMAN_ORIG,
        BATMAN_PREV_SENDER,
        BATMAN_TTL,
        BATMAN_NUM_TT,
        BATMAN_GW_FLAGS,
        BATMAN_MSG_TYPE,
        BATMAN_DST,
        BATMAN_UID,
        BATMAN_SEQNO,
        BATMAN_VIS_TYPE,
        BATMAN_ENTRIES,
        BATMAN_VIS_ORIG,
        BATMAN_TARGET_ORIG,
        BATMAN_SENDER_ORIG,
        BATMAN_ALIGN,
        BATMAN_PACKET_FORMATTING,
    };

#define BATMAN_PACKET_ATTRIBUTES_NB             12
#define BATMAN_ICMP_ATTRIBUTES_NB               8
#define BATMAN_UNICAST_ATTRIBUTES_NB            4
#define BATMAN_BCAST_ATTRIBUTES_NB              5
#define BATMAN_VIS_ATTRIBUTES_NB                9
#define BATMAN_UNICAST_FRAG_ATTRIBUTES_NB       7


#define BATMAN_PACKET_TYPE_ALIAS    "type"
#define BATMAN_VERSION_ALIAS        "version"
#define BATMAN_FLAGS_ALIAS          "flags"
#define BATMAN_TQ_ALIAS             "tq"
#define BATMAN_SEQNO_ALIAS          "seqno"
#define BATMAN_ORIG_ALIAS           "orig"
#define BATMAN_PREV_SENDER_ALIAS    "prev_send"
#define BATMAN_TTL_ALIAS            "ttl"
#define BATMAN_NUM_TT_ALIAS         "num_tt"
#define BATMAN_GW_FLAGS_ALIAS       "gw_flags"
#define BATMAN_MSG_TYPE_ALIAS       "msg_type"
#define BATMAN_DST_ALIAS	    "dst"
#define BATMAN_UID_ALIAS	    "uid"
#define	BATMAN_VIS_TYPE_ALIAS	    "vis_type"
#define	BATMAN_ENTRIES_ALIAS	    "entries"
#define	BATMAN_VIS_ORIG_ALIAS	    "vis_orig"
#define	BATMAN_TARGET_ORIG_ALIAS    "target_orig"
#define	BATMAN_SENDER_ORIG_ALIAS    "send_orig"
#define BATMAN_ALIGN_ALIAS          "align"
#define BATMAN_PACKET_FORMATTING_ALIAS "format"

    struct batman_packet {
        uint8_t packet_type;
        uint8_t version; /* batman version field */
        uint8_t flags; /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
        uint8_t tq;
        uint32_t seqno;
        uint8_t orig[6];
        uint8_t prev_sender[6];
        uint8_t ttl;
        uint8_t num_tt;
        uint8_t gw_flags; /* flags related to gateway class */
        uint8_t align;
    };

    struct batman_icmp {
        uint8_t packet_type;
        uint8_t version; /* batman version field */
        uint8_t msg_type; /* see ICMP message types above */
        uint8_t ttl;
        uint8_t dst[6];
        uint8_t orig[6];
        uint16_t seqno;
        uint8_t uid;
    };

    struct batman_unit {
        uint8_t packet_type;
        uint8_t version; /* batman version field */
        uint8_t dst[6];
        uint8_t ttl;
    };

    struct batman_bcast {
        uint8_t packet_type;
        uint8_t version; /* batman version field */
        uint8_t orig[6];
        uint8_t ttl;
        uint32_t seqno;
    };

    struct batman_vis {
        uint8_t packet_type;
        uint8_t version; /* batman version field */
        uint8_t vis_type; /* which type of vis-participant sent this? */
        uint8_t entries; /* number of entries behind this struct */
        uint32_t seqno; /* sequence number */
        uint8_t ttl; /* TTL */
        uint8_t vis_orig[6]; /* originator that announces its neighbors */
        uint8_t target_orig[6]; /* who should receive this packet */
        uint8_t sender_orig[6]; /* who sent or rebroadcasted this packet */
    };

    struct batman_uni_frag {
        uint8_t packet_type;
        uint8_t version; /* batman version field */
        uint8_t dst[6];
        uint8_t ttl;
        uint8_t flags;
        uint8_t orig[6];
        uint16_t seqno;
    };


    int init_batman_proto_struct();

#ifdef	__cplusplus
}
#endif

#endif	/* BATMAN_H */

