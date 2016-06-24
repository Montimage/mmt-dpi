/*
 * File:   data_defs.h
 * Author: montimage
 *
 * Created on 23 mai 2011, 16:34
 */

#ifndef DATA_DEFS_H
#define DATA_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "types_defs.h"
#include "mmt_exports.h"

#define NonClassified   0 /**< Non-classified protocol */
#define Classified      1 /**< Classified protocol */

#define Max_Alias_Len 64  /**< Max length of an alias name.
                               Applies to all alias names (protocol, attribute, etc..) .*/

typedef struct mmt_handler_struct               mmt_handler_t;
typedef struct mmt_session_struct               mmt_session_t;
typedef struct mmt_tcpip_internal_packet_struct mmt_tcpip_internal_packet_t;
typedef struct protocol_struct                  protocol_t;
typedef struct ipacket_struct                   ipacket_t;
typedef struct proto_statistics_struct          proto_statistics_t;
// typedef struct extra_struct                     extra_t;
// typedef void (*next_process_function) (ipacket_t * ipacket);
// typedef struct extra_struct{
    // proto_statistics_t * parent_stats;
    // int index;
    // int status;// MMT_CONTINUE/ MMT_SKIP
    // next_process_function next_process;
// }extra_t;
//BW - TODO: de we really need to override these??
/** Switches the order of bytes of a short int value */
#define swab16(x) ((uint16_t)(                         \
      (((uint16_t)(x) & (uint16_t)0x00ffU) << 8) |            \
      (((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))

/** Switches the order of bytes of an int value */
#define swab32(x) ((uint32_t)(                         \
      (((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) |      \
      (((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) |      \
      (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) |      \
      (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#undef ntohl
#undef ntohs

#define ntohl(x) swab32(x) /**< Redefinition of network to host byte ordering change of a long value (4 bytes)*/
#define ntohs(x) swab16(x) /**< Redefinition of network to host byte ordering change of a short value (2 bytes)*/

typedef uint64_t mmt_key_t;

/**
 * Signature of the function comparing two keys given by their addresses. An implementing function must return true
 * if the value of key1 given by its address is strictly lower than the value of key2; false is returned otherwise. (strict weak ordering operation).
 */
typedef bool (*generic_comparison_fct) (void * key_1, void * key_2); //public function

/**
 * Signature of the function comparing two unsigned int keys. An implementing function must return true
 * if the value of key1 is strictly lower than the value of key2; false is returned otherwise. (strict weak ordering operation).
 */
typedef bool (*generic_int_comparison_fct) (uint32_t key_1, uint32_t key_2); //public function

/**
 * Defines the meta-data of a packet.
 */
typedef struct pkthdr {
    struct timeval ts;   /**< time stamp that indicates the packet arrival time */
    unsigned int caplen; /**< length of portion of the packet that is present */
    unsigned int len;    /**< length of the packet (off wire) */
    void * user_args;    /**< Pointer to a user defined argument. Can be NULL, it will not be used by the library. */
} pkthdr_t;

/**
 * Defines the list of protocols.
 */
typedef struct proto_hierarchy_struct {
    int len;                         /**< Number of protocol layers */
    int proto_path[PROTO_PATH_SIZE]; /**< Tableau of protocol layers identifiers */
} proto_hierarchy_t;

/**
 * Defines a packet structure.
 */
struct ipacket_struct {
    uint64_t packet_id;                       /**< identifier of the packet. */
    unsigned nb_reassembled_packets;          /**< number of packets which are assembled to this packet */
    uint64_t total_caplen;                    /**< Total captured length of all packets which are assembled to this packet*/
    uint8_t is_completed;                     /**< 1 - yes, 0 - no: Indicate if the packet is completed to go to parse to next protocol*/
    uint8_t is_fragment;                      /**< 1 - yes, 0 - no: Indicate if the packet is a fragmented packet */  
    proto_hierarchy_t * proto_hierarchy;      /**< the protocol layers corresponding to this packet */
    proto_hierarchy_t * proto_headers_offset; /**< the offsets corresponding to the protocol layers of this packet */
    proto_hierarchy_t * proto_classif_status; /**< the classification status of the protocols in the path */
    mmt_session_t * session;                  /**< pointer to the session structure to which the packet belongs*/
    mmt_tcpip_internal_packet_t * internal_packet;  /**< pointer to opaque packet structure. for internal use only. Must never be changed */
    mmt_handler_t * mmt_handler;              /**< pointer to the mmt handler that processed this packet */
    pkthdr_t * p_hdr;                         /**< the meta-data of the packet */
    const u_char * data;                      /**< pointer to the packet data */
    const u_char * original_data;             /**< internal: - never modify it. pointer to the original packet data. It will be different than ipacket->data in case of IP assembled data*/
    int last_callback_fct_id;                           /**< The extra field for tcp packet handler */
    proto_hierarchy_t internal_proto_hierarchy; /**< internal: - never modify it. the protocol layers corresponding to this packet */
    proto_hierarchy_t internal_proto_headers_offset; /**< internal: - never modify it.  the offsets corresponding to the protocol layers of this packet */
    proto_hierarchy_t internal_proto_classif_status; /**< internal: - never modify it.  the classification status of the protocols in the path */
    pkthdr_t internal_p_hdr;                         /**< internal: - never modify it. the meta-data of the packet */
};

/**
 * Defines the identification info of a protocol attribute. This identification is defined by the tuple: protocol id and attribute id.
 * @obsolete this structure should never be used! It is maintained for backward compatibility. It will be removed from future versions.
 */
struct attribute_description_struct {
    uint32_t proto_id;                       /**< identifier of the protocol */
    uint32_t field_id;                          /**< identifier of the attribute */
    struct attribute_description_struct * next; /**< next attribute description */
};

/**
 * Defines the structure of an attribute.
 */
//This structure is a subset of "attribute_internal_t" defined in private include file "packet_processing.h" be careful when modifying this.
typedef struct attribute_struct {
    uint32_t proto_id;    /**< identifier of the protocol */
    uint32_t field_id;       /**< identifier of the attribute */
    unsigned protocol_index; /**< index of the protocol */
    int status;              /**< status of the attribute. Indicates if it is unset, set or consumed. */
    int data_type;           /**< the data type of the attribute */
    int data_len;            /**< the data length of the attribute */
    int position_in_packet;  /**< the position in the packet of the attribute. */
    int scope;               /**< the scope of the attribute (packet, session, ...). */
    void *data;              /**< pointer to the attribute data */
} attribute_t;

/**
 * Defines the protocol statistics instance structure. A protocol may have different protocol statistics instances
 * according to the protocol path in appears in. For example, facebook will have a statistics instance corresponding
 * to the path: eth.ip.tcp.http.facebook and another one corresponding to the path: eth.ip.tcp.ssl.facebook.
 */
struct proto_statistics_struct {
    uint32_t touched;                     /**< Indicates if the statistics have been updated since the last reset */
    uint64_t packets_count;               /**< Total number of packets seen by the protocol on a particular protocol path */
    uint64_t data_volume;                 /**< Total data volume seen by the protocol  on a particular protocol path */
    uint64_t ip_frag_packets_count;         /**< Total number of IP unknown fragmented packets seen by the IP protocol*/
    uint64_t ip_frag_data_volume;           /**< Total data volume of IP unknown fragmented packets seen by the IP protocol*/
    uint64_t ip_df_packets_count;         /**< Total number of defragmented IP packets seen by the IP protocol*/
    uint64_t ip_df_data_volume;           /**< Total data volume of defragmented IP packets seen by the IP protocol*/
    uint64_t payload_volume;              /**< Total payload data volume seen by the protocol  on a particular protocol path */
    uint64_t packets_count_direction[2];  /**< Total number of UL/DL packets seen by the protocol  on a particular protocol path */
    uint64_t data_volume_direction[2];    /**< Total UL/DL data volume seen by the protocol  on a particular protocol path */
    uint64_t payload_volume_direction[2]; /**< Total UL/DL payload data volume seen by the protocol  on a particular protocol path */
    uint64_t sessions_count;              /**< Total number of sessions seen by the protocol  on a particular protocol path */
    uint64_t timedout_sessions_count;     /**< Total number of timedout sessions (this is the difference between sessions count and active sessions count) on a particular protocol path */
    struct proto_statistics_struct *next; /**< next instance of statistics for the same protocol */
    struct timeval first_packet_time; // The time of the first packet of the protocol
    struct timeval last_packet_time; // The time of the last packet of the protocol
};

enum proto_stats_attr {
    PROTO_HEADER = 0x1000,
    PROTO_DATA,
    PROTO_PAYLOAD,
    PROTO_PACKET_COUNT,
    PROTO_DATA_VOLUME,
    PROTO_PAYLOAD_VOLUME,
    PROTO_IP_FRAG_PACKET_COUNT,
    PROTO_IP_FRAG_DATA_VOLUME,
    PROTO_IP_DF_PACKET_COUNT, 
    PROTO_IP_DF_DATA_VOLUME, 
    PROTO_SESSIONS_COUNT,
    PROTO_ACTIVE_SESSIONS_COUNT,
    PROTO_TIMEDOUT_SESSIONS_COUNT,
    PROTO_FIRST_PACKET_TIME,
    PROTO_LAST_PACKET_TIME,
    PROTO_STATISTICS,
    PROTO_STATS_ATTRIBUTES_NB = PROTO_STATISTICS - PROTO_HEADER + 1,
};

enum proto_common_attributes {
    PROTO_SESSION = PROTO_STATISTICS + 1,
    PROTO_SESSION_ID,
    PROTO_SESSION_ATTRIBUTES_NB = PROTO_SESSION_ID - PROTO_SESSION + 1,
};


typedef struct ip_rtt_struct{
    struct timeval rtt;
    uint8_t direction;
    mmt_session_t * session;
}ip_rtt_t;

#define PROTO_HEADER_LABEL                      "p_hdr"
#define PROTO_DATA_LABEL                        "p_data"
#define PROTO_PAYLOAD_LABEL                     "p_payload"
#define PROTO_PACKET_COUNT_LABEL                "packet_count"
#define PROTO_DATA_VOLUME_LABEL                 "data_count"
#define PROTO_IP_FRAG_PACKET_COUNT_LABEL        "ip_frag_packets_count"
#define PROTO_IP_FRAG_DATA_VOLUME_LABEL         "ip_frag_data_volume"
#define PROTO_IP_DF_PACKET_COUNT_LABEL          "ip_df_packets_count"
#define PROTO_IP_DF_DATA_VOLUME_LABEL           "ip_df_data_volume"
#define PROTO_PAYLOAD_VOLUME_LABEL              "payload_count"
#define PROTO_SESSIONS_COUNT_LABEL              "session_count"
#define PROTO_ACTIVE_SESSIONS_COUNT_LABEL       "a_session_count"
#define PROTO_TIMEDOUT_SESSIONS_COUNT_LABEL     "t_session_count"
#define PROTO_FIRST_PACKET_TIME_LABEL           "first_packet_time"
#define PROTO_LAST_PACKET_TIME_LABEL           "last_packet_time"
#define PROTO_STATISTICS_LABEL                  "stats"
#define PROTO_SESSION_LABEL                     "session"
#define PROTO_SESSION_ID_LABEL                  "session_id"
/**
 * Returns the protocol name given its identifier.
 * @param proto_id the identifier of the protocol
 * @return the protocol name.
 */
MMTAPI const char* MMTCALL get_protocol_name_by_id(
    uint32_t proto_id
);

/**
 * Returns the attribute name given the protocol and attribute identifiers.
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @return the name of the attribute.
 */
MMTAPI const char* MMTCALL get_attribute_name_by_protocol_and_attribute_ids(
    uint32_t proto_id,
    uint32_t attribute_id
);

/**
 * Returns the offset in number of bytes from the beginning of the packet for the protocol at the given index
 * @param ipacket the packet structure
 * @param index the index of the protocol
 * @return the offset in number of bytes since the beginning of the packet
 */
MMTAPI int MMTCALL get_packet_offset_at_index(
    const ipacket_t *ipacket,
    unsigned index
);

/**
 * Returns the identifier of the protocol at the given index
 * @param ipacket the packet structure
 * @param index the index of the protocol
 * @return the identifier of the protocol at the given index if such index exists, -1 otherwise.
 */
MMTAPI uint32_t MMTCALL get_protocol_id_at_index(
    const ipacket_t *ipacket,
    unsigned index
);

/**
 * Returns the index of the protocol given by its identifier.
 * If the protocol identifier is not valid or the protocol does not appear in the protocol stack, -1 is returned.
 * @param ipacket the packet structure
 * @param proto_id the identifier of the protocol to get its index
 * @return the index of the protocol given by its id.
 * If the protocol id is not valid or the protocol does not appear in the protocol hierarchy, -1 is returned.
 */
MMTAPI unsigned MMTCALL get_protocol_index_by_id(
    const ipacket_t *ipacket,
    uint32_t proto_id
);

/**
 * Returns the index of the protocol given by its name.
 * If the protocol name is not valid or the protocol does not appear in the protocol hierarchy, -1 is returned.
 * @param ipacket the packet structure
 * @param proto_name the name of the protocol to get its index
 * @return the index of the protocol given by its name.
 * If the protocol name is not valid or the protocol does not appear in the protocol hierarchy, -1 is returned.
 */
MMTAPI unsigned MMTCALL get_protocol_index_by_name(
    const ipacket_t *ipacket,
    const char *proto_name
);

/**
 * Returns the session ID associated to ipacket
 * @param ipacket the packet structure
 * @return the associated session identifier.
 */
MMTAPI uint64_t MMTCALL get_session_id_from_packet(
    const ipacket_t *ipacket
);

/**
 * Returns the user session context
 * @param ipacket the packet structure
 * @return the associated session context.
 */
MMTAPI void* MMTCALL get_user_session_context_from_packet(
    const ipacket_t *ipacket
);

/**
 * Sets the user session context
 * @param ipacket the packet structure
 * @param user_data a pointer to a user-defined session context
 */
MMTAPI void MMTCALL set_user_session_context_for_packet(
    const ipacket_t *ipacket,
    void *user_data
);

/**
 * Returns a pointer to initialized the session data of the protocol at the given index. NULL if the protocol has no registered session data.
 * @param ipacket the packet structure
 * @param index the index of the protocol in the path
 * @return pointer to initialized the session data of the protocol at the given index. NULL if the protocol has no registered session data.
 */
MMTAPI void* MMTCALL get_proto_session_data_from_packet(
    const ipacket_t *ipacket,
    unsigned index
);

/**
 * Returns a pointer to the session struct associated to ipacket
 * @param ipacket the packet structure
 * @return pointer to the associated session if it exists, NULL otherise.
 */
MMTAPI mmt_session_t* MMTCALL get_session_from_packet(
    const ipacket_t *ipacket
);

/**
 * Returns a pointer to the parent session struct
 * @param session the session structure
 * @return pointer to the parent session struct.
 */
MMTAPI mmt_session_t* MMTCALL get_session_parent(
    const mmt_session_t *session
);

/**
 * Returns the pointer to the mmt handler that is processing the given \session
 * @param session the session structure
 * @return the pointer to the mmt handler that is processing the given \session.
 */
MMTAPI mmt_handler_t* MMTCALL get_session_handler(
    const mmt_session_t *session
);

/**
 * Returns the index in the protocol hierarchy of the protocol \session belongs to
 * @param session the session structure
 * @return the index in the protocol hierarchy of the protocol \session belongs to.
 */
MMTAPI uint32_t MMTCALL get_session_protocol_index(
    const mmt_session_t *session
);

/**
 * Returns the pointer to the protocol hierarchy of the session
 * @param session the session structure
 * @return the pointer to the protocol hierarchy of the session.
 */
MMTAPI const proto_hierarchy_t* MMTCALL get_session_protocol_hierarchy(
    const mmt_session_t *session
);

/**
 * Returns the session ID associated to session
 * @param session the session structure
 * @return the associated session identifier.
 */
MMTAPI uint64_t MMTCALL get_session_id(
    const mmt_session_t *session
);

/**
 * Returns the user session context
 * @param session the session structure
 * @return the associated session context.
 */
MMTAPI void* MMTCALL get_user_session_context(
    const mmt_session_t *session
);

/**
 * Returns a pointer to initialized the session data of the protocol at the given index. NULL if the protocol has no registered session data.
 * @param session the session structure
 * @param index the index of the protocol in the path
 * @return pointer to initialized the session data of the protocol at the given index. NULL if the protocol has no registered session data.
 */
MMTAPI void* MMTCALL get_proto_session_data(
    const mmt_session_t *session,
    unsigned index
);


/**
 * Sets the protocol session data.
 * @param session the session structure
 * @param proto_data pointer to the protocol data
 * @param index the index of the protocol in the path
 */
MMTAPI void MMTCALL set_proto_session_data(
    mmt_session_t *session,
    void * proto_data,
    unsigned index
);

/**
 * Sets the user session context
 * @param session the session structure
 * @param user_data a pointer to a user-defined session context
 */
MMTAPI void MMTCALL set_user_session_context(
    mmt_session_t *session,
    void *user_data
);

/**
 * Returns the number of packets seen by this session
 * @param session the session structure
 * @return the number of packets seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_packet_count(
    const mmt_session_t *session
);

/**
 * Returns the number of packets captured by this session
 * @param session the session structure
 * @return the number of packets captured by this session.
 */
MMTAPI uint64_t MMTCALL get_session_packet_cap_count(
    const mmt_session_t *session
);


/**
 * Returns the volume of data captured by this session
 * @param session the session structure
 * @return the volume of data captured by this session.
 */
MMTAPI uint64_t MMTCALL get_session_data_cap_volume(
    const mmt_session_t *session
);

/**
 * Returns the uplink number of packets seen by this session
 * @param session the session structure
 * @return the uplink number of packets seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_ul_packet_count(
    const mmt_session_t *session
);

/**
 * Returns the uplink number of packets captured by this session
 * @param session the session structure
 * @return the uplink number of packets captured by this session.
 */
MMTAPI uint64_t MMTCALL get_session_ul_cap_packet_count(
    const mmt_session_t *session
);

/**
 * Returns the downlink number of packets seen by this session
 * @param session the session structure
 * @return the downlink number of packets seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_dl_packet_count(
    const mmt_session_t *session
);

/**
 * Returns the downlink number of packets captured by this session
 * @param session the session structure
 * @return the downlink number of packets captured by this session.
 */
MMTAPI uint64_t MMTCALL get_session_dl_cap_packet_count(
    const mmt_session_t *session
);

/**
 * Returns total volume in bytes seen by this session
 * @param session the session structure
 * @return total volume in bytes seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_byte_count(
    const mmt_session_t *session
);

/**
 * Returns total uplink volume in bytes seen by this session
 * @param session the session structure
 * @return total uplink volume in bytes seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_ul_byte_count(
    const mmt_session_t *session
);

/**
 * Returns total downlink volume in bytes seen by this session
 * @param session the session structure
 * @return total downlink volume in bytes seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_dl_byte_count(
    const mmt_session_t *session
);

/**
 * Returns total uplink volume in bytes captured by this session
 * @param session the session structure
 * @return total uplink volume in bytes captured by this session.
 */
MMTAPI uint64_t MMTCALL get_session_ul_cap_byte_count(
    const mmt_session_t *session
);

/**
 * Returns total downlink volume in bytes captured by this session
 * @param session the session structure
 * @return total downlink volume in bytes captured by this session.
 */
MMTAPI uint64_t MMTCALL get_session_dl_cap_byte_count(
    const mmt_session_t *session
);

/**
 * Returns the number of data packets seen by this session. <br>
 * A data packet is expected to contain effective application data.
 * TCP ACKs are not considered as data packets and will not be counted therefore.
 * @param session the session structure
 * @return the number of data packets seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_data_packet_count(
    const mmt_session_t *session
);

/**
 * Returns the uplink number of data packets seen by this session. <br>
 * A data packet is expected to contain effective application data.
 * TCP ACKs are not considered as data packets and will not be counted therefore.
 * @param session the session structure
 * @return the uplink number of data packets seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_ul_data_packet_count(
    const mmt_session_t *session
);

/**
 * Returns the number of downlink data packets seen by this session. <br>
 * A data packet is expected to contain effective application data.
 * TCP ACKs are not considered as data packets and will not be counted therefore.
 * @param session the session structure
 * @return the downlink number of data packets seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_dl_data_packet_count(
    const mmt_session_t *session
);

/**
 * Returns the total number of data bytes seen by this session. <br>
 * Only effective application payload data will be accounted.
 * TCP ACKs are not considered as data packets and will not be counted therefore.
 * @param session the session structure
 * @return total data volume in bytes seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_data_byte_count(
    const mmt_session_t *session
);

/**
 * Returns the total uplink number of data bytes seen by this session. <br>
 * Only effective application payload data will be accounted.
 * TCP ACKs are not considered as data packets and will not be counted therefore.
 * @param session the session structure
 * @return total uplink data volume in bytes seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_ul_data_byte_count(
    const mmt_session_t *session
);

/**
 * Returns the total downlink number of data bytes seen by this session. <br>
 * Only effective application payload data will be accounted.
 * TCP ACKs are not considered as data packets and will not be counted therefore.
 * @param session the session structure
 * @return total downlink data volume in bytes seen by this session.
 */
MMTAPI uint64_t MMTCALL get_session_dl_data_byte_count(
    const mmt_session_t *session
);

/**
 * Gets into \tv the session initialization time.
 * @param session the session structure
 * @param tv pointer to timeval struct where the session init time will be copied
 */
MMTAPI struct timeval MMTCALL get_session_init_time(
    const mmt_session_t *session
);

/**
 * Gets into \tv the session last activity time.
 * @param session the session structure
 * @param tv pointer to timeval struct where the session last activity time will be copied
 */
MMTAPI struct timeval MMTCALL get_session_last_activity_time(
    const mmt_session_t *session
);

/**
 * Gets into \tv the session establishment round trip time.
 * @param session the session structure.
 * @param tv pointer to timeval struct where the session establishment round trip time will be copied.
 */
MMTAPI struct timeval MMTCALL get_session_rtt(
    const mmt_session_t *session
);

/**
 * Returns the session content class id.
 * @param session the session structure.
 * @return the session content class id.
 */
MMTAPI uint16_t MMTCALL get_session_content_class_id(
    const mmt_session_t *session
);

/**
 * Returns the session content type id.
 * @param session the session structure.
 * @return the session content type id.
 */
MMTAPI uint16_t MMTCALL get_session_content_type_id(
    const mmt_session_t *session
);

/**
 * Returns the session content flags.
 * @param session the session structure.
 * @return the session content flags.
 */
MMTAPI uint32_t MMTCALL get_session_content_flags(
    const mmt_session_t *session
);

/**
 * Returns the number of retransmitted packets seen by the given session.
 * @param session the session structure.
 * @return the number of retransmitted packets seen by the given session.
 */
MMTAPI uint32_t MMTCALL get_session_retransmission_count(
    const mmt_session_t *session
);

/**
 * Get the next session of current session
 * @param  session session
 * @return         NULL if there is no next session
 *                 A pointer points to the next session of current session
 */
MMTAPI const mmt_session_t MMTCALL * get_session_next(
    const mmt_session_t *session
);

/**
 * Get the previous session of current session
 * @param  session current session
 * @return         NULL if there is no previous session
 *                 A pointer points to the previous session of current session
 */
MMTAPI const mmt_session_t MMTCALL * get_session_previous(
    const mmt_session_t *session
);

/**
 * Get session protocol path by direction
 * @param  session   session
 * @param  direction direction 0 / 1
 * @return           protocol path
 */
MMTAPI const proto_hierarchy_t MMTCALL * get_session_proto_path_direction(
    const mmt_session_t *session, int direction
);

//  - - - - - - - - - - - - - - - - - -
//  A T T R I B U T E   A C C E S S O R S
//  - - - - - - - - - - - - - - - - - -

/**
 * Returns the identifier of the protocol the given attribute belongs to.
 * @param attr pointer to the attribute structure.
 * @return the identifier of the protocol the given attribute belongs to.
 */
MMTAPI uint32_t MMTCALL get_attr_protocol_id( attribute_t * attr);

/**
 * Returns the identifier of the given attribute.
 * @param attr pointer to the attribute structure.
 * @return the identifier of the attribute.
 */
MMTAPI uint32_t MMTCALL get_attr_id( attribute_t * attr);

/**
 * Returns the index in the protocol where the given attribute is extracted.
 * @param attr pointer to the attribute structure.
 * @return the index in the protocol where the given attribute is extracted.
 */
MMTAPI int MMTCALL get_attr_protocol_index( attribute_t * attr);

/**
 * Returns the status of the given attribute.
 * @param attr pointer to the attribute structure.
 * @return the status of the attribute.
 */
MMTAPI int MMTCALL get_attr_status( attribute_t * attr);

/**
 * Returns the data type of the given attribute.
 * @param attr pointer to the attribute structure.
 * @return the data type of the attribute.
 */
MMTAPI int MMTCALL get_attr_data_type( attribute_t * attr);

/**
 * Returns the data length in bytes of the given attribute.
 * @param attr pointer to the attribute structure.
 * @return the data length in bytes of the given attribute.
 */
MMTAPI int MMTCALL get_attr_data_len( attribute_t * attr);

/**
 * Returns the relative offset in bytes of the given attribute with respect to its protocol header. <br>
 * If the attribute offset is not known, \POSITION_NOT_KNOWN will be returned.
 * @param attr pointer to the attribute structure.
 * @return the relative offset in bytes of the given attribute with respect to its protocol header.
 */
MMTAPI int MMTCALL get_attr_offset( attribute_t * attr);

/**
 * Returns the scope of the given attribute.
 * @param attr pointer to the attribute structure.
 * @return the scope of the given attribute.
 */
MMTAPI int MMTCALL get_attr_scope( attribute_t * attr);

/**
 * Returns the pointer to the attribute extracted data.
 * @param attr pointer to the attribute structure.
 * @return the pointer to the attribute extracted data.
 */
MMTAPI void* MMTCALL get_attr_data( attribute_t * attr);

//  - - - - - - - - - - - - - - - - - - - - -
//  M M T   H A N D L E R   A C C E S S O R S
//  - - - - - - - - - - - - - - - - - - - - -

/**
 * Returns the timestamp corresponding to the last processed packet by the handler.
 * @param handler the MMT handler structure.
 * @return timestamp corresponding to the last processed packet by the handler.
 */
MMTAPI struct timeval MMTCALL get_last_activity_time( mmt_handler_t * handler );


/**
 * Transforms the first len (in number of bytes) haxadecimal text represented in ASCI into binary format.
 * @param binary_data pointer where the transformed binary data will be stored
 * @param hex_data pointer to the hexadecimal ASCI string to transform
 * @param len the number of bytes to transform
 * @return the length of the transformed data on success, a negative value on failure.
 */
MMTAPI unsigned int MMTCALL htoi(
    char *binary_data,
    const char *hex_data,
    int len
);

/**
 * Returns the data size of the attribute given the protocol and attribute ids
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @return the data size of the attribute
 */
MMTAPI int MMTCALL get_data_size_by_proto_and_field_ids(
    uint32_t proto_id,
    uint32_t attribute_id
);

/**
 * Returns the data size of the given data type
 * @param data_type the identifier of the data type
 * @return the size in bytes of the given data type. 0 if the type is not known or invalid.
 */
MMTAPI uint32_t MMTCALL get_data_size_by_data_type(
    uint32_t data_type
);

/**
 * Returns the position in the message for the attribute identified by the protocol and attribute ids.
 * The position is defined as the byte offset offset from the beginning of the packet.
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @return the position of the attribute in the message. POSITION_NOT_KNOWN is returned if the proto_id and attribute_id couple are not valid.
 */
MMTAPI int MMTCALL get_field_position_by_protocol_and_field_ids(
    uint32_t proto_id,
    uint32_t attribute_id
);

/**
 * Indicates if the attribute identified by the protocol and attribute ids exists.
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @return true if the attribute exists, false otherwise
 */
MMTAPI int MMTCALL is_protocol_attribute(
    uint32_t proto_id,
    uint32_t attribute_id
);

/**
 * Returns the identifier of the protocol given its name
 * @param protocol_name the name of the protocol
 * @return the identifier (positive value) of the protocol on success, 0 otherwise
 */
MMTAPI uint32_t MMTCALL get_protocol_id_by_name(
    const char *protocol_name
);

/**
 * Returns the identifier of the attribute defined by the protocol name and attribute name
 * @param protocol_name the name of the protocol
 * @param attribute_name the name of the attribute
 * @return the identifier (positive value) of the attribute on success, 0 otherwise.
 */
MMTAPI uint32_t MMTCALL get_attribute_id_by_protocol_and_attribute_names(
    const char *protocol_name,
    const char *attribute_name
);

/**
 * Returns the identifier of the attribute defined by the protocol id and attribute name
 * @param proto_id the identifier of the protocol
 * @param attribute_name the name of the attribute
 * @return the identifier (positive value) of the attribute on success, 0 otherwise.
 */
MMTAPI uint32_t MMTCALL get_attribute_id_by_protocol_id_and_attribute_name(
    uint32_t proto_id,
    const char *attribute_name
);

/**
 * Return the data type of the attribute defined by its protocol and attribute ids
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @return the data type of the attribute if it is defined (attribute exists in the protocol), NOTYPE otherwise.
 */
MMTAPI long MMTCALL get_attribute_data_type(
    uint32_t proto_id,
    uint32_t attribute_id
);

/**
 * Returns the scope of the attribute defined by its protocol and attribute ids
 * @param proto_id the identifier of the protocol
 * @param attribute_id the identifier of the attribute
 * @return the scope of the attribute. This method should only be applied on valid attribute ids.
 */
MMTAPI int MMTCALL get_attribute_scope(
    uint32_t proto_id,
    uint32_t attribute_id
);

/**
 * Returns the number of microseconds elapsed between finishtime and starttime.
 * This function MUST only be used for times less than ~4000 seconds apart.
 * @param starttime the end time
 * @param finishtime the start time
 * @return the number of microseconds elapsed between finishtime and starttime.
 */
MMTAPI uint32_t MMTCALL short_time_diff(
    struct timeval *starttime,
    struct timeval *finishtime
);

/**
 * Returns the classification threshold which is the maximum number of packets to be analyzed
 * before considering the session as classified with protocol Unknown.
 * @return the classification threshold.
 */
MMTAPI uint32_t MMTCALL get_classification_threshold(
    void
);

/**
 * Transforms the given protocol hierarchy to string notation.
 * @param proto_hierarchy pointer to the protocol hierarchy.
 * @param dest pointer to where the protocol hierarchy will be printed.
 * @return the length of the string notation of the protocol hierarchy.
 */
MMTAPI int MMTCALL proto_hierarchy_to_str(
    const proto_hierarchy_t *proto_hierarchy,
    char *dest
);

/**
 * Returns a pointer to the application name corresponding to the given protocol hierarchy.
 * The application name is equivalent to the last protocol in the hierarchy.
 * @param proto_hierarchy pointer to the protocol hierarchy.
 * @return pointer to the application name corresponding to the given protocol hierarchy.
 */
MMTAPI const char* MMTCALL get_application_name(
    const proto_hierarchy_t *proto_hierarchy
);

/**
 * Alternative to toupper. Removes dependency on <locale>.
 * @param in input character.
 * @return uppercase of \in.
 */
MMTAPI char MMTCALL mmt_toupper(
    char in
);

/**
 * Alternative to tolower. Removes dependency on <locale> .
 * @param in input character.
 * @return lowercase of \in.
 */
MMTAPI char MMTCALL mmt_tolower(
    char in
);

/**
 * Case insensitive comparison of strings (even for non-ascii).
 * @param first string to be compared.
 * @param second string to be compared.
 * @return Zero if both strings are case insensitivly equal, positive value if to indicate that the first character that does
 * not match has a greater case insensitive value in \first than in \second; a negative value indicates the opposite.
 */
MMTAPI int MMTCALL mmt_strcasecmp(
    const char *first,
    const char *second
);

/**
 * Case insensitive comparison of strings (even for non-ascii).
 * @param first string to be compared.
 * @param second string to be compared.
 * @param max maximum number of characters to compare.
 * @return Zero indicates that the characters compared in both strings form the same case insensitive string;
 *         a positive value indicates that the first character that does not match has a greater case insensitive value in \first than in \second;
 *         a negative value indicates the opposite.
 */
MMTAPI int MMTCALL mmt_strncasecmp(
    const char *first,
    const char *second,
    size_t max
);

/**
 * Case insensitive comparison of strings (even for non-ascii).
 * @param first string to be compared.
 * @param second string to be compared.
 * @return Zero if both strings are equal, positive value if to indicate that the first character that does
 * not match has a greater value in \first than in \second; a negative value indicates the opposite.
 */
MMTAPI int MMTCALL mmt_strcmp(
    const char *first,
    const char *second
);

/**
 * Case insensitive comparison of strings (even for non-ascii).
 * @param first string to be compared.
 * @param second string to be compared.
 * @param max maximum number of characters to compare.
 * @return Zero indicates that the characters compared in both strings form the same string; positive value if to indicate that the first character that does
 * not match has a greater value in \first than in \second; a negative value indicates the opposite.
 */
MMTAPI int MMTCALL mmt_strncmp(
    const char *first,
    const char *second,
    size_t max
);

/**
 * Writes in a friendly format the attribute pointed by \attr to the stream pointed by \p.
 * @param f Pointer to a FILE object that identifies an output stream.
 * @param attr Pointer to the attribute to format.
 * @return On success, the total number of characters written is returned. <br>
 * If a writing error occurs, a negative value is returned.
 */
MMTAPI int MMTCALL mmt_attr_format(FILE * f, attribute_t * attr);

/**
 * Writes the string value of the attribute pointed by \attr to the stream pointed by \p.
 * @param f Pointer to a FILE object that identifies an output stream.
 * @param attr Pointer to the attribute to format.
 * @return On success, the total number of characters written is returned. <br>
 * If a writing error occurs, a negative value is returned.
 */
MMTAPI int MMTCALL mmt_attr_fprintf(FILE * f, attribute_t * attr);

/**
 * Writes the string value of the attribute pointed by \attr to the C string pointed by \p.
 * If the resulting string would be longer than \len - 1 characters, the remaining characters are discarded and not stored.
 * In this case, the value returned by the function would be higher than \len. <br>
 * A terminating null character is automatically appended.
 * @param buff Pointer to the C string where the attribute will be written to.
 * <br>The buffer should have a size of at least \len characters.
 * @param len Maximum number of bytes to be written to \buff.
 * @param attr Pointer to the attribute to print.
 * @return On success, the total number of characters that would have been written if \len had been sufficiently
 * large, not counting the terminating null character.<br>
 * If a writing error occurs, a negative value is returned.<br>
 * Notice that only when the returned value is positive and less than \len, the string has been completely written.
 */
MMTAPI int MMTCALL mmt_attr_sprintf(char * buff, int len, attribute_t * attr);

/**
 * Convert IPv4 and IPv6 addresses from binary to text form.
 * @param af IP address family (either AF_INET or AF_INET6)
 * @param src pointer to a struct in_addr / struct in6_addr
 * @param dst pointer to a C string where the result will be stored
 * @param len number of bytes available in dst
 */
MMTAPI const char* MMTCALL mmt_inet_ntop( int af, const void *src, char *dst, socklen_t len );

#ifdef __cplusplus
}
#endif

#endif /* DATA_DEFS_H */

