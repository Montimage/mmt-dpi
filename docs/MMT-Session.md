# MMT Sessions #

[TOC]

------------------


## Definition ##

`MMT session` is an abstract concept which binds all the packets passing through a particular data flow. It defines the operations and generic structure of a data flow. MMT does not define any specific session (such as: IP session, RTP session...) instead it provides the generic operation and structure. For example, MMT provide generic operation and structure which can be used by IP protocol to define IP session. MMT defines the session by `session_id` but for some specific protocol session is defined by `mmt_session_key`. As `mmt session` only have a `void` pointer pointed to the address of `mmt_session_key`, this design make the session key very flexible. For example, IP session and RTP session can have different structure of `mmt_session_key`.

`MMT session` is bidirectional that means every packets from `source -> destination` and `destination -> source` will be processed in the same session.

`MMT session` supports tunnelling for example: TCP stream tunneled in IP stream.

## API ##

** Session structure **
```c
/**
 * Defines the structure of a session.
 */
struct mmt_session_struct {
    uint64_t session_id;                     /**< session identifier */
    struct mmt_session_struct *parent_session; /**< pointer to the parent session */
    void * protocol_container_context;       /**< pointer to the protocol to which the session belongs */
    mmt_handler_t *mmt_handler;              /**< opaque pointer to the mmt handler that processed this session */
    uint32_t session_protocol_index;         /**< index of the protocol to which the session belongs */
    uint64_t packet_count;                   /**< tracks the number of packets */
    uint64_t data_volume;                    /**< tracks the octet data volume */
    uint64_t packet_count_direction[2];      /**< Session's packet count in both directions: initiator <-> remote */
    uint64_t data_volume_direction[2];       /**< Session's data volume in both directions: initiator <-> remote */

    uint64_t data_packet_count;              /**< tracks the number of packets holding effective payload data */
    uint64_t data_byte_volume;               /**< tracks the effective payload data volume */
    uint64_t data_packet_count_direction[2]; /**< Session's effective payload packet count in both directions: initiator <-> remote */
    uint64_t data_byte_volume_direction[2];  /**< Session's effective payload data volume in both directions: initiator <-> remote */

    struct timeval s_init_time;              /**< indicates the time when the session was first detected. */
    struct timeval s_last_activity_time;     /**< indicates the time when the last activity on this session was detected (time of the last packet). */

    uint32_t session_timeout_delay;          /**< The inactivity delay after which the session can be considered as expired */
    uint32_t session_timeout_milestone;      /**< The time expressed as seconds since Epoch (1st Jan 1970) when the session will be considered as expired */

    proto_hierarchy_t proto_path;            /**< The session detected protocol hierarchy */
    proto_hierarchy_t proto_headers_offset;  /**< The protocol offsets of the detected protocols */
    proto_hierarchy_t proto_classif_status;  /**< the classification status of the protocols in the path */

    void * session_data[PROTO_PATH_SIZE];    /**< Table of protocol specific session data. This is a repository where each
                                                  detected protocol of this session will maintain its session specific data. */

    void * session_key;                      /**< pointer ot the session key structure */
    void * internal_data;                    /**< interval data (Used by openDPI) */

    void * user_data;                        /**< user data associated with the structure */

    /* BW: MMT content type */
    struct {
        uint16_t content_class;
        uint16_t content_type;
    } content_info;

    /* Content Flags: Plugin specific */
    uint32_t content_flags;

    /* tcp sequence number connection tracking and retransmissions counting */
    uint32_t next_tcp_seq_nr[2];
    uint32_t tcp_retransmissions;            /**< number of TCP retransmissions */
    struct timeval rtt;                      /**< TCP RTT calculated at connection setup */

#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t status : 3;                      /**< indicate the status of the session */
    uint8_t force_timeout : 1;               /**< indicate if the session timed out (according to the protocol workflow)
                                                  This will be the case after the FIN - ACK tcp connection closing procedure. */
    /* init parameter, internal used to set up timestamp,... */
    uint8_t type : 2;
    uint8_t setup_packet_direction : 1;      /**< the direction of the first packet of this session (Lower_toHigher or Higher_to_Lower) */
    uint8_t last_packet_direction : 1;       /**< the direction of the current packet Lower_toHigher or Higher_to_Lower.
                                                  This is used as indicator to track direction change in bidirectional sessions */
#elif BYTE_ORDER == BIG_ENDIAN
    uint8_t last_packet_direction : 1, setup_packet_direction : 1, type : 2, status : 4;
#else
#error "BYTE_ORDER must be defined"
#endif
    uint8_t family;                          /**< identifier of the application family to which this session belongs. */
    struct mmt_session_struct * next;        /**< pointer to the next session in the expiry list --- for internal use must not be changed */
    struct mmt_session_struct * previous;    /**< pointer to the previous session in the expiry list --- for internal use must not be changed */
};
```
** IP session key - An example of `mmt_session_key` structure **

Session key is very flexible.
```c
    /**
     * Defines the structure of the key of a session.
     */
    typedef struct mmt_session_key_struct {
#if BYTE_ORDER == LITTLE_ENDIAN
        uint8_t is_lower_initiator : 2, is_lower_client : 2, ip_type : 4;
#elif BYTE_ORDER == BIG_ENDIAN
        uint8_t ip_type : 4, is_lower_client : 2, is_lower_initiator : 2;
#else
#error "BYTE_ORDER must be defined"
#endif
        uint8_t next_proto; /**< identifier of the encapsulated protocol (TCP, UDP, etc.) */
        uint16_t lower_ip_port; /**< identifier of the port number with the lower numerical value */
        uint16_t higher_ip_port; /**< identifier of the port number with the higher numerical value */
        void * lower_ip; /**< identifier of the IP address (IPv4 or IPv6) with the lower numerical value */
        void * higher_ip; /**< identifier of the IP address (IPv4 or IPv6) with the higher numerical value */
    } mmt_session_key_t;
```
### User API ###
```c
MMTAPI mmt_session_t* MMTCALL get_session_from_packet(
    const ipacket_t *ipacket
);
```
This function returns a pointer to the session struct associated to ipacket

```c
MMTAPI mmt_session_t* MMTCALL get_session_parent(
    const mmt_session_t *session
);
```
This function returns pointer to the parent session struct.

```c
MMTAPI mmt_handler_t* MMTCALL get_session_handler(
    const mmt_session_t *session
);
```
This function returns the pointer to the mmt handler that is processing the given session.
```c
MMTAPI uint32_t MMTCALL get_session_protocol_index(
    const mmt_session_t *session
);
```
This function returns the index in the protocol hierarchy of the protocol session it belongs to.
```c
MMTAPI const proto_hierarchy_t* MMTCALL get_session_protocol_hierarchy(
    const mmt_session_t *session
);
```
This function returns the pointer to the protocol hierarchy of the session.
```c
MMTAPI uint64_t MMTCALL get_session_id(
    const mmt_session_t *session
);
```
This function returns the associated session identifier.
```c
MMTAPI void* MMTCALL get_user_session_context(
    const mmt_session_t *session
);
```
This function returns the associated session context
```c
MMTAPI void* MMTCALL get_proto_session_data(
    const mmt_session_t *session,
    unsigned index
);
```
This function returns pointer to the initialized session data of the protocol at the given index. It returns NULL if the protocol has no registered session data.
```c
MMTAPI void MMTCALL set_proto_session_data(
    mmt_session_t *session,
    void * proto_data,
    unsigned index
);
```
This function sets the protocol session data.

```c
MMTAPI void MMTCALL set_user_session_context(
    mmt_session_t *session,
    void *user_data
);
```
This function sets the user session context

```c
MMTAPI uint64_t MMTCALL get_session_packet_count(
    const mmt_session_t *session
);
```
This function returns the number of packets transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_packet_cap_count(
    const mmt_session_t *session
);
```
This function returns the number of packets transmitted in a particular session (include fragmented packets).


```c
MMTAPI uint64_t MMTCALL get_session_ul_packet_count(
    const mmt_session_t *session
);
```
This function returns the uplink number of packets transmitted in a particular session.
```c
MMTAPI uint64_t MMTCALL get_session_dl_packet_count(
    const mmt_session_t *session
);
```
This function return the downlink number of packets transmitted in a particular session.


```c
MMTAPI uint64_t MMTCALL get_session_ul_cap_packet_count(
    const mmt_session_t *session
);
```
This function returns the uplink number of packets transmitted in a particular session (include fragmented packets).

```c
MMTAPI uint64_t MMTCALL get_session_dl_cap_packet_count(
    const mmt_session_t *session
);
```
This function return the downlink number of packets transmitted in a particular session (include fragmented packets).



```c
MMTAPI uint64_t MMTCALL get_session_byte_count(
    const mmt_session_t *session
);
```
This function returns total volume in bytes transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_ul_byte_count(
    const mmt_session_t *session
);
```
This function returns total uplink volume in bytes transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_dl_byte_count(
    const mmt_session_t *session
);
```
This function returns total downlink volume in bytes transmitted in a particular session. 

```c
MMTAPI uint64_t MMTCALL get_session_ul_cap_byte_count(
    const mmt_session_t *session
);
```
This function returns total uplink volume in bytes transmitted in a particular session (include fragmented packets).

```c
MMTAPI uint64_t MMTCALL get_session_dl_cap_byte_count(
    const mmt_session_t *session
);
```
This function returns total downlink volume in bytes transmitted in a particular session (include fragmented packets). 


```c
MMTAPI uint64_t MMTCALL get_session_data_packet_count(
    const mmt_session_t *session
);
```
This function returns the number of data packets transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_ul_data_packet_count(
    const mmt_session_t *session
);
```
This function returns the uplink number of data packets transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_dl_data_packet_count(
    const mmt_session_t *session
);
```
This function returns the downlink number of data packets transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_data_byte_count(
    const mmt_session_t *session
);
```
This function returns total data volume in bytes transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_ul_data_byte_count(
    const mmt_session_t *session
);
```
This function returns total uplink data volume in bytes transmitted in a particular session.

```c
MMTAPI uint64_t MMTCALL get_session_dl_data_byte_count(
    const mmt_session_t *session
);
```
This function returns total downlink data volume in bytes transmitted in a particular session.
```c
MMTAPI struct timeval MMTCALL get_session_init_time(
    const mmt_session_t *session
);
```
This function gets the session initialization time.
```c
MMTAPI struct timeval MMTCALL get_session_last_activity_time(
    const mmt_session_t *session
);
```
This function gets the session last activity time.
```c
MMTAPI struct timeval MMTCALL get_session_rtt(
    const mmt_session_t *session
);
```
This function gets the session establishment round trip time.

```c
MMTAPI uint16_t MMTCALL get_session_content_class_id(
    const mmt_session_t *session
);
```
This function returns the session content class id.

```c
MMTAPI uint16_t MMTCALL get_session_content_type_id(
    const mmt_session_t *session
);
```
This function returns the session content type id.
```c
MMTAPI uint32_t MMTCALL get_session_content_flags(
    const mmt_session_t *session
);
```
This function returns the session content flags.

```c
MMTAPI uint32_t MMTCALL get_session_retransmission_count(
    const mmt_session_t *session
);
```
This function returns the number of retransmitted packets seen by the given session.
```c
MMTAPI mmt_session_t MMTCALL get_session_next(
    const mmt_session_t *session
);
```
This function returns the next session of the given session. NULL if the given session does not have next session
```c
MMTAPI mmt_session_t MMTCALL get_session_previous(
    const mmt_session_t *session
);
```
This function returns the previous session of the given. NULL if the given session does not have previous session
## Open Issues ##


