# MMT Packet #

[TOC]

------------------

## Definition ##

A packet in MMT is a structured data element that can be analysed and classified in order to extract attributes of interest. A packet can be any data entry like a log entry, a network packet, a structured data, etc. A packet can belong to a path of protocols identified by the classification process of MMT. A packet is therefore the elementary data unit fed by the user to the MMT core.

## Packet Journey in the Core ##

Please refer to [Packet Journey](/montimage/mmt-sdk/wiki/Packet Journey/) page.

## API ##

### Packet Structure ###

An MMT user needs to feed the core with packets. A packet is identified by a the data place holder and some meta data including the packet real length, the packet snapshot length (what is really available).
MMT has only one entry point: `packet_process`. This is the API to feed MMT with data packets. Internally, MMT will create an `internal packet`

```
#!cpp
/**
 * Defines the meta-data of a packet.
 */
typedef struct pkthdr {
    struct timeval ts;   /**< time stamp that indicates the packet arrival time */
    unsigned int caplen; /**< length of portion of the packet that is present */
    unsigned int len;    /**< length of the packet (off wire) */
    void * user_args;    /**< Pointer to a user defined argument. Can be NULL, it will not be used by the library. */
} pkthdr_t;
```

```
#!cpp
/**
 * Defines a packet structure.
 */
struct ipacket_struct {
    uint64_t packet_id;                       /**< identifier of the packet. */
    proto_hierarchy_t * proto_hierarchy;      /**< the protocol layers corresponding to this packet */
    proto_hierarchy_t * proto_headers_offset; /**< the offsets corresponding to the protocol layers of this packet */
    proto_hierarchy_t * proto_classif_status; /**< the classification status of the protocols in the path */
    mmt_session_t * session;                  /**< pointer to the session structure to which the packet belongs*/
    void * internal_packet;                   /**< pointer to opaque packet structure. for internal use only. Must never be changed */
    mmt_handler_t * mmt_handler;              /**< opaque pointer to the MMT handler that processed this packet */
    pkthdr_t * p_hdr;                         /**< the meta-data of the packet */
    const u_char * data;                      /**< pointer to the packet data */
};
```

### User API ###

```c
   int packet_process(
      mmt_handler_t *mmt_handler,
      struct pkthdr *header,
      const u_char *packet);
```

This is the entry point for MMT. It feeds packets to the Core for processing by the given MMT handler.

```c
   int register_packet_handler(
      mmt_handler_t *mmt_handler,
      int packet_handler_id,
      generic_packet_handler_callback function,
      void *user);

   int is_registered_packet_handler(
      mmt_handler_t *mmt_handler,
      int packet_handler_id);

   int unregister_packet_handler(
      mmt_handler_t *mmt_handler,
      int packet_handler_id);
```

In addition to attributes handlers, the user can register packet handlers. It consists of user defined functions that will be called for every processed packet.
These functions provide the API for registering packet handlers, checking the existing of a particular packet handler, and, unregistering a packet handler.

### Getters and Setters API ###

```c
MMTAPI int MMTCALL get_packet_offset_at_index(
    const ipacket_t *ipacket,
    unsigned index
);
```

This function returns the offset in number of bytes from the beginning of the packet for the protocol at the given index.

```c
MMTAPI uint32_t MMTCALL get_protocol_id_at_index(
    const ipacket_t *ipacket,
    unsigned index
);
```

This function return the identifier of the protocol at the given index if such index exists, -1 otherwise.

```c
MMTAPI unsigned MMTCALL get_protocol_index_by_id(
    const ipacket_t *ipacket,
    uint32_t proto_id
);
```

This function return the index of the protocol given by its id. If the protocol id is not valid or the protocol does not appear in the protocol hierarchy, -1 is returned.

```c
MMTAPI unsigned MMTCALL get_protocol_index_by_name(
    const ipacket_t *ipacket,
    const char *proto_name
);
```

This function return the index of the protocol given by its name. If the protocol name is not valid or the protocol does not appear in the protocol hierarchy, -1 is returned.

```c
MMTAPI uint64_t MMTCALL get_session_id_from_packet(
    const ipacket_t *ipacket
);
```

This function returns the session ID associated to ipacket

```c
MMTAPI void* MMTCALL get_user_session_context_from_packet(
    const ipacket_t *ipacket
);
```

This function returns the user session context

```c
MMTAPI void MMTCALL set_user_session_context_for_packet(
    const ipacket_t *ipacket,
    void *user_data
);
```

This function sets the user session context for a given packet

```c
MMTAPI void* MMTCALL get_proto_session_data_from_packet(
    const ipacket_t *ipacket,
    unsigned index
);
```

This function returns pointer to initialized the session data of the protocol at the given index. NULL if the protocol has no registered session data.

```c
MMTAPI mmt_session_t* MMTCALL get_session_from_packet(
    const ipacket_t *ipacket
);
```

This function returns pointer to the associated session if it exists, NULL otherise.

## Open Issues ##
