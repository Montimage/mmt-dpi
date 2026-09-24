---
layout: default
title: "MMT Handler"
---

# MMT Handler #
## Definition ##
MMT Handler is an abstract instance responsible for processing data packets, extracting registered attributes, and notifying user about defined events.

## MMT Handler internals ##
MMT Handler has the following elements:

 * An associated [Protocol Stack](./Protocol-Stack.md). This defines the ROOT protocol this handler is expecting to process.
 * Instance of registered protocols. This is a complete or partial copy of the registered protocols defined in the [Global Handler](./Global-Handler.md).
 * List of user registered [attributes](./MMT-Attributes.md) for extraction.
 * List of user registered attribute handlers.
 * List of user defined packet handlers.
 * Timer management system (used mainly for sessions expiry detection). 
 * User defined handler callback upon session `timeout`.
 * Configuration options

## API ##
### User API ###
```c
   mmt_handler_t * mmt_init_handler(uint32_t stacktype, uint32_t options, char * errbuf);
```
   Initializes a new MMT handler. Once initialised, a handler can process data packets, register user requests, and notify user upon occurrence of identified events (packet processing, attribute detection, session timeout, etc.). 

```c
   void mmt_close_handler(mmt_handler_t *mmt_handler);
```
   Closes the given MMT handler and frees any allocated object (`src/mmt_core/public_include/mmt_core.h:218`).

```c
   uint64_t get_active_session_count(mmt_handler_t * mmt_handler);
```
   Returns the count of active sessions (`src/mmt_core/public_include/mmt_core.h:229`).

```c
   int get_data_link_type(mmt_handler_t *mmt_handler);
```
   Returns the data link type of the given mmt handler. The data link type is the identifier of the protocol stack.

```c
   void enable_protocol_statistics(mmt_handler_t *mmt_handler);

   void disable_protocol_statistics(mmt_handler_t *mmt_handler);
```
   Enables/Disables the **statistics** maintenance for the protocol of the given MMT Handler.

```c
   void enable_protocol_analysis(mmt_handler_t *mmt_handler, mmt_proto_id_t proto_id);

   void disable_protocol_analysis(mmt_handler_t *mmt_handler, mmt_proto_id_t proto_id);
```
   Enables/Disables the **analysis** sub-process for the protocol with the given id.

```c
   void enable_protocol_classification(mmt_handler_t *mmt_handler, mmt_proto_id_t proto_id);

   void disable_protocol_classification(mmt_handler_t *mmt_handler, mmt_proto_id_t proto_id);
```
   Enables/Disables the classification sub-process for the protocol with the given id.

Change the default session timedout values: 

```c
bool set_default_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
bool set_long_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
bool set_short_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
bool set_live_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
```

Enable/disable classification by hostname (enable by default)

```c
bool enable_hostname_classify(mmt_handler_t * mmt);
bool disable_hostname_classify(mmt_handler_t * mmt);
```

Enable/disable classification by ip address (enable by default)

```c
bool enable_ip_address_classify(mmt_handler_t * mmt);
bool disable_ip_address_classify(mmt_handler_t * mmt);
```

Enable/disable classification by port number (disable by default)

```c
bool enable_port_classify(mmt_handler_t * mmt);
bool disable_port_classify(mmt_handler_t * mmt);
```

Enable/disable using `mmt_reassembly` (disable by default)

```c
bool enable_mmt_reassembly(mmt_handler_t * mmt);
bool disable_mmt_reassembly(mmt_handler_t * mmt);
```

Process session timer handler which is registered by user

```c
void process_session_timer_handler(mmt_handler_t * mmt);
```

Register an evasion_handler

```c
bool register_evasion_handler(mmt_handler_t * mmt_handler, generic_evasion_handler_callback evasion_handler, mmt_opaque_t user_args);
```

Signature from `src/mmt_core/public_include/mmt_core.h:331`; `user_args` is passed back to the callback as `args`.

With `evasion_handler`:

```c
void evasion_handler(const ipacket_t * ipacket, mmt_proto_id_t proto_id, mmt_proto_index_t proto_index, unsigned evasion_id, mmt_opaque_t data, mmt_opaque_t args);
```

Signature from `src/mmt_core/public_include/mmt_core.h:125` (`generic_evasion_handler_callback`).

## Evasion event

Define the id of evasion (`src/mmt_core/public_include/mmt_core.h:106-110`):

```c
#define EVA_IP_FRAGMENT_PACKET 1 // Event: too many fragments in one packet
#define EVA_IP_FRAGMENT_SESSION 2 // Event: too many fragments in one session
#define EVA_IP_FRAGMENTED_PACKET_SESSION 3 // Event: too many fragmented packet in one session
#define EVA_IP_FRAGMENT_OVERLAPPED 4 // Event: IP fragmentation overlapping data
#define EVA_IP_FRAGMENT_DUPLICATED 5 // Event: IP fragmentation duplicated segments
```

Update the value for the limit number of fragment in packet (`src/mmt_core/public_include/mmt_core.h:580`)
```c
MMTAPI bool MMTCALL set_fragment_in_packet(
    mmt_handler_t *mmt_handler,
    uint32_t frag_in_packet
);
```
Set value for number of fragment in packet; returns `true` on success.

```c
MMTAPI bool MMTCALL set_fragmented_packet_in_session(
    mmt_handler_t *mmt_handler,
    uint32_t frag_packet_in_session
);
```

Set value for number of fragmented packet in session (`src/mmt_core/public_include/mmt_core.h:592`); returns `true` on success.

```c
MMTAPI bool MMTCALL set_fragment_in_session(
    mmt_handler_t *mmt_handler,
    uint32_t frag_in_session
);
```

Set value for number of fragments in one session (`src/mmt_core/public_include/mmt_core.h:604`); returns `true` on success.


## Open Issues ##