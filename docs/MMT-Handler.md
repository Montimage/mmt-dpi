# MMT Handler #
## Definition ##
MMT Handler is an abstract instance responsible for processing data packets, extracting registered attributes, and notifying user about defined events.

## MMT Handler internals ##
MMT Handler has the following elements:

 * An associated [Protocol Stack](/montimage/mmt-sdk/wiki/Protocol Stack/). This defines the ROOT protocol this handler is expecting to process.
 * Instance of registered protocols. This is a complete or partial copy of the registered protocols defined in the [Global Handler](/montimage/mmt-sdk/wiki/Global Handler/).
 * List of user registered [attributes](/montimage/mmt-sdk/wiki/MMT Attributes/) for extraction.
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
   Closes the given MMT handler and frees any allocated objet.

```c
   mmt_handler_t * get_active_session_count(mmt_handler_t * mmt_handler);
```
   Get number of active session

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
   void enable_protocol_analysis(mmt_handler_t *mmt_handler, uint32_t proto_id);

   void disable_protocol_analysis(mmt_handler_t *mmt_handler, uint32_t proto_id);
```
   Enables/Disables the **analysis** sub-process for the protocol with the given id.

```c
   void enable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id);

   void disable_protocol_classification(mmt_handler_t *mmt_handler, uint32_t proto_id);
```
   Enables/Disables the classification sub-process for the protocol with the given id.

Change the default session timedout values: 

```c
int set_default_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
int set_long_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
int set_short_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
int set_live_session_timed_out(mmt_handler_t *mmt_handler,uint32_t timedout_value);
```

Enable/disable classification by hostname (enable by default)

```c
int enable_hostname_classify(mmt_handler_t * mmt);
int disable_hostname_classify(mmt_handler_t * mmt);
```

Enable/disable classification by ip address (enable by default)

```c
int enable_ip_address_classify(mmt_handler_t * mmt);
int disable_ip_address_classify(mmt_handler_t * mmt);
```

Enable/disable classification by port number (disable by default)

```c
int enable_port_classify(mmt_handler_t * mmt);
int disable_port_classify(mmt_handler_t * mmt);
```

Enable/disable using `mmt_reassembly` (disable by default)

```c
int enable_mmt_reassembly(mmt_handler_t * mmt);
int disable_mmt_reassembly(mmt_handler_t * mmt);
```

Process session timer handler which is registered by user

```c
void process_session_timer_handler(mmt_hanlder_t * mmt);
```

Register an evasion_handler

```c
int register_evasion_handler(mmt_handler_t * mmt_handler, generic_evasion_handler_callback evasion_handler);
```

With `evasion_handler`:

```c
void evasion_handler(ipacket_t * ipacket, uint32_t proto_id, unsigned proto_index, unsigned evasion_id, void * data);
```

## Evasion event

Define the id of evasion (`mmt_core.h`)

```c
#define EVA_IP_FRAG_PACKET 1 // Event which relates to fragment in packet
#define EVA_IP_FRAG_SESSION 2 // Event which relates to fragmented packet in session
```

Update the value for the limit number of fragment in packet
```c
MMTAPI int MMTCALL set_fragment_in_packet(
    mmt_handler_t *mmt_handler,
    uint32_t frag_per_packet
);
```
Set value for number of fragment in packet

```c
MMTAPI int MMTCALL set_fragmented_packet_in_session(
    mmt_handler_t *mmt_handler,
    uint32_t frag_packet_per_session
);
```

Set value for number of fragmented packet in session


## Open Issues ##