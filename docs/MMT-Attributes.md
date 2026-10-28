---
layout: default
title: "MMT Attributes"
---

# MMT Attributes #

[TOC]

------------------

## Definition ##
An attribute is a value connected to a protocol that represents a protocol field or a value calculated based on the arriving protocol packets. 
An attribute can be part of the protocol's header/data like TCP source port, source IP address, etc. It can be a `virtual value` 
calculated from the protocol packets like TCP RTT, jitter, packet loss, etc.

## Attribute scopes ##
 * **packet scope**: indicates that the attribute belongs to a packet. It will change with every packet. Attributes with packet scope can be easily extracted from the packet. 
 * **session scope**: indicates that the attribute belongs to a session. It will not change all over the session lifetime. 
 * **session changing scope**: indicates that the attribute belongs to the session context but it might change during the session lifetime.
 * **on demand scope**: indicates that the attribute belongs to a demand.
 * **on event scope**: indicates that the attribute belongs to a event.
## Attribute structure ##
MMT attributes have the following metadata:

 * **Attribute ID**: identifier of the attribute, MUST be unique for a given protocol.
 * **Attribute Alias**: friendly name of the attribute, MUST be unique for a given protocol.
 * **Data type**: indicates the data type of the attribute. This MUST be one of [MMT Data Types](./Data-Types.md). 
 * **Data length**: indicates the length in octets of the attribute data.
 * **Position in packet**: indicates the packet offset of the attribute with respect to the protocol's data. This MUST only be set for binary protocols. 
   When the attribute has no known/fixed offset, this field MUST be set to -1 (`POSITION_NOT_KNOWN`).
 * **Scope**: indicates the scope of the attribute. It can be a `SCOPE_PACKET`/`SCOPE_SESSION`, `SCOPE_SESSION_CHANGING`, `SCOPE_ON_DEMAND`/`SCOPE_EVENT`.
 * **Extraction function**: this is the function that will actually extract the attribute and prepares it for the user. This field is relevant for attributes with on-demand scope. 

## Attribute extraction ##
The extraction of an attribute can be one of the following:

 * **Event based**: the attribute is extracted while parsing the packet data. This is useful for sessions attributes where the attribute appears in a subset of the packets. 
   It is also useful for repetitive attributes (they exist more than once in a packet: DNS). 
   The extraction is performed on a per attribute basis in the `analyse/parse` sub-process of the packet journey. 
   When an event based attribute is detected, the core will fire an event that will check if the attribute is registered for extraction by the user. 
   If this is the case, the attribute will be extracted and made ready to be used by the user. 
   If in addition, one or more attribute handlers are registered, they will be called. 
 * **On demand (lazy extraction)**: the attribute is extracted on the user request. 
   This strategy should be used for attributes with simple extraction like for binary protocols. 
   For example, the source IP address of a packet is a candidate for such extraction strategy.

## Attribute notification ##
Indicates at what points during the packet journey in the core, the user registered attribute handlers are called. This can be:

 * **Event based (while parsing the packet in the `analyse/parse` sub-process)**: The notification is done right after the detection of the attribute. 
 * **Explicit in the `notify` sub-process**: this is done for on-demand attributes within the `notify` sub-process. 
   The core checks for on-demand attributes with registered attribute handlers, and, for each calls the attribute's 
   extraction function then calls the user attribute handlers registered with the attribute.

## API ##
### User API ###
```c
   int register_extraction_attribute(mmt_handler_t * mmt_handler, uint32_t protocol_id, uint32_t attribute_id);

   int register_extraction_attribute_by_name(mmt_handler_t * mmt_handler, char * protocol_name, char * attribute_name);
```
   Allow registering an attribute for extraction. An attribute is identified by the protocol and attribute ids or names. If the registration succeeds, a positive value will be returned.

```c
   int is_registered_attribute(mmt_handler_t * mmt_handler, uint32_t protocol_id, uint32_t attribute_id);
```
   Allows verifying if an attribute, identified by its protocol and attribute identifiers, is already registered. It will return a positive value if the attribute is found registered.

```c
   int unregister_extraction_attribute(mmt_handler_t * mmt_handler, uint32_t protocol_id, uint32_t attribute_id);

   int unregister_extraction_attribute_by_name(mmt_handler_t * mmt_handler, char * protocol_name, char * attribute_name);
```
   Allow unregistering an already registered attribute. If the unregistration succeeds, a positive value will be returned.

```c
   int register_attribute_handler(mmt_handler_t * mmt_handler, uint32_t protocol_id, uint32_t attribute_id, 
                                  attribute_handler_function handler_fct, void * handler_condition, void * user);

   int register_attribute_handler_by_name(mmt_handler_t * mmt_handler, char * protocol_name, char * attribute_name, 
                                          attribute_handler_function handler_fct, void * handler_condition, void * user);
```
   Allow registering an attribute handler that is a callback that will be called each time the given attribute identified by its protocol and attribute ids or names is found. If needed, the user can provide a pointer to an argument that will be passed to the callback function when it is called. 

```c
   int unregister_attribute_handler(mmt_handler_t * mmt_handler, uint32_t protocol_id, uint32_t attribute_id);

   int unregister_attribute_handler_by_name(mmt_handler_t * mmt_handler, char * protocol_name, char * attribute_name);
```
   Allow unregistering an already registered attribute handler. If the unregistration succeeds, a positive value will be returned.

   A handler may unregister attribute handlers, itself included, from inside its callback: the handlers still registered on the attribute keep running for the current dispatch, and an attribute released this way is freed only once the dispatch returns (`src/mmt_core/src/packet_pipeline.c:821`, `src/mmt_core/src/packet_registry.c:1427`). A handler that unregisters and re-registers itself from its callback (to change its `user_args`) runs once for that dispatch, and the handlers and attributes after it still run: the handler dispatch continues from the handler that followed it, within a bound on the number of handlers it saw (`src/mmt_core/src/packet_pipeline.c:834`, `src/mmt_core/src/packet_pipeline.c:882`), and the attribute dispatch continues at the next field in field order, so each attribute runs at most once per packet (`src/mmt_core/src/packet_pipeline.c:861`). A handler registered from a callback may first run on the next packet or event. Unregistering a handler gives back the extraction registration only when that handler's registration created the attribute; an attribute you registered with `register_extraction_attribute()` stays registered until you unregister it (`src/mmt_core/src/packet_registry.c:1627`).

   For an event attribute, such as the HTTP header and body events, `attribute->data` points to the event payload only while the handler runs. The payload often lives on the engine's stack, so `data` is `NULL` once the dispatch returns (`src/mmt_core/src/packet_pipeline.c:927`). Copy any value you need to keep.

   Some attributes hand back a heap object instead of a value in the attribute's own buffer: the DNS `queries`, `answers` and `auth_records` lists, the FTP `packet_request`, `packet_request_parameter` and `packet_reponse_value` strings, and the NDN strings (`name_components`, `publisher_publickey_locator`, `exclude`, `content`, `signature_value`, `final_block_id`, `key_locator`). The handler owns that object. It stays valid while the current packet is processed and its handlers run, and the handler frees it when the next `packet_process()` call on it starts (`src/mmt_core/src/packet_pipeline.c:1516`) or when `mmt_close_handler()` runs (`src/mmt_core/src/packet_registry.c:1450`). Do not free it, and copy any part you need after the packet. Every read extracts the attribute again and allocates a new object, so read it once per packet. An extraction function in a plugin hands its heap value over the same way, with `mmt_packet_scratch_adopt()` (`src/mmt_core/public_include/plugin_defs.h:54`).

```c
   int is_registered_attribute_handler(mmt_handler_t * mmt_handler, uint32_t protocol_id, uint32_t attribute_id, attribute_handler_function handler_fct);
```
   Allows verifying if an attribute handler is registered with the attribute identified by its protocol and attribute identifiers. It will return a positive value if the attribute handler is found registered.

```c
   int has_registered_attribute_handler(mmt_handler_t * mmt_handler, uint32_t protocol_id, uint32_t attribute_id);
```
   Allows verifying if an attribute identified by its protocol and attribute identifiers has any attribute handlers. It will return a positive value if the attribute has any registered handler.

```c
   void * get_attribute_extracted_data(const ipacket_t * ipacket, uint32_t protocol_id, uint32_t attribute_id);

   void * get_attribute_extracted_data_by_name(const ipacket_t * ipacket, char * protocol_name, char * attribute_name);

   void * get_attribute_extracted_data_at_index(const ipacket_t * ipacket, uint32_t protocol_id, uint32_t attribute_id, unsigned index);
```
   Returns a pointer to the data corresponding to the attribute identified by its protocol and attribute ids or names if it was extracted in the last processed packet. NULL is returned otherwise. If the index is given, only the protocol at that index will be checked. Indicating the index is recommended. 

### Developer API ###
```c
   int register_attribute_with_protocol(protocol_t * protocol_struct, attribute_metadata_t attribute_meta_data);
```
   Allows to register the attribute defined by its meta-data structure with the protocol identified by a pointer to its opaque structure. It returns a positive value on success (valid attribute and not already registered), zero otherwise.

## Open Issues ##
 * Shall we support structured attributes?
 * Possible approach to cases where attributes get repeated within a stream?
