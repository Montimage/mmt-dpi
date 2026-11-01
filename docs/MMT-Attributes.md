---
layout: default
title: "MMT Attributes"
---

# MMT Attributes #

* TOC
{:toc}

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

## Classification method (`meta.classification_method`) ##
A session is `Classified` whether its application protocol was matched in the
payload or only guessed, so the status alone cannot tell a port guess from a
DPI match (issue #567, F-BUG-306). The session-scope attribute
`meta.classification_method` (`PROTO_META`, id `META_CLASSIFICATION_METHOD`,
`MMT_U8_DATA` — `src/mmt_core/src/proto_meta.c:136`,
`src/mmt_core/public_include/proto_meta.h:29`) carries how the verdict was
reached; `get_session_classification_method()` returns the same value from a
session (`src/mmt_core/public_include/data_defs.h:509`) and
`get_classification_method_name()` names it
(`src/mmt_core/public_include/data_defs.h:519`). Unlike `meta.classified`, it
is extracted for every packet that has a session, `none` included.

The values, in ascending order of confidence
(`src/mmt_core/public_include/data_defs.h:34-40`):

| Value | Name | Set when |
|-------|------|----------|
| `MMT_CLASSIFICATION_METHOD_NONE` (0) | `none` | no application verdict (yet) |
| `MMT_CLASSIFICATION_METHOD_PORT` (1) | `port` | the TCP/UDP fallback guessed from a well-known port (`port_classify`, `src/mmt_tcpip/lib/protocols/proto_tcp.c:1230`, `src/mmt_tcpip/lib/protocols/proto_udp.c:165`) |
| `MMT_CLASSIFICATION_METHOD_IP` (2) | `ip` | the IP-range table named the protocol — the TCP/UDP fallback (`src/mmt_tcpip/lib/protocols/proto_tcp.c:1226`, `src/mmt_tcpip/lib/protocols/proto_udp.c:160`), or the HTTP, TLS, RTP, SIP and STUN classifiers' address lookups (e.g. `src/mmt_tcpip/lib/protocols/http.c:942`, `src/mmt_tcpip/lib/protocols/proto_ssl.c:842`) — or a classifier matched a hard-coded address range (WhatsApp, Viber, Gameforge, Tango, LINE, Ustream, Spotify, NetEase POPO); an address range checked together with a payload property (FaceTime's 17.0.0.0/8 plus a 16-byte payload) counts as `dpi` |
| `MMT_CLASSIFICATION_METHOD_CORRELATED` (3) | `correlated` | a classifier inferred it from another protocol's content or from what the hosts were seen with (`MMT_CORRELATED_PROTOCOL`) |
| `MMT_CLASSIFICATION_METHOD_HOSTNAME` (4) | `hostname` | the hostname table matched the HTTP `Host` header or the TLS SNI/certificate name (`src/mmt_tcpip/lib/protocols/http.c:933`, `src/mmt_tcpip/lib/protocols/proto_ssl.c:602`, `src/mmt_tcpip/lib/protocols/proto_ssl.c:644`) |
| `MMT_CLASSIFICATION_METHOD_DPI` (5) | `dpi` | the protocol's own classifier matched the payload (`MMT_REAL_PROTOCOL`), or a dissector above the transport layer claimed the layer itself (DICOM, S1AP, QUIC, HTTP/2 — `src/mmt_core/src/packet_pipeline.c:653`); such a claim also covers layers that are not an application (SCTP chunks, tunnel headers such as GTP), so a tunnel or SCTP session reads `dpi` |

The method follows the protocol at the top of the session's application stack
(`src/mmt_tcpip/lib/mmt_tcpip_plugin_internal.c:217`): when a classifier puts a
new protocol there, its method replaces the previous one — HTTP matched by DPI
and then attributed to a service from its `Host` header reads `hostname` — and
re-asserting the protocol already on top only raises the method; a protocol
inserted beneath a different one on top leaves it. A payload match therefore
replaces the TCP/UDP fallback's earlier port or IP-range guess, while a service
attributed on top of HTTP or TLS keeps its method when the wire protocol is
matched again beneath it.
`tools/phase0/ci/check_precision.sh` reports the precision of each method over
the labelled set (the `per-method` block of
`tools/phase0/ci/baseline/precision.txt`).

## API ##
### User API ###
```c
   bool register_extraction_attribute(mmt_handler_t * mmt_handler, mmt_proto_id_t proto_id, uint32_t attribute_id);

   bool register_extraction_attribute_by_name(mmt_handler_t * mmt_handler, const char * protocol_name, const char * attribute_name);
```
   Allow registering an attribute for extraction. An attribute is identified by the protocol and attribute ids or names. They return `true` when the registration succeeds, `false` otherwise.

```c
   bool is_registered_attribute(mmt_handler_t * mmt_handler, mmt_proto_id_t proto_id, uint32_t attribute_id);
```
   Allows verifying if an attribute, identified by its protocol and attribute identifiers, is already registered. It returns `true` if the attribute is found registered.

```c
   bool unregister_extraction_attribute(mmt_handler_t * mmt_handler, mmt_proto_id_t proto_id, uint32_t attribute_id);

   bool unregister_extraction_attribute_by_name(mmt_handler_t * mmt_handler, const char * protocol_name, const char * attribute_name);
```
   Allow unregistering an already registered attribute. They return `true` when the unregistration succeeds.

```c
   bool register_attribute_handler(mmt_handler_t * mmt_handler, mmt_proto_id_t proto_id, uint32_t attribute_id, 
                                  attribute_handler_function handler_fct, mmt_opaque_t handler_condition, mmt_opaque_t user);

   bool register_attribute_handler_by_name(mmt_handler_t * mmt_handler, const char * protocol_name, const char * attribute_name, 
                                          attribute_handler_function handler_fct, mmt_opaque_t handler_condition, mmt_opaque_t user);
```
   Allow registering an attribute handler that is a callback that will be called each time the given attribute identified by its protocol and attribute ids or names is found. If needed, the user can provide a pointer to an argument that will be passed to the callback function when it is called. 

```c
   bool unregister_attribute_handler(mmt_handler_t * mmt_handler, mmt_proto_id_t proto_id, uint32_t attribute_id, attribute_handler_function handler_fct);

   bool unregister_attribute_handler_by_name(mmt_handler_t * mmt_handler, const char * protocol_name, const char * attribute_name, attribute_handler_function handler_fct);
```
   Allow unregistering an already registered attribute handler: `handler_fct` names which of the handlers registered on the attribute to remove. They return `true` when the unregistration succeeds.

   A handler may unregister attribute handlers, itself included, from inside its callback: the handlers still registered on the attribute keep running for the current dispatch, and an attribute released this way is freed only once the dispatch returns (`src/mmt_core/src/packet_pipeline.c:893`, `src/mmt_core/src/packet_registry_attr.c:125`). A handler that unregisters and re-registers itself from its callback (to change its `user_args`) runs once for that dispatch, and the handlers and attributes after it still run: the handler dispatch continues from the handler that followed it, within a bound on the number of handlers it saw (`src/mmt_core/src/packet_pipeline.c:906`, `src/mmt_core/src/packet_pipeline.c:954`), and the attribute dispatch continues at the next field in field order, so each attribute runs at most once per packet (`src/mmt_core/src/packet_pipeline.c:933`). A handler registered from a callback may first run on the next packet or event. Unregistering a handler gives back the extraction registration only when that handler's registration created the attribute; an attribute you registered with `register_extraction_attribute()` stays registered until you unregister it (`src/mmt_core/src/packet_registry_attr.c:325`).

   For an event attribute, such as the HTTP header and body events, `attribute->data` points to the event payload only while the handler runs. The payload often lives on the engine's stack, so `data` is `NULL` once the dispatch returns (`src/mmt_core/src/packet_pipeline.c:999`). Copy any value you need to keep.

   Some attributes hand back a heap object instead of a value in the attribute's own buffer: the DNS `queries`, `answers` and `auth_records` lists, the FTP `packet_request`, `packet_request_parameter` and `packet_reponse_value` strings, and the NDN strings (`name_components`, `publisher_publickey_locator`, `exclude`, `content`, `signature_value`, `final_block_id`, `key_locator`). The handler owns that object. It stays valid while the current packet is processed and its handlers run, and the handler frees it when the next `packet_process()` call on it starts (`src/mmt_core/src/packet_pipeline.c:1590`) or when `mmt_close_handler()` runs (`src/mmt_core/src/packet_registry_attr.c:148`). Do not free it, and copy any part you need after the packet. Every read extracts the attribute again and allocates a new object, so read it once per packet. An extraction function in a plugin hands its heap value over the same way, with `mmt_packet_scratch_adopt()` (`src/mmt_core/public_include/plugin_defs.h:54`).

```c
   bool is_registered_attribute_handler(mmt_handler_t * mmt_handler, mmt_proto_id_t proto_id, uint32_t attribute_id, attribute_handler_function handler_fct);
```
   Allows verifying if an attribute handler is registered with the attribute identified by its protocol and attribute identifiers. It returns `true` if the attribute handler is found registered.

```c
   bool has_registered_attribute_handler(mmt_handler_t * mmt_handler, mmt_proto_id_t proto_id, uint32_t attribute_id);
```
   Allows verifying if an attribute identified by its protocol and attribute identifiers has any attribute handlers. It returns `true` if the attribute has any registered handler.

```c
   void * get_attribute_extracted_data(const ipacket_t * ipacket, mmt_proto_id_t proto_id, uint32_t attribute_id);

   void * get_attribute_extracted_data_by_name(const ipacket_t * ipacket, const char * protocol_name, const char * attribute_name);

   void * get_attribute_extracted_data_at_index(const ipacket_t * ipacket, mmt_proto_id_t proto_id, uint32_t attribute_id, unsigned index);
```
   Returns a pointer to the data corresponding to the attribute identified by its protocol and attribute ids or names if it was extracted in the last processed packet. NULL is returned otherwise. If the index is given, only the protocol at that index will be checked. Indicating the index is recommended. 

### Developer API ###
```c
   bool register_attribute_with_protocol(protocol_t * protocol_struct, attribute_metadata_t * attribute_meta_data);
```
   Allows to register the attribute defined by its meta-data structure with the protocol identified by a pointer to its opaque structure. It returns `true` on success (valid attribute and not already registered), `false` otherwise.

## Open Issues ##
 * Shall we support structured attributes?
 * Possible approach to cases where attributes get repeated within a stream?
