# Discussion Points #

[TOC]

------------------

* generalize the protocol API to structured data
* Protocol Modelling for automatic generation of plugins (binary + text based protocol) : BNF + IETF
* global attributes (packet count, data volume, session count, etc...) per protocol, protocol family, ID
  * protocol statistics: common for all protocols. Maintained by the Core. Include:
    * packet count and data volume
    * sessions nb, active sessions number
    * packet and data rates (pps and Bps)
    * new sessions rate and timedout sessions rate (in sessions per second)
  * protocol family statistics: TBD
  * End point statistics: TBD
  * protocol meta data: common for all protocols. Maintained by the protocols. The core provides utility functions that can be used. Include:
    * header: common attribute that should return the pointer to the header of the protocol. The implementation depends on the protocol. Example: HTTP does not provide the header in every packet.
    * payload OR data: common attribute that should return the pointer to the data of the protocol. Example: data of IP is the header of L4 protocol.
* specific context per protocol (derived from global context)
* what is a `mmt_id` ?
  * `mmt_id` is an abstract concept closely related to the `session`/`stream` concepts. It is an end-point in a communication stream. `mmt_id` MUST be a part of the identifier of a session\stream. Example: in an IP flow, both end_points are considered instances of `mmt_id`.
  * `mmt_id` SHOULD be composed of:
    * common context: TBD
    * protocol specific context: TBD

## Classification ##

* classification API: provide a simple API to extend the classification capabilities:
  * port based classification: should be provided by port based protocols (TCP, UDP, etc.)
    * API: `register_protocol_by_port_nb(parent_proto_id, proto_id, port_nb, weight)`
  * IP based classification: should be provided by IPv4 & IPv6
    * API: `register_protocol_by_address(parent_proto_id, proto_id, IP_range, weight)`
  * HTTP signatures based classification: provides classification capabilities based on the values of the HTTP header fields
    * API: `register_protocol_by_hostname(parent_proto_id, proto_id, hostname, weight)`
    * API: `register_protocol_by_useragent(parent_proto_id, proto_id, useragent, weight)`
    * API: `register_protocol_by_cname(parent_proto_id, proto_id, cname, weight)`
    * TBD

## Integration / Monitoring ##

* Runtime configuration (eg.: get/set default timeout for sessions)
* Logging: we should have a proper logging mechanism, probably integrated in a larger scoped, platform-specific logging facility (syslog on Unix, SNMP, whatever event logging subsystem Windows is using, etc...).  Of course, the specifics should be abstracted away from the user (we just want to call `log( "blabla.. %s", bla )` from the code, no matter the underlying platform).
* [Memory Management](/montimage/mmt-sdk/wiki/Memory Management/): `mmt_malloc()` / `mmt_free()` are sparsely used in the code, mostly due to `mmt_free()` being rather impractical.  We should come up with a better wrapping scheme, let the user set thresholds at which events would be thrown (e.g.: "warning, memory usage has reached 80%"), and get some statistics for continuous integration.

## Other points to discuss ##

* Updates with zero loss (of library, main, plugins...)
* Shared memory between different processes
* Type-length-value (TLV) manipulation
* Inline functions: inline functions can improve the performance of a code. Internal short functions that are highly used are perfect candidates! Shall we use inline functions?
