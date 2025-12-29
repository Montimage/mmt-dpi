# MMT Protocol Stack #

[TOC]

------------------

## Definition ##

In MMT, a protocol stack is an abstract concept that defines what ROOT protocol is expected when processing a data packet.
We can make a link between a stack and a `data link protocol`. For example, the Ethernet protocol defines also a stack that starts by Ethernet as a ROOT protocol.
Any packet in the Ethernet stack, has Ethernet as ROOT protocol. As the concept of protocol is abstract in MMT, a root protocol does not necessarily need to be a
 !LinkLayerProtocol (Layer 2 of the OSI model). Rather, any protocol can be associated to a stack.

## Internals ##

A stack must have the following information

* **Identifier**: must be unique
* **Name**: must be unique
* **Classification function**: indicating the ROOT protocol
* **Internal context**: Opaque from user point of view

An [MMT Handler](/montimage/mmt-sdk/wiki/MMT Handler/) **MUST** be associated to a protocol stack.
When the handler processes a packet, it will first call the classification function of the stack to identify the ROOT protocol.

## API ##

MMT users need not to handle stacks. They only need to indicate the identifier of the stack when creating an MMT Handler.

### User API ###

```c
   mmt_handler_t * mmt_init_handler(uint32_t stacktype, uint32_t options, char * errbuf);
```

Initializes a new MMT handler with the given stack identifier. Once initialised, a handler can process data packets,
register user requests, and notify user upon occurrence of identified events (packet processing, attribute detection, session timeout, etc.).

```c
   int get_data_link_type(mmt_handler_t *mmt_handler);
```

   Returns the data link type of the given mmt handler. The data link type is the identifier of the protocol stack.

### Developer API ###

```c
   int register_protocol_stack(uint32_t s_id, char *s_name, generic_stack_classification_function fct);

   int register_protocol_stack_full(uint32_t s_id,
      char *s_name, generic_stack_classification_function fct,
      stack_internal_cleanup stack_cleanup,
      void * stack_internal_context
    );
```

   Registers a protocol stack given its identifier, name and classification function. In case the stack maintains a local context,
   the cleanup function needs to be given. The registration fails if a protocol stack is already registered with the given identifier or name.

```c
   int unregister_protocol_stack(uint32_t s_id);
```

   Unregisters a protocol stack given its identifier.

## Open Issues ##

* The function `iterate_through_protocol_stacks` should be public. In this case we need to add utility functions to access to the stack structure that needs to be opaque for the user.

* List protocol based on port number: [https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt)
