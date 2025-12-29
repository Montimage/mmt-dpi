# Workflow to Add New Protocol

[TOC]

------------------

In order to add a new protocol to the TCP/IP plugins you can follow the following methodology.

In the next sections we will describe the procedure to add a new Web Protocol. For this we will consider the French newspaper **lemonde.fr**.

## 1- Create the Protocol Plugin

In the TCP/IP header file **include/mmt_tcpip_protocols.h** add:

```c
// Add the following line to the end of the protocol numbers definitions
#define PROTO_LEMONDE XXX //XXX is the highest existing protocol number + 1

// Update the value of LAST_IMPLEMENTED_PROTOCOL
#define LAST_IMPLEMENTED_PROTOCOL PROTO_LEMONDE

// Add an alias for Lemonde protocol
#define PROTO_LEMONDE_ALIAS "lemonde"
```

In the TCP/IP protocols folder **lib/protocols/** add the following filename **proto_lemonde.c**:

```c
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_lemonde_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_LEMONDE, PROTO_LEMONDE_ALIAS);
    if (protocol_struct != NULL) {
        return register_protocol(protocol_struct, PROTO_LEMONDE);
    } else {
        return 0;
    }
}
```

## 2- Initialize the Protocol

In the TCP/IP internal include header file **lib/mmt_common_internal_include.h** add **lemonde** protocol intialization definition at the end of the protocol initialization definitions block:

```c
    /////////// PLUGIN INIT FOR PROTO_LEMONDE //////////////////
    int init_proto_lemonde_struct();
    /////////////////////////////////////////////////
```

If a protocol needs a classification for example protocol rtp, we need to add a function

```c

    int mmt_check_rtp_udp(ipacket * ipacket, unsigned index);

```

In the TCP/IP configured protocols library file **lib/configured_protocols.c** add **lemonde** protocol initialization at the end of protocold initialization block:

```c
    /////////// INITILIZING PROTO_LEMONDE //////////////////
    if (!init_proto_lemonde_struct()) {
        fprintf(stderr, "Error initializing protocol proto_lemonde\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
```

If a protocol needs a classification for example protocol rtp, we need to add a classification function

```c

  register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_rtp_udp, 50);

```

In the same file, update function **get_application_class_by_protocol_id** to include **lemonde** as a WEB protocol.

## 3- Add Classification for the Protocol

Now comes the last part where the classification rules for **lemonde** needs to be added. As **lemonde** is a WEB protocol, the classification is directly derived from the **hostnames** of **lemonde** website. An investigation needs to be performed in order to gat the list of domain names for a Web application as there could be many. We will consider here that **lemonde** protocol uses just one hostname **lemonde.fr**.

In the TCP/IP classification utilities source file **lib/mmt_tcpip_classif_utils.c** add to the end of **doted_host_names** structure the following:

```c
    // Add a line for every domain name you have
    {".lemonde.fr", PROTO_LEMONDE, MMT_STATICSTRING_LEN(".lemonde.fr")},
```

## 4- Voilà Voilà
