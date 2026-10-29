---
layout: default
title: "Workflow to Add New Protocol"
---

# Workflow to Add New Protocol

[TOC]

------------------


In order to add a new protocol to the TCP/IP plugins you can follow the following methodology. 

In the next sections we will describe the procedure to add a new Web Protocol. For this we will consider the French newspaper **lemonde.fr**.

## 1- Create the Protocol Plugin

In the TCP/IP header file **`src/mmt_tcpip/include/mmt_tcpip_protocols.h`** add:

```c
// Add the following line to the end of the protocol numbers definitions
#define PROTO_LEMONDE XXX //XXX is the highest existing protocol number + 1

// Update the value of LAST_IMPLEMENTED_PROTOCOL
#define LAST_IMPLEMENTED_PROTOCOL PROTO_LEMONDE

// Add an alias for Lemonde protocol
#define PROTO_LEMONDE_ALIAS "lemonde"
```

**lemonde** only needs to be registered — it is classified by hostname (section 3) and has no attributes or classifier of its own — so it needs **no source file**: its `MMT_PROTO_SIMPLE` row in `proto_init_list.def` (section 2) registers it (issue #542). A protocol that does need its own code (attributes, a classifier, session context) gets a file **`src/mmt_tcpip/lib/protocols/proto_<name>.c`** defining `int init_proto_<name>_struct()` (see existing `src/mmt_tcpip/lib/protocols/proto_dns.c` for a reference) and an `MMT_PROTO_INIT` row instead.

## 2- Initialize the Protocol

The `init_proto_<name>_struct()` declaration of an `MMT_PROTO_INIT` row is generated in **`src/mmt_tcpip/lib/mmt_common_internal_include.h`** from the same list; do not add it by hand.

If a protocol needs a classification for example protocol rtp, we need to add a function

```c
    
    int mmt_check_rtp_udp(ipacket * ipacket, unsigned index);
   
```

In the protocol-init list **`src/mmt_tcpip/lib/proto_init_list.def`** (included by `configured_protocols.c`, which expands it into the `proto_init_table[]` walked by `init_tcpip_plugin()`) add **lemonde** protocol initialization at the end of the list — order is significant, it decides classifier chain order:

```c
    MMT_PROTO_SIMPLE(PROTO_LEMONDE, PROTO_LEMONDE_ALIAS, "proto_lemonde")
```
A protocol with its own source file uses `MMT_PROTO_INIT(init_proto_<name>_struct, "proto_<name>")` instead.

If a protocol needs a classification for example protocol rtp, we need to add a classification function entry in the inter-protocol list **`src/mmt_tcpip/lib/inter_proto_classif_list.def`** (expanded into `inter_proto_table[]` in the same function):

```c
    
  MMT_INTER_PROTO(PROTO_UDP, mmt_check_rtp_udp, 50)
   
```
A classifier for a service that has been shut down uses `MMT_INTER_PROTO_LEGACY(parent, fn, weight)` instead: it stays in the chain but runs only under the opt-in `legacy` DPI profile ([DPI-Profiles.md](DPI-Profiles.md), issue #540).
Then update function **get_application_class_by_protocol_id** in **`src/mmt_tcpip/lib/mmt_tcpip_classes.c`** to include **lemonde** as a WEB protocol.

## 3- Add Classification for the Protocol

Now comes the last part where the classification rules for **lemonde** needs to be added. As **lemonde** is a WEB protocol, the classification is directly derived from the **hostnames** of **lemonde** website. An investigation needs to be performed in order to gat the list of domain names for a Web application as there could be many. We will consider here that **lemonde** protocol uses just one hostname **lemonde.fr**.

In the hostname-match data unit **`src/mmt_tcpip/lib/mmt_tcpip_classif_doted_host_names.inc`** (included by `mmt_tcpip_classif_utils.c`) add to the end of **`doted_host_names`** structure the following:

```c
    // Add a line for every domain name you have
    {".lemonde.fr", PROTO_LEMONDE, MMT_STATICSTRING_LEN(".lemonde.fr")},
```

Entries are matched **case-insensitively** (issue #105): they are stored
lowercased in the hostname trie and lookups fold the wire hostname, so write
them in lowercase — a mixed-case entry folds onto its lowercase twin.

## 4- Voilà Voilà