# MMT-Extract
*Version: 2.0*

**User guide - July 07 2015**

[TOC]

-----------------------------
# 1. Introduction
MMT-Extract is a software C library designed to extract data attributes from network packets, server logs, and in general, from any structured data, in order to make them available for analysis. For this purpose, Deep Packet Inspection (DPI) techniques are used. In the rest of the document the terms: *packet*, *message* and *event* are used interchangeably. 

The remainder of this document is organized as follows:

* **Section 2**: the User Guide that describes how to install and use the MMT-Extract C Library in your code.

* **Section 3**: the Developer Guide that describes how to add or edit the extraction for a new protocols using the plugin architecture.

# 2. User guide

Before installing MMT-Extract, you need to install some libraries/applications: `pcap, make`

## 2.1 Installing MMT-Extract

### 2.1.1 For Linux user

#### 2.1.1.1 Install from .zip file

** Download **
For debian 32 bits:

[mmt_sdk_0.1-0_x32_all.zip](http://www.montimage.eu/download/mmt_sdk_0.1-0_x32_all.zip)

For debian 64 bits:

[mmt_sdk_0.1-0_x64_all.zip](http://www.montimage.eu/download/mmt_sdk_0.1-0_x64_all.zip)

** Install **
Install some required packages:

```bash
sudo apt-get install libxml2-dev make
```

You only need to download and decompress the MMT-Extract package which is suitable for your system. The package includes the following content:

* **lib/**: encloses the extraction libraries

* **include/**: contains the required header files specifying the library API

* **examples/**: include some examples to test the use of mmt-extract. **Note that** we use `libpcap` as a tool to capture the packets, so to compile the example you need to install `libpcap`

* **Makefile**: makefile for the installation

To install MMT-Extract:

```bash
sudo make install
```

To uninstall MMT-Extract:

```bash
sudo make uninstall
```

#### 2.1.1.2 Install from .deb file

** Download .deb file **

For debian 32 bits:

[mmt_sdk_0.1-0_x32_all.deb](http://www.montimage.eu/download/mmt_sdk_0.1-0_x32_all.deb)

For debian 64 bits:

[mmt_sdk_0.1-0_x64_all.deb](http://www.montimage.eu/download/mmt_sdk_0.1-0_x64_all.deb)

** Install **

Run this command to install

```sh
sudo dpkg -i ./mmt_sdk_x.x-x_xx_xx.deb

```

> **Note:** Only Linux is currently supported. macOS and Windows are not supported.

## 2.2 Using MMT-Extract in your project

In order to use the MMT-Extract library in your developments you must perform the following actions:

* Include the header file `mmt/mmt_core.h`: This file is the only one you need to include. 

* By default, plugins are located in `/opt/mmt/plugins/`. Also you can create a folder called `plugins` in the directory where the executable is located. If you have any MMT-Extraction plugins, you MUST copy them into this `plugins` folder or in `/opt/mmt/plugins/`. Note that the `plugins` folder in the directory where the executable is located has higher priority than the folder at `/opt/mmt/plugins/`

## 2.3 Extraction API description

The MMT-Extract API is specified in the header files provided with the download package. In the following we will shortly describe the content of the different header files (for further details, please refer to the *documentation*):

* `mmt_core.h`: this is where the core extraction API functions are defined. 

* `data_defs.h`: this is where the data related API functions are defined. In addition, the different data structures that might be used in an integration project are defined here.

* `types_defs.h`: this is where the new data types are defined. 

* `extraction_lib.h`: this file contains the generic extraction functions.

* `plugin_defs.h`: this file contains the definitions that can be used for the plugin development (see Section 3).

### 2.3.1 Initialization
In order to use the MMT-Extract library, you MUST initialize it; this is done using the following command:
```c
    int init_extraction();
```

The initialization returns a positive value on success. It is good practice to always check the return value of “init_extract”.

```c
   int close_extraction();
```

This function will close the extraction and free any previously allocated memory. 

### 2.3.2 Message processing
MMT-Extract can process network packets in the de-facto pcap format, raw messages, log messages, etc. 

The following function handles a message/packet to the core engine of MMT-Extract:
```c
int packet_process(mmt_handler_t *handler, struct pkthdr *header, u_char * packet); 
```

This function should be called for every packet/message/event to process. The header parameter of the function is a pointer to the meta-data of the message that include the message arrival time, the message length, etc. The packet parameter of the function is a pointer to the message data. The `packet_process` function will return a positive value on successful processing. A negative value is returned if an internal error is encountered, although this should not happen.
```c
void setDataLinkType(int dltype);
```
This function sets the link type to indicate the nature of the lower layer protocol. By default, the library is configured to process network packets in the *pcap* format with Ethernet as the link layer.

### 2.3.3 Registering extraction attributes
The MMT-Extract library allows registering attributes for extraction. Attributes are fields in network packets, specific data in event logs, etc. 
```c
void register_extraction_attribute(mmt_handler, protocol_id, attribute_id);
void register_extraction_attribute_by_name(mmt_handler, proto_name, attribute_name);
```
Either one of these two functions allows registering an attribute for extraction. An attribute is identified by the protocol and attribute id or names. If the registration succeeds, a positive value will be returned.
```c
int is_registered_attribute(mmt_handler, protocol_id, attribute_id);
```
Allows verifying if an attribute, identified by its protocol and attribute identifiers, is already registered. It will return a positive value if the attribute is found registered.
```c
int unregister_extraction_attribute(mmt_handler, protocol_id, attribute_id);
int unregister_extraction_attribute_by_name(mmt_handler, proto_name, attribute_name);
```
Either one of these two functions allow unregistering an already registered attribute. If the un-registration succeeds, a positive value will be returned.
```c
void * get_attribute_extracted_data(ipacket, protocol_id, attribute_id);
void * get_attribute_extracted_data_by_name(ipacket, protocol_name, attribute_name)
```
Either one of these functions will return a pointer to the data corresponding to the provided attribute if it was detected in the last provided event, or NULL otherwise. 

### 2.3.4 Registering callback handlers

The MMT-Extract library allows registering callback handler functions to be called (1) following the extraction of specific attribute, or (2) after the processing of a packet/message/event log/etc. 

#### 2.3.4.1 Packet handlers
```c
int register_packet_handler(mmt_handler_t *mmt_handler, 
                            int packet_handler_id,
                            generic_packet_handler_callback function,
                            u_char * args);
```
This function allows registering a packet handler that is a callback and will be called each time a packet is received. If needed, the user can provide a pointer to an argument that will be passed to the callback function when it is called. The callback function is associated with an identifier that should be unique, i.e., two callback functions cannot have the same identifier. This function will return a positive value upon success.

To verify whether a callback function is registered with a given identifier, you can use the following function:
```c
int is_registered_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id);
```
This function returns a positive value if a registered callback function is found for the provided identifier.

In order to unregister an already registered packet handler you can use:
```c
int unregister_packet_handler(mmt_handler_t *mmt_handler, int packet_handler_id);
```

#### 2.3.4.2 Attribute handlers
```c
int register_attribute_handler( mmt_handler_t * mmt_handler,
                                int protocol_id, 
                                int attribute_id,
                                attribute_handler_function handler_fct, 
                                void * handler_condition, 
                                void * user_args); 

int register_attribute_handler_by_name( mmt_handler_t * mmt_handler,
                                        char * protocol_name, 
                                        char * attribute_name,
                                        attribute_handler_function handler_fct, 
                                        void * handler_condition, 
                                        void * user_args);
```
This function allows registering an attribute handler that is a callback and will be called each time the attribute is identified in the packet under processing. If needed, the user can provide a pointer to an argument that will be passed to the callback function when it is called. The attribute is identified by its protocol and attribute ids or names. The “handler_condition” is not used in this version of the library, and therefore it should be set to NULL. This function will return a positive value upon success.

To verify whether an attribute has a registered attribute handler, you can use the following function:
```c
int has_registered_attribute_handler(int protocol_id, int attribute_id);
```
This function returns a positive value if the attribute identified by its protocol and attribute ids has a registered attribute handler.

In order to unregister an already registered attribute handler you can use:
```c
int unregister_attribute_handler(mmt_handler_t *mmt_handler, 
                                 int protocol_id, 
                                 int attribute_id);

int unregister_attribute_handler_by_name(mmt_handler_t * mmt_handler,
                                         char * protocol_name, 
                                         char * attribute_name);
```

### 2.3.5 Data function

In addition to the core functions presented so far, MMT-Extract provides a number of utility functions to assist the user of the library. 
```c
const char * get_protocol_name_by_id(long protocol_id);
```
Returns the protocol name, given its identifier; NULL is returned if the given identifier does not correspond to any configured protocol. 
```c
long get_protocol_id_by_name(const char *protocol_name);
```
Returns the identifier of the protocol, given its name; “0” is returned if the given name does not correspond to any configured protocol. 
```c
int is_protocol_attribute(int protocol_id, int attribute_id);
```
Indicates if the attribute exists for the given protocol and attribute ids.
```c
const char * get_attribute_name_by_protocol_and_attribute_ids(long protocol_id,
                                        long attribute_id);
```
Returns the name of the attribute corresponding to the given protocol and attribute identifiers; NULL is returned if there is no attribute corresponding to the given identifiers. 
```c
long get_attribute_id_by_protocol_and_attribute_names(  const char *protocol_name,
                                                        const char* attribute_name);
```
Returns the identifier of the attribute corresponding to the given protocol and attribute names; “0” is returned if there is no attribute corresponding to the given names. 
```c
long get_attribute_id_by_protocol_id_and_attribute_name(long protocol_id, 
                                                        const char *attribute_name);
```
Returns the identifier of the attribute corresponding to the given protocol id and attribute name; “0”is returned if there is no attribute corresponding to the given parameters. 
```c
long get_attribute_data_type(long protocol_id, long attribute_id);
```
Returns the identifier of the data type of the attribute corresponding to the given protocol and attribute identifiers; “0”is returned if there is no attribute corresponding to the given parameters. 
```c
int get_data_size_by_proto_and_field_ids(int protocol_id, int attribute_id);
```
Returns the data size of the attribute corresponding to the given protocol and attribute identifiers; “0”is returned if there is no attribute corresponding to the given parameters. 
```c
int get_data_size_by_data_type(int data_type);
```
Returns the data size of the given data type; “0”is returned if the data type is unknown.
```c
int get_field_position_by_protocol_and_field_ids(int protocol_id,
                                                 int attribute_id);
```
Returns the position in the message of the attribute corresponding to the given protocol and attribute identifiers; for attributes where the position depends on the content of the message, `POSITION_NOT_KNOWN` (value -1) will be returned. 
The position is defined as the byte offset from the beginning of the packet.
```c
void iterate_through_protocol_attributes(int protocol_id,
                                         generic_protocol_attribute_iteration_callback iterator_fct, 
                                         void * args);
```
Iterates through the given protocol's attributes. The given `iterator_fct` will be called for every attribute. This function is useful when the user needs to discover the attributes of a given protocol. 
## 2.4 Extraction example
```c
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "mmt_core.h"

void packet_handler(const ipacket_t * ipacket, u_char * user_args) {
  static int count = 0;
  printf("Processed packet number %i\n", count++);
}

void attr_handler(const ipacket_t * ipacket, 
            attribute_t * attribute, void * user_args) {
    unsigned short eth_proto = *((unsigned short *) attribute->data);
    printf("Ethernet protocol number = %ih\n", eth_proto);
}

int main(int argc, char** argv) {
  pcap_t *pcap;
  const unsigned char *data;
  struct pcap_pkthdr p_pkthdr;
  struct pkthdr header;
  char errbuf[1024];

  init_extraction(); //This will initialize the extraction library

  //Initialize MMT handler
  mmt_handler = mmt_init_handler(DLT_EN10MB,0,mmt_errbuf);
  if(!mmt_handler){
     fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
     return EXIT_FAILURE;
  }

  //We will register a number of attributes to extract
  register_extraction_attribute_by_name(mmt_handler, "META", "UTIME");
  register_extraction_attribute_by_name(mmt_handler, "ARP", "ARP_OPCODE");
  register_extraction_attribute_by_name(mmt_handler, "IP", "IP_PROTO_ID");
  register_extraction_attribute_by_name(mmt_handler, "ETHERNET", "ETH_PROTOCOL");
  register_extraction_attribute_by_name(mmt_handler, "UDP", "UDP_SRC_PORT");

  //We register a packet handler
  register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler, NULL);
  register_packet_handler(mmt_handler, 2, packet_handler, NULL);

  //We register an attribute handler
  register_attribute_handler_by_name(mmt_handler, "ETHERNET", "ETH_PROTOCOL", 
                            attr_handler , NULL, NULL);

  pcap = pcap_open_offline(argv[1], errbuf); // open offline trace
  if (!pcap) { /* pcap error ? */
        fprintf(stderr, "Error 105: pcap_open failed for the following reason: %s\n", errbuf);
        return;
  }

  while ((data = pcap_next(pcap, &p_pkthdr))) {
    header.ts = p_pkthdr.ts;
    header.caplen = p_pkthdr.caplen;
    header.len = p_pkthdr.len;
    //Send the packet to the MMT-Core for processing
    if (!packet_process(mmt_handler, &header, data)) { 
      fprintf(stderr, "Error: Packet data extraction failure.\n");
    }
  }

  //Close the MMT handler
  mmt_close_handler(mmt_handler);

  close_extraction(); //Close the extraction before exiting
  return (EXIT_SUCCESS);
}
```

# 3. Developer guide

The MMT-Extraction library has a plugin architecture. It is possible to extend the extraction engine with new protocols. For this, a plugin needs to be created specifying the extraction to add. An MMT-Extraction plugin will initialize a protocol structure that contains the required information regarding the protocol attributes, as well as the functions allowing extracting the data corresponding to these attributes. In this section we will describe the required steps in order to create a new MMT-Extraction plugin.

## 3.1 The MMT-Extract plugin API

When creating a new MMT-Extraction plugin, you MUST use the API functions described in the following sub-sections.

### 3.1.1 Initializing a protocol structure

Creating a new plugin requires the initialization of a protocol structure. A protocol is defined by a unique identifier. The first step in the process of creating a plugin is to get a protocol structure using the following function:
```c
protocol_t * init_protocol_struct_for_registration(int protocol_id, 
                                                   char * protocol_name);
```
This function will return a pointer to a free protocol structure with the given identifier. If a protocol with the same identifier is already registered, this function will return **NULL**.

### 3.1.2 Registering protocol attributes

Once the protocol structure is initialized, you need to add the attributes belonging to the protocol. An attribute has an identifier, a name, a data type, a data length, a position within the packet (offset), a scope (packet or session) and an extraction function (can be generic if the position and data length are known). 
```c
int register_attribute_with_protocol(protocol_t * protocol_struct,
                                     attribute_metadata_t attr);
```
This function registers the attribute `attr` with the protocol `protocol_struct`.

### 3.1.3 Registering a classification function (optional)

Once the protocol structure is initialized, you need to add a classification function. A classification function identifies the type of protocol/message encapsulated in the current protocol/message. For example, the classification function of “IP” protocol will tell if the encapsulated protocol is “TCP”, “UDP”, “ICMP”, etc. The classification function is protocol specific and needs to be implemented by the user. 
```c
void register_classification_function(protocol_t * protocol_struct,
                                      generic_classification_function classification_fct);
```
This function registers a classification function `classification_fct` for the protocol identified by the `protocol_struct` parameter. The signature of the classification function is defined by the function type `generic_classification_function` defined in `mmt_core.h`

### 3.1.4 Registering and initialized protocol structure

The final step when creating a plugin is to register the created protocol structure in the MMT-Extraction core. For this purpose, you must use the following function:
```c
int register_protocol(protocol_t * protocol_struct, int protocol_id);
```
This function registers the protocol defined by the given protocol structure and protocol identifier in the extraction core. Remember that a protocol has a unique identifier, and registering a protocol structure with an already used identifier will cause the function to fail. On success, this function will return `PROTO_REGISTERED` (value 1).  `PROTO_NOT_REGISTERED` (value 0) will be returned on failure.

### 3.1.5 Utility function

The MMT-Extraction plugin API has a number of utility functions that can be very useful when creating a new plugin. 
```c
int is_valid_protocol_id(int protocol_id);
```
This function verifies if a given identifier is valid. A protocol identifier MUST have a positive value less than the PROTO_MAX_IDENTIFIER. A positive value is returned if the given identifier is valid, a negative value otherwise.
```c
int is_registered_protocol(int protocol_id);
```
This function verifies if a protocol with the given identifier is already registered. “PROTO_REGISTERED” (value 1) is returned if a protocol is already registered, “PROTO_NOT_REGISTERED” (value 0) is returned otherwise.
```c
int is_free_protocol_id_for_registraction(int protocol_id);
```
This function returns a positive value if there is no protocol registered with the given identifier. A negative value is returned otherwise.

### 3.1.6 Generic extraction functions

A number of generic extraction functions are implemented in the MMT-Extraction core and can be reused by the plugins. They include:
```c
int general_byte_to_byte_extraction(const ipacket_t * packet, 
                                    int proto_index,
                                    attribute_t * extracted_data);
```
This is a generic extraction function. It will copy, into the data part of extracted_data structure a defined number of bytes from the data part of the packet structure. Any extraction function MUST have the same signature and MUST return a positive value if the extraction is successful.
```c
int general_short_extraction_with_ordering_change(const ipacket_t * packet, 
                                                  int proto_index,
                                                  attribute_t * extracted_data);

int general_int_extraction_with_ordering_change(const ipacket_t * packet, 
                                                int proto_index,
                                                attribute_t * extracted_data);

int general_short_extraction(const ipacket_t * packet, 
                             int proto_index,
                             attribute_t * extracted_data);

int general_int_extraction(const ipacket_t * packet, 
                           int proto_index,
                           attribute_t * extracted_data);
```
These 4 functions provide the extraction of `short` (2 bytes) and `int` (4 bytes) data with or without ordering change. 

### 3.1.7 Utility structures

In addition to the utility functions, the MMT-Extraction plugin API has a number of structures that can help organizing plugin-related data. 
```c
typedef struct attribute_metadata_struct {
  int id; /**< identifier of the attribute. */
  char alias[Max_Alias_Len + 1]; /**< the alias(name) of the attribute */
  int data_type; /**< the data type of the attribute */
  int data_len; /**< the data length of the attribute */
  int position_in_packet; /**< the position in the packet of the attribute. */
  int scope; /**< the scope of the attribute (packet, session, ...). */
  generic_attribute_extraction_function extraction_function; /**< the extraction function for this attribute. */
} attribute_metadata_t;
```
This structure defines the attribute-related information; it can be used to model the information of the protocol attributes. 

This can be seen in the following code for the UDP protocol, that models UDP’s attributes related information.  
```c
static attribute_metadata_t udp_attributes_metadata[UDP_ATTRIBUTES_NB] = {
  {UDP_SRC_PORT, UDP_SRC_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 0,
            SCOPE_PACKET, general_short_extraction_with_ordering_change},
  {UDP_DEST_PORT, UDP_DEST_PORT_ALIAS, MMT_U16_DATA, sizeof (short), 2, 
            SCOPE_PACKET, general_short_extraction_with_ordering_change},
  {UDP_LEN, UDP_LEN_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, 
            general_short_extraction_with_ordering_change},
  {UDP_CHECKSUM, UDP_CHECKSUM_ALIAS, MMT_U16_DATA, sizeof (short), 6,
            SCOPE_PACKET, general_short_extraction_with_ordering_change},
};
```

## 3.2 Creating an MMT-Extract plugin

A MMT-Extract plugin, as described above, will initialize and register a protocol structure. This initialization/registration MUST be performed by using a function called “init_proto”. When the Extraction core tries to load a plugin, it will search for and execute the function with this name. If the plugin does not implement such a function, it is considered invalid. Therefore, the creation of a new plugin is equivalent to the implementation of this function “init_proto”. 
The following steps describe the creation of a plugin:

**Pre step**

Create a new function `init_proto`
```c
int init_proto();
```
This function MUST implement the next steps. It is highly recommended that you use the utility function when creating a plugin. 

**First step**

Request a protocol structure with a defined protocol identifier for initialization using: 
```c
protocol_t * init_protocol_struct_for_registration(int protocol_id, 
                                                   char * protocol_name);
```

**Second step**

Define the protocol attributes and create an array of the attributes (see section 3.1.7). Register the defined attributes with the protocol structure initialized in step 1. 

This is where the protocol specific code will be created. 

**Third step**

Once the protocol structure is initialized, you can add a classification function. A classification function identifies the type of protocol/message encapsulated in the current protocol/message. For example, the classification function of “IP” protocol will tell if the encapsulated protocol is “TCP”, “UDP”, “ICMP”, etc. The classification function is protocol specific and needs to be implemented by the user. To register a classification function use:
```c
void register_classification_function(protocol_t * protocol_struct,
                                      generic_classification_function classification_fct);
```
If the protocol does not require a classification function, this step can be omitted, or NULL can be registered. For example, ARP protocol does not encapsulate any other protocol, and therefore it does not require a classification function.

**Forth step**

The final step, when creating a plugin, is to register the created protocol structure in the MMT-Extraction core. For this purpose, you must use:
```c
int register_protocol(protocol_t * protocol_struct, int protocol_id);
```
This function will register the protocol structure if no other protocol is already registered with the given protocol identifier. 

If the protocol registration is successful, the plugin function `init_proto` MUST return a positive value indicating that the plugin has been successfully loaded; otherwise a negative value MUST be returned to let the core perform the necessary cleanup.