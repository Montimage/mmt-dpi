---
layout: default
title: "MMT Data Types"
---

# MMT Data Types #
## Definition ##

[TOC]

------------------


MMT Data types are defined in order to provide an harmonized type definitions for [MMT Attributes](./MMT-Attributes.md). 
## API ##
### Supported Data Types ###
The list of supported data types is defined in [types_defs.h](https://github.com/montimage-projects/mmt-dpi/blob/main/src/mmt_core/public_include/types_defs.h).
```c
   MMT_UNDEFINED_TYPE, /**< no type constant value */
```
   Constant that identifies an undefined type.

```c
   MMT_U8_DATA, /**< unsigned 1-byte constant value */
```
   Identifier of unsigned char type. It has a length of 1 octet.

```c
   MMT_U16_DATA, /**< unsigned 2-bytes constant value */
```
   Identifier of unsigned short type. It has a length of 2 octets.

```c
   MMT_U32_DATA, /**< unsigned 4-bytes constant value */
```
   Identifier of unsigned int type. It has a length of 4 octets.

```c
   MMT_U64_DATA, /**< unsigned 8-bytes constant value */
```
   Identifier of unsigned long long type. It has a length of 8 octet.

```c
   MMT_DATA_POINTER, /**< pointer constant value (size is CPU dependant) */
```
   Identifier of pointer type. Its length is CPU dependant.

```c
   MMT_DATA_MAC_ADDR, /**< ethernet mac address constant value */
```
   Identifier of IEEE 802.1 MAC address (ethernet address). It has a length of 6 octets.

```c
   MMT_DATA_IP_ADDR, /**< ip address constant value */
```
   Identifier of IPv4 address. It has a length of 4 octets (in network byte ordering).

```c
   MMT_DATA_IP6_ADDR, /**< ip6 address constant value */
```
   Identifier of IPv6 address. It has a length of 16 octets.

```c
   MMT_DATA_PATH, /**< protocol path constant value */
```
   Identifier of `proto_hierarchy_t` type (defined in [source:mmt/src/mmt_core/public_include/data_defs.h data_defs.h]). It has a length of `sizeof(proto_hierarchy_t)`.

```c
   MMT_DATA_TIMEVAL, /**< number of seconds and microseconds constant value */
```
   Identifier of `struct timeval` timestamp type. It has a length of `sizeof(struct timeval)`.

```c
   MMT_STATS, /**< pointer to MMT Protocol statistics */
```
   Identifier of a pointer to `proto_statistics_t`. Its length is CPU dependent (sizeof (void *)). 

```c
   MMT_BINARY_DATA, /**< binary constant value */
```
   Identifier of binary data. Defined as `mmt_binary_data_t` in `sdk/include/types_defs.h:89` — a `uint32_t len` followed by `uint8_t data[BINARY_64DATA_LEN]` (64 bytes). Total length is `BINARY_64DATA_TYPE_LEN` (68 bytes).

```c
   MMT_BINARY_VAR_DATA, /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */
```
   Identifier of binary data. Defined as `mmt_binary_var_data_t` in `sdk/include/types_defs.h:101` — a `uint32_t len` followed by `uint8_t data[BINARY_1024DATA_LEN]` (1024 bytes). Total length is `BINARY_1024DATA_TYPE_LEN` (1028 bytes).

```c
   MMT_STRING_DATA, /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum BINARY_64DATA_LEN long */
```
   Identifier of a text string (null-terminated). Defined as `mmt_string_data_struct` in `sdk/include/types_defs.h:106` — a `uint32_t len` followed by `char data[BINARY_64DATA_LEN]` (64 bytes max, null-terminated). Total length is `BINARY_64DATA_TYPE_LEN` (68 bytes).

```c
   MMT_STRING_LONG_DATA_POINTER, /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum STRING_DATA_LEN octets long */
```
   Identifier of a long text string (null-terminated). Defined as `MMT_STRING_LONG_DATA` in `sdk/include/types_defs.h:197` — a `uint32_t len` followed by `char data[STRING_DATA_LEN]` (1504 bytes max). Total length is `STRING_DATA_TYPE_LEN` (1508 bytes).

```c
   MMT_STRING_DATA_POINTER, /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */
```
   Identifier of a string data pointer. The data pointed to is of type string with null terminating character included. Its length is CPU dependent. 


```c
   MMT_HEADER_LINE, /**< string pointer value with variable size. The data pointed to is of type string however,  not necessary null terminating */
```
   Identifier of a header line pointer. The data pointed to is of type string, not necessarily null-terminated. Max accepted header line length is 8k (default for Apache). 



### User API ###
```c
   uint32_t get_data_size_by_data_type(uint32_t data_type);
```
   Returns the size in bytes of the given data type. Zero is returned if the type is not known or invalid.

## Open Issues ##
 * Extend the list of data types 
 * Review the names of data types as Binary_var_XXX