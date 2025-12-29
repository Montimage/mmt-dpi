# Attribute Conditions #

[TOC]

------------------

> THIS WORK IS STILL UNDER DEVELOPMENT

## What is it ##

Attribute condition is a logical expression on the value of an attribute.

## What is it not ##

The conditions is not meant to:

* Compare attributes from different packets
* Compare different attributes of the same packet

## Use Case ##

Attribute conditions are mainly designed to work with attribute handlers. The user indicates the condition to be met in order to call its handler.

```
   Example:
   The user wants its attribute handler registered with HTTP.Host be called only when the hostname is "abc.def.com".
```

## Examples ##

```c
   IP.SRC == 192.168.1.1

   IP.SRC in 192.168.1.0/24

   TCP.SRC_PORT >= 80 AND <= 1024

   TCP.SRC_PORT NOT in 100:200

   HTTP.USER_AGENT contains "android"

   HTTP.HOST_NAME contains "pipo"

   HTTP.HOST_NAME == "montimage.com"

   IP.PROTO_ID == 6

   IP.PROTO_ID == TCP

   ETH.SRC == 00:00:00:00:00:00

```

## Operators ##

### Comparison Operators ###

* eq ==
* neq !=
* gt >
* ge >=
* lt <
* le <=

### Bitwise operators ###

* | (Bitwise OR)
* & (Bitwise AND)
* ^ (Bitwise XOR)
* ~ (Complement)
* << (left shift)
* **>>** (right shift)

### Logical operators ###

* AND
* OR
* NOT
* XOR

### Other operators ###

* in
* nin
* contains
* starts (start with)
* ends (ends with)
