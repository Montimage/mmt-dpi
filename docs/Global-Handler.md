---
layout: default
title: "MMT Global Handler"
---

# MMT Global Handler #

[TOC]

------------------

## Definition ##
MMT global handler is a set of internal global variables that maintain the state of MMT and allow it to function. The elements of the global handler are not directly exposed to the user of MMT. 

## Internals ##
MMT global handler is constituted of:

 * The list of registered [protocols](./MMT-Protocol.md)
 * The list of registered [protocol stacks](./Protocol-Stack.md)
 * Global configuration options (default values for the configuration options)
 * The list of initialised [MMT Handlers](./MMT-Handler.md)

## API ##

Get current version of `MMT-DPI`:

```c
char * mmt_version();
```

(`sdk/include/mmt_core.h:1045`)

`init_extraction()` / `close_extraction()`: (`sdk/include/mmt_core.h:165,178`)

### User API ###
#### Initialization
```c
   int init_extraction();
```
Initializes MMT global context. This function MUST be called before any use of MMT. It returns a positive value on success and zero on failure (`sdk/include/mmt_core.h:165`).

#### Cleanup
```c
   int close_extraction();
```
Closes MMT global context and frees any previously allocated memory (`sdk/include/mmt_core.h:178`). 

## Open Issues ##