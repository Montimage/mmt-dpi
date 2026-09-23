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

(`src/mmt_core/public_include/mmt_core.h:1228`)

`init_extraction()` / `close_extraction()`: (`src/mmt_core/public_include/mmt_core.h:185,198`)

### User API ###
#### Initialization
```c
   bool init_extraction();
```
Initializes MMT global context. This function MUST be called before any use of MMT, including `mmt_init_handler()`. It returns `true` on success and `false` on failure (`src/mmt_core/public_include/mmt_core.h:185`).

#### Cleanup
```c
   void close_extraction();
```
Closes MMT global context and frees any previously allocated memory (`src/mmt_core/public_include/mmt_core.h:198`). Call it last, after `mmt_close_handler()` on every handler; it force-closes any handler still open, so no handler may be used afterwards. The full lifecycle is in [USER_GUIDE.md §3](./USER_GUIDE.md#3-minimum-embedding-pattern). 

## Open Issues ##