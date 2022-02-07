# MMT Global Handler #

[TOC]

------------------

## Definition ##
MMT global handler is a set of internal global variables that maintain the state of MMT and allow it to function. The elements of the global handler are not directly exposed to the user of MMT. 

## Internals ##
MMT global handler is constituted of:

 * The list of registered [protocols](/montimage/mmt-sdk/wiki/MMT Protocol/)
 * The list of registered [protocol stacks](/montimage/mmt-sdk/wiki/Protocol Stack/)
 * Global configuration options (default values for the configuration options)
 * The list of initialised [MMT Handlers](/montimage/mmt-sdk/wiki/MMT Handler/)

## API ##

Get current version of `MMT-DPI`:

```c
char * mmt_version();
```

### User API ###
#### Initialization
```c
   int init_extraction();
```
Initializes MMT global context. This function MUST be called before any use of MMT. It returns a positive value on success and zero on failure. It is good practice to always check the return value of `init_extraction`.

#### Cleanup
```c
   int close_extraction();
```
Closes MMT global context and frees any previously allocated memory. This function should be called when no further use of MMT is needed. 

## Open Issues ##