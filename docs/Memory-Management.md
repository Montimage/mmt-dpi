---
layout: default
title: "Memory Management"
---

# Memory Management #

* TOC
{:toc}

------------------


This is an overview of the memory management features implemented in `src/mmt_core/src/memory.c`.

## Scope ##

* Monitor global memory usage for `mmt_core` and `mmt_tcpip`,
* Provide some statistics on memory allocation,
* Provide a general-purpose listener/observer mechanism so that specific action can be taken on user-defined conditions
  (e.g.: threshold on memory usage, etc..)

## Implementation ##

`mmt_malloc()`/`mmt_realloc()`/`mmt_free()` are thin libc pass-throughs — requests reach the heap at their natural size class (the per-block `size_t` prefix was dropped in issue #255, and the `mmt_meminfo()` counters went with it).

![MMT Memory Management](images/mmt_malloc.png)

## Basic Usage ##

Just use `mmt_malloc()`, `mmt_realloc()` and `mmt_free()` instead of `malloc()`, `realloc()` and `free()`, respectively.

The memory allocator does the housekeeping in a (hopefully) transparent way.

**Check every allocation.** `mmt_malloc()` and `mmt_realloc()` return `NULL` when the allocation fails; they do not abort (`src/mmt_core/src/memory.c:8-17`). Test the result before using it.

## Extracted Attribute Values ##

An extraction function that returns a heap object through `attribute_t.data` hands it to the handler with `mmt_packet_scratch_adopt(ipacket, value, release)` (`src/mmt_core/public_include/plugin_defs.h:54`). Nothing else frees an extracted value: before issue #506 the DNS, FTP and NDN extractors leaked one object per read.

* The handler chains the value on a per-packet list. The list records are bump-allocated from an `mmt_arena_t` that the handler creates on first use (`src/mmt_core/src/packet_pipeline.c:1575`).
* When the next `packet_process()` call starts, the handler calls each `release` and rewinds the arena, keeping its first block (`src/mmt_core/src/packet_pipeline.c:1540`, `src/mmt_core/src/packet_pipeline.c:1599`). `mmt_close_handler()` releases the values and frees the arena (`src/mmt_core/src/packet_registry_attr.c:148`).
* The extractor sets `data` and returns 1 only when `mmt_packet_scratch_adopt()` returns `true`. On `false` the value is already released (or was `NULL`), so the extractor reports that nothing was extracted.

Consumers must not free these values, and must copy what they need before the next packet. [MMT Attributes](./MMT-Attributes.md) lists the attributes concerned.

## Failure Management ##

The contract is the standard `malloc()`/`realloc()` one, stated in `src/mmt_core/src/memory.c:8-17`:

* `mmt_malloc()` logs the failure and returns `NULL` (`src/mmt_core/src/memory.c:40-45`).
* `mmt_realloc()` returns `NULL` and leaves the original block untouched, so the caller still owns it and must free it (`src/mmt_core/src/memory.c:73-79`).
* `mmt_arena_alloc()` returns `NULL` on out-of-memory (`src/mmt_core/public_include/mmt_core.h:1284-1285`).

The library runs inside the host process. An allocation that a packet can trigger must not end that process. The library used to call `abort()` when an allocation failed, so a packet that triggered a huge allocation could crash the host: a remote denial of service (B5 in `src/mmt_core/src/memory.c:8-17`). Code that assumes success has the same effect, because the `NULL` it ignored crashes the process later.

When an allocation fails, the caller must:

1. Check the result. Never write through it or pass it on unchecked.
2. Release whatever the function already allocated, so a partial failure leaks nothing. `init_http_parser()` shows the pattern: it frees the parser when a stream processor cannot be allocated (`src/mmt_tcpip/lib/http_parser_integration.h:90-107`).
3. Report the failure upward: return `NULL`, `0` or an error code, or drop the packet or the session attribute that needed the memory. Keep processing the next packet.

The `fault_injection` suite tests this contract. It fails the Nth allocation of the allocator, the hashmap and the HTTP-parser constructor, then checks that the result is `NULL` or that the entry was dropped, that nothing leaked and that nothing was freed twice (`tests/fault_injection/run_tests.sh`).
