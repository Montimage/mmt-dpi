---
layout: default
title: "MMT-DPI Threading Model"
---

# MMT-DPI Threading Model

This document describes the threading contract for MMT-DPI: what state is
global, what state is per-handler, and the rules a multi-threaded application
must follow to use the library safely.

## Summary of the contract

1. **Initialization before workers.** `init_extraction()` and all protocol /
   plugin (un)registration must complete on a single thread *before* any worker
   thread starts processing packets.
2. **One handler per worker.** Each worker thread owns its own
   `mmt_handler_t` (created with `mmt_init_handler()`). A handler must not be
   shared or used concurrently by more than one thread. Creating and destroying
   handlers (`mmt_init_handler()` / `mmt_close_handler()`) *concurrently* from
   multiple threads is supported — the global handler-bookkeeping map they mutate
   is mutex-guarded (see below), and the shared protocol-descriptor
   analysis/classification status flags that the *first* `mmt_init_handler()`
   enables are accessed atomically (see the note under *Locking*), so even the
   very first handlers may be created concurrently from cold.
3. **No registration once workers are running.** Registering or unregistering
   protocols/plugins while workers are processing packets is discouraged; if a
   defensive caller does so, the mutations are mutex-guarded (see below) but the
   per-handler snapshot taken at `mmt_init_handler()` time will not reflect the
   change.

Following these rules makes the per-packet hot path completely lock-free.

## Global (process-wide) state

Three pieces of state are global and shared across all handlers/threads:

- `plugin_handlers_list` (`src/mmt_core/src/plugins_engine.c`) - linked list of
  loaded plugin handles.
- `configured_protocols[PROTO_MAX_IDENTIFIER]` and
  `configured_protocols_names_map` (`src/mmt_core/src/packet_registry.c`) -
  the table of protocol descriptors and the name->descriptor index.
- `mmt_configured_handlers_map` (`src/mmt_core/src/packet_registry.c`) -
  handler-lifecycle bookkeeping: the set of live `mmt_handler_t` instances, used
  by `iterate_through_mmt_handlers()` and force-closed at teardown. It is *not*
  touched on the per-packet hot path.

These are written only at these moments:

| Phase            | Functions                                                                 |
|------------------|---------------------------------------------------------------------------|
| Init             | `init_extraction()` (allocates `configured_protocols[]` and `mmt_configured_handlers_map`) |
| Plugin load      | `load_plugin()` / `load_plugins()` (append to `plugin_handlers_list`)      |
| (Un)registration | `register_protocol()`, `unregister_protocol_by_id()`, `unregister_protocol_by_name()` |
| Handler create/destroy | `mmt_init_handler()` (insert), `mmt_close_handler()` (delete) — mutate `mmt_configured_handlers_map` |
| Teardown         | `close_extraction()` (internally `close_plugins()`, `free_registered_protocols()`) |

### Locking

Each global has a dedicated `pthread_mutex_t`:

- `plugin_handlers_list_mutex` guards the list mutations in `load_plugin()` and
  `close_plugins()`.
- `configured_protocols_mutex` guards the registry mutations in
  `register_protocol()`, `unregister_protocol_by_id()` and
  `unregister_protocol_by_name()`.
- `configured_handlers_map_mutex` guards the `mmt_configured_handlers_map`
  mutations in `mmt_init_handler()` (insert) and `mmt_close_handler()` (delete),
  making concurrent handler create/destroy race-free.

The locks are never held nested, so there is no lock-ordering hazard:
`load_plugin()` releases the plugin-list lock around `init_proto_fct()`, which is
the call that may take `configured_protocols_mutex` via `register_protocol()`;
`configured_handlers_map_mutex` is held only around the single map insert/delete
call and takes no other lock while held.

The single-threaded teardown iteration in `close_extraction()` walks the map via
`iterate_through_mmt_handlers()` (an unlocked read) and force-closes each handler
through `mmt_close_handler()` (which takes the lock). This is safe only because
teardown runs on a single thread per the init-before-workers contract; taking
the lock in the iterator would self-deadlock against that nested
`mmt_close_handler()` delete. For the same reason, `iterate_through_mmt_handlers()`
(a public symbol) is **not** safe to call concurrently with
`mmt_init_handler()` / `mmt_close_handler()` — it is an unlocked reader of the map.

#### Note: shared protocol-descriptor status flags are atomic, not mutex-guarded

`mmt_init_handler()` also enables analysis and classification on the **shared
global** protocol descriptors — `enable_protocol_analysis()` /
`enable_protocol_classification()` set `protocol->data_analyser.status` /
`protocol->classify_next.status`. Those flags are read **lock-free on the
per-packet hot path** (`proto_packet_analyze()`, `proto_packet_classify_next()`),
so they deliberately cannot be mutex-guarded without defeating the lock-free read
design.

Instead, **every access to these flags is atomic** (issue #69): the hot-path
reads and the `enable_*`/`disable_*` writes go through `proto_status_load()` /
`proto_status_store()` in `src/mmt_core/private_include/packet_processing.h`, which use the compiler
`__atomic_*` builtins with `__ATOMIC_RELAXED` ordering. The flag stays a plain
`int` in the struct (no ABI/layout change); only the accesses are atomic. A
relaxed atomic load of an `int` compiles to a plain load on common targets, so
the hot path stays lock-free and just as cheap. Relaxed ordering is sufficient
because the flag only gates *whether* analysis/classification runs: the function
pointers and analyse/classify lists it guards are populated during
single-threaded `init_extraction()` / registration and are stable before any
worker observes the flag, so no other data is published through it. The writes
are idempotent (always set to `1`) and never reset by `mmt_close_handler()`.

Consequence: issuing the very first handler creation from multiple threads
simultaneously (with no prior single-threaded `mmt_init_handler()`) is now
**race-free** — TSan is clean on this cold concurrent-create path. Before #69
this was a deliberately accepted, currently-benign data race that required a
prior single-threaded `mmt_init_handler()` (e.g. the warmup the `handler-churn`
harness used) to finalize the flags.

These mutexes are taken **only** on the (un)registration/teardown mutation
paths. They are deliberately **not** taken on the per-packet processing hot
path. That is safe because:

- `init_extraction()` allocates the descriptor table once, before workers start.
- `mmt_init_handler()` copies (snapshots) the descriptor pointers from the
  global `configured_protocols[]` into the handler's own
  `mmt_handler->configured_protocols[]` array.
- Packet processing reads only that per-handler snapshot, never the global
  table.

So under the documented init-before-workers ordering, the global registries are
read-only while workers run, and concurrent calls to `mmt_init_handler()` only
perform concurrent reads of the global table - which is safe.

## Per-handler state (not shared)

The following live inside `mmt_handler_t` and are private to the owning thread,
so they need no locking as long as the "one handler per worker" rule holds:

- `mmt_handler->configured_protocols[]` - the per-handler snapshot of protocol
  descriptors plus that handler's session/protocol contexts.
- `sessions_map` (per protocol instance) - session tables.
- `ip_streams` - IP reassembly/stream state.
- `timeout_milestones_map`, packet counters, current-packet scratch state, etc.

## Checklist for multi-threaded use

1. On the main thread: call `init_extraction()` (which loads plugins and
   registers protocols). Wait for it to finish.
2. Create one `mmt_handler_t` per worker thread with `mmt_init_handler()`.
   Creating them on the main thread before spawning is always safe. Creating
   them inside the workers concurrently is safe too — the handler-bookkeeping map
   insert is guarded by `configured_handlers_map_mutex`, the global protocol
   table is read-only by then, and the shared protocol-descriptor
   analysis/classification status flags are accessed atomically (see the note
   under *Locking*), so even the very first handlers may be created concurrently
   from cold.
3. Each worker feeds packets only to *its own* handler.
4. On shutdown: stop all workers first, free each handler with
   `mmt_close_handler()`, then call the public global teardown
   `close_extraction()` once, on a single thread. It force-closes any handler
   still registered and runs the internal `close_plugins()` /
   `free_registered_protocols()` steps itself
   (`src/mmt_core/src/packet_registry.c:1333-1351`); a handler must not be
   used or closed after it returns. The single-threaded embedding sequence is
   in [USER_GUIDE.md §3](./USER_GUIDE.md#3-minimum-embedding-pattern).

## Verification (ThreadSanitizer harness)

The contract above is mechanically verified by a multi-threaded harness
(`tools/phase0/tests/mt_tsan_harness.c`) built and run under ThreadSanitizer.
Because TSan only detects races in code compiled with `-fsanitize=thread`, the
SDK itself is built with the `BUILD=tsan` profile (see `rules/common.mk`) and the
harness is compiled and linked against that instrumented build — including the
dlopen'd `libmmt_tcpip.so` protocol plugin.

The harness has three modes:

- **`replay`** — follows the documented init-before-workers contract:
  `init_extraction()`, all registration, and one *own* `mmt_handler_t` per worker
  are all created on the main thread; then N worker threads run concurrently,
  each replaying the *same* read-only packet array through its own handler (the
  lock-free per-packet hot path). Each worker builds an order-independent
  classification fingerprint; the harness asserts every worker's fingerprint
  equals a single-thread baseline. Replaying a synthetic multi-flow RADIUS pcap
  exercises the per-session RADIUS parser state (issue #23) concurrently across
  threads.
- **`registry-stress`** — spawns N threads that concurrently drive the global
  registry mutation API (`unregister_protocol_by_id` /
  `unregister_protocol_by_name`), hammering `configured_protocols_mutex` directly
  (issue #22). This is intentionally *not* the normal runtime pattern; it drives
  the lock so TSan can confirm the mutex serialises the registry mutations.
- **`handler-churn`** — spawns N threads that concurrently create and destroy
  their own `mmt_handler_t` in a loop (`mmt_init_handler()` /
  `mmt_close_handler()`), hammering the global handler bookkeeping map
  (`mmt_configured_handlers_map`) guarded by `configured_handlers_map_mutex`
  (issue #67). Without that lock the concurrent `insert_key_value` /
  `delete_key_value` map mutations are a data race that TSan flags; with it the
  run is clean. The workers are the **first** callers of `mmt_init_handler()`
  after `init_extraction()` — there is **no** main-thread warmup handler — so
  this mode also exercises the **cold concurrent-create path** that writes the
  shared protocol-descriptor status flags (issue #69); those flag accesses are
  atomic, so TSan stays clean. `init_extraction()`/`close_extraction()` still
  bracket the run on the main thread, so the map alloc/free stays single-threaded.

Run it locally:

```sh
bash tools/phase0/tests/run_mt_tsan_test.sh
```

The script builds + installs the `BUILD=tsan` SDK into a temporary prefix,
synthesizes the RADIUS pcap, compiles the harness, and runs it under TSan
(`-fno-sanitize-recover=all`, so any detected race aborts). CI runs the same
script in the `harness-run_mt_tsan_test.sh` job of `.github/workflows/phase0-baseline.yml`.
