---
layout: default
title: "Adding a New Protocol"
---

# Adding a New Protocol

* TOC
{:toc}

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

So each row has one of the two forms the list's header comment documents, `MMT_PROTO_INIT(init_function, "display_name")` or `MMT_PROTO_SIMPLE(PROTO_ID, PROTO_ID_ALIAS, "display_name")`, and starts its own line. Then regenerate the published listing with `bash tools/gen-protocol-list.sh` (it rewrites `docs/PROTOCOLS.md` and reads only rows that start a line, so the header comment's examples are not listed) and update the count on the landing page's `PROTOCOLS.html` chip in `docs/index.html`: `bash tools/ci/check-protocol-count.sh` fails while either lags the list (issue #559).

If a protocol needs a classification for example protocol rtp, we need to add a classification function entry in the inter-protocol list **`src/mmt_tcpip/lib/inter_proto_classif_list.def`** (expanded into `inter_proto_table[]` in the same function):

```c
    
  MMT_INTER_PROTO(PROTO_UDP, mmt_check_rtp_udp, 50, PROTO_RTP)
   
```
The fourth column is the protocol id the checker's source file passes as the last argument of its `mmt_init_classify_bitmasks()` call (the id its excluded bitmask holds), or `PROTO_UNKNOWN` when the checker has no such call. `init_tcpip_plugin()` stores it, with that call's selection mask, in the checker's entry of the frozen chain, and fails when no protocol source recorded the id (issue #560).
The classifier walk then evaluates the checker's guard itself — the selection mask, the detection set and the flow's exclusion of that id — and calls the checker only when it is open, so the checker does not open with that test (issue #561). A checker whose closed guard must have a side effect (excluding itself on the flow, as `mmt_check_tpkt` does) keeps its own guard: its init calls `mmt_checker_keeps_local_guard(PROTO_X)` after `mmt_init_classify_bitmasks()` (as does a unit whose checker must run unguarded, like GTP's). A flow excludes a protocol with `MMT_EXCLUDE_PROTOCOL(flow, PROTO_X)` and tests it with `MMT_FLOW_EXCLUDES(flow, PROTO_X)`; the id needs a row in `src/mmt_tcpip/lib/excluded_protocols.def`, or the macro does not compile. `tests/parser_boundaries/check_inter_proto_excluded.py` checks the guard placement against the sources.
A classifier for a service that has been shut down uses `MMT_INTER_PROTO_LEGACY(parent, fn, weight, excluded_proto)` instead: it stays in the chain but runs only under the opt-in `legacy` DPI profile ([DPI-Profiles.md](DPI-Profiles.md), issue #540).
Then add a row for **lemonde** to the **`application_class_by_protocol_id`** table in **`src/mmt_tcpip/lib/mmt_tcpip_classes.c`** (read by `get_application_class_by_protocol_id()`, issue #547), so it is a WEB protocol:

```c
    [PROTO_LEMONDE] = PROTO_CLASS_WEB,
```

## 3- Add Classification for the Protocol

Now comes the last part where the classification rules for **lemonde** needs to be added. As **lemonde** is a WEB protocol, the classification is directly derived from the **hostnames** of **lemonde** website. An investigation needs to be performed in order to gat the list of domain names for a Web application as there could be many. We will consider here that **lemonde** protocol uses just one hostname **lemonde.fr**.

The hostname table is data, not code (issue #566): its source is the versioned
data file **`data/hostnames.txt`**, one `<suffix> <PROTO_ID>` entry per line
under a `# version: YYYY-MM-DD` header. Add a line for every domain name you have:

```
.lemonde.fr PROTO_LEMONDE
```

set the `version:` line to the date of the change, and regenerate the C table
**`src/mmt_tcpip/lib/mmt_tcpip_classif_doted_host_names.inc`** (included by
`mmt_tcpip_classif_utils.c`) — never edit the `.inc` by hand:

```bash
python3 tools/gen-hostname-table.py           # rewrite the .inc from the data file
python3 tools/gen-hostname-table.py --check   # exit 1 when the .inc is stale
```

The generator computes each entry's length and refuses a missing or malformed
version line, a duplicate suffix, a `PROTO_*` name the protocol header does not
define, and an uppercase or dotless suffix; the `core_engine` suite runs
`--check`, so a stale `.inc` fails the tests. A suffix also matches the bare
domain (`.lemonde.fr` matches `lemonde.fr`), and the longest listed suffix of a
hostname wins, so entry order carries no meaning. A relabel changes
classification: rerun both phase0 gates (`tools/phase0/README.md`).

Entries are matched **case-insensitively** (issue #105): they are stored
lowercased in the hostname trie and lookups fold the wire hostname, so write
them in lowercase — the generator rejects an uppercase suffix.

## 4- Voilà Voilà

## Classes in a plugin of your own

A plugin outside `mmt_tcpip` gives its protocols an application or content class by calling `mmt_register_class_provider()` from its `init_proto()` (`mmt_class_provider.h`), filling in only the callbacks it needs. Consumers read the classes with `mmt_application_class()` and its siblings, or the `get_*_class_*` names of `mmt_tcpip.h`, and link `libmmt_core` alone. The core forgets every provider in `close_extraction()`, before it unloads the plugins.

## Logging and branch hints in a plugin of your own

Since 1.10.0 (issue #537) the installed headers no longer define `debug()`, `log_err()`, `log_warn()`, `log_info()`, `check()`, `likely()` or `unlikely()`: those names collided with consumers' own macros, so they stay private to the SDK sources (`src/mmt_core/private_include/dbg.h`). An out-of-tree plugin uses these instead (issue #66):

| Removed macro | Replacement | Header |
|---------------|-------------|--------|
| `log_err(fmt, ...)` | `mmt_log_error(fmt, ...)` | `mmt_log.h` (opt-in) |
| `log_warn(fmt, ...)` | `mmt_log_warn(fmt, ...)` | `mmt_log.h` (opt-in) |
| `log_info(fmt, ...)` | `mmt_log_info(fmt, ...)` | `mmt_log.h` (opt-in) |
| `debug(fmt, ...)` | `mmt_log_debug(fmt, ...)` | `mmt_log.h` (opt-in) |
| `likely(x)` / `unlikely(x)` | `MMT_LIKELY(x)` / `MMT_UNLIKELY(x)` | `mmt_utils.h` (through `mmt_core.h`) |

`mmt_log.h` is installed with the other headers but no installed header includes it, so a consumer that does not include it gets none of its names, and every name it defines starts with `mmt_log` or `MMT_LOG` (`src/mmt_core/public_include/mmt_log.h:130-150`). `MMT_LIKELY()`/`MMT_UNLIKELY()` wrap `__builtin_expect()` and evaluate to `!!(x)` (`src/mmt_core/public_include/mmt_utils.h:32-39`).

The logger behaves differently from the old macros, which wrote to stderr whenever they were reached — `debug()` unless the plugin was built with `-DNDEBUG`:

- it is off by default: lines are written only when `MMT_DPI_LOG_LEVEL=error|warn|info|debug` (or `mmt_log_set_level()`) raises the threshold, and each call site writes at most 10 lines per second;
- `mmt_log_debug()` compiles to nothing unless the plugin itself is compiled with `-DDEBUG`, and its arguments are then not evaluated: a helper called only from it is unused in a release build (`-Wunused-function`);
- each line reads `[mmt-dpi][E|W|I|D] <file>:<line>: <message>`, and a trailing newline in the format is dropped;
- the `errno: <strerror>` suffix of `log_err()`/`log_warn()` is gone: pass `strerror(errno)` in the message where it matters.

`check()`, `check_mem()`, `check_debug()`, `sentinel()` and `clean_errno()` have no replacement: write the test yourself, e.g. `if (p == NULL) { mmt_log_error("out of memory"); goto error; }`.

Plugin code that keeps the old names maps them in the plugin itself, never in a header other code includes:

```c
#include "mmt_log.h"

#define debug(...)   mmt_log_debug(__VA_ARGS__)
#define log_err(...) mmt_log_error(__VA_ARGS__)
```

Build it, put the `.so` in the plugin directory (`$(MMT_BASE)/plugins`, or the absolute directory named by `MMT_DPI_PLUGINS_DIR`) and raise the threshold to see the lines:

```bash
gcc -Wall -fPIC -shared -DDEBUG -o libmmt_myproto.so -I /opt/mmt/dpi/include myproto_plugin.c
MMT_DPI_LOG_LEVEL=debug ./my_probe
```

The `installed_consumer` suite builds such a plugin against an installed SDK, with and without `-DDEBUG`, and checks the lines it writes (`tests/installed_consumer/test_plugin_log.c`).
