# http_parser → llhttp migration guide

*Plan task 4.5 (spike) — closes `F-DEP-201`; consumed by task 4.6 (issue #222), which
performs the migration. This document is the audit-required guide: it changes no code
and no build input.*

## 1. Current state

MMT-DPI vendors **nodejs/http-parser 2.9.4** at `src/mmt_tcpip/lib/http_parser.c` /
`http_parser.h` (`HTTP_PARSER_VERSION_*` at `http_parser.h:28-30`; bumped from 2.5.0 by
issue #142, hardened by issue #204). Upstream was archived on 2022-06-19 and points at
**llhttp** as its successor — the dependency is terminal and unmaintained.

The entire call surface is three files:

| File | Role |
|------|------|
| `src/mmt_tcpip/lib/http_parser_integration.h` | `stream_parser_t` (one `http_parser` per direction), `stream_processor_t` (per-parser `data` payload), `init_http_parser`/`close_http_parser` inline helpers |
| `src/mmt_tcpip/lib/http_parser_integration.c` | the eight callbacks and the `http_parser_settings` table (`get_settings()`) |
| `src/mmt_tcpip/lib/protocols/proto_http.c` | the only driver: `http_parser_execute()` at `proto_http.c:383`, `parser->upgrade` at `:384`, `HTTP_PARSER_ERRNO`/`http_errno_description` at `:389`, and the reset-on-error `http_parser_init(parser, HTTP_BOTH)` at `:396` |

Out of scope by construction: HTTP/2 is parsed by a bespoke frame parser in
`src/mmt_tcpip/lib/protocols/http2.c`, not by http_parser — the migration does not
touch it.

## 2. Version to adopt

**llhttp v9.4.3** — the current stable of the 9.4.x line (upstream releases: v9.4.1
2026-04-30, v9.4.2 2026-06-18, v9.4.3 latest). llhttp is maintained by the Node.js
project (MIT licence, same as http-parser — vendoring stays licence-compatible).

Vendor the **generated C sources** published on the `release/v9.4.3` tag:

- `include/llhttp.h` — the full public API (types, settings, errno enum, functions)
- `src/llhttp.c` — the llparse-generated state machine
- `src/api.c` + `src/http.c` — the helper layer (`llhttp_*` functions)

These four files are plain C with no third-party includes — drop them in next to
`http_parser.c` and adjust `sdk/Makefile`'s source list for the `libmmt_tcpip` objects.
The TypeScript/Node.js toolchain (`npm install && make` upstream) is a
**generation-time** dependency only; it never enters this build, CI, or release
packaging. Regeneration is for maintainers tracking upstream releases, not for the
build.

## 3. Toolchain floor

Task 4.2 (issue #218, `F-DEP-207`) declared and enforces the floor:

- **GCC ≥ 11, glibc ≥ 2.34, libstdc++6 ≥ 11** — `MMT_GCC_MIN`, `MMT_GLIBC_MIN`,
  `MMT_LIBSTDCXX_MIN` in `rules/common.mk:481-483`, enforced at parse time by
  `rules/arch-linux-gcc.mk`, documented in `docs/AGENT_ENVIRONMENT.md` §1, and
  exercised by the `toolchain-floor` CI job on `ubuntu-22.04` (GCC 11.4).

The generated llhttp sources are freestanding C89/C99 — no C++, no GNU extensions, no
libc calls beyond `stdlib.h`/`string.h`/`stdio.h` — so **the floor is unchanged**:
llhttp v9.4.3 compiles on GCC 11 / glibc 2.34 with room to spare, adds no `NEEDED`
entry to the shipped `.so`, and does not move the `.deb` `Depends:` floors.

## 4. Symbol map

Every `http_parser` symbol this codebase uses, with its llhttp equivalent. Column
*Site* cites the MMT call site. API names are from the upstream llhttp API reference
(`include/llhttp.h` on `release/v9.4.3`, and `src/native/api.h`/`api.c` on `main`).

### 4.1 Symbols used by `http_parser_integration.c` / `.h`

| Site | http_parser symbol | llhttp equivalent | Notes |
|------|--------------------|-------------------|-------|
| `integration.h:24` | `http_parser` (type, `parser[2]`) | `llhttp_t` | typedef of `llhttp__internal_t`; still embeddable by value |
| `integration.c:167` | `http_parser_settings` (type) | `llhttp_settings_t` | same callback field names, plus `*_complete` / `on_reset` additions |
| `integration.c:169-176` | `.on_message_begin`, `.on_header_field`, `.on_header_value`, `.on_url`, `.on_status`, `.on_body`, `.on_headers_complete`, `.on_message_complete` | identical field names on `llhttp_settings_t` | signatures change to `llhttp_cb` (`int (*)(llhttp_t*)`) / `llhttp_data_cb` (`int (*)(llhttp_t*, const char*, size_t)`) — same shapes, parameter type only |
| `integration.c:10-162` | `p->data` in every callback | `parser->data` | unchanged: `void *data` survives on `llhttp_t` |
| `integration.h:90-91` | `http_parser_init(&p->parser[i], HTTP_BOTH)` | `llhttp_init(&parser[i], HTTP_BOTH, get_settings())` | **llhttp_init takes the settings**; `HTTP_BOTH` keeps its name (`llhttp_type_t`). See §5.5 — `llhttp_init` does **not** preserve `data`; assign `parser->data` *after* init |
| `integration.c:141` (commented) | `http_should_keep_alive(parser)` | `llhttp_should_keep_alive(parser)` | direct equivalent, should it ever be enabled |

### 4.2 Symbols used by `proto_http.c`

| Site | http_parser symbol | llhttp equivalent | Notes |
|------|--------------------|-------------------|-------|
| `proto_http.c:383` | `nparsed = http_parser_execute(parser, settings, data, len)` | `err = llhttp_execute(parser, data, len)` | **return-type change**: `size_t` bytes-parsed → `llhttp_errno_t`. `HPE_OK` means all input consumed; on error `llhttp_get_error_pos(parser)` points at the first un-parsed byte, so `nparsed == error_pos - data`. Settings are bound at init, not per call. See §5.4 |
| `proto_http.c:384` | `parser->upgrade` | `llhttp_get_upgrade(parser)` | field → accessor (the `upgrade` field still exists but the API accessor is the stable surface) |
| `proto_http.c:389` | `HTTP_PARSER_ERRNO(parser)` | `llhttp_get_errno(parser)` | macro on `parser->http_errno` → getter on `parser->error` |
| `proto_http.c:389` | `http_errno_description(err)` | `llhttp_get_error_reason(parser)` (prose) or `llhttp_errno_name(err)` (code name) | llhttp stores a per-parser reason string; `HPE_USER` carries a caller-set reason via `llhttp_set_error_reason()` |
| `proto_http.c:396` | `http_parser_init(parser, HTTP_BOTH)` (reset-on-error) | `llhttp_reset(parser)` | **not** `llhttp_init` — `llhttp_reset` preserves type, settings, `data`, and lenient flags, exactly the property `proto_http.c:395` relies on. See §5.5 |

### 4.3 Public http_parser API not used by MMT (mapped for completeness)

| http_parser | llhttp | Used? |
|-------------|--------|-------|
| `http_parser_version()` | `LLHTTP_VERSION_MAJOR/MINOR/PATCH` macros in `llhttp.h` | no |
| `http_parser_settings_init()` | `llhttp_settings_init()` | no (settings are a static designated initializer) |
| `http_parser_pause(p, int)` | `llhttp_pause` / `llhttp_resume` / `llhttp_resume_after_upgrade` | no — see §5.3 |
| `http_body_is_final()` | `llhttp_message_needs_eof()` + `llhttp_finish()` | no |
| `http_method_str()` / `http_status_str()` | `llhttp_method_name()` / `llhttp_status_name()` | no (method comes from the legacy line scanner) |
| `http_parser_parse_url()` + `struct http_parser_url`/`UF_*` | **no equivalent** — llhttp does not split URLs | no (`request_url_cb` is a no-op) — no gap |
| `http_parser_set_max_header_size()` | **no equivalent** — llhttp dropped the max-header-size knob | no — see §5.8 |
| `enum http_errno` / `HPE_*` | `enum llhttp_errno` / `HPE_*` superset (`HPE_USER`, `HPE_PAUSED_UPGRADE` added) | indirectly |
| `HTTP_REQUEST` / `HTTP_RESPONSE` / `HTTP_BOTH` | same names in `llhttp_type_t` | yes (`HTTP_BOTH`) |

## 5. Behavioural differences that matter here

### 5.1 Strict-mode semantics — the F-BUG-060 interaction

http-parser's strictness is a **compile-time** flag: `#if HTTP_PARSER_STRICT` guards
`STRICT_CHECK` throughout `http_parser.c` (e.g. `http_parser.c:463-472`), raising
`HPE_STRICT` on malformed tokens. F-BUG-060 found it gated on `SHOWLOG`, so every
release build parsed leniently; issue #204 (task 2.6) gave it its own flag defaulting
on — `rules/common.mk:173-183` sets `HTTP_PARSER_STRICT := 1` unless explicitly
overridden.

**llhttp is strict by default, unconditionally compiled in.** There is no compile-time
leniency switch; leniency is a **per-parser, runtime** opt-in through the
`llhttp_set_lenient_*` family (`llhttp.h` + upstream README API section):

`lenient_headers`, `lenient_chunked_length`, `lenient_keep_alive`,
`lenient_transfer_encoding`, `lenient_version`, `lenient_data_after_close`,
`lenient_optional_lf_after_cr`, `lenient_optional_cr_before_lf`,
`lenient_optional_crlf_after_chunk`, `lenient_spaces_after_chunk_size`,
`lenient_header_value_relaxed` — each `llhttp_set_lenient_*(parser, 1)` and each
documented upstream as a request-smuggling / cache-poisoning exposure when enabled.

Consequence for the migration: **task 4.6's "strict parsing remains on by default per
task 2.6's flag" is satisfied by doing nothing** — defaults are already strict, and
the F-BUG-060 failure mode (strictness silently dropping out of a build flavour)
cannot recur because no build flag controls it. If an operator-facing leniency escape
hatch is wanted, it maps to runtime setters after `llhttp_init`, not to a
`-DHTTP_PARSER_STRICT` analogue; that decision belongs to #222.

Note the granularity shift: `HTTP_PARSER_STRICT` was all-or-nothing over a fixed
check set; llhttp's flags let a caller relax exactly one rule (e.g. bare-LF headers
from legacy embedded devices) while keeping the smuggling checks on.

### 5.2 Callback return conventions

http-parser: every callback returns `int`; any non-zero aborts parsing and maps to a
callback-specific `HPE_CB_*` errno. `on_headers_complete` additionally accepts `1`
(message has no body — skip to complete) and `2` (no body, and do not treat the
connection as upgraded).

llhttp splits this by callback class (upstream README, `llhttp_settings_t` comments):

- **Notification callbacks** (`on_message_begin`, `on_message_complete`,
  `on_*_complete`, `on_chunk_header`, `on_chunk_complete`, `on_reset`):
  `0` proceed · `-1` error · `HPE_PAUSED` pause.
- **Data callbacks** (`on_url`, `on_status`, `on_method`, `on_protocol`,
  `on_version`, `on_header_field`, `on_header_value`, `on_body`,
  `on_chunk_extension_*`): `0` proceed · `-1` error (translated to `HPE_USER` by
  `api.c`'s `SPAN_CALLBACK_MAYBE`) · `HPE_USER` for a user-defined abort, with
  `llhttp_set_error_reason()` setting the message.
- **`on_headers_complete`**: `0` normal · `1` no body, proceed to next message ·
  `2` no body **and** `llhttp_execute` returns `HPE_PAUSED_UPGRADE` · `-1` error ·
  `HPE_PAUSED` pause.

All eight MMT callbacks return `0` unconditionally, so the conventions port
mechanically — the only renames are the parameter types (`http_parser*` →
`llhttp_t*`). The one subtlety: http-parser turned *any* non-zero into `HPE_CB_*`;
llhttp reads `-1` specifically, so a stray `return 1` from a data callback would mean
something different. Keep the `return 0` discipline.

### 5.3 Pause / resume handling

http-parser offered `http_parser_pause(parser, is_error)` plus the `HPE_PAUSED`
errno — a flag the caller set *between* `execute` calls.

llhttp makes pause a first-class state:

- A callback pauses by **returning `HPE_PAUSED`** — upstream is explicit that
  `llhttp_pause()` must *not* be called from inside a callback (`api.h`/`api.c`;
  it exists only so a caller can pre-arm a pause before the next `execute`).
- `llhttp_execute` returns `HPE_PAUSED`; the caller later calls `llhttp_resume()`
  and re-invokes `llhttp_execute` with the input advanced to
  `llhttp_get_error_pos()` — the byte at which parsing stopped.
- The Upgrade/CONNECT flow returns `HPE_PAUSED_UPGRADE` after the message is fully
  parsed; resuming past it requires `llhttp_resume_after_upgrade()`, not
  `llhttp_resume()`.

MMT currently never pauses, but the mapping matters for the `parser->upgrade` check
at `proto_http.c:384`: under llhttp, "this was an upgrade" arrives as the
`HPE_PAUSED_UPGRADE` return code (or `on_headers_complete` returning `2`) plus
`llhttp_get_upgrade(parser)` — not only as a sticky flag after `execute`.

### 5.4 `execute` return contract

`http_parser_execute` returns `size_t nparsed`; `nparsed != len` at `proto_http.c:386`
is MMT's error test. `llhttp_execute` returns `llhttp_errno_t`; `HPE_OK` asserts *all*
input was consumed, and `llhttp_get_error_pos()` yields the stop position for any
byte accounting the caller still wants. The `nparsed != len` test becomes
`err != HPE_OK`.

**Error stickiness:** once `llhttp_execute` returns a non-pause error it returns that
same error on every subsequent call until the parser is re-initialised — so the
reset-on-error path is mandatory, not defensive. http-parser did not make this
guarantee explicit.

### 5.5 Init vs. reset — `data` preservation

`http_parser_init` preserves `parser->data` (MMT relies on this at
`proto_http.c:395-396`, where re-init keeps the `stream_processor_t`).

`llhttp_init` calls `llhttp__internal_init`, which zeroes the struct — **`data` is
lost** — then stores `type` and a *pointer* to `settings`. Two consequences:

- Initialisation order changes: `llhttp_init(...)` first, `parser->data = ...` after
  (or assign `data` inside the same helper, mirroring `init_http_parser` today).
- The reset-on-error site maps to **`llhttp_reset(parser)`**, which is documented and
  implemented to preserve type, settings, `data`, and `lenient_flags`
  (`api.c` `llhttp_reset`) — the exact semantics MMT's comment assumes.

Also note: `settings` is stored **by pointer**, so the `llhttp_settings_t` object must
outlive the parser. MMT's `static` table in `http_parser_integration.c` satisfies this
for free — a stack-local settings object would not.

### 5.6 End-of-stream messages

http-parser's EOF story was `http_parser_execute(p, s, NULL, 0)` plus
`http_body_is_final`. llhttp formalises it: call `llhttp_finish(parser)` at close;
`llhttp_message_needs_eof(parser)` reports whether the in-flight message requires EOF
to terminate (close-delimited bodies). MMT feeds packet payloads and never drives an
EOF signal today — worth adopting only if task 4.6 wants `message_complete` events for
close-delimited responses.

### 5.7 New hooks worth using

llhttp adds `on_reset` (between two messages on the same parser — the natural place to
re-arm `sp->hfield_valid`), `on_url_complete` / `on_header_field_complete` /
`on_header_value_complete` (commit points that replace MMT's per-span accumulation
buffers, if desired), `on_method`, `on_protocol`, `on_version`, and
`on_chunk_extension_*`. None are required; the eight existing callbacks suffice.

### 5.8 Dropped knobs

`http_parser_set_max_header_size()` (80 KiB default cap in 2.9.x) has no llhttp
counterpart — llhttp does not bound cumulative header bytes. MMT never calls it, so
there is no regression to manage; if a header-size bound is ever wanted it must live
in the callbacks (`on_header_field`/`on_header_value` length accumulation).

`http_parser_parse_url` has no counterpart either, and is unused — `request_url_cb`
is a no-op and URL extraction rides the legacy line scanner.

## 6. Suggested call-site mapping (sketch for task 4.6)

```c
/* init (init_http_parser, integration.h) */
llhttp_init(&parser->parser[i], HTTP_BOTH, get_settings());
parser->parser[i].data = init_stream_processor();   /* after init, not before */

/* execute + error path (proto_http.c) */
enum llhttp_errno err =
    llhttp_execute(parser, (const char *) packet->payload, packet->payload_packet_len);
if (err == HPE_PAUSED_UPGRADE || llhttp_get_upgrade(parser)) {
    /* upgraded connection — unchanged TODO */
} else if (err != HPE_OK) {
    debug("... Error %s: %s\n", llhttp_errno_name(err), llhttp_get_error_reason(parser));
    llhttp_reset(parser);                           /* preserves data/settings */
    ((stream_processor_t *) parser->data)->hfield_valid = 0;
}
```

## 7. Verification handoff (for #222)

- `SANITIZE=asan bash tests/run_all_tests.sh http_header_case` plus the phase0
  golden-pcap fingerprint — llhttp accepts a different edge set than http-parser
  (e.g. bare `LF` line endings are rejected by default where non-strict http-parser
  tolerated them), so a fingerprint diff means a real parse-behaviour change, not a
  bug in the harness.
- The `hfield_valid` invariant (issue #204, `F-BUG-056`) must survive the port —
  keep it in `stream_processor_t`, unchanged.

## References

- llhttp API reference — `include/llhttp.h` and the README *API* section on
  `nodejs/llhttp` (https://github.com/nodejs/llhttp#api); helper semantics in
  `src/native/api.c` / `api.h`.
- llhttp changelog — GitHub releases (`release/v9.x.y` tags,
  https://github.com/nodejs/llhttp/releases); v9.4.3 is the adoption target.
- nodejs/http-parser — archived upstream (https://github.com/nodejs/http-parser);
  vendored copy at 2.9.4 (`src/mmt_tcpip/lib/http_parser.h:28-30`).
- In-repo: task 2.6 strict-mode fix (`rules/common.mk:173-183`, issue #204);
  toolchain floor (`rules/common.mk:481-483`, `docs/AGENT_ENVIRONMENT.md` §1,
  issue #218); prior parser spike (`docs/DECISIONS.md`, issue #142 entry).
