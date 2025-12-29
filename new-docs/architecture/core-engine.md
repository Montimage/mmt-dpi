# Core Engine Architecture

The core engine (`libmmt_core`) provides the foundational packet processing infrastructure.

## Component Overview

```mermaid
classDiagram
    class mmt_handler_t {
        +int link_type
        +uint32_t snap_len
        +void* user_data
        +protocol_stack_t* protocol_stack
        +session_map_t* sessions
    }

    class packet_t {
        +struct pkthdr header
        +u_char* data
        +uint32_t length
        +uint64_t packet_id
    }

    class session_t {
        +uint64_t session_id
        +protocol_t* protocol
        +void* session_data
        +uint64_t packet_count
        +struct timeval last_activity
    }

    class protocol_t {
        +uint32_t protocol_id
        +char* name
        +classify_func classify
        +extract_func extract
        +cleanup_func cleanup
    }

    mmt_handler_t "1" --> "*" session_t : manages
    mmt_handler_t "1" --> "1" protocol_stack_t : contains
    session_t --> protocol_t : uses
    packet_t --> mmt_handler_t : processed by
```

## Source Files

| File | Purpose | Lines |
|------|---------|-------|
| `packet_processing.c` | Main packet processing engine | ~5000 |
| `plugins_engine.c` | Protocol plugin management | ~800 |
| `hashmap.c` | Session hash table | ~400 |
| `mempool.c` | Memory pool allocator | ~300 |
| `mmt_errors.c` | Error handling framework | ~400 |
| `mmt_logging.c` | Logging system | ~300 |

## Packet Processing Pipeline

```mermaid
sequenceDiagram
    participant App as Application
    participant Handler as mmt_handler_t
    participant Proc as Packet Processor
    participant Reg as Protocol Registry
    participant Proto as Protocol Handler
    participant Sess as Session Manager

    App->>Handler: mmt_process_packet(header, data)
    Handler->>Proc: process_packet()
    Proc->>Reg: classify_protocol(packet, offset)
    Reg->>Proto: protocol->classify()
    Proto-->>Reg: protocol_id
    Reg-->>Proc: protocol_t*

    Proc->>Sess: get_or_create_session()
    Sess-->>Proc: session_t*

    Proc->>Proto: protocol->extract(packet, session)
    Proto-->>Proc: extracted_attributes

    Proc->>App: attribute_callback(attributes)
```

## Key Design Decisions

### 1. Protocol Registry with Read-Write Locks

Protocols are registered at initialization and rarely modified. Using read-write locks allows:
- Multiple threads to read protocol definitions simultaneously
- Safe protocol registration during runtime (rare)

### 2. Session Map with Per-Protocol Locks

Each protocol maintains its own session map with dedicated locks:
- Reduces lock contention between protocols
- Allows parallel processing of different protocol types

### 3. Memory Pool for Session Allocation

Sessions are frequently created/destroyed. The memory pool:
- Pre-allocates session memory blocks
- Provides O(1) allocation and deallocation
- Reduces fragmentation

### 4. Hash Table Optimization

Session lookup uses optimized hash tables:
- 4096 slots (power of 2 for bitmask hashing)
- Bitmask instead of modulo (10-40x faster)
- ~0.4% collision rate (down from ~6%)

## Thread Safety Model

```mermaid
graph LR
    subgraph "Thread-Safe Components"
        REG[Protocol Registry<br/>rwlock]
        SESS[Session Maps<br/>per-protocol lock]
        POOL[Memory Pool<br/>mutex]
        LOG[Logging<br/>atomic writes]
    end

    subgraph "Lock-Free Paths"
        PROC[Packet Processing]
        ATTR[Attribute Extraction]
        HASH[Hash Computation]
    end

    REG -.-> PROC
    SESS -.-> PROC
    POOL -.-> SESS
```

## Error Handling Architecture

The error framework provides structured error reporting:

```c
// Error codes organized by category (1000+ codes)
MMT_ERROR_NONE           = 0
MMT_ERROR_MEMORY         = 1001-1099
MMT_ERROR_PACKET         = 2001-2099
MMT_ERROR_PROTOCOL       = 3001-3099
MMT_ERROR_SESSION        = 4001-4099
```

See [Error Handling](../api-reference/error-handling.md) for details.
