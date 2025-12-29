# Data Flow Architecture

This document describes how packets flow through the MMT-DPI processing pipeline.

## High-Level Data Flow

```mermaid
flowchart LR
    subgraph Input
        PCAP[libpcap<br/>Packet Capture]
        FILE[PCAP File]
        LIVE[Live Interface]
    end

    subgraph Processing
        HANDLER[mmt_handler_t]
        DECODE[Protocol<br/>Decoding]
        EXTRACT[Attribute<br/>Extraction]
        SESSION[Session<br/>Tracking]
    end

    subgraph Output
        CB[Attribute<br/>Callbacks]
        STATS[Statistics]
        EXPORT[Data Export]
    end

    LIVE --> PCAP
    FILE --> PCAP
    PCAP --> HANDLER
    HANDLER --> DECODE
    DECODE --> EXTRACT
    EXTRACT --> SESSION
    SESSION --> CB
    SESSION --> STATS
    CB --> EXPORT
```

## Detailed Processing Flow

```mermaid
sequenceDiagram
    participant Capture as Packet Capture
    participant Handler as mmt_handler_t
    participant Decode as Decoder
    participant Proto as Protocol Handler
    participant Session as Session Manager
    participant Callback as User Callback

    Capture->>Handler: mmt_process_packet(hdr, data)

    rect rgb(240, 248, 255)
        Note over Handler,Decode: Layer 2 Processing
        Handler->>Decode: decode_layer2(packet)
        Decode->>Proto: ethernet_classify()
        Proto-->>Decode: next_protocol, offset
    end

    rect rgb(255, 248, 240)
        Note over Handler,Decode: Layer 3 Processing
        Decode->>Proto: ip_classify()
        Proto-->>Decode: next_protocol, offset
    end

    rect rgb(240, 255, 240)
        Note over Handler,Decode: Layer 4 Processing
        Decode->>Proto: tcp_classify()
        Proto-->>Decode: next_protocol, offset
    end

    rect rgb(255, 240, 255)
        Note over Handler,Session: Layer 7 Processing
        Decode->>Proto: http_classify()
        Proto->>Session: get_session(flow_key)
        Session-->>Proto: session_t*
        Proto->>Proto: parse_http_message()
        Proto-->>Decode: attributes[]
    end

    Decode->>Callback: attribute_handler(attrs)
    Callback-->>Handler: continue/stop
```

## Memory Flow

```mermaid
flowchart TB
    subgraph "Memory Allocation"
        POOL[Memory Pool<br/>Pre-allocated blocks]
        HEAP[Heap<br/>Large allocations]
    end

    subgraph "Session Lifecycle"
        NEW[New Session]
        ACTIVE[Active Session]
        TIMEOUT[Timeout Check]
        CLEANUP[Cleanup]
    end

    subgraph "Packet Processing"
        PKT[Packet Buffer]
        ATTR[Attribute Buffer]
        TEMP[Temp Allocations]
    end

    POOL -->|O(1) alloc| NEW
    NEW --> ACTIVE
    ACTIVE -->|packet arrives| ACTIVE
    ACTIVE -->|no activity| TIMEOUT
    TIMEOUT -->|expired| CLEANUP
    CLEANUP -->|return to pool| POOL

    PKT -->|stack allocated| ATTR
    HEAP -->|large data| ATTR
    TEMP -->|freed per packet| TEMP
```

## Session State Machine

```mermaid
stateDiagram-v2
    [*] --> NEW: First Packet

    NEW --> ESTABLISHED: Handshake Complete
    NEW --> TIMEOUT: No Response

    ESTABLISHED --> ACTIVE: Data Transfer
    ACTIVE --> ACTIVE: More Data
    ACTIVE --> CLOSING: FIN/RST

    CLOSING --> CLOSED: Graceful Close
    ACTIVE --> TIMEOUT: Idle Timeout
    ESTABLISHED --> TIMEOUT: Idle Timeout

    TIMEOUT --> CLEANUP: Sweep Timer
    CLOSED --> CLEANUP: Immediate

    CLEANUP --> [*]: Memory Released
```

## Attribute Extraction Flow

```mermaid
flowchart TD
    PKT[Packet Data] --> PROTO[Protocol Handler]

    PROTO --> VALIDATE{Validate<br/>Bounds}
    VALIDATE -->|Invalid| ERROR[Return Error]
    VALIDATE -->|Valid| PARSE[Parse Field]

    PARSE --> TYPE{Field Type}
    TYPE -->|Integer| INT[Extract Integer]
    TYPE -->|String| STR[Extract String]
    TYPE -->|Binary| BIN[Extract Binary]
    TYPE -->|Nested| NEST[Recursive Parse]

    INT --> ATTR[Attribute Structure]
    STR --> ATTR
    BIN --> ATTR
    NEST --> ATTR

    ATTR --> CB{Callback<br/>Registered?}
    CB -->|Yes| NOTIFY[Invoke Callback]
    CB -->|No| STORE[Store in Session]
```

## Concurrency Model

```mermaid
flowchart TB
    subgraph "Multiple Capture Threads"
        T1[Thread 1]
        T2[Thread 2]
        T3[Thread N]
    end

    subgraph "Per-Thread Handlers"
        H1[Handler 1]
        H2[Handler 2]
        H3[Handler N]
    end

    subgraph "Shared Resources (Locked)"
        REG[Protocol Registry<br/>RW Lock]
        PROTO[Protocol Definitions<br/>Read-Only]
    end

    subgraph "Per-Handler Resources (Independent)"
        S1[Sessions 1]
        S2[Sessions 2]
        S3[Sessions N]
    end

    T1 --> H1
    T2 --> H2
    T3 --> H3

    H1 --> S1
    H2 --> S2
    H3 --> S3

    H1 -.->|read| REG
    H2 -.->|read| REG
    H3 -.->|read| REG
    REG --> PROTO
```

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Session lookup | O(1) average | Hash table with 4096 slots |
| Session creation | O(1) | Memory pool allocation |
| Protocol classification | O(L) | L = number of layers |
| Attribute extraction | O(A) | A = number of attributes |
| Callback invocation | O(C) | C = registered callbacks |
