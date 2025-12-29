# API Reference

Complete API documentation for MMT-DPI libraries.

## Quick Reference

| Header | Purpose |
|--------|---------|
| `mmt_core.h` | Core API - handlers, packet processing |
| `mmt_errors.h` | Error handling framework |
| `mmt_logging.h` | Logging system |
| `mmt_protocol_validation.h` | Input validation macros |
| `mmt_recovery.h` | Error recovery strategies |
| `mmt_debug.h` | Debug utilities |
| `tcpip/mmt_tcpip.h` | TCP/IP protocol initialization |

## Core API Overview

### Handler Lifecycle

```c
#include "mmt_core.h"

// Create handler for Ethernet packets
mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, NULL);

// Process a packet
int result = mmt_process_packet(handler, &pkthdr, packet_data);

// Close handler and free resources
mmt_close_handler(handler);
```

### Protocol Registration

```c
#include "tcpip/mmt_tcpip.h"

// Register all TCP/IP protocols
init_proto_tcpip_struct();

// Or register specific protocol
register_protocol(&my_protocol, MY_PROTOCOL_ID);
```

### Attribute Callbacks

```c
// Define callback function
void my_callback(const ipacket_t *packet,
                 attribute_t *attribute,
                 void *user_data) {
    // Process extracted attribute
}

// Register callback for HTTP host attribute
mmt_register_extraction_attribute(handler,
    PROTO_HTTP,          // Protocol ID
    HTTP_HOST,           // Attribute ID
    my_callback,         // Callback function
    NULL);               // User data
```

## Documentation Index

| Document | Description |
|----------|-------------|
| [Core API](core-api.md) | Handler, packet processing, sessions |
| [Error Handling](error-handling.md) | Error codes, checking macros, context |
| [Logging](logging.md) | Log levels, categories, configuration |
| [Validation](validation.md) | Input validation macros |

## Header Files Location

```
src/mmt_core/public_include/
├── mmt_core.h              # Main API
├── mmt_errors.h            # Error framework
├── mmt_logging.h           # Logging system
├── mmt_debug.h             # Debug utilities
├── mmt_recovery.h          # Recovery mechanisms
├── mmt_safe_access.h       # Safe packet access
├── mmt_safe_string.h       # Safe string operations
├── mmt_safe_math.h         # Safe arithmetic
├── mmt_protocol_validation.h  # Validation macros
├── data_defs.h             # Data structures
├── types_defs.h            # Type definitions
├── plugin_defs.h           # Plugin system
└── mempool.h               # Memory pool

src/mmt_tcpip/include/
└── tcpip/
    └── mmt_tcpip.h         # TCP/IP protocols
```

## Common Data Types

```c
// Packet handler context
typedef struct mmt_handler_struct mmt_handler_t;

// Internal packet representation
typedef struct ipacket_struct ipacket_t;

// Extracted attribute
typedef struct attribute_struct attribute_t;

// Protocol session
typedef struct mmt_session_struct mmt_session_t;

// Protocol definition
typedef struct protocol_struct protocol_t;

// Error codes
typedef int32_t mmt_error_t;
```

## Protocol and Attribute IDs

Protocol and attribute IDs are defined in header files:

```c
// Protocol IDs (from protocol headers)
#define PROTO_ETHERNET  1
#define PROTO_IP        10
#define PROTO_TCP       6
#define PROTO_UDP       17
#define PROTO_HTTP      80
#define PROTO_DNS       53

// Attribute IDs (protocol-specific)
#define IP_SRC          1
#define IP_DST          2
#define TCP_SRC_PORT    1
#define TCP_DST_PORT    2
#define HTTP_HOST       10
#define HTTP_URI        11
```

## Thread Safety

| Component | Safety | Notes |
|-----------|--------|-------|
| `mmt_handler_t` | Per-thread | Create one handler per thread |
| Protocol registry | Thread-safe | Read-write locks |
| Session maps | Thread-safe | Per-protocol locks |
| Logging | Thread-safe | Atomic writes |
| Error context | Thread-local | Per-thread error state |

## See Also

- [Architecture Overview](../architecture/README.md)
- [Development Guide](../guides/development.md)
- [Examples](../guides/examples.md)
