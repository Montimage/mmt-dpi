# Error Handling API

The error handling framework provides structured error reporting with 1000+ error codes organized by category.

## Header

```c
#include "mmt_errors.h"
```

## Error Code Categories

| Range | Category | Description |
|-------|----------|-------------|
| 0 | Success | No error |
| 1001-1099 | Memory | Memory allocation failures |
| 2001-2099 | Packet | Packet processing errors |
| 3001-3099 | Protocol | Protocol-specific errors |
| 4001-4099 | Session | Session management errors |
| 5001-5099 | I/O | Input/output errors |
| 6001-6099 | Config | Configuration errors |
| 7001-7099 | Security | Security-related errors |
| 8001-8099 | System | System errors |

## Common Error Codes

```c
// Success
MMT_ERROR_NONE              = 0

// Memory errors
MMT_ERROR_MEMORY_ALLOC      = 1001
MMT_ERROR_MEMORY_POOL       = 1002
MMT_ERROR_OUT_OF_MEMORY     = 1003

// Packet errors
MMT_ERROR_PACKET_TOO_SHORT  = 2001
MMT_ERROR_PACKET_MALFORMED  = 2002
MMT_ERROR_PACKET_TRUNCATED  = 2003
MMT_ERROR_INVALID_OFFSET    = 2004

// Protocol errors
MMT_ERROR_UNKNOWN_PROTOCOL  = 3001
MMT_ERROR_PROTOCOL_INVALID  = 3002
MMT_ERROR_HEADER_INVALID    = 3003

// Session errors
MMT_ERROR_SESSION_NOT_FOUND = 4001
MMT_ERROR_SESSION_EXPIRED   = 4002
MMT_ERROR_SESSION_LIMIT     = 4003

// I/O errors
MMT_ERROR_FILE_NOT_FOUND    = 5001
MMT_ERROR_FILE_READ         = 5002
MMT_ERROR_FILE_WRITE        = 5003

// Validation errors
MMT_ERROR_NULL_POINTER      = 6001
MMT_ERROR_INVALID_ARGUMENT  = 6002
MMT_ERROR_OUT_OF_RANGE      = 6003
MMT_ERROR_OVERFLOW          = 6004
```

## Error Checking Macros

### MMT_CHECK_NOT_NULL

Checks for null pointer and returns error if null.

```c
MMT_CHECK_NOT_NULL(ptr, description)
```

**Example:**
```c
int process_data(void *data) {
    MMT_CHECK_NOT_NULL(data, "input data");
    // data is guaranteed non-null here
    return MMT_ERROR_NONE;
}
```

### MMT_CHECK

Checks a condition and returns error if false.

```c
MMT_CHECK(condition, error_code, message)
```

**Example:**
```c
int validate_length(size_t length) {
    MMT_CHECK(length > 0, MMT_ERROR_INVALID_ARGUMENT, "length must be positive");
    MMT_CHECK(length <= MAX_LENGTH, MMT_ERROR_OUT_OF_RANGE, "length exceeds maximum");
    return MMT_ERROR_NONE;
}
```

### MMT_RETURN_ERROR

Returns an error with context information.

```c
MMT_RETURN_ERROR(error_code, message)
```

**Example:**
```c
int parse_header(const uint8_t *data, size_t len) {
    if (len < HEADER_MIN_SIZE) {
        MMT_RETURN_ERROR(MMT_ERROR_PACKET_TOO_SHORT,
                         "packet shorter than minimum header size");
    }
    // Continue processing...
    return MMT_ERROR_NONE;
}
```

### MMT_CHECK_BOUNDS

Validates bounds before accessing packet data.

```c
MMT_CHECK_BOUNDS(offset, length, packet_len, error_code)
```

**Example:**
```c
int extract_field(const ipacket_t *packet, size_t offset, size_t len) {
    MMT_CHECK_BOUNDS(offset, len, packet->len, MMT_ERROR_PACKET_TOO_SHORT);
    // Safe to access packet->data[offset..offset+len]
    return MMT_ERROR_NONE;
}
```

## Error Context

### mmt_get_last_error

Gets the last error context for the current thread.

```c
const mmt_error_context_t* mmt_get_last_error(void);
```

### Error Context Structure

```c
typedef struct {
    mmt_error_t code;           // Error code
    const char *message;        // Error message
    const char *file;           // Source file
    int line;                   // Line number
    const char *function;       // Function name
    struct timeval timestamp;   // When error occurred
} mmt_error_context_t;
```

**Example:**
```c
int result = some_mmt_function();
if (result != MMT_ERROR_NONE) {
    const mmt_error_context_t *err = mmt_get_last_error();
    fprintf(stderr, "Error %d: %s\n", err->code, err->message);
    fprintf(stderr, "  at %s:%d in %s()\n",
            err->file, err->line, err->function);
}
```

### mmt_clear_error

Clears the error context.

```c
void mmt_clear_error(void);
```

### mmt_error_to_string

Converts an error code to a human-readable string.

```c
const char* mmt_error_to_string(mmt_error_t error);
```

**Example:**
```c
mmt_error_t result = process_packet(packet);
if (result != MMT_ERROR_NONE) {
    printf("Error: %s\n", mmt_error_to_string(result));
}
```

## Protocol Handler Error Patterns

### Pattern 1: Early Return on Error

```c
static int parse_tcp_header(const ipacket_t *packet, size_t offset) {
    // Validate packet length
    MMT_CHECK_NOT_NULL(packet, "packet");
    MMT_CHECK_BOUNDS(offset, sizeof(tcp_header_t), packet->len,
                     MMT_ERROR_PACKET_TOO_SHORT);

    // Get header pointer safely
    const tcp_header_t *tcp = (const tcp_header_t*)(packet->data + offset);

    // Validate header fields
    size_t header_len = (tcp->data_offset >> 4) * 4;
    MMT_CHECK(header_len >= 20, MMT_ERROR_HEADER_INVALID,
              "TCP header length too small");

    return MMT_ERROR_NONE;
}
```

### Pattern 2: Error Propagation

```c
static int process_http_request(session_t *session, const ipacket_t *packet) {
    mmt_error_t err;

    // Each function returns error code
    err = validate_http_headers(packet);
    if (err != MMT_ERROR_NONE) return err;

    err = parse_http_method(packet, session);
    if (err != MMT_ERROR_NONE) return err;

    err = extract_http_uri(packet, session);
    if (err != MMT_ERROR_NONE) return err;

    return MMT_ERROR_NONE;
}
```

### Pattern 3: Cleanup on Error

```c
static int create_session(mmt_handler_t *handler, session_t **out) {
    session_t *session = NULL;

    session = mmt_pool_alloc(handler->session_pool);
    if (!session) {
        MMT_RETURN_ERROR(MMT_ERROR_OUT_OF_MEMORY, "failed to allocate session");
    }

    mmt_error_t err = initialize_session(session);
    if (err != MMT_ERROR_NONE) {
        mmt_pool_free(handler->session_pool, session);
        return err;
    }

    *out = session;
    return MMT_ERROR_NONE;
}
```

## See Also

- [Logging API](logging.md)
- [Validation Macros](validation.md)
- [Recovery Strategies](recovery.md)
