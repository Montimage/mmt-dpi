# Input Validation API

The validation framework provides macros for safe packet access and bounds checking.

## Header

```c
#include "mmt_protocol_validation.h"
```

## Header Validation

### MMT_VALIDATE_MIN_HEADER

Validates minimum header size before parsing.

```c
MMT_VALIDATE_MIN_HEADER(ipacket, offset, header_type, proto_id)
```

**Example:**
```c
static int parse_tcp(const ipacket_t *packet, size_t offset) {
    // Ensure we have at least sizeof(tcp_header_t) bytes
    MMT_VALIDATE_MIN_HEADER(packet, offset, tcp_header_t, PROTO_TCP);

    // Safe to access TCP header fields
    const tcp_header_t *tcp = (const tcp_header_t*)(packet->data + offset);
    return MMT_ERROR_NONE;
}
```

### MMT_GET_HEADER_PTR

Safely extracts a header pointer with bounds checking.

```c
MMT_GET_HEADER_PTR(ipacket, offset, header_type, ptr_var, proto_id)
```

**Example:**
```c
static int parse_udp(const ipacket_t *packet, size_t offset) {
    const udp_header_t *udp;
    MMT_GET_HEADER_PTR(packet, offset, udp_header_t, udp, PROTO_UDP);

    // udp is now a valid, bounds-checked pointer
    uint16_t src_port = ntohs(udp->src_port);
    uint16_t dst_port = ntohs(udp->dst_port);

    return MMT_ERROR_NONE;
}
```

## Range Validation

### MMT_VALIDATE_RANGE

Validates a value is within an expected range.

```c
MMT_VALIDATE_RANGE(value, min, max, field_name, proto_id)
```

**Example:**
```c
static int validate_tcp_ports(uint16_t src_port, uint16_t dst_port) {
    MMT_VALIDATE_RANGE(src_port, 1, 65535, "src_port", PROTO_TCP);
    MMT_VALIDATE_RANGE(dst_port, 1, 65535, "dst_port", PROTO_TCP);
    return MMT_ERROR_NONE;
}
```

### MMT_VALIDATE_NONZERO

Validates a value is non-zero.

```c
MMT_VALIDATE_NONZERO(value, field_name, proto_id)
```

**Example:**
```c
static int validate_length(size_t length) {
    MMT_VALIDATE_NONZERO(length, "payload_length", PROTO_HTTP);
    return MMT_ERROR_NONE;
}
```

## Safe Arithmetic

### MMT_SAFE_ADD_OR_FAIL

Adds two values with overflow checking.

```c
MMT_SAFE_ADD_OR_FAIL(a, b, result, proto_id)
```

**Example:**
```c
static int compute_total_length(size_t header_len, size_t payload_len,
                                size_t *total_len) {
    MMT_SAFE_ADD_OR_FAIL(header_len, payload_len, *total_len, PROTO_IP);
    return MMT_ERROR_NONE;
}
```

### MMT_SAFE_MULT_OR_FAIL

Multiplies two values with overflow checking.

```c
MMT_SAFE_MULT_OR_FAIL(a, b, result, proto_id)
```

**Example:**
```c
static int compute_array_size(size_t count, size_t element_size,
                              size_t *array_size) {
    MMT_SAFE_MULT_OR_FAIL(count, element_size, *array_size, PROTO_DNS);
    return MMT_ERROR_NONE;
}
```

### MMT_SAFE_SUB_OR_FAIL

Subtracts two values with underflow checking.

```c
MMT_SAFE_SUB_OR_FAIL(a, b, result, proto_id)
```

**Example:**
```c
static int compute_remaining(size_t total, size_t used, size_t *remaining) {
    MMT_SAFE_SUB_OR_FAIL(total, used, *remaining, PROTO_TCP);
    return MMT_ERROR_NONE;
}
```

## Bounds Checking

### MMT_VALIDATE_BOUNDS

Validates offset + length is within packet bounds.

```c
MMT_VALIDATE_BOUNDS(offset, length, packet_len, proto_id)
```

**Example:**
```c
static int extract_field(const ipacket_t *packet, size_t offset,
                         size_t field_len) {
    MMT_VALIDATE_BOUNDS(offset, field_len, packet->len, PROTO_HTTP);

    // Safe to access packet->data[offset..offset+field_len-1]
    memcpy(buffer, packet->data + offset, field_len);
    return MMT_ERROR_NONE;
}
```

### MMT_VALIDATE_OFFSET

Validates offset is within packet bounds.

```c
MMT_VALIDATE_OFFSET(offset, packet_len, proto_id)
```

## String Validation

### MMT_VALIDATE_STRING_LENGTH

Validates string length is within bounds.

```c
MMT_VALIDATE_STRING_LENGTH(str, max_len, field_name, proto_id)
```

### MMT_SAFE_STRNCPY

Safe string copy with null termination.

```c
MMT_SAFE_STRNCPY(dest, src, dest_size)
```

**Example:**
```c
static int copy_hostname(char *dest, size_t dest_size,
                         const char *src) {
    MMT_VALIDATE_STRING_LENGTH(src, MAX_HOSTNAME, "hostname", PROTO_DNS);
    MMT_SAFE_STRNCPY(dest, src, dest_size);
    return MMT_ERROR_NONE;
}
```

## Complete Protocol Handler Example

```c
#include "mmt_core.h"
#include "mmt_protocol_validation.h"

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed)) tcp_header_t;

static int tcp_classify(const ipacket_t *packet, size_t offset) {
    // Validate minimum header size
    MMT_VALIDATE_MIN_HEADER(packet, offset, tcp_header_t, PROTO_TCP);

    // Get header pointer safely
    const tcp_header_t *tcp;
    MMT_GET_HEADER_PTR(packet, offset, tcp_header_t, tcp, PROTO_TCP);

    // Validate data offset (header length)
    uint8_t data_offset = (tcp->data_offset >> 4);
    MMT_VALIDATE_RANGE(data_offset, 5, 15, "data_offset", PROTO_TCP);

    // Calculate actual header length
    size_t header_len;
    MMT_SAFE_MULT_OR_FAIL(data_offset, 4, header_len, PROTO_TCP);

    // Validate we have full header
    MMT_VALIDATE_BOUNDS(offset, header_len, packet->len, PROTO_TCP);

    // Calculate payload offset
    size_t payload_offset;
    MMT_SAFE_ADD_OR_FAIL(offset, header_len, payload_offset, PROTO_TCP);

    // Continue with application protocol detection...
    return detect_application_protocol(packet, payload_offset);
}

static int tcp_extract_port(const ipacket_t *packet, size_t offset,
                            attribute_t *attr) {
    const tcp_header_t *tcp;
    MMT_GET_HEADER_PTR(packet, offset, tcp_header_t, tcp, PROTO_TCP);

    attr->data = &tcp->dst_port;
    attr->data_len = sizeof(uint16_t);

    return MMT_ERROR_NONE;
}
```

## Validation Macro Summary

| Macro | Purpose |
|-------|---------|
| `MMT_VALIDATE_MIN_HEADER` | Check minimum header size |
| `MMT_GET_HEADER_PTR` | Get bounds-checked header pointer |
| `MMT_VALIDATE_RANGE` | Check value in range |
| `MMT_VALIDATE_NONZERO` | Check value is non-zero |
| `MMT_VALIDATE_BOUNDS` | Check offset + length in bounds |
| `MMT_VALIDATE_OFFSET` | Check offset in bounds |
| `MMT_SAFE_ADD_OR_FAIL` | Add with overflow check |
| `MMT_SAFE_SUB_OR_FAIL` | Subtract with underflow check |
| `MMT_SAFE_MULT_OR_FAIL` | Multiply with overflow check |
| `MMT_SAFE_STRNCPY` | Safe string copy |

## See Also

- [Error Handling](error-handling.md)
- [Adding Protocols Guide](../guides/adding-protocols.md)
