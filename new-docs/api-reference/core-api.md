# Core API Reference

The core API is defined in `mmt_core.h` and provides the fundamental functions for packet processing.

## Handler Management

### mmt_init_handler

Creates a new packet handler.

```c
mmt_handler_t* mmt_init_handler(
    int link_type,      // Link layer type (DLT_EN10MB, etc.)
    uint32_t snap_len,  // Snapshot length (0 = default)
    void *user_data     // Optional user data pointer
);
```

**Returns:** Handler pointer on success, NULL on failure.

**Example:**
```c
// Create handler for Ethernet packets
mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, NULL);
if (!handler) {
    fprintf(stderr, "Failed to create handler\n");
    return -1;
}
```

### mmt_close_handler

Closes a handler and frees all resources.

```c
void mmt_close_handler(mmt_handler_t *handler);
```

**Example:**
```c
mmt_close_handler(handler);
handler = NULL;
```

## Packet Processing

### mmt_process_packet

Processes a single packet through the DPI engine.

```c
int mmt_process_packet(
    mmt_handler_t *handler,     // Handler context
    struct pkthdr *header,       // Packet header (timestamp, length)
    const u_char *packet         // Raw packet data
);
```

**Returns:**
- `1` on success
- `0` on failure

**Example:**
```c
struct pcap_pkthdr *pcap_header;
const u_char *packet_data;

while (pcap_next_ex(pcap, &pcap_header, &packet_data) >= 0) {
    struct pkthdr header;
    header.ts = pcap_header->ts;
    header.caplen = pcap_header->caplen;
    header.len = pcap_header->len;

    mmt_process_packet(handler, &header, packet_data);
}
```

## Attribute Extraction

### mmt_register_extraction_attribute

Registers a callback for a specific protocol attribute.

```c
int mmt_register_extraction_attribute(
    mmt_handler_t *handler,          // Handler context
    uint32_t protocol_id,            // Protocol ID
    uint32_t attribute_id,           // Attribute ID
    attribute_handler_function func, // Callback function
    void *user_data                  // User data for callback
);
```

**Callback signature:**
```c
typedef void (*attribute_handler_function)(
    const ipacket_t *packet,    // Packet context
    attribute_t *attribute,      // Extracted attribute
    void *user_data              // User data
);
```

**Example:**
```c
void http_host_handler(const ipacket_t *packet,
                       attribute_t *attribute,
                       void *user_data) {
    if (attribute->data) {
        printf("HTTP Host: %s\n", (char*)attribute->data);
    }
}

mmt_register_extraction_attribute(handler,
    PROTO_HTTP,
    HTTP_HOST,
    http_host_handler,
    NULL);
```

### mmt_register_packet_handler

Registers a callback for all packets matching a protocol.

```c
int mmt_register_packet_handler(
    mmt_handler_t *handler,
    uint32_t protocol_id,
    packet_handler_function func,
    void *user_data
);
```

## Session Management

### mmt_get_session

Gets the current session for a packet.

```c
mmt_session_t* mmt_get_session(const ipacket_t *packet);
```

### mmt_get_session_id

Gets the unique session identifier.

```c
uint64_t mmt_get_session_id(const mmt_session_t *session);
```

### mmt_get_session_protocol_id

Gets the protocol ID associated with a session.

```c
uint32_t mmt_get_session_protocol_id(const mmt_session_t *session);
```

**Example:**
```c
void packet_handler(const ipacket_t *packet, void *user_data) {
    mmt_session_t *session = mmt_get_session(packet);
    if (session) {
        uint64_t session_id = mmt_get_session_id(session);
        uint32_t proto_id = mmt_get_session_protocol_id(session);
        printf("Session %lu, Protocol %u\n", session_id, proto_id);
    }
}
```

## Protocol Information

### mmt_get_protocol_name

Gets the name of a protocol by ID.

```c
const char* mmt_get_protocol_name(uint32_t protocol_id);
```

### mmt_get_attribute_name

Gets the name of an attribute by protocol and attribute ID.

```c
const char* mmt_get_attribute_name(
    uint32_t protocol_id,
    uint32_t attribute_id
);
```

## Packet Information

### get_packet_id

Gets the unique packet identifier.

```c
uint64_t get_packet_id(const ipacket_t *packet);
```

### get_packet_len

Gets the original packet length.

```c
uint32_t get_packet_len(const ipacket_t *packet);
```

### get_packet_cap_len

Gets the captured packet length.

```c
uint32_t get_packet_cap_len(const ipacket_t *packet);
```

### get_packet_timestamp

Gets the packet timestamp.

```c
struct timeval get_packet_timestamp(const ipacket_t *packet);
```

## Complete Example

```c
#include <stdio.h>
#include <pcap.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

void dns_query_handler(const ipacket_t *packet,
                       attribute_t *attribute,
                       void *user_data) {
    if (attribute->data) {
        printf("[%lu] DNS Query: %s\n",
               get_packet_id(packet),
               (char*)attribute->data);
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open pcap file
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    // Initialize handler
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, NULL);
    if (!handler) {
        fprintf(stderr, "Failed to create handler\n");
        return 1;
    }

    // Register protocols
    init_proto_tcpip_struct();

    // Register callback for DNS queries
    mmt_register_extraction_attribute(handler,
        PROTO_DNS, DNS_QNAME,
        dns_query_handler, NULL);

    // Process packets
    struct pcap_pkthdr *pcap_hdr;
    const u_char *data;

    while (pcap_next_ex(pcap, &pcap_hdr, &data) >= 0) {
        struct pkthdr hdr = {
            .ts = pcap_hdr->ts,
            .caplen = pcap_hdr->caplen,
            .len = pcap_hdr->len
        };
        mmt_process_packet(handler, &hdr, data);
    }

    // Cleanup
    mmt_close_handler(handler);
    pcap_close(pcap);

    return 0;
}
```

**Compile:**
```bash
gcc -I/opt/mmt/dpi/include example.c -L/opt/mmt/dpi/lib \
    -lmmt_core -lmmt_tcpip -lpcap -o example
```
