Adapted from the canonical runnable example
[`src/examples/packet_handler.c`](https://github.com/montimage-projects/mmt-dpi/blob/main/src/examples/packet_handler.c),
which CI compiles on every build. `META`/`PACKET_LEN` is a built-in meta
attribute available on every packet:

```c
#include "mmt_core.h"

int packet_handler(const ipacket_t *ipacket, void *user_args) {
    uint32_t *p_len = (uint32_t *)get_attribute_extracted_data_by_name(
        ipacket, "META", "PACKET_LEN");
    if (p_len)
        printf("Packet size: %u\n", *p_len);
    return 0; // the callback contract is int-returning; 1 ends the packet early
}

int main() {
    init_extraction();
    char errbuf[1024];
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!handler) {
        fprintf(stderr, "handler init failed: %s\n", errbuf);
        return 1;
    }

    register_extraction_attribute_by_name(handler, "META", "PACKET_LEN");
    register_packet_handler(handler, 1, packet_handler, NULL);

    // Process packets from pcap or live capture...

    mmt_close_handler(handler);
    close_extraction();
}
```
