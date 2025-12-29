# Troubleshooting Guide

Common issues and solutions for MMT-DPI.

## Build Issues

### Library Not Found During Build

```
/usr/bin/ld: cannot find -lpcap
```

**Solution:**
```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# RHEL/CentOS
sudo dnf install libpcap-devel

# macOS
brew install libpcap
```

### libxml2 Not Found (macOS)

```
fatal error: 'libxml/parser.h' file not found
```

**Solution:**
```bash
brew install libxml2

# Verify installation
ls /opt/homebrew/opt/libxml2/include/libxml2/
```

### Undefined Reference Errors

```
undefined reference to `mmt_init_handler'
```

**Causes:**
1. Library not linked properly
2. Wrong library order in linker flags

**Solution:**
```bash
# Ensure correct link order
gcc -o myapp myapp.c -L/opt/mmt/dpi/lib \
    -lmmt_core -lmmt_tcpip -lpcap -lpthread
```

### Architecture Mismatch

```
skipping incompatible libmmt_core.so
```

**Solution:**
Rebuild for correct architecture:
```bash
make clean
make ARCH=linux -j$(nproc)   # For Linux
make ARCH=osx -j$(nproc)     # For macOS
```

## Runtime Issues

### Library Not Found at Runtime

```
error while loading shared libraries: libmmt_core.so: cannot open shared object file
```

**Solution (Linux):**
```bash
# Option 1: Set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH

# Option 2: Add to ldconfig
echo "/opt/mmt/dpi/lib" | sudo tee /etc/ld.so.conf.d/mmt-dpi.conf
sudo ldconfig
```

**Solution (macOS):**
```bash
export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH
```

### Permission Denied (Packet Capture)

```
pcap_open_live: You don't have permission to capture on that device
```

**Solution (Linux):**
```bash
# Option 1: Run with sudo
sudo ./my_mmt_app

# Option 2: Set capabilities (preferred)
sudo setcap cap_net_raw,cap_net_admin=eip ./my_mmt_app
```

**Solution (macOS):**
```bash
# Run with sudo
sudo ./my_mmt_app
```

### Interface Not Found

```
pcap_open_live: eth0: No such device exists
```

**Solution:**
```bash
# List available interfaces
ip link show          # Linux
ifconfig              # macOS

# Use correct interface name
./my_mmt_app -i enp0s3   # Linux example
./my_mmt_app -i en0      # macOS example
```

### Plugins Not Found

```
Warning: Could not load plugin directory
```

**Solution:**
```bash
# Set plugins path
export MMT_PLUGINS_PATH=/opt/mmt/plugins

# Verify plugins exist
ls -la /opt/mmt/plugins/
```

## Performance Issues

### High CPU Usage

**Diagnosis:**
```bash
# Check packet rate
iftop -i eth0

# Profile application
perf top -p $(pgrep my_mmt_app)
```

**Solutions:**

1. **Reduce attribute callbacks:**
   ```c
   // Only register callbacks you need
   mmt_register_extraction_attribute(handler, PROTO_HTTP, HTTP_HOST, ...);
   // Don't register: HTTP_URI, HTTP_METHOD if not needed
   ```

2. **Increase worker threads:**
   ```c
   // Use multiple handlers for parallel processing
   pthread_t threads[NUM_THREADS];
   for (int i = 0; i < NUM_THREADS; i++) {
       // Each thread has its own handler
   }
   ```

3. **Use BPF filter:**
   ```c
   struct bpf_program filter;
   pcap_compile(pcap, &filter, "tcp port 80", 1, PCAP_NETMASK_UNKNOWN);
   pcap_setfilter(pcap, &filter);
   ```

### Memory Growth

**Diagnosis:**
```bash
# Monitor memory
top -p $(pgrep my_mmt_app)

# Check for leaks
valgrind --leak-check=full ./my_mmt_app
```

**Solutions:**

1. **Session cleanup:**
   ```c
   // Periodically cleanup expired sessions
   mmt_cleanup_expired_sessions(handler, timeout_seconds);
   ```

2. **Reduce session timeout:**
   ```c
   // Lower timeout for faster cleanup
   #define SESSION_TIMEOUT 60  // 60 seconds
   ```

3. **Limit session count:**
   ```c
   // Check session count before creating new
   if (active_sessions > MAX_SESSIONS) {
       // Reject or cleanup oldest sessions
   }
   ```

### Packet Loss

**Diagnosis:**
```bash
# Check interface drops
netstat -su
cat /proc/net/dev

# Check pcap stats
```

**Solutions:**

1. **Increase kernel buffers:**
   ```bash
   sudo sysctl -w net.core.rmem_max=134217728
   sudo sysctl -w net.core.rmem_default=134217728
   ```

2. **Increase pcap buffer:**
   ```c
   pcap_set_buffer_size(pcap, 128 * 1024 * 1024);  // 128 MB
   ```

3. **Use multiple capture threads:**
   ```c
   // Spread load across threads
   for (int i = 0; i < num_cpus; i++) {
       pthread_create(&threads[i], NULL, capture_thread, &args[i]);
   }
   ```

## Protocol Detection Issues

### Protocol Not Detected

**Diagnosis:**
1. Check if protocol is registered
2. Verify packet format
3. Enable debug logging

**Solutions:**

1. **Verify protocol registration:**
   ```c
   init_proto_tcpip_struct();  // Register all protocols

   // Check specific protocol
   const char *name = mmt_get_protocol_name(PROTO_HTTP);
   if (name) {
       printf("HTTP protocol registered: %s\n", name);
   }
   ```

2. **Enable verbose logging:**
   ```c
   mmt_log_init();
   mmt_log_set_level(MMT_LOG_DEBUG);
   mmt_log_enable_category(MMT_LOG_CAT_PROTOCOL);
   ```

3. **Check packet data:**
   ```c
   // Hexdump packet to verify contents
   MMT_HEXDUMP(packet->data, packet->len);
   ```

### Attributes Not Extracted

**Diagnosis:**
```c
void my_callback(const ipacket_t *packet,
                 attribute_t *attribute,
                 void *user_data) {
    if (!attribute || !attribute->data) {
        printf("Attribute is NULL!\n");
    }
}
```

**Solutions:**

1. **Verify attribute registration:**
   ```c
   int ret = mmt_register_extraction_attribute(handler,
       PROTO_HTTP, HTTP_HOST, my_callback, NULL);
   if (ret != 0) {
       printf("Failed to register attribute\n");
   }
   ```

2. **Check attribute availability:**
   ```c
   const char *attr_name = mmt_get_attribute_name(PROTO_HTTP, HTTP_HOST);
   printf("Attribute name: %s\n", attr_name ? attr_name : "NOT FOUND");
   ```

## Debugging

### Enable Debug Logging

```c
#include "mmt_logging.h"

mmt_log_init();
mmt_log_set_level(MMT_LOG_DEBUG);

// Enable specific categories
mmt_log_enable_category(MMT_LOG_CAT_PACKET);
mmt_log_enable_category(MMT_LOG_CAT_PROTOCOL);
mmt_log_enable_category(MMT_LOG_CAT_SESSION);
```

### Get Error Context

```c
#include "mmt_errors.h"

int result = some_mmt_function();
if (result != MMT_ERROR_NONE) {
    const mmt_error_context_t *err = mmt_get_last_error();
    fprintf(stderr, "Error %d: %s\n", err->code, err->message);
    fprintf(stderr, "  at %s:%d in %s()\n",
            err->file, err->line, err->function);
}
```

### Packet Hex Dump

```c
#include "mmt_debug.h"

void packet_handler(const ipacket_t *packet, void *user_data) {
    printf("Packet %lu:\n", get_packet_id(packet));
    MMT_HEXDUMP(packet->data, packet->len);
}
```

### GDB Debugging

```bash
# Build with debug symbols
make DEBUG=1

# Run with GDB
gdb ./my_mmt_app
(gdb) break mmt_process_packet
(gdb) run -t test.pcap
(gdb) bt          # Backtrace on crash
(gdb) print *packet
```

### Valgrind Memory Check

```bash
valgrind --leak-check=full --show-leak-kinds=all \
    ./my_mmt_app -t test.pcap 2>&1 | tee valgrind.log
```

## Common Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | MMT_ERROR_NONE | Success |
| 1001 | MMT_ERROR_MEMORY_ALLOC | Memory allocation failed |
| 2001 | MMT_ERROR_PACKET_TOO_SHORT | Packet too short for header |
| 2002 | MMT_ERROR_PACKET_MALFORMED | Malformed packet data |
| 3001 | MMT_ERROR_UNKNOWN_PROTOCOL | Protocol not recognized |
| 4001 | MMT_ERROR_SESSION_NOT_FOUND | Session lookup failed |
| 6001 | MMT_ERROR_NULL_POINTER | Null pointer passed |
| 6002 | MMT_ERROR_INVALID_ARGUMENT | Invalid function argument |

## Getting Help

1. **Check documentation:** [docs/](../../docs/)
2. **Search issues:** [GitHub Issues](https://github.com/Montimage/mmt-dpi/issues)
3. **Contact support:** contact@montimage.com

## See Also

- [Installation Guide](../guides/installation.md)
- [Development Guide](../guides/development.md)
- [API Reference](../api-reference/README.md)
