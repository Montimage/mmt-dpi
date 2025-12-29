# Logging API

The logging system provides 5 severity levels and 10 categories for structured log output.

## Header

```c
#include "mmt_logging.h"
```

## Log Levels

| Level | Value | Description |
|-------|-------|-------------|
| `MMT_LOG_FATAL` | 0 | Critical errors, application cannot continue |
| `MMT_LOG_ERROR` | 1 | Errors that need attention |
| `MMT_LOG_WARN` | 2 | Warnings about potential issues |
| `MMT_LOG_INFO` | 3 | Informational messages |
| `MMT_LOG_DEBUG` | 4 | Debug information |

## Log Categories

| Category | Value | Description |
|----------|-------|-------------|
| `MMT_LOG_CAT_CORE` | 0 | Core engine |
| `MMT_LOG_CAT_PACKET` | 1 | Packet processing |
| `MMT_LOG_CAT_PROTOCOL` | 2 | Protocol handling |
| `MMT_LOG_CAT_SESSION` | 3 | Session management |
| `MMT_LOG_CAT_MEMORY` | 4 | Memory allocation |
| `MMT_LOG_CAT_PLUGIN` | 5 | Plugin system |
| `MMT_LOG_CAT_SECURITY` | 6 | Security events |
| `MMT_LOG_CAT_NETWORK` | 7 | Network operations |
| `MMT_LOG_CAT_CONFIG` | 8 | Configuration |
| `MMT_LOG_CAT_USER` | 9 | User-defined |

## Initialization

### mmt_log_init

Initializes the logging system.

```c
void mmt_log_init(void);
```

### mmt_log_set_level

Sets the minimum log level.

```c
void mmt_log_set_level(mmt_log_level_t level);
```

### mmt_log_set_output

Sets the log output file.

```c
void mmt_log_set_output(FILE *output);
```

**Example:**
```c
// Initialize logging
mmt_log_init();

// Set log level (only INFO and above)
mmt_log_set_level(MMT_LOG_INFO);

// Log to file instead of stderr
FILE *logfile = fopen("mmt.log", "a");
mmt_log_set_output(logfile);
```

## Logging Macros

### Basic Logging

```c
MMT_LOG_FATAL(format, ...)
MMT_LOG_ERROR(format, ...)
MMT_LOG_WARN(format, ...)
MMT_LOG_INFO(format, ...)
MMT_LOG_DEBUG(format, ...)
```

**Example:**
```c
MMT_LOG_INFO("Processing packet %lu", packet_id);
MMT_LOG_WARN("Session timeout: id=%lu", session_id);
MMT_LOG_ERROR("Failed to allocate memory: %zu bytes", size);
```

### Category-Specific Logging

```c
MMT_LOG_DEBUG_CAT(category, format, ...)
MMT_LOG_INFO_CAT(category, format, ...)
MMT_LOG_WARN_CAT(category, format, ...)
MMT_LOG_ERROR_CAT(category, format, ...)
```

**Example:**
```c
MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_PACKET,
    "Packet length: %u, offset: %u", len, offset);

MMT_LOG_INFO_CAT(MMT_LOG_CAT_SESSION,
    "New session created: id=%lu, proto=%u", session_id, proto_id);

MMT_LOG_WARN_CAT(MMT_LOG_CAT_SECURITY,
    "Malformed packet from %s", src_ip);
```

## Category Filtering

### mmt_log_enable_category

Enables logging for a specific category.

```c
void mmt_log_enable_category(mmt_log_category_t category);
```

### mmt_log_disable_category

Disables logging for a specific category.

```c
void mmt_log_disable_category(mmt_log_category_t category);
```

**Example:**
```c
// Only enable packet and security logging
mmt_log_disable_category(MMT_LOG_CAT_CORE);
mmt_log_disable_category(MMT_LOG_CAT_SESSION);
mmt_log_disable_category(MMT_LOG_CAT_MEMORY);

mmt_log_enable_category(MMT_LOG_CAT_PACKET);
mmt_log_enable_category(MMT_LOG_CAT_SECURITY);
```

## Log Output Format

Default log format:
```
[TIMESTAMP] [LEVEL] [CATEGORY] FILE:LINE - MESSAGE
```

Example output:
```
[2025-01-15 14:30:45.123] [INFO] [PACKET] packet_processing.c:256 - Processing packet 12345
[2025-01-15 14:30:45.124] [WARN] [SESSION] session.c:89 - Session timeout: id=67890
[2025-01-15 14:30:45.125] [ERROR] [MEMORY] mempool.c:45 - Pool exhausted, falling back to malloc
```

## Performance Considerations

Logging macros are designed for minimal overhead when disabled:

```c
// When log level is INFO, DEBUG calls are compiled out
MMT_LOG_DEBUG("Expensive debug: %s", compute_debug_string());
// ^^^ compute_debug_string() is NOT called if DEBUG is disabled
```

For expensive computations, use conditional logging:

```c
if (mmt_log_level_enabled(MMT_LOG_DEBUG)) {
    char *debug_info = compute_expensive_debug_info();
    MMT_LOG_DEBUG("Debug info: %s", debug_info);
    free(debug_info);
}
```

## Thread Safety

The logging system is thread-safe:
- Log writes are atomic
- Category enable/disable is atomic
- Output file changes are synchronized

## Complete Example

```c
#include "mmt_core.h"
#include "mmt_logging.h"

int main(int argc, char *argv[]) {
    // Initialize logging
    mmt_log_init();
    mmt_log_set_level(MMT_LOG_INFO);

    // Optional: log to file
    FILE *logfile = fopen("mmt_dpi.log", "a");
    if (logfile) {
        mmt_log_set_output(logfile);
    }

    MMT_LOG_INFO("Starting MMT-DPI application");

    // Initialize handler
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, NULL);
    if (!handler) {
        MMT_LOG_FATAL("Failed to create handler");
        return 1;
    }

    MMT_LOG_INFO("Handler created successfully");

    // Process packets...
    for (int i = 0; i < num_packets; i++) {
        MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_PACKET,
            "Processing packet %d of %d", i + 1, num_packets);

        int result = mmt_process_packet(handler, &headers[i], packets[i]);
        if (result != 1) {
            MMT_LOG_WARN("Packet %d processing failed", i);
        }
    }

    MMT_LOG_INFO("Processed %d packets", num_packets);

    // Cleanup
    mmt_close_handler(handler);

    if (logfile) {
        fclose(logfile);
    }

    return 0;
}
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MMT_LOG_LEVEL` | Set default log level (0-4) |
| `MMT_LOG_FILE` | Set log file path |
| `MMT_LOG_CATEGORIES` | Comma-separated list of enabled categories |

**Example:**
```bash
export MMT_LOG_LEVEL=4           # DEBUG level
export MMT_LOG_FILE=/var/log/mmt.log
export MMT_LOG_CATEGORIES=PACKET,SESSION,SECURITY
./my_mmt_app
```

## See Also

- [Error Handling](error-handling.md)
- [Debug Utilities](debug.md)
