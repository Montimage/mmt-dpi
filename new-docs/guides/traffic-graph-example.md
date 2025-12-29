# Traffic Graph Example

A live traffic monitoring tool that displays an ASCII time-series graph showing network bandwidth usage with separate lines for download (inbound) and upload (outbound) traffic.

## Features

- Live packet capture from network interfaces using libpcap
- Real-time ASCII line chart with filled areas
- Distinct colors: Cyan for download, Green for upload
- Configurable update interval (default: 5 seconds)
- Auto-scaling Y-axis based on peak traffic
- 40 data points of history displayed
- Statistics: average speeds, totals, duration, packet count
- Offline mode for testing with pcap files

## Screenshot

```
╔════════════════════════════════════════════════════════════════════╗
║  MMT-DPI Traffic Monitor - en0 (5s intervals)                      ║
╚════════════════════════════════════════════════════════════════════╝

  2.9 MB │                                              ○
         │                                           ○  ░░
         │                                        ○  ░░ ░░  ○
         │                                     ░░ ░░ ░░ ░░  ░░
  1.4 MB │                                  ○  ░░ ░░ ░░ ░░  ░░
         │                               ░░ ░░ ░░ ░░ ░░ ░░  ░░
         │                            ░░ ░░ ░░ ░░ ░░ ░░ ░░  ░░
         │  ●●●●●●●●●●●●●●●●●●●●●●●●●●░░●░░●░░●░░●░░●░░●░░●●●●●●●●●●●
       0 └──────────────────────────────────────────────────────────→
          -195s      -145s      -95s       -45s              Now

  ● Download (Inbound)    ○ Upload (Outbound)

╭─────────────────────────────────────────────────────────────────────╮
│  ▼ Download:  Avg: 245.3 KB/s   Total: 12.4 MB                      │
│  ▲ Upload:    Avg: 52.1 KB/s    Total: 2.6 MB                       │
│  Duration: 55s          Packets: 10171                              │
╰─────────────────────────────────────────────────────────────────────╯
```

## Building

### Prerequisites

- MMT-DPI SDK built (`cd sdk && make ARCH=osx -j$(sysctl -n hw.ncpu)`)
- libpcap development headers

### Compile

**From the MMT-DPI root directory:**

**macOS:**
```bash
clang -o traffic_graph src/examples/traffic_graph.c \
    -I sdk/include -I sdk/include/tcpip \
    -L sdk/lib -lmmt_core -lmmt_tcpip -lpcap -ldl -lm \
    -Wl,-rpath,$(pwd)/sdk/lib
```

**Linux:**
```bash
gcc -o traffic_graph src/examples/traffic_graph.c \
    -I sdk/include -I sdk/include/tcpip \
    -L sdk/lib -lmmt_core -lmmt_tcpip -lpcap -ldl -lm \
    -Wl,-rpath,$(pwd)/sdk/lib
```

## Running

### Live Capture (requires root)

Live packet capture requires root/sudo privileges.

**macOS:**

Due to macOS security restrictions (System Integrity Protection), `DYLD_LIBRARY_PATH` is stripped when using sudo. Use this command format:

```bash
sudo bash -c "export MMT_PLUGINS_PATH=$(pwd)/sdk/lib && \
              export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib && \
              $(pwd)/traffic_graph -i en0"
```

Or with absolute paths:
```bash
sudo bash -c "export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib && \
              export DYLD_LIBRARY_PATH=/path/to/mmt-dpi/sdk/lib && \
              /path/to/mmt-dpi/traffic_graph -i en0"
```

**Linux:**
```bash
sudo MMT_PLUGINS_PATH=$(pwd)/sdk/lib \
     LD_LIBRARY_PATH=$(pwd)/sdk/lib \
     ./traffic_graph -i eth0
```

### Offline Mode (pcap file)

For testing without root privileges:

```bash
export MMT_PLUGINS_PATH=$(pwd)/sdk/lib
export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib  # macOS only

./traffic_graph -t capture.pcap -n 1
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i <interface>` | Network interface for live capture (e.g., `en0`, `eth0`) | - |
| `-t <file>` | Read from pcap file instead of live capture | - |
| `-n <seconds>` | Update interval in seconds (1-60) | 5 |
| `-h` | Show help message | - |

### Examples

```bash
# macOS - capture on en0 with 5-second intervals
sudo bash -c "export MMT_PLUGINS_PATH=$(pwd)/sdk/lib && \
              export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib && \
              $(pwd)/traffic_graph -i en0"

# macOS - capture with 2-second intervals
sudo bash -c "export MMT_PLUGINS_PATH=$(pwd)/sdk/lib && \
              export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib && \
              $(pwd)/traffic_graph -i en0 -n 2"

# Linux - capture on eth0
sudo MMT_PLUGINS_PATH=$(pwd)/sdk/lib ./traffic_graph -i eth0

# Test with pcap file
./traffic_graph -t src/examples/google-fr.pcap -n 1
```

## Understanding the Output

### Graph Elements

- **Cyan filled circles (●)**: Download (inbound) traffic line
- **Green hollow circles (○)**: Upload (outbound) traffic line
- **Cyan filled area**: Area under the download line
- **Green filled area**: Area under the upload line
- **Y-axis**: Auto-scaled based on peak traffic in visible window
- **X-axis**: Time, with "Now" at the right edge

### Statistics Box

- **Avg Download/Upload**: Average transfer rate in bytes/second
- **Total Download/Upload**: Cumulative bytes transferred
- **Duration**: Time since capture started
- **Packets**: Total number of packets processed

### Traffic Direction

The tool uses MMT-DPI's session-based direction detection:

- **Download (Inbound)**: Packets coming TO your machine (server responses)
- **Upload (Outbound)**: Packets going FROM your machine (client requests)

Direction is determined by the `META_PACKET_DIRECTION` attribute which tracks whether a packet is going in the same direction as the session initiator.

## Troubleshooting

### Segmentation Fault on macOS with sudo

**Problem:**
```
[1]    12345 segmentation fault  sudo ./traffic_graph -i en0
```

**Cause:** macOS strips `DYLD_LIBRARY_PATH` for security when using sudo.

**Solution:** Use the `sudo bash -c` pattern to set environment variables inside the sudo context:
```bash
sudo bash -c "export MMT_PLUGINS_PATH=$(pwd)/sdk/lib && \
              export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib && \
              $(pwd)/traffic_graph -i en0"
```

### Permission Denied

**Problem:**
```
[error] Could not open interface en0: You don't have permission
```

**Solution:** Run with sudo (root privileges required for packet capture).

### Interface Not Found

**Problem:**
```
[error] Could not open interface eth0: No such device exists
```

**Solution:** Use correct interface name for your system:
- macOS: `en0` (WiFi), `en1` (Ethernet)
- Linux: `eth0`, `enp0s3`, `wlan0`

List interfaces: `ifconfig` or `ip link show`

### No Traffic Shown

**Possible causes:**
1. Wrong interface - verify with `ifconfig`
2. No actual network activity
3. Firewall blocking packet capture

**Debug:** Try with a pcap file first to verify the tool works:
```bash
./traffic_graph -t src/examples/google-fr.pcap -n 1
```

### Download Always Shows 0

If download traffic shows as 0 while upload shows traffic (or vice versa), this may be a direction detection issue. The direction is determined by MMT-DPI's session tracking:

- First packet of a session establishes the "initiator" direction
- Subsequent packets are classified relative to this

For accurate bidirectional statistics, ensure you're capturing traffic from the start of connections.

## Technical Details

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Main Loop                                                   │
│  - pcap_dispatch() for live capture                         │
│  - Interval timer check                                     │
├─────────────────────────────────────────────────────────────┤
│ MMT-DPI Packet Handler Callback                             │
│  - Extract META_P_LEN (packet length)                       │
│  - Extract META_PACKET_DIRECTION                            │
│  - Accumulate bytes into current interval                   │
├─────────────────────────────────────────────────────────────┤
│ Interval Management                                         │
│  - Push completed interval to ring buffer                   │
│  - Reset current interval counters                          │
│  - Trigger graph redraw                                     │
├─────────────────────────────────────────────────────────────┤
│ ASCII Graph Rendering                                       │
│  - Calculate auto-scale from max value                      │
│  - Draw lines and filled areas with ANSI colors             │
│  - Display statistics                                       │
└─────────────────────────────────────────────────────────────┘
```

### Data Structures

- **Ring buffer**: Fixed 40-element array for history
- **Interval counters**: `bytes_in`, `bytes_out`, `packets_in`, `packets_out`
- **Running totals**: For average speed calculation

### MMT-DPI Integration

The tool uses these MMT-DPI APIs:
- `init_extraction()` / `close_extraction()`: Library initialization
- `mmt_init_handler()` / `mmt_close_handler()`: Handler management
- `register_extraction_attribute()`: Register for packet length and direction
- `register_packet_handler()`: Callback for each packet
- `packet_process()`: Process packets from pcap
- `get_attribute_extracted_data()`: Extract attribute values

### Dependencies

- **libmmt_core**: Core DPI engine
- **libmmt_tcpip**: TCP/IP protocol handlers
- **libpcap**: Packet capture library

## See Also

- [Installation Guide](installation.md) - Building MMT-DPI
- [Development Guide](development.md) - Development environment setup
- [API Reference](../api-reference/core-api.md) - MMT-DPI API documentation
