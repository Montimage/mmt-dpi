# Development Guide

This document is the deep-dive build/debug/extend reference. For the
end-user install path see [USER_GUIDE.md](USER_GUIDE.md); for
contribution flow (fork/branch/PR/commit conventions) see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Prerequisites

MMT-DPI builds on Linux with the GNU toolchain. CI exercises the build
on `ubuntu-latest`.

- GCC 4.9 to 9.x (CI uses the system GCC on `ubuntu-latest`).
- GNU Make and CMake (CMake is pulled in by some sub-targets).
- `libxml2-dev`
- `libpcap-dev` (required for the example binaries and most test cases)
- Valgrind (optional, for the leak-check workflow below).

On Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential gcc make cmake \
    libxml2-dev libpcap-dev \
    valgrind
```

The top-level `install.sh` also handles dependency installation for
Debian/Ubuntu, Fedora/RHEL, and openSUSE — read it for the exact
package lists per distribution.

## Build

All build targets live in `sdk/Makefile` and dispatch into the per-
arch rules under `rules/arch-*.mk`.

| Command | Result |
|---|---|
| `cd sdk && make -j$(nproc)` | Build all libraries and example binaries (default target: `sdk`). |
| `cd sdk && sudo make install` | Install to `MMT_BASE/dpi/` (default `/opt/mmt/dpi/`). |
| `cd sdk && make clean` | Remove object files. |
| `cd sdk && make dist-clean` | Remove object files and the install tree. |
| `cd sdk && make deb` | Produce a Debian package (`.deb`). |
| `cd sdk && make zip` | Produce a portable ZIP distribution. |
| `cd sdk && make test` | Run the in-tree test target (see Testing). |

Useful build-time flags (pass on the `make` command line):

| Flag | Meaning |
|---|---|
| `MMT_BASE=/path` | Install prefix (default `/opt/mmt`, becomes `/opt/mmt/dpi/`). |
| `ARCH=linux` | Target architecture rules to include (default `linux`). |
| `DEBUG=1` | Enable assertions and debug symbols. |
| `NDEBUG=1` | Show internal debug messages. |
| `SHOWLOG=1` | Emit `MMT_LOG` messages at runtime. |
| `VALGRIND=1` | Build with Valgrind-friendly options. |
| `TCP_SEGMENT=1` | Enable TCP segment reassembly. |
| `STATIC_LINK=1` | Link statically. |

> Only Linux is supported. macOS and Windows are not on the supported
> matrix.

## Testing

The smoke test wired into CI is the `test` target in `sdk/Makefile`,
which builds and runs the `proto_attributes_iterator` example against
the in-tree pcap. The CI workflow (`.github/workflows/c-cpp.yml`)
invokes `make test` on every push and pull request to `main`.

Run it locally:

```bash
cd sdk
make test
```

To exercise a specific example against a capture:

```bash
cd src/examples
gcc -o extract_all extract_all.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
./extract_all -t google-fr.pcap
```

### Memory leak checks

```bash
valgrind --leak-check=full --show-reachable=yes \
    ./extract_all -t google-fr.pcap
```

Build with `VALGRIND=1` to suppress benign warnings from the custom
allocator code paths.

## Debugging tips

- Build with `DEBUG=1` to enable assertions plus debug symbols.
- For GDB sessions on examples, recompile the example with `-g`.
- `proto_attributes_iterator` is the quickest way to confirm the
  protocol/attribute registry looks right after a parser change.
- Cross-check protocol classification against Wireshark on the same
  pcap.

## Code organisation

```
src/
  mmt_core/           Core engine: handler, session, attribute, plugin loader
    public_include/   Public C headers shipped under /opt/mmt/dpi/include/
  mmt_tcpip/          TCP/IP and L7 protocol parsers (HTTP, DNS, FTP, QUIC, ...)
  mmt_mobile/         Mobile-network protocols (NAS, S1AP, NGAP, GTP, Diameter)
  mmt_business_app/   Business-application protocols
  mmt_security/       Security-related protocol handling
  mmt_dicom/          DICOM medical-imaging protocol
  mmt_fuzz_engine/    Fuzzing harness
  examples/           Stand-alone C examples that link against libmmt_core
sdk/                  Build orchestrator (Makefile only — invokes rules/)
rules/                Per-arch build rules included from sdk/Makefile
dist/                 Packaging helpers (install.sh, uninstall.sh, ZIP layout)
```

Each protocol parser typically lives in `proto_<name>.c` inside the
relevant plugin directory. New parsers register themselves with the
core engine at plugin load time.

## Adding a new protocol

See [Add-New-Protocol.md](Add-New-Protocol.md) for the step-by-step
walkthrough (registering the protocol id, declaring attributes,
implementing the classification and extraction callbacks, wiring the
parser into the plugin's makefile, and adding a test pcap).

Related references:

- `docs/Protocol-Stack.md` — how protocols chain together.
- `docs/MMT-Attributes.md` — attribute model and types.
- `docs/Packet-Journey.md` — packet flow through the engine.
- `docs/Memory-Management.md` — allocation conventions.
