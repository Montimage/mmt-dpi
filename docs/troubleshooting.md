---
layout: default
title: "Troubleshooting"
---

# Troubleshooting the first run

The errors below are the ones a first build, install, compile or run of
MMT-DPI can stop on, in the order you meet them. Each one gives the message
as it is printed — search this page for the part of your error that names a
file or a function — then why it happens and the fix.

Commands use the default install prefix, `/opt/mmt`. If you installed
somewhere else (`MMT_BASE=...` or `--prefix`), substitute that directory.
Packages to install before any of this are listed in the
[prerequisites](./Compilation-and-Installation-Instructions.md#prerequisites).

* TOC
{:toc}

## Building and installing from a checkout

### `install: cannot create directory '/opt/mmt': Permission denied`

`make -C sdk install` ran as your user, and the prefix belongs to root. The
same cause can also print `install: cannot change permissions of '/opt/mmt'`,
or, when `/opt/mmt` already exists (after an earlier `sudo` install, for
example), one
`install: cannot create regular file '/opt/mmt/dpi/lib/...': Permission denied`
line per library.

Fix: build as your user, then install with `sudo`:

```bash
make -C sdk -j$(nproc)
sudo make -C sdk install
```

Or install into a directory you own, passing the same `MMT_BASE` to both
commands:

```bash
make -C sdk MMT_BASE="$HOME/mmt" -j$(nproc)
make -C sdk MMT_BASE="$HOME/mmt" install
```

An install that does not run as root does not register the libraries with
the system loader, so programs need `LD_LIBRARY_PATH` to run: see the
`error while loading shared libraries` entry below.

### `ERROR: no SDK build under .../sdk/lib`

The full message ends with `run 'make -C sdk MMT_BASE=...' (as your user)
before 'make install'`. `make install` never compiles: it copies what a
previous build produced, and there is none.[^check-built]

Fix: run the build it names first, as your user, then the install.

### `ERROR: the SDK under .../sdk/lib was built for plugin directory '...', but this install targets '...'`

The build and the install used different prefixes. The plugin directory,
`<prefix>/plugins`, is compiled into the library, so a build made for one
prefix cannot be installed under another.[^check-built] The usual cause is
`make -C sdk MMT_BASE=/some/dir` followed by a plain `sudo make -C sdk install`,
which targets `/opt/mmt`.

Fix: install with the same `MMT_BASE` you built with, or rebuild for the new
prefix with the command the error prints:
`make -C sdk clean && make -C sdk MMT_BASE=<prefix>`.

## Compiling your program

### `fatal error: mmt_core.h: No such file or directory`

The compiler cannot find the MMT-DPI headers: the `-I` option is missing or
names another prefix, or the SDK is not installed.

Fix: pass the include directory of the install, and check that the header is
there:

```bash
ls /opt/mmt/dpi/include/mmt_core.h
gcc -o hello_packet hello_packet.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
```

### `fatal error: pcap.h: No such file or directory`

The libpcap development headers are not installed. The `.deb`/`.rpm`
packages do not install libpcap at all: no MMT-DPI library links it, only the
example programs do.

Fix: install `libpcap-dev` (Debian, Ubuntu) or `libpcap-devel` (Fedora, Rocky
Linux, AlmaLinux, CentOS Stream, openSUSE), as the
[prerequisites](./Compilation-and-Installation-Instructions.md#prerequisites)
show.

## Linking

### `cannot find -lmmt_core`

The linker cannot find `libmmt_core.so`: the `-L` option is missing or names
another prefix.

Fix: add `-L /opt/mmt/dpi/lib` (your prefix's `dpi/lib`) before
`-lmmt_core`.

### `cannot find -lpcap`

The libpcap development package, which provides the `libpcap.so` the linker
looks for, is not installed (a libpcap runtime alone is not enough).

Fix: install `libpcap-dev` or `libpcap-devel`, as for the missing `pcap.h`
above.

### ``undefined reference to `pcap_open_offline'``

The program calls libpcap but the command does not link it — or it does, but
names the libraries before the source file. The same error naming an MMT-DPI
function, such as `get_attribute_extracted_data_by_name`, means `-lmmt_core`
is missing or misplaced: a library serves only the files named before it on
the command line (on Debian and Ubuntu, whose linker drops a shared library
nothing before it uses).

Fix: keep every `-l` option at the end, after the source file:
`gcc -o hello_packet hello_packet.c -I ... -L ... -lmmt_core -ldl -lpcap`.

## Running your program

### `error while loading shared libraries: libmmt_core.so.1: cannot open shared object file`

The program compiled, but the system loader does not know where the MMT-DPI
libraries are. A `sudo` install registers `/opt/mmt/dpi/lib` with the loader;
an install that did not run as root, or ran with `LDCONF=0`, does not, and
says so when it finishes.[^loader] With a v1.9.1 install the file name is
`libmmt_core.so`.

Fix, any one of:

- point the loader at the libraries for this run:
  `LD_LIBRARY_PATH=/opt/mmt/dpi/lib ./hello_packet traffic.pcap`
  (`export` it for a whole shell session);
- install as root, which writes `/etc/ld.so.conf.d/mmt-dpi.conf`;
  `ldconfig -p | grep libmmt_core` then lists the library;
- record the directory in the program itself when you link it:
  add `-Wl,-rpath,/opt/mmt/dpi/lib` to the `gcc` command.

### `handler init failed: Unsupported stack type`

`mmt_init_handler()` reports `Unsupported stack type` when no protocol plugin
was loaded, so even Ethernet is unknown.[^stack] The plugins are read from the
directory compiled into the library — `<prefix>/plugins` of the build — and
when that directory is missing or empty `init_extraction()` still succeeds,
without protocols.[^plugins] That happens when the installed tree was moved
or copied to another directory after it was built, or when the plugins were
deleted.

Fix: check that the plugins are where the build expects them
(`ls /opt/mmt/plugins` lists `libmmt_tcpip.so` among others). If the tree
moved, rebuild and reinstall for its new prefix, or name the directory for
this run with an absolute path:
`MMT_DPI_PLUGINS_DIR=/new/prefix/plugins ./hello_packet traffic.pcap`.

### `MMT_DPI_PLUGINS_DIR must be an absolute directory` or `Cannot read plugin directory`

`MMT_DPI_PLUGINS_DIR` is set to a relative path, or to a directory that does
not exist or cannot be read. The library prints the message, then
`Error while loading plugins`, and `init_extraction()` fails.[^plugins]

Fix: set the variable to the absolute path of an existing plugin directory,
or unset it to use the compiled-in one.

### `cannot open capture 'traffic.pcap': traffic.pcap: No such file or directory`

`hello_packet` was given a capture that is not in the current directory. For
the sample capture it also prints the `curl` command that fetches it.

Fix: run the `curl` line the message shows, or pass the capture's full path.
The same message ending in `Permission denied` means the file exists but your
user cannot read it: check it with `ls -l` and make it readable, or copy it.

## Capturing live traffic

### `You don't have permission to perform this capture on that device`

The program prints `pcap_open_live: <interface>: ` followed by one of these,
depending on the libpcap release:

- `You don't have permission to perform this capture on that device (socket: Operation not permitted)`
  (libpcap 1.10.3 to 1.10.5: Debian 12 and 13, Ubuntu 24.04);
- `You don't have permission to perform this capture on that device (Attempt to create packet socket failed - CAP_NET_RAW may be required)`
  (libpcap 1.10.6: Ubuntu 26.04);
- `You don't have permission to capture on that device (socket: Operation not permitted)`
  (libpcap 1.10.1: Ubuntu 22.04).

Opening a network interface needs the `CAP_NET_RAW` capability, which a
normal user does not have. libpcap prints the same message for an interface
name that does not exist, so check the name with `ip link` too.

Fix, either:

- run the program as root: `sudo ./live_sessions eth0`. `sudo` drops
  `LD_LIBRARY_PATH`, so with a prefix the loader does not know, pass it
  through `env`: `sudo env LD_LIBRARY_PATH=/opt/mmt/dpi/lib ./live_sessions eth0`;
- or grant the program the capability once:
  `sudo setcap cap_net_raw=eip ./live_sessions`. The loader ignores
  `LD_LIBRARY_PATH` for a program with capabilities, so link it with
  `-Wl,-rpath,/opt/mmt/dpi/lib` (or install as root) first.

## Still stuck?

Open an issue with the
[bug report template](https://github.com/montimage-projects/mmt-dpi/blob/main/.github/ISSUE_TEMPLATE/bug_report.md):
include the command you ran, its complete output, your distribution,
`gcc --version`, and how you installed MMT-DPI (package, installer or
checkout, and the prefix).

[^check-built]: `make install` checks the build first: `sdk/Makefile:70-80`.
[^loader]: Loader registration on install: `sdk/Makefile:136-144`.
[^stack]: `src/mmt_core/src/packet_registry_handler.c:123`.
[^plugins]: Plugin directory resolution and the missing-directory case: `src/mmt_core/src/plugins_engine.c:48-82`.
