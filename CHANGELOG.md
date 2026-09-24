RELEASE NOTES
---

Unreleased
---

Changes on `main` since the v1.8.0 tag, grouped by theme; parenthetical
numbers are the tracking issues. Keep this section current — the PR template
checklist requires a line here for every user-visible change.

### Documentation
- align the contributor and user docs with the code — the agent-runnable environment guide, tracked CLAUDE.md/AGENTS.md role briefs, user-guide anchor fixes and the http_parser→llhttp migration guide (#119, #120, #157, #178, #179, #180, #196, #211, #221)
- publish the Jekyll guides on the docs site, fix landing navigation and the trunk link check (#247)
- close the remaining documentation drift (#249)
- correct the documented embedding lifecycle: `init_extraction()` before any handler, checked failures, handler teardown before `close_extraction()` and one handler per worker, with source citations; `packet_handler.c` now follows that order on every path, and the new `docs_lifecycle` suite compiles and runs it against a throwaway installed SDK (#392)
- publish a first run that works from an empty directory: the site serves a complete `hello_packet.c` (processing loop, checked lifecycle, clear missing-capture error) and a synthetic, redistributable `traffic.pcap`; the README/site first example and the landing-page copy controls show the exact fetch, compile and run steps and the output to expect, and the new `docs_onboarding` suite runs those steps verbatim against a throwaway installed SDK (#393)
- reconcile the version, protocol-count and changelog claims: one canonical feature list, quick-start and first example shared between README and the site, and a CI gate that the quoted counts match the built SDK (#248)

### Build, CI and packaging
- harden the installers and deduplicate the ZIP variant (#159)
- secret scanning and private vulnerability reporting, with a provably-run gitleaks gate (#160, #191)
- make the documented gates real — the sanitizer matrix and coverage reporting, the pre-commit framework, doc validators, phase0 harness enumeration, the security-engine CI build and the verification-helper machinery (#123, #126, #181, #182, #184, #185, #187, #190)
- pin the runners, the compiler range, the Jekyll theme and the release actions, and move GitHub Actions off the deprecated Node 20 runtime (#96, #122, #125, #138, #213)
- reproducible, tag-verified package builds (#220)
- pin the asn1c generator and gate the regenerated tree weekly (#223)
- add CodeQL SAST and a bounded mutation-fuzz gate (#224)
- repin the centos-stream9 base image after an upstream digest GC (#310)
- measure resolved dependency advisory status — docs gems, pinned actions and the release-distro runtime packages — with `tools/ci/check-dependency-advisories.sh`, which fails closed when a required scanner did not run (#384)

### Core and protocols
- bound the parsers and core APIs against short and attacker-controlled buffers — caplen guards for attribute extraction and packet-data reads, bounded header and stream walkers, and hardening of the FTP, RADIUS, S1AP/NGAP and NAS IE decoders plus the rule-engine command-injection fix (#127–#137, #146, #192, #193, #205)
- bound the UDP payload by the datagram's own length field and the enclosing IP payload (IPv4 tot_len, IPv6 payload_len net of extension headers, explicit jumbogram handling), so captured bytes past the declared UDP datagram can no longer drive payload extraction, detection or session data-volume accounting; new `parser_boundaries` suite covers the unit and packet/API paths under ASan/UBSan (#375)
- make the IPv6 session-key address ordering (`MMT_COMPARE_IPV6_ADDRESSES`), the session-map address hash/compares and the `packet->iphv6` header view alignment-safe — misaligned accesses on IPv6-over-Ethernet packets aborted under UBSan; the byte-identical memcpy/aligned(1) reads keep behaviour unchanged (#375)
- name the classifier verdict constants, drive the protocol declarations and dispatch table from one list, table-drive the MIME registry, and deprecate the uncalled public ABI symbols (#148, #149, #150, #152)
- integrate the modernization sweep: NAS/NAS5G IE decoders, SCTP-carried mobile protocols, shared HTTP/1+2 and RFC2822 fixes, TLS/QUIC/DTLS/DNS extractors, extraction-callback caplen prologues, classifier tables/AVL/log fixes, fuzz-engine DICOM and business-app coverage, crafted-input and fault-injection suites, build-hardening and assertion policy (#177)
- migrate the HTTP parser from vendored http_parser to llhttp v9.4.3 (#222)
- split the packet-processing pipeline and registry (#239)
- replace weak types on the public API with typedefs and bool (#231); adopt typed accessors and proto-id typedefs (#230)
- remove the dead non-Linux portability layer (#228); delete uncalled `mmt_classify_me_*` clones (#225); fold identical init wrappers into a generic helper (#226)
- flatten and deduplicate IRC classification (#237); repair the business-app header install and strip the decoy API surface (#229)
- security engine: thread `verify()`'s invariant arguments through a context struct (#233) and split `verify()` into one handler per node type (#234)
- configurable DPI profiles: four named presets (`default`/`minimal`/`balanced`/`full`) plus operator-defined profiles bundle the detection levers — classification-depth cap, application/hostname detection, port-based and IP-range hints — applied per handler via API, `MMT_DPI_PROFILE`/`MMT_DPI_PROFILES_FILE` env vars or a profiles file; a depth cap also skips the per-layer checker walk for the CPU saving (#87)

### Performance
- remove unconditional packet-path writes to stdout/stderr (#246)
- separate library RSS from harness RSS in the phase0 benchmark (#251)
- reject duplicate TCP segments before allocating reassembly storage and cap each flow's reserved storage — segment blocks including headers plus both image capacities — at the `set_tcp_reassembly_limit()` budget (default 4 MiB), with a documented drop-and-count exhaustion policy; the 1,024-retained/174,080-offer duplicate workload now holds 7 blocks (114,912 B) instead of 1,024 (16,809,984 B); new `resource_bounds` `tcp-memory` fixture (#380)
- slim the session record by 272 B (child statistics and per-direction path copies move to a lazily-allocated tunnel-parent extension), drop the allocator's per-block size prefix, and share the per-packet path-array reset (#255)

### Tests and hygiene
- pcap-driven harnesses for the TCP/IP-stack and mobile/security parsers (#143, #144)
- dead-code batches, TODO/FIXME triage and repo-root report hygiene (#145, #147, #153, #158)
- core-engine unit suite part 1 — session lifecycle and arena allocator (#241)
- business-app plugin suite plus crafted-input regression tests for the 1.8.0 syslog, PTP and DCERPC fixes; the contiguous-uncovered-run gate now holds at 10 lines (#243)
- delete commented-out code and triage the marker backlog, enforced by lint gates (#232)
- characterize TCP reassembly ordering, duplicates, overlaps, 32-bit sequence wrap, partial consumption and teardown with byte-exact output assertions — new `tcp_pending_order` suite; the interleaved-insert walk counts (261,632 at 1,024 segments, 67,100,672 at 16,384) are recorded as evidence ahead of the insertion-structure change (#381)
- measure SDK code reached by integration suites: `--coverage` now builds their SDK with the new `BUILD=coverage` profile, harvests its counters after each suite (before the next rebuild or prefix cleanup loses them) and adds `unit`, `sdk_integration`, `combined` and `generated_asn1c` cohorts, each with its own denominator, to `tests/coverage/summary.json`, leaving the unit-only top-level keys and floor unchanged; new `sdk_coverage` suite proves a controlled SDK call raises its hit count and removing it restores zero (#387)
- consolidate the adversarial resource budgets: the `resource_bounds` fixtures record seeds, accepted/refused work and counters into a machine-readable `results.json` and are checked against the committed `budgets.json` — deterministic counts only, no timing (#394)

Version 2.0.0 (unreleased — scheduled removals)
- remove the four deprecated public symbols recorded under issues #149 and #237 (issue #232):
  `setDataLinkType` (obsolete; no replacement),
  `get_attribute_extracted_data_encap_index` (use `get_attribute_extracted_data_at_index`),
  `mmt_print_all_protocols` (use `iterate_through_protocols`), all in `libmmt_core`,
  and `mmt_search_irc_ssl_detect_ninty_percent_but_very_fast` (use `mmt_search_irc_ssl_detect`)
  in `libmmt_tcpip`. All four are `__attribute__((deprecated))` today and keep their
  exported ABI until this major release.

Version 1.8.0 (23 July 2026 - by EM)
- add DICOM protocol plugin (libmmt_dicom): classify DICOM flows and extract A-ASSOCIATE, C-FIND and P-DATA attributes (called/calling AE titles, max PDU length, command group length and command field, patient name)
- add syslog protocol parser supporting both RFC 3164 and RFC 5424 message formats
- add classification for PTP (Precision Time Protocol) packets
- improve Microsoft 365 and cloud service detection coverage
- externalize IP-range and port attribution into editable data files, with IPv6 and override support and a precision test harness
- add Cloudflare and Azure IP range detection; refresh CDN ranges and demote port-only classification unless payload-confirmed
- enhance Citrix ICA protocol detection with nDPI-compatible patterns
- improve Redis detection with a port-6379 hint and a broader RESP opener heuristic
- guard global registries for multi-threaded use and document the library threading contract
- add one-line install script for easy deployment; support rootless containers and GCC 15
- add CI to build and release multi-distro packages (.deb and .rpm)
- harden parser bounds-checking against malformed packets across DNS, HTTP2, TLS/SSL, QUIC, HTTP, FTP and TCP/IP (buffer over-read guards, recursion caps, minimum-length gates)
- replace exit()/abort() calls in the shared library with error propagation
- fix memory leaks: reassembly packets on analyzer DROP/SKIP paths, per-packet embedded-session offsets, FTP context teardown, allocator ownership for sessions/hashmap/evasion handler
- fix thread-safety issues: atomic protocol-descriptor status flags, mutex-guarded configured-handlers map, RADIUS parser state moved from __thread to per-session
- fix misaligned IP/L4, IPv6 and application-layer header reads reported by UBSan
- fix GTP classification: infinite loop on zero-length next header, hardened padding handling, unknown protocol after echo request/response
- fix TLS/SSL: read record version at the correct offset for TLS 1.2; structurally parse SNI and enlarge its buffer to 256B
- fix DTLS: add standard bitmask guards and drop invalid version 0x0100
- fix HTTP: case-insensitive header name matching; recognize PATCH/MKCOL/LOCK methods and populate http.method/http.uri for them
- fix Skype false-positive UDP/TCP classification heuristic
- restore classification give-up for unknown TCP flows and validate TCP data offset before use
- fix DCERPC packet type offset and payload threshold
- fix DICOM AE Title buffer overflow and strengthen DICOM payload validation
- resize protocol bitmask to cover the full protocol id range
- fix .deb packaging: architecture detection, dependencies, maintainer scripts
- improve packet-processing performance: open-addressing session hash table (replacing std::map), single-pass packet dispatch, per-flow arena allocator with buffer reuse
- reduce lookup overhead: memoized packet offsets, name-to-id hashmap, cached AVL node heights for O(1) balance-factor lookups
- build hardening: LTO and section garbage-collection, hardening flags, link-flag hygiene, libxml2 via pkg-config
- add ASan/UBSan and multi-threaded TSan harnesses plus comprehensive unit test suites for core utility libraries
- update all references from montimage.com to montimage.eu
- documentation overhaul: redesigned landing page, refreshed build and protocol pages, docs reconciled to code with validation scripts

Version 1.7.10 (17 Jully 2023 - by HN)
- fixed bug in INT protocol when parsing cloudgaming metadata

Version 1.7.9 (01 Juin 2023 - by HN)
- add HTTP2 mutation functions
- update Inband Network Telemetry protocol to parse 10th attribute

Version 1.7.8 (17 May 2023 - by HN)
- improved and fixed minor issues in http2 protocol

Version 1.7.7 (04 May 2023 - by FC)
- add http2 protocol

Version 1.7.6 (16 Mar 2023 - by HN)
- classify and extract attributes of QUIC IETF rfc9000
- calculate RTT, in microsecond, of QUIC packets by using QUIC spinbit. Every QUIC packets in the same flight will receive the same RTT.

Version 1.7.5 (30 Nov 2022 - by HN)
- fixed multiple definition errors in sctp.h when compiling using gcc 11

Version 1.7.4 (14 Oct 2022 - by HN)
- extend `ngap.ran_ue_id` to store 64-bit values (instead of 16 bit)
- add `p_data_len` to `meta` to represent size of `p_data` attribute
- add `-lm` in CFLAGS when compiling within lib math

Version 1.7.3 (19 May 2022 - by HN)
- support `MMT_U16_ARRAY` data type
- Inspire5G+: add rule 79 to ensure DTLS traffic is in v1.2 or v1.3 and its ciphersuite is in a given list giving by `MMT_SEC_DTLS_CIPHER_ALLOWLIST` environment variable


Version 1.7.2 (17 February 2022 - by @nhnghia)
- Classify and extract inband-network telemetry protocol and report
- Add mmt_u32_array and mmt_u64_array data type structs
- Fixed [bug](#2) in GTP classification
- Extract pdu extension of GTP: `next_header_type`, `pdu_length`, `pdu_type`, `pdu_qfi`, `pdu_next_header_type`
- Enable Github CI to check code and create a new debian package when releasing a new tag


Version 1.7.1.0 (19 january 2022 - by HN)
- Extract IP attributes for L4S implementation: jitter, l4s_ecn, l4s_marked
- Extract TCP option fiels: tsval, tsecr
- Extract NAS_5GS attributes: authentication_code, sequence_number
- Extract NGAP 5G attributes: amf_ue_id, ran_ue_id
- Add meta.packet_index to get order of packets
- Add ips_data, GTPv2, Diameter protocols
- Rename libmmt_lte.so to libmmt_mobile.so

Version 1.7.0.0
- Add classificaiton for protocol MQTT
- Add S1AP protocol (Huu Nghia)
- Extract some VLAN attributes
- Release a new stable version

Version 1.6.15.1
- Update protocol SMB: extract version, command, file name, padding and payload
- Add protocol 802.1ad

Version 1.6.15.0
- Update protocol IPV6: process fragmentation, extract number of extension header, number of fragment packets, check fragment order

Version 1.6.14.2
- Add is_fragmenting in session to mark a session holding a incompleted packet
- Update API for session_timer_handler, add parameter to choose executing the session handler with or without incompleted packet.

Version 1.6.14.1
- Update DPI for correcting the statistics of IP fragmentation (which is encapsulated in other IP packet)
- remove TCP_SEGMENT compile option.
- new API: update_protocol(proto_id, action_id), to update protocol structure after initializing
- 2 action for protocol tcp: TCP_ENABLE_REASSEMBLE (to enable tcp reasseble process) and TCP_DISABLE_REASSEMBLE
- Return single pointer when extracting session data

Version 1.6.14.0
- Open new APIs to get session statistics with 2 possibilities: with subsession and without subsession. By default, when talking about session statistic which means it does not include subsession statistics
- Add TCP_SEGMENT option: to enable handling tcp_segment inside mmt-sdk. Support for: reconstruct the payload, manage outoforder, retransmission, overlapping, ...
- To enable this feature in mmt-dpi -> compile with option: `make -j4 TCP_SEGMENT=1`

Version 1.6.13.2
- Fix bug: incorrect protocol path - eth.ip.ip
- Fix bug which cause segmentation fault in PROTO_GTP (temporary fix)
- Update Makefile for new plugin path (@huunghia PR)

Version 1.6.13.1
- Fix memory leak when using with mmt-reassembly library
- Fix some bug in http.c and proto_tpkt.c
- Update proto_sctp.c: do not add UNKNOWN protocol at the end
- Update make file to disable SECURITY by default. To compile mmt-sdk with security: make ENABLESEC=1


Version 1.6.13.0
- Add new API to extract protocol attributes with encapsulation index
- Extract some more information in GTP: sequence number, IMSI values
- Extract RF_FLAG in IP header
- Extract ip.opts_type and ip.padding_check
- Fix setting value of has_reassembly when enable/disable tcp_reassembly

Version 1.6.12.2
- Open API to register evasion_event_handler
- Handle some IP fragmentation event:
	+ Too many fragments in one packet
	+ Too many fragments in one session
	+ Too many fragmented packets in one session
	+ Duplicated segments
	+ Overlapping segments

Version 1.6.12.1
- Add APIs to enable/disable classification by hostname and ip address

Version 1.6.12.0
- Improve source code quality with Static code analysis tool: PVS-Studio

Version 1.6.11.1
- Add new Protocols: CTP (Configuration Test Protocol), CDP (Cisco Discovery Protocol), DTP (Dynamic Trunk Protocol), XID (Logical-Link Control Based XID)

Version 1.6.11.0
- Add APIs: enable_port_classify()/ disable_port_classify() to change the classification based on port number. Disable by default
- Add new protocol stack: PROTO_LOOPBACK -> Prove that PROTO_VNC has been classified correctly
- Add classification of PROTO_RTSP which is not based on port number
- Add protocols: TPKT, COTP, S7COMM
- Update Makefile, add option to build installation file:
	+ make zip: create zip file to install mmt-dpi on unix machine
	+ make deb: create deb file to install mmt-dpi on debian machine
	+ make rpm: create rpm file to install mmt-dpi on centos (redhat) machine
- Change classification order: PROTO_MDNS before PROTO_DNS
- Update mmt_check_http: using stage to classify HTTP


Version 1.6.10.5
- Fix classification of PROTO_DNS -> Not use port number
- Correct some license and copyright
- Optimize some functions to improve the performance
- Add VALGRIND as an compile option
- Fix getting port number in proto_mssql.c
- Replace macro MMT_STATICSTRING_LEN by static value -> improve performance
- Fix setting classification function weight

Version 1.6.10.4
- Implemented some optimization techniques to improve the performance
- Update classification of PROTO_MSSQL (to ignore port 102 - port for PROTO_S7COMM)
- Fixed some inline functions for compatible with newer version of gcc compiler (> 4.9)

Version 1.6.10.3
- Skip extracting HTTP header information if there is no data_analyser require for HTTP protocols: Improve the performance

Version 1.6.10.2
- Fixed NFS extraction
- Add PROTO_UNKNOWN if cannot find the protocol of some protocol which has classify_next_proto function base on a header value such as: PROTO_ETHERNET, PROTO_IP, PROTO_IPV6, PROTO_GTE, PROTO_GTP,...
- Change the minimum payload length of SSDP from 100 -> 50: there is the case that the SSDP packet payload length is 91 bytes. 50 is used as temporary value
- Add new protocol: PROTO_LLMNR, PROTO_ECLIPSE_TCF
- Remove LIGHTSDK -> we don't need LIGHTSDK since we have 2 APIs: disable_protocol_analysis() and disable_protocol_classification()

Version 1.6.10.1
- Fixed GTP offset
- Fixed FTP memory corruption when freeing command which contains special character
- Fixed Redis classification

Version 1.6.10.0
- Add classification function to 25 unknown protocols
- Update PROTO_SCTP: Extract more information
- Replace the 8 dead hostname protocols by new protocols from top 50 in France

#Version 1.6.9.2
- Deliver to THALES
- Fixed double free AVL tree on Centos environment
- Replace PROTO_GCM by PROTO_TWITCH
- Replace PROTO_GTP2 by PROTO_20MINUTES
- Replace PROTO_IMESSAGE by PROTO_ALIEXPRESS
- Replace PROTO_MANET by PROTO_FNAC
- Replace PROTO_QUICKTIME by PROTO_FORBES
- Replace PROTO_HTTP_CONNECT by PROTO_FOXNEWS
- Replace PROTO_FOXNEWS by PROTO_REUTERS

#Version 1.6.9.1
- Update PROTO_GTP: classify_next, extract GTP header information such as: version, proto_type,...
- Update PROTO_SCTP: add next protocols: PROTO_SCTP_INT, PROTO_SCTP_SACK, PROTO_SCTP_DATA
- Fixed FTP reconstruction in ACTIVE MODE - remove some unexpected value in the command
- Fixed problem with protocol loop: IP - GRE - IP - GRE - IP - TCP - HTTP
- Replace the 8 dead hostname protocols by new protocols from top 50 in France
	- Replace protocol grooveshark by groovesharks - hostname has changed
	- Update PROTO_GAZETEVATAN with new hostname
	- Change PROTO_INCREDIBAR by PROTO_LEBONCOIN
	- Replace PROTO_KAZAA by PROTO_ORANGEFR
	- Replace PROTO_LOKERZ by PROTO_LEMONDE
	- Replace PROTO_MSCDN by PROTO_LEFIGARO
	- Update hostname for PROTO_LIMELIGHT: add new hostnames: limelight.com, llnw.net
- Add classification function to 25 unknown protocols
	- Replace PROTO_302_FOUND by PROTO_ZONE_TELECHARGEMENT
	- Replace PROTO_GOSMS by PROTO_JEUXVIDEO
	- Add classification for PROTO_IPSEC by port number: 500 (Ref: nDPI)
	- Add classification for PROTO_OGG by content type after HTTP
	- Add classification for protocols by hostnames: PROTO_WECHAT, PROTO_BITGRAVITY, PROTO_CACHEFLY, PROTO_CDN77, PROTO_CDNETWORKS, PROTO_CHINACACHE, PROTO_FASTLY, PROTO_HIGHWINDS, PROTO_INTERNAP, PROTO_LEVEL3, PROTO_MAXCDN, PROTO_FBMSG
	- Replace PROTO_TLS by PROTO_CDISCOUNT
	- Replace PROTO_YAHOOGAMES by PROTO_ALLOCINE
	- Replace PROTO_COTENDO by PROTO_FRANCETVINFO
	- Replace PROTO_VOXTEL by PROTO_STACKPATH

Version 1.6.9.0
- Fixed some protocols based on hostname -> there are 8 protocol based on the hostname that does not exist anymore
- Fixed memory leaks in PROTO_NFS
- Fixed classification of PROTO_MANOLITO
- Fixed classification of PROTO_VNC: classified by port number - 5900, 5901, 5800 - nDPI
- Fixed classification of PROTO_EDONKEY: payload_len = 6 and some specific characters ('server status request') : resource - https://www.symantec.com/connect/articles/identifying-p2p-users-using-traffic-analysis
- Fixed classificaiton of PROTO_USENET: excluded incorrect protocol
- Fixed the classification of PROTO_THUNDER
- Fixed the classification of PROTO_I23V5
- Fixed the classification of PROTO_DIRECTCONNECT
- Fixed the classification of some protocols based on port number
- Fixed the classification of PROTO_SOULSEEK


Version 1.6.8.0
- Change package name (of .deb file) from mmt-sdk to mmt-dpi
- Fixed classification of PROTO_MSSQL
- Added classification of PROTO_PTP over ETHERNET (Need to do for PROTO_PTP Over UDP)
- Added classification of PROTO_PPP over ETHERNET
- Added classification of PROTO_FC over ETHERNET
- Added classification of PROTO_GTP
- Added classification of PPP over GRE
- Updated all application protocols which based on IP ranges
- Updated all application protocols which based on hostname
- Update with some optimisations in classifying protocol based on hostname and parsing HTTP header value
- Remove some APIs: unused (register_attribute), need to private (mmt_drop_packet,..)
- Add patch to fix the classification of Application protocol base on hostname
- Extract more HTTP header fields: Connection, Upgrade
- Cover also the header fields name is lowercase, uppercase, ...
- Fixed FTP/TCP/IPv6 segmentation fault and some memory leaks in proto_ftp.c
- Move some IP statistics to IP protocol: active_session, timedout_session, defragmentation, ....
- Fixed IP options pointer

Version 1.6.7.0
- Fixed buffer overflow when working with HTTP header field
- Fixed in FTP protocol: check tuple6==NULL and memory leak
- 1.6.6.1 - Fixed problem with IP fragmentation
- 1.6.6.2 - Revert to not copy IP address when building session key
- Fixed in HTTP protocol and SSL protocol: Change excluded_protocol_bitmask
- Fixed problem with IP Defragmentation and Packet padding
- Add PROTO_UNKNOWN after TCP if cannot classify TCP payload
- Refactory Makefile with some compiling options:
	+ NDEBUG = 1 : show all messages in debug(...),
	+ DEBUG = 1 : enable debug mode,
	+ SHOWLOG = 1 : show all messages in MMT_LOG(...),
	+ LIGHTSDK = 1 : compile the light version of SDK

Release version 1.6.6.0
- Add timestamp to built .deb and .zip files
- Extract file name from NFS protocol version 4 - only focus on some operation: OPEN, LOOKUP, REMOVE, RENAME
- Version 1.6.5.1: Fixed insert_key_value() - use memcpy to build session_key instead of using reference address
- Use inline function to optimize performance - Done by @Huu Nghia

Release version 1.6.5.0
- API for set SESSION TIMEDOUT
- Fixed classify SMTP protocol - not done
- Added GIT_VERSION into mmt_version()
- Fixed symbolic link warning when installing mmt-sdk
- Fixed attribute status when calling extraction function from mmt_security -> set ATTRIBUTE_CONSUMED flag.
- Initialize value for mmt_handler->current_ipacket
- Commented out some unused function in proto_dns.c. (Note: When testing memory leak, we need to test with dns-extraction.c to avoid memory from dns attributes)


Release version 1.6.4.0
- Add API function to unregister a protocol
- Add firing event when TCP session closed
- Extract DNS packets
- Updated ftp extraction functions - easy for probe to use
- Reconstruct HTTP packets
- Fixed some bugs and memory leaks in NDN protocol


Release version 1.6.3.1
- Hot fixed for ipv6 parsing
- Relocated mmt-sdk to opt/mmt/dpi

Release version 1.6.3.0
13 July 2016
- Added IP session ID to each FTP session
- Fixed extracting control session information for FTP Data packet
- Added number of capture packet and capture data volume in session
- Fixed some case of IP fragmentation: out of order, duplicated, lost fragment, ...
- Strategy for duplicated IP fragmentation: Not overwrite fragment (can be change easily)
- Added information about IP fragmentation in IP protocol statistic
- Updated session report - includes packet count and data volume from IP fragment packet (Fixed losing 20% of traffic)
- Fixed bug #78 -> Updated http_method after parsing header line in proto_http.c
- Fixed some memory leak in FTP plugin.
- Merge with ndn_http branch
- Classify all NDN packets as NDN_HTTP packets
- Change the installation location. Moved everything (lib, include, examples) to `/opt/mmt`. Created `/etc/ld.so.conf.d/mmt.conf` to update the environment variable for MMT
- Update script generates the installation file (.deb, .zip)


Release version 1.6.2.1
04 May 2016
- Fixed a bug with FTP PORT command
- Fixed proto_header_offsets and proto_classif_status for session base on ipacket hierarchy

Release version 1.6.2.0
2 May 2016
- Added proto_path_direction for session
- Fixed proto_path if the proto_path different with ipacket->proto_hierachy: ETH.IP/ ETH.802Q.IP

Release version 1.6.1.0
12 April 2016
- Added and updated some protocols:
	+ oracle
	+ quic
	+ redis_net
	+ vmware
	+ viber
	+ twitter
	+ skype
	+ mail_imap
	+ mail_pop
	+ mail_smtp
- Applied software versioning method to version number of release

Release version 1.6
06 April 2016

- Added option to use mmt-reassembly with mmt-sdk
- Has been tested with valgrind for: memory leak and multiple-thread

Release version 1.5
05 April 2016

- No copy packet in sdk
- Added new protocols: QUIC, NDN
- Fixed some data race to work with multi-thread
- Fixed some bugs in SDK
