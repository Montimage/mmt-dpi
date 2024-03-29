RELEASE NOTES
---

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
