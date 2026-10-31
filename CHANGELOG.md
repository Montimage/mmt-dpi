RELEASE NOTES
---

Unreleased
---

### ABI changes (every library's SONAME moves to `lib<name>.so.1`, #536)
- adopt a SOVERSION policy and gate it: every shared library is now linked with the versioned SONAME `lib<name>.so.$(SOVERSION)` (`SOVERSION := 1`, `rules/common.mk`), where v1.9.1 and earlier used the unversioned `lib<name>.so` — so a consumer or plugin built against v1.9.1 must be rebuilt once: the loader does not catch it (its NEEDED names the unversioned `lib<name>.so`, which every install still provides as the development link, and plugins are dlopen'ed with no NEEDED on `libmmt_core`). A consumer linked against SOVERSION 1 is refused by the loader when a later incompatible library bumps SOVERSION, instead of reading the wrong layout. Every install route lays down the runtime link `lib<name>.so.1 -> lib<name>.so.1.9.1` beside the library — `make -C sdk install` (recorded in the install manifest, removed by `uninstall`), the `.deb`/`.rpm` payloads (the `mmt-dpi-security` package carries its engines' links) and the offline ZIP (`SOVERSION` stamped into `mmt-install-common.sh` by `make zip`); upgrading in place, `make install` and the ZIP installer remove the earlier `lib<name>.so.<version>` files and links of each library they install, because one from v1.9.1 or before still carries SONAME `lib<name>.so` and `ldconfig` would otherwise repoint the development link at it; the unversioned `lib<name>.so` stays the development (link-time) link; the derived package dependencies are unchanged. Policy: an incompatible change to an installed library (a public struct layout, a removed or re-typed export) bumps `SOVERSION` and is recorded here. `tools/ci/abi-diff.sh` reports such a change as RECORDED when the library's SONAME moved, and `--fail-on incompatible` fails only on an unrecorded one (an unreadable SONAME counts as unrecorded); the `abi-diff` job runs both legs (the v1.9.1 tag rebuilt with types, the shipped v1.9.1 `.deb` symbols) with it and is listed in `.github/required-checks.txt`; `version-agreement` now also requires the job's `ABI_BASELINE` and the script's default baseline to equal the installer's pinned release tag, so the baseline moves with every release; fixture self-tests in the `release_gates` suite (#536)
- record the v1.9.0 packet layout change the v1.9.0 notes missed: v1.9.0 widened `ipv6_ext_headers_offset` in `struct ipacket_struct` (`ipacket_t`, `data_defs.h`) from `uint16_t` to `uint32_t` (#201) and appended the internal `proto_headers_offset_owned` (#199), `mmt_current_classifier` and `mmt_classifier_claim` (#252), so `sizeof(ipacket_t)` grew from 648 to 704 bytes on LP64 and every field from `ipv6_ext_headers_len` on moved 32 bytes later (`proto_hierarchy` 456 → 488, `session` 480 → 512, `data` 560 → 592) — under the same unversioned SONAME, so a consumer or plugin built against v1.8.0 read the wrong offsets from v1.9.0 libraries. Rebuild against v1.9.0 or later; the SONAME bump above makes the next such mismatch a load error (#536)
- move the engine-internal packet fields behind a private extension and pin the public packet layout (#535): `struct ipacket_struct` (`ipacket_t`, `data_defs.h`) keeps only its 19 public fields — `internal_proto_hierarchy`, `internal_proto_headers_offset`, `internal_proto_classif_status`, `internal_p_hdr`, `original_data`, `internal_cumulative_offset`, `internal_cumulative_offset_valid`, `internal_cumulative_offset_hwm`, `proto_headers_offset_owned`, `mmt_current_classifier` and `mmt_classifier_claim` now live in the engine-private `ipacket_internal_t` that embeds it. `sizeof(ipacket_t)` drops from 704 to 344 bytes on amd64/arm64; `packet_id` … `nb_reassembled_packets` keep their offsets, while `proto_hierarchy`, `proto_headers_offset`, `proto_classif_status`, `session`, `internal_packet`, `mmt_handler`, `p_hdr` and `data` move (to 280, 288, 296, 304, 312, 320, 328, 336). A consumer that only reads fields through the `ipacket_t *` it receives needs a rebuild, not a source change (`docs/first-run/hello_packet.c` builds unchanged); one that allocated, copied or embedded an `ipacket_t`, or read a removed field, must stop. An out-of-tree protocol plugin must be rebuilt too: one built against the old header has the old inline `invalidate_packet_offset_cache()` compiled in, which writes at the old offset into the new layout. `_Static_assert`s in `data_defs.h` pin every public offset and the size on LP64. `invalidate_packet_offset_cache()` is now an exported `libmmt_core` function instead of a header inline (same signature, NULL ignored). The engine hands `attribute_t *` out as a member of its internal attribute record instead of casting the whole record (`attribute_t` is unchanged)

### Core and protocols
- expose how each verdict was reached (#567, F-BUG-306): a DPI match, a hostname-table attribution (HTTP `Host`, TLS SNI), a correlated inference, an IP-range attribution and a port guess all set a session `Classified`, so a guess could not be told from a match. The new session attribute `meta.classification_method` (`META_CLASSIFICATION_METHOD`, appended to the `PROTO_META` attributes) and the new exports `get_session_classification_method()` and `get_classification_method_name()` return one of `MMT_CLASSIFICATION_METHOD_NONE`, `_PORT`, `_IP`, `_CORRELATED`, `_HOSTNAME`, `_DPI` (`data_defs.h`, ascending confidence), recorded where the verdict is decided — the tcpip flow-protocol funnel, the TCP/UDP IP-range and port fallbacks, the HTTP/TLS/RTP/SIP/STUN address and hostname lookups, the classifiers that match a hard-coded address range (WhatsApp, Viber, Gameforge, Tango, LINE, Ustream, Spotify, NetEase POPO: `ip`), and dissector claims above the transport layer in `set_classified_proto()`; it follows the protocol at the top of the session's application stack, so a later payload match replaces an earlier guess. The method byte sits in existing padding of the private session struct (no size change), the exports are additive; `docs/MMT-Attributes.md` documents the values, and the landing page's attribute count moves from 7,480 to 7,481. `check_precision.sh` now reports precision per method (`precision.txt` gains the per-method block and the abstention set's accepted-by-method line; every other row is unchanged), and the `classification-method` fixture of the `parser_boundaries` suite checks the method on accuracy-corpus captures of each kind; the golden classification fingerprint is unchanged
- bound the per-handler FTP control state and TCP reassembly memory (#563): FTP now registers a session-data cleanup, so a control session leaves the per-handler list when its flow expires instead of staying until the handler closes; a new control session is appended in O(1) instead of after a walk of every session ever seen (100,000 sessions: 0 list visits instead of 4,999,950,000), a data flow that outlives its control flow keeps the control session alive until it expires itself, data-connection lookups walk only live control sessions, and handler teardown frees the list iteratively instead of one stack frame per session. A data connection that opens after its control flow expired is no longer attributed to it. The FTP analysis no longer leaks its per-packet tuple (both IPv6 address buffers on every IPv6 FTP packet, and the whole tuple on a data packet seen before any control session). New `set_tcp_reassembly_budget(handler, bytes)` (additive export; 0, the default, leaves only the per-flow `set_tcp_reassembly_limit()` ceiling) bounds the sum over a handler's flows of reserved reassembly storage plus the image growth owed to flatten admitted bytes: segments past it are refused, dropped and counted by `mmt_tcp_reasm_bytes_dropped()`, and every admitted byte can still be flattened. New `resource_bounds` fixture `ftp-control` and a handler-budget case in `tcp-memory`; both phase0 baselines are unchanged
- fix the STATIC_LINK mode of 5Greplay and NetworkFuzzer (#675): a consumer that links `libmmt_core.a` before `libmmt_tcpip.so` holds only the archive members its references pull, and no core object called the functions the plugins import from `mmt_utils.o` (`hex2int`, `str_combine`, `str_copy`, `str_get_indexes_n`, `str_hex2str`, `str_sub_n`, used by `libmmt_tcpip`) and `mmt_log.o` (`mmt_log_event`, `mmt_log_write`, used by `libmmt_tmobile`), so the link stopped on `libmmt_tcpip.so`'s undefined references, or a dlopen()ed plugin failed with "undefined symbol". `mmt_init.c`, which every `init_extraction()` pulls, now references them (SDK build only); no export changed. `tools/ci/check-static-link.sh` links a consumer in the downstream order, requires every core symbol a plugin imports to be in the executable and runs it; the `installer` suite runs it against its installed SDK
- fix a reference-count leak in the IP session store (#707): `get_session()` (`ip_session_id_management.c`) raised the counts of both interned address ids before inserting the new session into the session map, and when that insert failed the rollback freed only the ids the call had created, so an address shared with a live session kept one count too many and its id and `ips_map` entry were never released. The counts are now raised only after a successful insert, for IPv4 and IPv6; the `core_engine` rollback test asserts that a failed insert leaves a shared lower and a shared higher id at their prior count. The path is reached only on an allocation failure or a saturated table; classification and both phase0 baselines are unchanged
- `unregister_protocol_by_id()` returns 0 without touching memory for an id at or above `PROTO_MAX_IDENTIFIER` and for a NULL registry slot: it read `is_free_protocol_id_for_registration()`'s 0, which also means "out of range", as "registered" and wrote through `configured_protocols[proto_id]` past the end of the array; it and `unregister_protocol_by_name()` now test the slot directly (range, NULL, `is_registered`), and the `core_engine` suite covers the out-of-range, NULL-slot and registered cases (#673)
- run one security engine per handler: the rule engine's state (`op`, `top_rule`, the packet counter, the XML loader's stacks, the corrupted-message count) moves from process globals into a per-engine `mmt_sec_engine_t`, so several handlers of one process can each load their own rule file with `init_sec_lib()` and report independent verdicts, also from different threads; a second `init_sec_lib()` on the same handler is still refused (Error 105), the new internal `close_sec_lib(mmt)` frees a handler's engine, and `docs/THREADING.md` lifts the one-engine-per-process rule of #512. Hash-table seeds are now drawn from `getrandom()` once per process instead of a fixed constant, so they are no longer predictable; `MMT_DETERMINISTIC_SEED=1` restores the fixed legacy sequence and the golden classification gate, the precision gate and the resource budgets set it (#551)
- route packet-path diagnostics through one logger (`src/mmt_core/private_include/mmt_log.h`, `mmt_log.c`): off by default, stderr only (never stdout), rate-limited to 10 lines per second per call site with the dropped count reported on the site's next line, and every event counted per level whether written or not (`mmt_log_get_stats()`); `MMT_DPI_LOG_LEVEL=off|error|warn|info|debug` sets the threshold at run time and a `SHOWLOG=1` build defaults it to `debug`; `mmt_log_debug()` lines compile out unless the build defines `DEBUG`, so a release build cannot print the subscriber-identifying fields they carry. S1AP decode failures (`S1AP_ERROR`/`S1AP_WARN`, which wrote one stdout line per malformed PDU) and the NAS decoder's `LOG` go through it; S1AP's `XER_FPRINT` trace writes to stderr; one-shot plugin init failures use `mmt_stderr_log`. The 1,180 `MMT_LOG*()` call sites in `mmt_tcpip`, defined as `{}` since 2014, are deleted (the built `libmmt_tcpip` code is unchanged but for two `__LINE__` constants). `tools/ci/lint-packet-path-io.sh` now also scans `src/mmt_mobile` (not its generated `asn1c/`), `src/mmt_business_app` and `src/mmt_dicom`, and fails on a macro definition line that writes to stdout (#545)
- decode NAS and NGAP fields as the specs lay them out (#573): the EPS QoS IE (TS 24.301 §9.9.4.3) is consumed whole for every content length, its rate groups are decoded when the length holds them whole and the Rel-11 extended-2 group is kept in the new `bit_rates_ext2`, so a 13-octet QoS no longer shifts the APN and PDN address of an Activate Default EPS Bearer Context Request; `s1ap.ue_ipv4` is now also extracted from an IPv4v6 PDN address (the IPv4 after the IPv6 interface identifier); `nas_5g.message_type` reports the inner message type of a 5GMM message with security header type 1 (integrity protected, not ciphered), which read 0; and `encode_ngap()` returns the bytes it wrote, as documented, instead of `aper_encode_to_buffer()`'s bit count — so the exported `update_ngap_data()`, which 5Greplay calls, now returns bytes: a caller that divided its result by 8 must stop. Regression tests in the `nas_ies_tail` and `s1ap_ngap_decode` suites; both phase0 baselines are unchanged
- move the hostname-suffix table to a versioned data file and give the Microsoft 365 suffixes their own labels (#566): `data/hostnames.txt` (`# version: YYYY-MM-DD` header, one `<suffix> <PROTO_ID>` per line) is the source of `mmt_tcpip_classif_doted_host_names.inc`, which `python3 tools/gen-hostname-table.py` regenerates and `--check` (run by the `core_engine` suite) keeps current; Teams, SharePoint and Office traffic that #82 labelled `livemail` is now `ms_teams`, `sharepoint` and `office365` (new protocol ids 664-666), OneDrive is `skydrive`, Entra ID sign-in (`microsoftonline.com`) is `azure` and `live.net` is `live` — 673 protocols, 7,480 attributes

- split the FTP dissector by concern: `proto_ftp.c` (3,355 lines) keeps the classifier, the session-data analysis and the registration, and four new units take the rest — `proto_ftp_session.c` (connection tuple and session structure lifecycles), `proto_ftp_parse.c` (command and reply parsing), `proto_ftp_addr.c` (PORT/EPRT/LPRT and 227/228/229 address parameters) and `proto_ftp_extract.c` (the extractors and the attribute table); `ftp.h` declares what they share and its classifier statics move into `proto_ftp.c`. The 25 FTP session extractors, which each carried a copy of the control/data session-resolution block, now share one resolver, `ftp_resolve_session()`; no file is over 1,200 lines, every attribute returns what it did (the new `ftp-sessions` fixture of the `parser_boundaries` suite reads all 25 from both connections of a passive download and from a data flow detached by the 226 reset), no export changed and both phase0 baselines are unchanged (#544)
- break up the last over-200-line functions of the security engine, DICOM and NDN, and replace the NAS decoder check macros (#548): `store_history`, `create_boolean_expression`, `compare_values`, `get_data_from_pcap`, DICOM's `_extraction_att` and `ndn_session_data_analysis` become dispatchers over static helpers (each ≤200 lines, nesting ≤6); the four `CHECK_*DECODER` macros of `src/mmt_mobile/nas/util/decoder.h`, which hid a `return`, become the `nas_check_pdu`/`nas_check_length` inline functions with explicit returns at each call site, and NAS warnings still name the decoding file and line. No behaviour change: the golden classification fingerprint and precision baselines are unchanged, and the `verify-helpers` job now gates the shape of these sources
- put the 38 defunct-service checker registrations (35 checkers) behind an opt-in `legacy` DPI profile (#540): MSN, Yahoo Messenger, AIM/ICQ (OSCAR), Meebo, Kazaa, iMesh, Pando, PPStream, the Zattoo P2P client protocol, pcAnywhere, MMS and the rest (`MMT_INTER_PROTO_LEGACY` rows of `inter_proto_classif_list.def`) no longer run on every unknown flow, while still-live services (Gnutella, NetEase POPO, SopCast, Kontiki, PPLive/PPTV, WinMX, AppleJuice) stay in the default chains; `mmt_apply_dpi_profile_by_name(h, "legacy")`, `MMT_DPI_PROFILE=legacy` or a sixth column of 1 in a custom profiles file restores them (`docs/DPI-Profiles.md`). Traffic of those services is now reported unknown by default — on the mmt-test captures, 296 MSN packets of `smallFlows.pcap` and 20 YMSG packets of `bigFlows.pcap`; the CI fingerprint and precision/recall baselines are unchanged. MSN no longer re-inspects flows already classified SSL, and the never-called `init_http_proto_struct()`, `tcp_seg_new()` and the undefined `PROTO_WINDOWS_UPDATE` paths are deleted
- delete the internal code the linker found unreachable (#541): `tools/ci/report-unreachable-sections.sh` builds the default SDK at -O0 with `-ffunction-sections` and `-Wl,--print-gc-sections` and lists every section the release link drops; 71 hidden functions and 8 data tables with no caller in any build profile, test or harness are deleted (in `libmmt_core`: `generic_data_extraction`, the `packet_stats.c` wrappers, `getmapsize`, `update_key_value`; in `libmmt_tcpip`: the unregistered HTTP attribute table and its lookups, the BATMAN sub-protocol inits, the DNS session callbacks, `mmt_check_ndn`, six unused `tcp_seg_*` list helpers, the IP/IPv6 fragment dumps and more); none was exported, so the ABI is unchanged; the HTTP/2 packet-rewrite functions stay, because 5Greplay calls `update_http2_data` through `libmmt_tcpip.a`; 30 public `libmmt_core` functions with no known caller in the SDK, its documentation, mmt-probe, mmt-security or 5Greplay are deprecated for removal in 2.0.0 (list in `docs/Exported-Symbols.md`)

### Build, CI and packaging
- bring the protocol listing, the heuristics catalogue and the landing page's claims back in line with the code (#559, #578): `tools/gen-protocol-list.sh` reads only line-initial rows of `proto_init_list.def`, so `docs/PROTOCOLS.md` no longer lists the header comment's `display_name` placeholder (649 initializers, not 650), and `tools/ci/check-protocol-count.sh` fails when the listing is stale or the landing-page chip quotes another count; every `file:line` link of `docs/Phase2-Heuristics.md` is re-cited and status-checked (H4 symmetric since #99, H8 resolved by #330) and guarded by `scripts/validate-doc-drift.sh`; the landing page replaces the unmeasured "line rate" claim with the bigFlows figures of the #555 replay benchmark, linked to it and its instruction-count gate, quotes the 6 distributions the install smoke matrix supports with a link to it, and describes both plugin routes; `tools/ci/check-runtime-protocol-count.sh` stages the plugins through `MMT_DPI_PLUGINS_DIR` since #503 stopped scanning the working directory
- add `mmt-dpi.spec`, an RPM recipe built from the release source tarball through `make -C sdk install-fhs` (`mmt-dpi` + `mmt-dpi-devel`, usable by COPR/OBS); the new `rpm-package` job builds it with `rpmbuild -ba`, lints it with `rpmlint` and runs the installed consumer on every EL image of the release matrix, amd64 and arm64 — not published: the GitHub Release `.rpm` assets still come from `make rpm`. Every install route now ships the pkg-config file `mmt-dpi.pc`: `make install` writes `$(MMT_LIB)/pkgconfig/mmt-dpi.pc` (recorded in the install manifest; with `-Wl,-rpath` for the prefix, so `PKG_CONFIG_PATH=/opt/mmt/dpi/lib/pkgconfig pkg-config --cflags --libs mmt-dpi` builds a consumer that runs without `LD_LIBRARY_PATH`), the `make deb`/`make rpm` packages ship it with a `/usr/share/pkgconfig/mmt-dpi.pc` link, and the installed-consumer check compiles through it. The offline ZIP (`dist/ZIP/`, `make zip`), which no workflow built, is retired and `install.sh` no longer sources its common file; the installed examples are now exactly the `src/examples/*.c` programs (`mmt_export_info.c` added; three nonexistent files and an uncopied capture dropped from `MMT_EXAMPLES_SRC`) (#550)
- close the M3 coverage gap and ratchet the floors (#554): a new `tests/core_engine` unit test, `test_ip_session_ids.c`, covers the IP session store (`ip_session_id_management.c`: IPv4/IPv6 address interning, `get_session()` and `free_session_data()` reference counting and expiry-list unlinking, every allocation and insert failure rolled back through link-time `--wrap` faults, the per-protocol session counters), taking the unit cohort from 81.5% to 84.35% and the whole SDK to 71.66% (aarch64, GCC 13.3); `tests/coverage/floor.json` moves the unit floor 73.7 to 83.1 (47 instrumented files), `whole_sdk_line_pct` 64.5 to 70.6 and the core, tcpip, dicom and security_fuzz family floors to the lower of the aarch64 measurement and the x86-64 projection minus 1 (mobile and business_app keep theirs, which measured minus 1 would not raise); the test found that a failed session-map insert leaves a shared address id's count one too high (#707), left unfixed here
- grow the accuracy corpus by a second tranche: 40 new synthetic cases give 20 more default-chain classifiers a positive and a negative case (NNTP, ActiveSync, Icecast, SHOUTcast, NDN-over-HTTP, DCE/RPC, AFP, Citrix ICA, RTMP, ICE-TCP STUN, IAX2, Eclipse TCF, MQTT, X11/XDMCP over TCP and UDP, TeamViewer over TCP and UDP, Steam, World of Warcraft, Xbox Live), so 68 of the 143 classifiers are covered and `coverage-pending.txt` shrinks from 95 to 75 entries; the pending reasons now name the classifiers no genuine flow can reach (VNC and TPKT excluded on the TCP handshake, TDS shadowed by MSSQL, RTP over TCP shadowed by STUN, Spotify and direct-download links keyed on real addresses and host names); no classifier source and no gate baseline changed (#527)
- benchmark the attribute/handler path and gate its instruction counts (#555): `phase0_throughput` takes `PHASE0_MODE=bare|attrs8|all` — no attribute, a fixed 8-attribute set fetched by a packet handler, or fetch-all (every protocol attribute registered, and every attribute of each layer of the packet's protocol path fetched per packet) — and appends a `ns_per_pkt` column; the new required `instruction-gate` job (`phase0-baseline.yml`, `ubuntu-24.04-arm`) runs `tools/phase0/ci/check_instructions.sh`, which counts the replay's instructions under callgrind (bracketed by `CALLGRIND_TOGGLE_COLLECT`, `MMT_DETERMINISTIC_SEED=1`) over the vendored CI pcaps per mode and fails when one rises more than 2 % above `tools/phase0/ci/baseline/instructions.txt` (aarch64 / GCC 13: bare 10,510, attrs8 11,589, fetch-all 51,790 instructions per packet); `tools/phase0/capture_perf.sh` refreshes `tools/phase0/baseline/perf/throughput.txt` per mode, now measured on the aarch64 reference host: bigFlows bare 3,461,380 pps (288.9 ns/pkt), fetch-all 1,780.3 ns/pkt, library RSS peak 33,148 KiB over 200 iterations; acceptance harness `tools/phase0/tests/run_throughput_attrs_test.sh`

Version 1.9.1 (21 October 2026)
---

### Build, CI and packaging
- cache SDK builds and run the PR gates locally: `MMT_CCACHE=ccache` puts an opt-in compiler cache in front of the GCC toolchain's compiler (unset changes nothing; `BUILD=coverage` stays uncached), the per-install-prefix `PLUGINS_REPOSITORY_OPT` and per-commit `GIT_VERSION` defines now reach only `plugins_engine.o` and `packet_processing.o` so every other compile line is stable across prefixes and commits (the built libraries are byte-identical), the `unit-tests` and `sanitizer-tests` jobs restore a ccache that push and schedule runs save, the new `tools/ci/local-gates.sh` (`--fast`/`--full`) runs the `lint`, `verify-helpers` and `doc-validators` steps read from `c-cpp.yml` in a container built from the lint job's pinned image, and the gitleaks pre-commit hook is pinned to its tag's commit (#553)
- grow the accuracy corpus toward every classifier of the default TCP/UDP chains: `tools/ci/tests/check-accuracy-corpus.py` now reads the registrations in `inter_proto_classif_list.def` and requires a positive and a negative case naming each classifier, or an entry with its reason in the shrink-only `tools/phase0/ci/accuracy/coverage-pending.txt` (enforced against the base commit with `--base`); 92 new synthetic cases cover 48 of the 143 classifiers (95 pending) and record known misses (BitTorrent DHT, MySQL 8 greetings) and a port-only MQTT accept; `check_precision.sh` also runs a seeded random-payload abstention set (12 lengths, TCP and UDP) and the precision baseline records its unknown rate in a new section, the labelled FTP/HTTP rows unchanged (#527)
- give the secret scan real detection rules: `.gitleaks.toml` loaded no rules (only a legacy `[allowlist]`), so the scan passed on any secret; it now extends gitleaks' default ruleset, uses `[[allowlists]]` (the S1AP regex matches the whole finding via `regexTarget = "match"`), suppresses the 52 history-only `.ep` false positives by fingerprint in `.gitleaksignore`, and `tools/ci/check-gitleaks-allowlist.sh` fails a rule-less config; the new `tools/ci/tests/test-gitleaks-canary.sh` (secret-scan job) asserts a planted AWS key fails `tools/ci/run-gitleaks.sh`; SECURITY.md and CONTRIBUTING.md describe the actual pinned v8.30.1 scan (#488)
- make `rules/common.mk` `VERSION` the single version source: bump to 1.9.1 (the v1.9.0 tag shipped `VERSION := 1.8.0`); `scripts/validate-release-prep.sh` now compares every version site with it — `mmt_core.h`, the ZIP fallback, this file's topmost heading, `debian/changelog` when present, and the installer's pinned `RELEASE_TAG` with the README and site mentions of it — and runs as its own blocking PR job, `version-agreement`, with a mismatch-fixture self-test; the release checklist lists exactly those sites, the v1.9.0 date is corrected to its tag date, and PRs now add their line to the topmost `Version x.y.z (unreleased)` section (#483)
- repair the source one-liner: `install.sh` pinned `v1.9.0` to the v1.8.0 commit, so every documented install aborted — `RELEASE_TAG_SHA` is now the peeled `v1.9.0` commit, and `tools/ci/check-release-tag.sh` fails when it is not `git rev-parse "$RELEASE_TAG^{commit}"` (blocking in the `version-agreement` PR job, with a fixture self-test in the `release_gates` suite; `--write-pin vX.Y.Z` writes both lines after a release); under `curl | bash` the installer no longer treats the caller's working directory as its checkout; the dnf/yum branches enable CRB / PowerTools so `libpcap-devel` installs on EL8/EL9; every documented one-liner uses `curl -fsSL` so an HTTP error aborts instead of piping an error page to bash (#484)
- make the release workflow the only publisher: `tools/ci/check-release-tag.sh <tag>` now also requires the tagged commit to be an ancestor of `origin/main` (`git merge-base --is-ancestor`; v1.9.0 was tagged on a stale release-branch commit), fail-closed on a missing tag or base ref or a shallow clone; the `release` job creates the Release itself through `tools/ci/publish-release.sh` — draft with every asset, then published — and refuses when one already exists (a hand-made Release), replacing `softprops/action-gh-release`; a new `release-alert` job opens an issue when a tag run fails; the release checklist tags on `main` and forbids publishing by hand; fixture self-tests in the `release_gates` suite (#489)
- repin the centos-stream9 base image twice after upstream digest GCs; quay retags `stream9` about weekly and drops old manifests (#587, #590)
- pin and auto-refresh every CI image and tool: `tools/ci/check-image-digests.sh` with no argument now scans every workflow and composite action (`image:`, `container:`, `uses: docker://` and `docker run|create|pull` operands) and fails on a floating, unrecorded or unused pin; the asn1c gate container `buildpack-deps:bookworm` is digest-pinned and recorded in `tools/ci/base-images.txt`; the new daily `base-image-refresh` workflow runs `tools/ci/refresh-base-images.sh --check`, which resolves every recorded tag with `docker buildx imagetools inspect` and fails on a moved tag or a digest the registry no longer serves, then proposes the `--write` repin as one pull request (with the optional `BASE_IMAGE_REFRESH_TOKEN` secret, since `GITHUB_TOKEN` cannot push workflow changes) or else one "Base image pins out of date" issue carrying the diff; Dependabot also tracks the docs site gems (`bundler`, `/docs`); the CI `pre-commit` install is pinned to 4.6.2; fixture self-tests in the `release_gates` suite (#491)
- register the loader on every root install and ship a working uninstall: `make -C sdk install` registers `$(MMT_LIB)` in `/etc/ld.so.conf.d/mmt-dpi.conf` and runs `ldconfig` whenever it runs as root, whatever `MMT_BASE` is (it used to only when `MMT_BASE` was unset, so the one-command installer never registered it); `LDCONF=0` opts out; new `make -C sdk uninstall` (`dist-clean` is now its alias — it used to leave the plugins, examples and drop-in behind) and `install.sh --uninstall`; the installer registers the loader itself on root installs and drops its `LD_LIBRARY_PATH` advice then; `make install` no longer depends on `sdk` and never compiles — it refuses a missing build or one made for another prefix, and `plugins_engine.o` now recompiles only when the plugin directory changes; the new `root-install` CI job runs `tools/ci/tests/run-root-install.sh` in `ubuntu:24.04` (root install, consumer with `LD_LIBRARY_PATH` unset via the new `run-installed-consumer.sh --root-install`, uninstall leaves nothing); uninstall removes only the entries `install` recorded in `<prefix>/.mmt-dpi-manifest` — never `rm -rf` on the include/examples trees — and both `install`/`uninstall` and `install.sh` refuse a prefix (or SDK directory) with an empty, `.` or `..` component, a glob or whitespace character, or one outside `MMT_BASE` (#485)
- make the dependency advisory gate passable and run it weekly: `tools/ci/check-dependency-advisories.sh` no longer counts Debian `unimportant` / Ubuntu `negligible` records as blocking, reads time-boxed per-advisory decisions from the new `tools/ci/advisory-dispositions.txt` (an expired entry fails the run), also queries the repository security advisories of the direct docs gems and the pinned actions (it now reports GHSA-572m-7cg5-6j5r and GHSA-3343-386p-v26g against `docs/Gemfile.lock`), maps Debian 13/trixie and excludes the `buildpack-deps` tooling image; the new weekly `dependency-advisories` workflow uploads the report as an artifact, replacing the committed `tools/ci/dependency-advisories.md` snapshot; fixture self-test in the `release_gates` suite (#492)
- record and check the required status checks: `.github/required-checks.txt` lists the 27 contexts branch protection on `main` must require (the 16 set by #184 plus toolchain-floor, assertions-live, codeql, fuzz, both resource-budgets legs, site-onboarding, root-install, leak-gate, version-agreement and packages-gate); `tools/ci/check-required-checks.sh` (verify-helpers, blocking) fails on a context that names no job reporting on pull requests; `release-packages.yml` gained the always-reporting `packages-gate` aggregate (its path filter moved into a `changes` job); `leak-gate` and `version-agreement` report under their job ids; `.github/CODEOWNERS` now covers the CI scripts and configs, installers, build rules, packaging and `SECURITY.md` (#490)
- smoke-test the one-command install per advertised distribution: the new `install-smoke` workflow runs `tools/ci/smoke-install.sh` in a fresh container per distribution the docs name — the README `curl -fsSL … | bash`, then the landing-page `hello_packet` steps of `docs/_includes/first-example.md` with `LD_LIBRARY_PATH` unset, compared with the displayed output; pull requests touching the installer or first-run files read `install.sh` from the checkout over `file://` and redirect its clone there, while the weekly, post-release (completed tag run or `release: published`) and manual runs use the published script and site; Ubuntu 22.04/24.04, Debian 12, Rocky 9, CentOS Stream 9, Fedora 44 and openSUSE Leap 16.0 must pass, Arch and Alpine (musl: the SDK does not build there) are best-effort, and a failing supported leg on an unattended run opens an `Install smoke matrix failing` issue; README and the site now label Arch, Alpine and RHEL itself best-effort; `tools/ci/refresh-base-images.sh` honours a per-entry `# platforms: linux/amd64` for the amd64-only `archlinux` image, and `tools/ci/check-dependency-advisories.sh` excludes the four smoke-only images (no package ships for them) and drops inline baseline comments; the release checklist gains the v1.9.1 cut sequence (#493)

Version 1.9.0 (26 September 2026)
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
- verify the first run through the built site artifact: CI builds the site and runs the displayed steps against `docs/_site`; the landing page's first-example card no longer widens the page past a phone screen, the fetch hint is shown only for the sample capture, and desktop/mobile browser checks are recorded in `docs/DECISIONS.md` (#396)
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
- the fuzz gate's quality-estimation driver frees every model it parses, and `tools/ci/run-fuzz.sh` runs that target with LeakSanitizer on (`detect_leaks=1`), so a model the XML parser leaks on a mutated input is a finding; the pcap target keeps `detect_leaks=0` (#470)

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
- QUIC-IETF: classify QUIC version 2 (RFC 9369) alongside version 1 and report its long packet types in RFC 9000 numbering; classify coalesced packets of one datagram (RFC 9000 §12.2) as QUIC after QUIC, dropping the chained layer again on later single-packet datagrams; parse short headers with the connection-ID length the receiving endpoint announced in its long headers instead of a fixed 8 bytes (packet numbers are now read big-endian at that offset); probe QUIC over INT at the INT shim length. The accuracy corpus' QUIC v2 case becomes a positive case and a draft-29 Initial is the new ambiguous case; new `parser_boundaries` `quic` fixture (#333)
- implement advertised TCP/IP attribute extractions: new `tcp.mss`, `tcp.wscale` and `tcp.sack_permitted` option attributes (appended ids; 7,450 attribute registrations), `tcp.syn_received` now fills its declared 4-byte width, `radius.dns_ipv6` reports the primary 3GPP IPv6 DNS server, and the (currently uncalled) legacy HTTP attribute-scope getter reads each attribute's own scope; GRE sequence/loss tracking and the other design-dependent items move to #455 (#331)
- INT: claim INT only when the carrier DSCP is 0x20 **and** the TCP/UDP payload starts with a valid INT v1.0 shim + metadata header (type 0/1, Length of at least 3 words fitting the payload, Ver 1) — DSCP 0x20 is also the standard CS4 class, so CS4-marked non-INT traffic is no longer labelled INT; one shared validator (`proto_int_valid_shim_length`) sizes the layer after INT, the QUIC-over-INT offset and the INT-report inner packet, which now carries an INT layer only with a valid shim; hops advance by Hop ML when it covers the parsed fields; INT-report inner non-first IPv4 fragments are rejected; `int_report.ip_src`/`ip_dst` are now in network byte order like `ip.src`/`ip.dst` (they printed byte-swapped before) (#453)
- close the remaining #331 items: `gre.seq_out`, `gre.seq_in`, `gre.seq_gap` and `gre.loss` are deprecated — never extracted, ids reserved and still registrable (derive per-tunnel sequence state from `gre.key`/`gre.seqnb`); GTP keeps one arm for every non-G-PDU message (none carries a T-PDU; `gtp.msg_type` exposes the type); the internal-struct realignment note is dropped pending profiling data; libmmt_fuzz gains `init_application_quality_estimation_context()`/`free_application_quality_estimation_context()`, the generic per-session setup RTP now uses, and its sampler no longer writes one element past its stack array (#455)
- S1AP: libmmt_tmobile no longer exports the generated asn1c runtime (`asn_*`, `aper_*`, …; built with `-fvisibility=hidden`), so a host linking its own asn1c cannot interpose it or see the ANY-decoder patch; UEContextRelease Command/Request skip IEs from later releases (e.g. id 264) instead of rejecting the message; IMSIs of 6–13 digits (IE length 4–7) are decoded per TS 24.301 §9.9.3.12 (#443)
- NAS: a ciphered EPS NAS PDU is no longer parsed as plain text when its S1 connection's Security Mode Command selected EEA1/EEA2/EEA3 (learned from DownlinkNASTransport into a bounded 1024-slot table), so `s1ap.ue_ipv4` and `s1ap.m_tmsi` are not read from ciphertext; with no Security Mode Command seen, only a PDU whose first octet is that of a plain NAS message is decoded. NAS decryption stays out of scope (docs/DECISIONS.md) (#452)
- fuzz engine (`ENABLESEC=1`): the quality-estimation XML parser attaches a model's `<rules>` to the model's own quality metric instead of a hard-coded metric id 3, and frees — and reports — a rule set it cannot attach or that a later `<rules>` node replaces (the last one is kept) instead of leaking it; new NULL-safe `free_application_quality_estimation_rules()` in `fuzz/mmt_quality_estimation_utilities.h` (#466)
- fuzz engine (`ENABLESEC=1`): the quality-estimation XML parser frees — and reports — a second `<indexs>` quality metric the model cannot hold instead of leaking it with its grades (new NULL-safe `free_metric_struct()`), and `init_application_quality_estimation_context()` refuses a model whose quality metric has no usable rules (no `<rules>`, `<rules>` before `<kpis>`, a rule without input/output elements) while the estimation path skips such rules instead of dereferencing NULL (#468, #469)

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
- enforce the resource budgets in CI: new `resource-budgets` job runs every `resource_bounds` fixture on amd64 and arm64, validates `results.json` against its schema and re-checks every budget with `tools/ci/check-resource-budgets.py`, failing on an over-budget count or a missing dimension, workload record or metric (its `--self-test` proves each failure is detected) and uploading the results; malformed budgets are now named (`invalid budget`) instead of reported as a missing metric, and per-fixture wall-clock is recorded only as a labelled observation (#395)

Version 2.0.0 (unreleased — scheduled removals)
- remove the four deprecated public symbols recorded under issues #149 and #237 (issue #232):
  `setDataLinkType` (obsolete; no replacement),
  `get_attribute_extracted_data_encap_index` (use `get_attribute_extracted_data_at_index`),
  `mmt_print_all_protocols` (use `iterate_through_protocols`), all in `libmmt_core`,
  and `mmt_search_irc_ssl_detect_ninty_percent_but_very_fast` (use `mmt_search_irc_ssl_detect`)
  in `libmmt_tcpip`. All four are `__attribute__((deprecated))` today and keep their
  exported ABI until this major release.
- remove `is_free_protocol_id_for_registractionl` from `libmmt_core` (issue #546):
  the misspelled name of `is_free_protocol_id_for_registration`, deprecated and still
  exported until this major release.
- remove the 30 `libmmt_core` functions deprecated under issue #541 for having no known caller (listed in `docs/Exported-Symbols.md`), once the mmt-probe, mmt-security and 5Greplay maintainers confirm they do not use them, and the three `mmt_utils.h` functions deprecated in favour of their bounded `_n` variants (`str_hex2int`, `str_sub`, `str_get_indexes`; issue #541 names the release).

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
