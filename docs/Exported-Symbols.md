---
layout: default
title: "Exported Symbols"
---

> ⚠️ This document is auto-generated and may drift as symbols change.
> The first table lists the `T` symbols `nm -gC --defined-only` reports for
> the built `libmmt_core.so`; the `public` column is derived from membership
> in the installed public headers (`src/mmt_core/public_include/*.h`), not
> from the symbol table. The protocol-plugin tables at the end list what
> `nm -D --defined-only` reports for each plugin. Regenerate/check with:
> `bash scripts/validate-exported-symbols.sh [--write]` — the doc-validators CI
> job runs it on every PR (issue #187, Task 0.7).

Here is the complete list of the functions `libmmt_core.so` exports, followed
by the export sets of the protocol plugins.

Since issue #533, `MMTAPI` is the export marker: the core objects are compiled
with `-fvisibility=hidden` (`rules/common.mk`, the #533 block at the end of the
file) and `MMTAPI` carries `visibility("default")` inside the SDK build
(`src/mmt_core/public_include/mmt_exports.h`). A core symbol is exported only
when it is declared `MMTAPI`. The `public = N` rows are private-header
internals that `libmmt_tcpip` resolves after `dlopen()`
(`src/mmt_core/private_include/hash_utils.h`, `hashmap.h`,
`packet_processing.h`). They stay `MMTAPI` while `libmmt_tcpip` needs them
(#534 hid the plugins' own internals and left these in place). The
four `MMT_DPI_PROFILE_*` objects are exported `R` (read-only data) symbols, so
this `T` table does not list them. Tests that call hidden internals link
`libmmt_core.a` (`tools/phase0/tests/static_core_link.sh`).
`scripts/validate-exported-symbols.sh` also fails when `nm -D --defined-only`
lists more symbols than the `MMTAPI` declarations in
`src/mmt_core/{public,private}_include/*.h` plus 5, any symbol that is not
one of those declarations, or misses one of them.

> **Deprecation note (2026-09, #149):** The following 3 public ABI symbols are exported
> (`nm -D local_install/dpi/lib/libmmt_core.so | grep ' T '` confirms) but have **0 callers**
> outside their definition/headers (`grep -r <symbol> src sdk/tests sdk/examples tests examples`
> shows only declaration+definition). They are now marked
> `__attribute__((deprecated))` in `src/mmt_core/public_include/mmt_core.h:938,795,640`
> (and mirrored in `sdk/include/mmt_core.h`) and are scheduled for removal in
> release 2.0.0 — recorded in `CHANGELOG.md` (issue #232):
> `setDataLinkType` (obsolete, @obsolete since long), `get_attribute_extracted_data_encap_index`
> (redundant with `get_attribute_extracted_data_at_index`), `mmt_print_all_protocols` (debug helper, prefer `iterate_through_protocols`).

> **Deprecation note (2026-09, #237):** `mmt_search_irc_ssl_detect_ninty_percent_but_very_fast`
> (libmmt_tcpip) keeps its exported symbol for ABI stability but is now
> `__attribute__((deprecated))` in `src/mmt_tcpip/lib/protocols/proto_irc.c:376-377`.
> It is declared `MMTAPI` there, so it stays exported from the hidden-visibility
> plugin (issue #534) until its removal.
> Use the correctly named alias `mmt_search_irc_ssl_detect` (same signature and
> behaviour, defined alongside at `proto_irc.c:356`). The misspelled name is
> scheduled for removal in release 2.0.0.

Symbol table


| #   | symbol | public |
|-:|:-|:-:|
|1|`char2int`|**Y**|
|2|`clear_map_space`|N|
|3|`close_extraction`|**Y**|
|4|`debug_extracted_attributes_printout_handler`|**Y**|
|5|`delete_key_value`|N|
|6|`delete_map_space`|N|
|7|`delete_session_from_protocol_context`|N|
|8|`disable_hostname_classify`|**Y**|
|9|`disable_ip_address_classify`|**Y**|
|10|`disable_mmt_reassembly`|**Y**|
|11|`disable_port_classify`|**Y**|
|12|`disable_port_classify_payload_confirm`|**Y**|
|13|`disable_protocol_analysis`|**Y**|
|14|`disable_protocol_classification`|**Y**|
|15|`disable_protocol_statistics`|**Y**|
|16|`enable_hostname_classify`|**Y**|
|17|`enable_ip_address_classify`|**Y**|
|18|`enable_mmt_reassembly`|**Y**|
|19|`enable_port_classify`|**Y**|
|20|`enable_port_classify_payload_confirm`|**Y**|
|21|`enable_protocol_analysis`|**Y**|
|22|`enable_protocol_classification`|**Y**|
|23|`enable_protocol_statistics`|**Y**|
|24|`find_key_value`|N|
|25|`fire_attribute_event`|**Y**|
|26|`fire_evasion_event`|**Y**|
|27|`general_byte_to_byte_extraction`|**Y**|
|28|`general_char_extraction`|**Y**|
|29|`general_int_extraction`|**Y**|
|30|`general_int_extraction_with_ordering_change`|**Y**|
|31|`general_short_extraction`|**Y**|
|32|`general_short_extraction_with_ordering_change`|**Y**|
|33|`get_active_session_count`|**Y**|
|34|`get_application_name`|**Y**|
|35|`get_attr_data`|**Y**|
|36|`get_attr_data_len`|**Y**|
|37|`get_attr_data_type`|**Y**|
|38|`get_attr_id`|**Y**|
|39|`get_attr_offset`|**Y**|
|40|`get_attr_protocol_id`|**Y**|
|41|`get_attr_protocol_index`|**Y**|
|42|`get_attr_scope`|**Y**|
|43|`get_attr_status`|**Y**|
|44|`get_attribute_data_type`|**Y**|
|45|`get_attribute_extracted_data`|**Y**|
|46|`get_attribute_extracted_data_at_index`|**Y**|
|47|`get_attribute_extracted_data_by_name`|**Y**|
|48|`get_attribute_extracted_data_encap_index`|**Y**|
|49|`get_attribute_id_by_protocol_and_attribute_names`|**Y**|
|50|`get_attribute_id_by_protocol_id_and_attribute_name`|**Y**|
|51|`get_attribute_name_by_protocol_and_attribute_ids`|**Y**|
|52|`get_attribute_scope`|**Y**|
|53|`get_children_stats`|**Y**|
|54|`get_classification_max_depth`|**Y**|
|55|`get_classification_threshold`|**Y**|
|56|`get_data_link_type`|**Y**|
|57|`get_data_size_by_data_type`|**Y**|
|58|`get_data_size_by_proto_and_field_ids`|**Y**|
|59|`get_extracted_attribute`|**Y**|
|60|`get_extracted_attribute_at_index`|**Y**|
|61|`get_extracted_attribute_at_index_by_name`|**Y**|
|62|`get_extracted_attribute_by_name`|**Y**|
|63|`get_field_position_by_protocol_and_field_ids`|**Y**|
|64|`get_last_activity_time`|**Y**|
|65|`get_packet_offset_at_index`|**Y**|
|66|`get_proto_attribute_id`|**Y**|
|67|`get_proto_attribute_length`|**Y**|
|68|`get_proto_attribute_name`|**Y**|
|69|`get_proto_attribute_position`|**Y**|
|70|`get_proto_attribute_scope`|**Y**|
|71|`get_proto_attribute_type`|**Y**|
|72|`get_proto_session_data`|**Y**|
|73|`get_proto_session_data_from_packet`|**Y**|
|74|`get_protocol_id_at_index`|**Y**|
|75|`get_protocol_id_by_name`|**Y**|
|76|`get_protocol_index_by_id`|**Y**|
|77|`get_protocol_index_by_name`|**Y**|
|78|`get_protocol_name_by_id`|**Y**|
|79|`get_protocol_stack_name`|**Y**|
|80|`get_protocol_stats`|**Y**|
|81|`get_protocol_stats_path`|**Y**|
|82|`get_protocol_struct_by_id`|**Y**|
|83|`get_protocol_struct_for_registration_if_free`|**Y**|
|84|`get_session_byte_count`|**Y**|
|85|`get_session_content_class_id`|**Y**|
|86|`get_session_content_flags`|**Y**|
|87|`get_session_content_type_id`|**Y**|
|88|`get_session_data_byte_count`|**Y**|
|89|`get_session_data_cap_volume`|**Y**|
|90|`get_session_data_packet_count`|**Y**|
|91|`get_session_dl_byte_count`|**Y**|
|92|`get_session_dl_cap_byte_count`|**Y**|
|93|`get_session_dl_cap_packet_count`|**Y**|
|94|`get_session_dl_data_byte_count`|**Y**|
|95|`get_session_dl_data_packet_count`|**Y**|
|96|`get_session_dl_packet_count`|**Y**|
|97|`get_session_from_packet`|**Y**|
|98|`get_session_from_protocol_context_by_session_key`|N|
|99|`get_session_handler`|**Y**|
|100|`get_session_id`|**Y**|
|101|`get_session_id_from_packet`|**Y**|
|102|`get_session_init_time`|**Y**|
|103|`get_session_last_activity_time`|**Y**|
|104|`get_session_last_data_packet_time_by_direction`|**Y**|
|105|`get_session_last_packet_direction`|**Y**|
|106|`get_session_next`|**Y**|
|107|`get_session_outoforder_count`|**Y**|
|108|`get_session_packet_cap_count`|**Y**|
|109|`get_session_packet_count`|**Y**|
|110|`get_session_parent`|**Y**|
|111|`get_session_previous`|**Y**|
|112|`get_session_proto_path_direction`|**Y**|
|113|`get_session_protocol_hierarchy`|**Y**|
|114|`get_session_protocol_index`|**Y**|
|115|`get_session_retransmission_count`|**Y**|
|116|`get_session_rtt`|**Y**|
|117|`get_session_setup_direction`|**Y**|
|118|`get_session_total_byte_count`|**Y**|
|119|`get_session_total_data_byte_count`|**Y**|
|120|`get_session_total_data_cap_volume`|**Y**|
|121|`get_session_total_data_packet_count`|**Y**|
|122|`get_session_total_dl_byte_count`|**Y**|
|123|`get_session_total_dl_cap_byte_count`|**Y**|
|124|`get_session_total_dl_cap_packet_count`|**Y**|
|125|`get_session_total_dl_data_byte_count`|**Y**|
|126|`get_session_total_dl_data_packet_count`|**Y**|
|127|`get_session_total_dl_packet_count`|**Y**|
|128|`get_session_total_packet_cap_count`|**Y**|
|129|`get_session_total_packet_count`|**Y**|
|130|`get_session_total_ul_byte_count`|**Y**|
|131|`get_session_total_ul_cap_byte_count`|**Y**|
|132|`get_session_total_ul_cap_packet_count`|**Y**|
|133|`get_session_total_ul_data_byte_count`|**Y**|
|134|`get_session_total_ul_data_packet_count`|**Y**|
|135|`get_session_total_ul_packet_count`|**Y**|
|136|`get_session_ul_byte_count`|**Y**|
|137|`get_session_ul_cap_byte_count`|**Y**|
|138|`get_session_ul_cap_packet_count`|**Y**|
|139|`get_session_ul_data_byte_count`|**Y**|
|140|`get_session_ul_data_packet_count`|**Y**|
|141|`get_session_ul_packet_count`|**Y**|
|142|`get_user_session_context`|**Y**|
|143|`get_user_session_context_from_packet`|**Y**|
|144|`has_registered_attribute_handler`|**Y**|
|145|`hashmap_get`|N|
|146|`hashmap_insert_kv`|N|
|147|`hashmap_remove`|N|
|148|`hashmap_walk`|N|
|149|`hex2char`|**Y**|
|150|`hex2dec`|**Y**|
|151|`hex2int`|**Y**|
|152|`hex2str`|**Y**|
|153|`htoi`|**Y**|
|154|`init_extraction`|**Y**|
|155|`init_map_space`|N|
|156|`init_protocol_struct_for_registration`|**Y**|
|157|`insert_key_value`|N|
|158|`insert_session_into_protocol_context`|N|
|159|`is_free_protocol_id_for_registractionl`|**Y**|
|160|`is_protocol_attribute`|**Y**|
|161|`is_registered_attribute`|**Y**|
|162|`is_registered_attribute_handler`|**Y**|
|163|`is_registered_packet_handler`|**Y**|
|164|`is_registered_protocol`|**Y**|
|165|`is_valid_proto_attribute`|**Y**|
|166|`is_valid_protocol_id`|**Y**|
|167|`iterate_through_mmt_handlers`|**Y**|
|168|`iterate_through_protocol_attributes`|**Y**|
|169|`iterate_through_protocols`|**Y**|
|170|`mapspace_iteration_callback`|N|
|171|`mmt_apply_dpi_profile`|**Y**|
|172|`mmt_apply_dpi_profile_by_name`|**Y**|
|173|`mmt_arena_alloc`|**Y**|
|174|`mmt_arena_create`|**Y**|
|175|`mmt_arena_destroy`|**Y**|
|176|`mmt_arena_reset`|**Y**|
|177|`mmt_attr_format`|**Y**|
|178|`mmt_attr_fprintf`|**Y**|
|179|`mmt_attr_sprintf`|**Y**|
|180|`mmt_close_handler`|**Y**|
|181|`mmt_drop_packet`|**Y**|
|182|`mmt_free`|**Y**|
|183|`mmt_inet_ntop`|**Y**|
|184|`mmt_init_handler`|**Y**|
|185|`mmt_load_dpi_profiles_file`|**Y**|
|186|`mmt_malloc`|**Y**|
|187|`mmt_packet_scratch_adopt`|**Y**|
|188|`mmt_print_all_protocols`|**Y**|
|189|`mmt_print_info`|**Y**|
|190|`mmt_realloc`|**Y**|
|191|`mmt_strcasecmp`|**Y**|
|192|`mmt_strcmp`|**Y**|
|193|`mmt_strncasecmp`|**Y**|
|194|`mmt_strncmp`|**Y**|
|195|`mmt_strnstr`|N|
|196|`mmt_tcp_reasm_stat_drop`|N|
|197|`mmt_tcp_reasm_stat_live`|N|
|198|`mmt_tcp_reasm_stat_move`|N|
|199|`mmt_tcp_reasm_stat_visit`|N|
|200|`mmt_tolower`|**Y**|
|201|`mmt_toupper`|**Y**|
|202|`mmt_version`|**Y**|
|203|`packet_process`|**Y**|
|204|`process_packet_handler`|**Y**|
|205|`process_session_timer_handler`|**Y**|
|206|`proto_hierarchy_to_str`|**Y**|
|207|`proto_hierarchy_to_str_with_size`|**Y**|
|208|`protocol_sessions_iteration_callback`|N|
|209|`register_attribute_handler`|**Y**|
|210|`register_attribute_handler_by_name`|**Y**|
|211|`register_attribute_with_protocol`|**Y**|
|212|`register_classification_function`|**Y**|
|213|`register_classification_function_full`|**Y**|
|214|`register_classification_function_with_parent_protocol`|**Y**|
|215|`register_evasion_handler`|**Y**|
|216|`register_extraction_attribute`|**Y**|
|217|`register_extraction_attribute_by_name`|**Y**|
|218|`register_packet_handler`|**Y**|
|219|`register_pre_post_analysis_functions`|**Y**|
|220|`register_pre_post_classification_functions`|**Y**|
|221|`register_proto_context_init_cleanup_function`|**Y**|
|222|`register_protocol`|**Y**|
|223|`register_protocol_stack`|**Y**|
|224|`register_protocol_stack_full`|**Y**|
|225|`register_session_data_analysis_function`|**Y**|
|226|`register_session_data_analysis_function_full`|**Y**|
|227|`register_session_data_analysis_function_with_protocol`|**Y**|
|228|`register_session_data_cleanup_function`|**Y**|
|229|`register_session_data_initialization_function`|**Y**|
|230|`register_session_equal_function`|**Y**|
|231|`register_session_hash_function`|**Y**|
|232|`register_session_timeout_handler`|**Y**|
|233|`register_session_timer_handler`|**Y**|
|234|`register_sessionizer_function`|**Y**|
|235|`reset_statistics`|**Y**|
|236|`setDataLinkType`|**Y**|
|237|`set_classification_max_depth`|**Y**|
|238|`set_classified_proto`|**Y**|
|239|`set_default_session_timed_out`|**Y**|
|240|`set_fragment_in_packet`|**Y**|
|241|`set_fragment_in_session`|**Y**|
|242|`set_fragmented_packet_in_session`|**Y**|
|243|`set_live_session_timed_out`|**Y**|
|244|`set_long_session_timed_out`|**Y**|
|245|`set_proto_session_data`|**Y**|
|246|`set_session_timeout_delay`|**Y**|
|247|`set_short_session_timed_out`|**Y**|
|248|`set_tcp_reassembly_limit`|**Y**|
|249|`set_user_session_context`|**Y**|
|250|`set_user_session_context_for_packet`|**Y**|
|251|`short_time_diff`|**Y**|
|252|`silent_extraction`|**Y**|
|253|`str_combine`|**Y**|
|254|`str_compare`|**Y**|
|255|`str_copy`|**Y**|
|256|`str_get_indexes`|**Y**|
|257|`str_get_indexes_n`|**Y**|
|258|`str_hex2int`|**Y**|
|259|`str_hex2int_n`|**Y**|
|260|`str_hex2str`|**Y**|
|261|`str_index`|**Y**|
|262|`str_print_array`|**Y**|
|263|`str_replace`|**Y**|
|264|`str_sub`|**Y**|
|265|`str_sub_n`|**Y**|
|266|`str_subvalue`|**Y**|
|267|`unregister_attribute_handler`|**Y**|
|268|`unregister_attribute_handler_by_name`|**Y**|
|269|`unregister_extraction_attribute`|**Y**|
|270|`unregister_extraction_attribute_by_name`|**Y**|
|271|`unregister_packet_handler`|**Y**|
|272|`unregister_protocol_by_id`|**Y**|
|273|`unregister_protocol_by_name`|**Y**|
|274|`unregister_protocol_stack`|**Y**|
|275|`update_protocol`|**Y**|

## Protocol plugins

Since issue #534 the protocol plugins are built like the core: their objects
are compiled with `-fvisibility=hidden` (`rules/common.mk`, the #534 block at
the end of the file), so a plugin exports only what is declared `MMTAPI`:
the entry points `init_proto`/`cleanup_proto` that `plugins_engine.c` looks
up with `dlsym()`, and the functions the plugin's installed headers declare.
Everything else, such as the protocol classifiers, the attribute extractors
and the vendored llhttp parser, stays inside the library and its static
archive. Tests that call a hidden plugin internal link that archive
(`tools/phase0/tests/static_core_link.sh`, `mmt_static_plugin_link`).

`scripts/validate-exported-symbols.sh` compares each table below with the
built library and fails when they differ, naming every symbol added or
removed (the loader's `_init`/`_fini` and the linker's `_edata`/`_end`/
`__bss_start` are not listed). A change to a plugin's export set is recorded
by regenerating these tables with `--write` in the same pull request; the
prose above each table is kept as written.

## libmmt_tcpip

`init_proto`, `cleanup_proto`, `init_tcpip_plugin` and `cleanup_tcpip_plugin`
are declared in `src/mmt_tcpip/include/mmt_tcpip_plugin.h`; the six
`get_content_class_*` / `get_application_class_*` lookups are declared in
`src/mmt_tcpip/include/mmt_tcpip.h` and defined in
`src/mmt_tcpip/lib/mmt_tcpip_classes.c` (issue #537 — they were `static inline`
header bodies, so a consumer calling them now links `-lmmt_tcpip`). The misspelled
`mmt_search_irc_ssl_detect_ninty_percent_but_very_fast` stays exported until
2.0.0 (the #237 note above).

| symbol |
|:-|
|`cleanup_proto`|
|`cleanup_tcpip_plugin`|
|`get_application_class_by_protocol_id`|
|`get_application_class_name_by_protocol_id`|
|`get_content_class_by_content_flags`|
|`get_content_class_by_content_type`|
|`get_content_class_name_by_content_flags`|
|`get_content_class_name_by_content_type`|
|`init_proto`|
|`init_tcpip_plugin`|
|`mmt_search_irc_ssl_detect_ninty_percent_but_very_fast`|

## libmmt_tmobile

`init_proto` and `cleanup_proto` are declared in
`src/mmt_mobile/mmt_mobile_internal.h`, the `s1ap_entities_*` functions in
`src/mmt_mobile/include/proto_s1ap.h`, and `update_ngap_data` in
`src/mmt_mobile/include/proto_ngap.h` (5Greplay calls it to rewrite NGAP
attributes). The asn1c runtime has been hidden since #443.

| symbol |
|:-|
|`cleanup_proto`|
|`init_proto`|
|`s1ap_entities_count`|
|`s1ap_entities_reset`|
|`s1ap_entities_update`|
|`update_ngap_data`|

## libmmt_business_app

`init_proto` and `cleanup_proto` are declared in
`src/mmt_business_app/mmt_business_app_internal.h`.

| symbol |
|:-|
|`cleanup_proto`|
|`init_proto`|

## libmmt_tdicom

Every symbol is declared in `src/mmt_dicom/include/dicom.h`.

| symbol |
|:-|
|`cleanup_proto`|
|`dicom_stack_classification`|
|`init_dicom_proto_struct`|
|`init_proto`|
|`mmt_check_dicom`|
|`mmt_check_dicom_hdr`|
|`mmt_check_dicom_payload`|
|`mmt_check_dicom_tcp`|
