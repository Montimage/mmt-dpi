/*
 * tcp_reasm_stubs.h — reassembly gauges and mmt_core link stubs for test
 * TUs that include proto_tcp.c and tcp_segment.c directly (issue #380's
 * tcp-memory fixture; shared with tests/tcp_pending_order, issue #381).
 *
 * Include it once, AFTER proto_tcp.c: the gauges (g_visits, g_moved,
 * g_dropped, g_live) replace mmt_core/packet_pipeline.c's counters, and the
 * stubs satisfy proto_tcp.c's classification/registration references,
 * which these tests never drive — only its reassembly helpers.
 */
#ifndef MMT_TEST_TCP_REASM_STUBS_H
#define MMT_TEST_TCP_REASM_STUBS_H

/* ---- reassembly gauges (normally mmt_core/packet_pipeline.c) ---- */

static uint64_t g_visits, g_moved, g_dropped;
static int64_t g_live;
void mmt_tcp_reasm_stat_visit(void) { g_visits++; }
void mmt_tcp_reasm_stat_move(uint32_t bytes) { g_moved += bytes; }
void mmt_tcp_reasm_stat_drop(uint32_t bytes) { g_dropped += bytes; }
void mmt_tcp_reasm_stat_live(int64_t delta) { g_live += delta; }

/* ---- link stubs: proto_tcp.c's classification/registration paths are
 * never driven here, only its reassembly helpers ---- */

int get_packet_offset_at_index(const ipacket_t *ipacket, unsigned index) {
	(void) ipacket; (void) index;
	return -1;
}
int set_classified_proto(ipacket_t *ipacket, unsigned index, classified_proto_t p) {
	(void) ipacket; (void) index; (void) p;
	return 0;
}
uint32_t get_proto_id_from_address(ipacket_t *ipacket) {
	(void) ipacket;
	return PROTO_UNKNOWN;
}
unsigned int mmt_guess_protocol_by_port_number(ipacket_t *ipacket) {
	(void) ipacket;
	return PROTO_UNKNOWN;
}
void fire_attribute_event(ipacket_t *ipacket, mmt_proto_id_t proto_id,
		uint32_t attribute_id, unsigned index, mmt_opaque_t data) {
	(void) ipacket; (void) proto_id; (void) attribute_id; (void) index; (void) data;
}
void set_session_timeout_delay(mmt_session_t *session, uint32_t timeout_delay) {
	(void) session; (void) timeout_delay;
}
int general_short_extraction_with_ordering_change(const ipacket_t *packet,
		mmt_proto_index_t proto_index, attribute_t *extracted_data) {
	(void) packet; (void) proto_index; (void) extracted_data;
	return 0;
}
int general_int_extraction_with_ordering_change(const ipacket_t *packet,
		mmt_proto_index_t proto_index, attribute_t *extracted_data) {
	(void) packet; (void) proto_index; (void) extracted_data;
	return 0;
}
protocol_t *get_protocol_struct_by_id(mmt_proto_id_t proto_id) {
	(void) proto_id;
	return NULL;
}
protocol_t *init_protocol_struct_for_registration(uint32_t proto_id,
		const char *protocol_name) {
	(void) proto_id; (void) protocol_name;
	return NULL;
}
bool register_protocol(protocol_t *protocol_struct, uint32_t proto_id) {
	(void) protocol_struct; (void) proto_id;
	return 0;
}
bool register_attribute_with_protocol(protocol_t *protocol_struct,
		attribute_metadata_t *attribute_metadata) {
	(void) protocol_struct; (void) attribute_metadata;
	return 0;
}
bool register_pre_post_classification_functions(protocol_t *protocol_struct,
		generic_classification_function pre_classification,
		generic_classification_function post_classification) {
	(void) protocol_struct; (void) pre_classification; (void) post_classification;
	return 0;
}
void register_session_data_cleanup_function(protocol_t *protocol_struct,
		generic_session_data_cleanup_function fct) {
	(void) protocol_struct; (void) fct;
}

#endif /* MMT_TEST_TCP_REASM_STUBS_H */
