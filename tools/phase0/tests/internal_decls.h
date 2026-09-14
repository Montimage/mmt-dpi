/*
 * internal_decls.h — the single declaration point for the non-static SDK
 * internals the phase0 harnesses exercise (issue #186, F-TEST-012).
 *
 * These entry points are exported (external linkage) but deliberately absent
 * from the installed public headers: they are internals. The harnesses used
 * to re-declare them per file — and one test hand-copied the private
 * dns_name_t layout — so a signature or field change in the library still
 * linked and then read wrong offsets. One shared header means exactly one
 * place tracks the library.
 *
 * dns_name_t below mirrors src/mmt_tcpip/lib/protocols/dns.h — keep it in
 * step with that file (it is the only result struct a harness reads back;
 * everything else is reached through public types).
 *
 * Types referenced below come from <stdint.h>, <sys/types.h> (u_char) and
 * the installed "mmt_core.h" (ipacket_t, mmt_key_t, attribute_t), all
 * included here so the header is self-contained. Parameters of internal
 * struct types are spelled with their struct tags — a forward declaration
 * suffices in a prototype, and the harness .c pulls the full definition from
 * the real internal header when it needs member access.
 */
#ifndef MMT_PHASE0_INTERNAL_DECLS_H
#define MMT_PHASE0_INTERNAL_DECLS_H

#include <stdint.h>
#include <sys/types.h>   /* u_char */
#include "mmt_core.h"    /* ipacket_t, mmt_key_t, attribute_t */

/* Internal struct types used by the prototypes below. The including .c gets
 * the full definitions from the real internal headers (netinet/ip.h,
 * protocols/ipv6.h, protocols/ip_session_id_management.h) where it needs
 * them. */
struct iphdr;
struct ipv6hdr;
struct ext_hdr_fragment;
struct mmt_session_key_struct;
struct attribute_internal_struct;

/* src/mmt_tcpip/lib/protocols/dns.h — result struct read back by
 * dns_parser_test.c. */
typedef struct dns_name_struct {
    char *value;
    uint16_t length;
    uint8_t is_ref;
    uint16_t real_length;
    struct dns_name_struct *next;
} dns_name_t;

/* --- protocols/proto_dns.c ------------------------------------------------- */
int dns_check_payload(const u_char *payload, int payload_packet_len);
dns_name_t *dns_extract_name_value(const u_char *dns_name_payload,
                                   const u_char *dns_payload,
                                   const u_char *payload_end);
void dns_free_name(dns_name_t *dns_name);

/* --- protocols/proto_dtls.c ------------------------------------------------ */
int classify_dtls_from_udp(ipacket_t *ipacket, unsigned index);
void mmt_init_classify_me_dtls(void);

/* --- mmt_tcpip_classif_utils.c (externally-updatable IP-range / port map) --- */
int mmt_tcpip_load_ip_ranges_file(const char *path);
int mmt_tcpip_load_port_map_file(const char *path);
int _find_proto_id_by_address(uint32_t ip_src, uint32_t ip_dst);
int _find_proto_id_by_address6(const uint8_t ip_src[16],
                               const uint8_t ip_dst[16]);

/* --- protocols/proto_ftp.c -------------------------------------------------- */
char *ftp_get_data_client_addr_v6_from_LPRT(char *payload, uint32_t payload_len);
char *ftp_get_data_client_addr_v6_from_EPRT(char *payload, uint32_t payload_len);
unsigned short ftp_get_data_client_port_from_EPRT(char *payload, uint32_t payload_len);
unsigned short ftp_get_data_client_port_from_LPRT(char *payload, uint32_t payload_len);
unsigned int ftp_get_addr_from_parameter(char *payload, unsigned int payload_len);
/* src/mmt_tcpip/lib/protocols/ftp.h — result structs read back by
 * ftp_lprt_eprt_test.c; mirrored here (like dns_name_t above) because ftp.h
 * is not self-contained: it needs the internal bitmask types. Keep in step
 * with that file (#206). */
typedef struct ftp_command_struct {
    uint16_t cmd;
    char *str_cmd;
    char *param;
} ftp_command_t;
typedef struct ftp_response_struct {
    uint16_t code;
    char *str_code;
    char *value;
} ftp_response_t;
ftp_command_t *ftp_get_command(char *payload, int payload_len);
void free_ftp_command(ftp_command_t *cmd);
ftp_response_t *ftp_get_response(char *payload, int payload_len);
void free_ftp_response(ftp_response_t *res);

/* --- protocols/http2.c ------------------------------------------------------ */
int http2_header_length_extraction(const ipacket_t *packet,
        unsigned proto_index, attribute_t *extracted_data);
int http2_header_method_extraction(const ipacket_t *packet,
        unsigned proto_index, attribute_t *extracted_data);
int http2_payload_stream_id_extraction(const ipacket_t *packet,
        unsigned proto_index, attribute_t *extracted_data);
int http2_payload_length_extraction(const ipacket_t *packet,
        unsigned proto_index, attribute_t *extracted_data);
int http2_payload_data_extraction(const ipacket_t *packet,
        unsigned proto_index, attribute_t *extracted_data);
int http2_stream_id_extraction(const ipacket_t *packet,
        unsigned proto_index, attribute_t *extracted_data);
int _http2_classify_next_proto(ipacket_t *ipacket, unsigned index);
int mmt_check_http2(ipacket_t *ipacket, unsigned proto_index);

/* issue #204 (F-BUG-057): packet-mutation helpers — every one of them now
 * takes the destination buffer size and refuses out-of-window writes. */
int update_http2_data(char *data_out, uint32_t data_size,
        const ipacket_t *packet, uint32_t proto_id, uint32_t att_id,
        uint32_t new_val);
int update_stream_id(char *data_out, int proto_offset, uint32_t new_val,
        uint32_t data_out_size);
int restore_http2_packet(uint8_t *data_out, const ipacket_t *packet,
        int proto_offset, uint32_t data_out_size);
int modify_get(uint8_t *data_out, int proto_offset, uint32_t data_out_size);
uint32_t update_window_update(char *data_out, int proto_offset,
        uint32_t modify, uint32_t data_out_size);
int inject_http2_packet(uint8_t *data_out, uint8_t *data_to_inject,
        int proto_offset, int data_to_inject_len, uint32_t data_out_size);
int fuzz_payload(uint8_t *data_out, const ipacket_t *packet, int proto_offset,
        uint32_t data_out_size);

/* --- http parsing helpers ----------------------------------------------------
 * get_request_method_uri_offset is extern in protocols/http.c;
 * http_request_url_offset is extern in protocols/proto_http.c (http.c also
 * has a static inline same-named helper — TU-local, no collision). */
int get_request_method_uri_offset(const char *msg, int msg_len, int *method);
uint16_t http_request_url_offset(ipacket_t *ipacket);

/* issue #204: HTTP session lifecycle + MIME-table invariant (F-BUG-048,
 * F-BUG-053) exercised by http_session_test.c. The session argument is the
 * private struct mmt_session_struct — pull it from packet_processing.h. */
void http_session_data_init(ipacket_t *ipacket, unsigned index);
void http_session_data_cleanup(mmt_session_t *session, unsigned index);
int http_session_data_analysis(ipacket_t *ipacket, unsigned index);
int mmt_http_content_tables_check(void);
int http_internal_session_data_analysis(ipacket_t *ipacket, unsigned index);

/* --- protocols/rfc2822utils.c ------------------------------------------------ */
int get_next_white_space_offset_no_limit(const char *str, int max);
int get_next_non_white_space_offset_no_limit(const char *str, int max);
/* issue #204: header-line scanner (F-BUG-046), bounded char search
 * (F-BUG-047), field/value offset helpers feeding F-BUG-052. */
int get_next_header_line_length(const char *msg, int msg_len, int *code);
const char *mmt_find_char_instance(const char *str, char char_to_find, int max);
int get_field_len(const char *str, int line_len);
int get_value_offset(const char *msg, int line_len);

/* --- mmt_tcpip_utils.c ------------------------------------------------------- */
void _mmt_parse_packet_line_info(ipacket_t *ipacket);
uint32_t mmt_bytestream_to_number(const uint8_t *str,
                                  uint16_t max_chars_to_read,
                                  uint16_t *bytes_read);

/* --- protocols/proto_ip.c / proto_ipv6.c (session & fragment keys) ---------- */
uint8_t build_ipv4_session_key(u_char *ip_packet, unsigned ip_packet_len,
        struct mmt_session_key_struct *ipv4_session);
int build_ipv6_session_key(ipacket_t *ipacket, int offset,
        struct mmt_session_key_struct *ipv6_session);
mmt_key_t ip_fragment_key(const struct iphdr *ip);
mmt_key_t ip6_fragment_key(const struct ipv6hdr *ip6h,
        const struct ext_hdr_fragment *frag_header);

/* --- mmt_tcpip_plugin_internal.c (payload-confirms-protocol hook) ----------- */
int mmt_payload_confirms_proto(uint32_t proto_id,
                               const unsigned char *payload,
                               int payload_packet_len);

/* --- protocols/proto_quic.c --------------------------------------------------- */
int mmt_check_quic(ipacket_t *ipacket, unsigned index);
void mmt_init_classify_me_quic(void);

/* --- protocols/proto_redis.c -------------------------------------------------- */
int redis_is_resp_opener(uint8_t c);
int redis_resp_exchange_match(uint8_t a, uint8_t b);

/* --- protocols/proto_skype.c -------------------------------------------------- */
int mmt_check_skype_tcp(ipacket_t *ipacket, unsigned index);
int mmt_check_skype_udp(ipacket_t *ipacket, unsigned index);
void mmt_init_classify_me_skype(void);

/* --- protocols/proto_ssl.c (SNI / record / version helpers) ------------------- */
int getServerNameFromClientHello(ipacket_t *ipacket, char *buffer, int buffer_len);
int ssl_is_tls_record_header(const uint8_t *payload, int payload_len);
int tls_get_number_records(const ipacket_t *ipacket);
int mmt_classify_me_ssl(ipacket_t *ipacket, unsigned index);
int tls_content_type_extraction(const ipacket_t *ipacket, unsigned proto_index,
        attribute_t *extracted_data);
int tls_version_extraction(const ipacket_t *ipacket, unsigned proto_index,
        attribute_t *extracted_data);
int tls_length_extraction(const ipacket_t *ipacket, unsigned proto_index,
        attribute_t *extracted_data);

/* --- protocols/proto_quic_ietf.c / proto_dtls.c extraction entry points ------
 * Exported non-static solely so the crafted-input harnesses can drive them
 * (issue #203). */
int _extraction_quic_ietf_att(const ipacket_t *ipacket, unsigned index,
        attribute_t *extracted_data);
int _dtls_extract_attribute(const ipacket_t *ipacket, unsigned proto_index,
        attribute_t *extracted_data);

/* --- protocols/proto_tcp.c ----------------------------------------------------- */
int tcp_pre_classification_function(ipacket_t *ipacket, unsigned index);

/* --- protocols/proto_rtp.c (issue #205 harness) ------------------------------- */
int rtp_csrc_list_extraction(const ipacket_t *packet, unsigned proto_index,
        attribute_t *extracted_data);
int mmt_check_rtp_udp(ipacket_t *ipacket, unsigned index);
void mmt_init_classify_me_rtp(void);

/* --- protocols/proto_smb.c (issue #205 harness) ------------------------------- */
const uint8_t *get_smb_payload(const ipacket_t *ipacket, unsigned proto_index);
int smb_session_data_analysis(ipacket_t *ipacket, unsigned index);

/* --- protocols/proto_sip.c (issue #205 harness) ------------------------------- */
int mmt_check_sip(ipacket_t *ipacket, unsigned index);
void mmt_init_classify_me_sip(void);

/* --- protocols/ndn.c (issue #205 harness) -------------------------------------- */
struct ndn_tlv_struct;
struct ndn_tlv_struct *ndn_TLV_parser(char *payload, int offset,
        int total_length);
void ndn_TLV_free(struct ndn_tlv_struct *ndn);
int mmt_check_ndn_payload(char *payload, int packet_len);
/* --- hand-written extraction callbacks (issue #202, F-BUG-033) -------------
 * Every non-static *_extraction callback in proto_{ip,tcp,gre,gtp,icmp}.c is
 * declared here so extraction_caplen_prologue_test.c can drive them directly
 * on crafted truncated captures. (_extract_l4s_metrics and
 * _gtp_extract_pdu_extension_header_field are TU-static — corpus-only.) */

/* protocols/proto_ip.c */
int ip_version_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_ihl_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_rf_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_df_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_mf_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_frag_offset_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_client_port_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_server_port_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_client_addr_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_server_addr_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_options_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_opts_type_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int ip_padding_check_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int _extract_jitter(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);

/* protocols/proto_tcp.c */
int tcp_data_offset_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_fin_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_syn_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_rst_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_psh_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_ack_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_urg_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_ece_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_cwr_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_established_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_connection_closed_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_flags_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_payload_len_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_retransmission_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_outoforder_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_session_retransmission_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_session_payload_up_len_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_session_payload_up_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_session_payload_down_len_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_session_payload_down_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_session_rtt_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int tcp_option_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);

/* protocols/proto_gre.c */
int gre_c_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gre_k_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gre_s_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gre_version_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gre_csum_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gre_key_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gre_seqnb_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);

/* protocols/proto_gtp.c */
int gtp_version_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_protocol_type_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_reserved_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_extension_header_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_seq_check_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_seq_num_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_imsi_mmc_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_imsi_mnc_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int gtp_npdu_number_flag_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int _gtp_extract_next_extension_header_type(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);

/* protocols/proto_icmp.c */
int icmp_identifier_and_seq_nb_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int icmp_gateway_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);
int icmp_data_extraction(const ipacket_t *ipacket, unsigned proto_index, attribute_t *extracted_data);

/* --- mmt_core/src/packet_processing.c (central caplen guard, issue #193) ----
 * internal_extract_attribute is exported non-static; the attribute struct tag
 * is forward-declared above and defined by the real private header
 * (src/mmt_core/private_include/packet_processing.h) which the harness
 * includes for member access. The mmt_caplen_guard_* accessors are always
 * exported; their counters only increment in assert-enabled (NDEBUG
 * undefined) or sanitizer-instrumented (MMT_BUILD_ASAN/MMT_BUILD_TSAN)
 * builds — in a plain release build they return 0. */
int internal_extract_attribute(const ipacket_t *ipacket,
        struct attribute_internal_struct *tmp_attr_ref, unsigned index);
/* Registry accessor exercised by extraction_caplen_prologue_test.c
 * (issue #202, F-BUG-010): look up a registered protocol struct. */
protocol_t *get_protocol_struct_by_protocol_id(uint32_t proto_id);
uint64_t mmt_caplen_guard_total_count(void);
uint64_t mmt_caplen_guard_refused_count(void);
uint64_t mmt_caplen_guard_unvalidated_count(void);
void mmt_caplen_guard_stats_reset(void);

#endif /* MMT_PHASE0_INTERNAL_DECLS_H */
