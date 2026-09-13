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
unsigned int ftp_get_addr_from_parameter(char *payload, unsigned int payload_len);

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

/* --- http parsing helpers ----------------------------------------------------
 * get_request_method_uri_offset is extern in protocols/http.c;
 * http_request_url_offset is extern in protocols/proto_http.c (http.c also
 * has a static inline same-named helper — TU-local, no collision). */
int get_request_method_uri_offset(const char *msg, int msg_len, int *method);
uint16_t http_request_url_offset(ipacket_t *ipacket);

/* --- protocols/rfc2822utils.c ------------------------------------------------ */
int get_next_white_space_offset_no_limit(const char *str, int max);
int get_next_non_white_space_offset_no_limit(const char *str, int max);

/* --- mmt_tcpip_utils.c ------------------------------------------------------- */
void _mmt_parse_packet_line_info(ipacket_t *ipacket);

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

/* --- protocols/proto_tcp.c ----------------------------------------------------- */
int tcp_pre_classification_function(ipacket_t *ipacket, unsigned index);

#endif /* MMT_PHASE0_INTERNAL_DECLS_H */
