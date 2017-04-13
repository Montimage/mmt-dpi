#ifndef __MMT_TCPIP_PLUGIN_STRUCTS__
#define __MMT_TCPIP_PLUGIN_STRUCTS__

#include "mmt_tcpip_internal_defs_macros.h"

#ifdef MMT_SUPPORT_IPV6

typedef struct {
    char *string_to_match;
    int proto_id;
    int str_len;
    uint32_t content_flags;
} protocol_match;

struct mmt_ip6_addr {

    union {
        uint8_t u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
        uint64_t u6_addr64[2];
    } mmt_v6_u;

#define mmt_v6_addr		mmt_v6_u.u6_addr8
#define mmt_v6_addr16		mmt_v6_u.u6_addr16
#define mmt_v6_addr32		mmt_v6_u.u6_addr32
#define mmt_v6_addr64		mmt_v6_u.u6_addr64
};

struct mmt_ipv6hdr {
    /* use userspace and kernelspace compatible compile parameters */
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t priority : 4, version : 4;
#elif BYTE_ORDER == BIG_ENDIAN
    uint8_t version : 4, priority : 4;
#else
#error	"__LITTLE_ENDIAN_BITFIELD or __BIG_ENDIAN_BITFIELD must be defined, should be done by <asm/byteorder.h>"
#endif

    uint8_t flow_lbl[3];

    uint16_t payload_len;
    uint8_t nexthdr;
    uint8_t hop_limit;

    struct mmt_ip6_addr saddr;
    struct mmt_ip6_addr daddr;
};
#endif							/* MMT_SUPPORT_IPV6 */

typedef union {
    uint32_t ipv4;
    uint8_t ipv4_u8[4];
#ifdef MMT_SUPPORT_IPV6
    struct mmt_ip6_addr ipv6;
#endif
} mmt_ip_addr_t;

typedef struct mmt_proto_port_mapping_struct {
    uint16_t port;
    uint16_t l4proto;
    uint32_t appproto;
}mmt_proto_port_mapping_t;

typedef struct index_struct {
        uint16_t index : 6; //64 mappings max
}index_t;

typedef struct mmt_server_local_proto_struct {
    index_t index;
    mmt_proto_port_mapping_t port_proto_mapping[64];
}mmt_server_local_proto_t;

typedef struct mmt_conv_proto_last_seen_signalling_struct {
    uint32_t proto;
    struct timeval last_seen;
}mmt_conv_proto_last_seen_signalling_t;

typedef struct mmt_internal_tcpip_id_struct {
    MMT_PROTOCOL_BITMASK detected_protocol_bitmask;
    mmt_server_local_proto_t local_protos;
    mmt_conv_proto_last_seen_signalling_t conv_proto;
#ifdef PROTO_FTP
    mmt_ip_addr_t ftp_ip;
#endif
#ifdef PROTO_RTSP
    mmt_ip_addr_t rtsp_ip_address;
#endif
#ifdef PROTO_PPLIVE
    MMT_INTERNAL_TIMESTAMP_TYPE pplive_last_packet_time;
#endif
#ifdef PROTO_SIP
#ifdef PROTO_YAHOO
    MMT_INTERNAL_TIMESTAMP_TYPE yahoo_video_lan_timer;
#endif
#endif
#ifdef PROTO_IRC
    MMT_INTERNAL_TIMESTAMP_TYPE last_time_port_used[16];
#endif
#ifdef PROTO_FTP
    MMT_INTERNAL_TIMESTAMP_TYPE ftp_timer;
#endif
#ifdef PROTO_IRC
    MMT_INTERNAL_TIMESTAMP_TYPE irc_ts;
#endif
#ifdef PROTO_GNUTELLA
    MMT_INTERNAL_TIMESTAMP_TYPE gnutella_ts;
#endif
#ifdef PROTO_BATTLEFIELD
    MMT_INTERNAL_TIMESTAMP_TYPE battlefield_ts;
#endif
#ifdef PROTO_THUNDER
    MMT_INTERNAL_TIMESTAMP_TYPE thunder_ts;
#endif
#ifdef PROTO_RTSP
    MMT_INTERNAL_TIMESTAMP_TYPE rtsp_timer;
#endif
#ifdef PROTO_OSCAR
    MMT_INTERNAL_TIMESTAMP_TYPE oscar_last_safe_access_time;
#endif
#ifdef PROTO_GADUGADU
    uint32_t gg_ft_ip_address;
    MMT_INTERNAL_TIMESTAMP_TYPE gg_timeout;
#endif
#ifdef PROTO_ZATTOO
    MMT_INTERNAL_TIMESTAMP_TYPE zattoo_ts;
#endif
#ifdef PROTO_UNENCRYPED_JABBER
    MMT_INTERNAL_TIMESTAMP_TYPE jabber_stun_or_ft_ts;
#endif
#ifdef PROTO_MANOLITO
    uint32_t manolito_last_pkt_arrival_time;
#endif
#ifdef PROTO_DIRECTCONNECT
    MMT_INTERNAL_TIMESTAMP_TYPE directconnect_last_safe_access_time;
#endif
#ifdef PROTO_SOULSEEK
    MMT_INTERNAL_TIMESTAMP_TYPE soulseek_last_safe_access_time;
#endif
#ifdef PROTO_DIRECTCONNECT
    uint16_t detected_directconnect_port;
    uint16_t detected_directconnect_udp_port;
    uint16_t detected_directconnect_ssl_port;
#endif
#ifdef PROTO_PPLIVE
    uint16_t pplive_vod_cli_port;
#endif
#ifdef PROTO_IRC
    uint16_t irc_port[16];
#endif
#ifdef PROTO_GADUGADU
    uint16_t gg_ft_port;
#endif
#ifdef PROTO_UNENCRYPED_JABBER
#define JABBER_MAX_STUN_PORTS 6
    uint16_t jabber_voice_stun_port[JABBER_MAX_STUN_PORTS];
    uint16_t jabber_file_transfer_port[2];
#endif
#ifdef PROTO_GNUTELLA
    uint16_t detected_gnutella_port;
#endif
#ifdef PROTO_GNUTELLA
    uint16_t detected_gnutella_udp_port1;
    uint16_t detected_gnutella_udp_port2;
#endif
#ifdef PROTO_SOULSEEK
    uint16_t soulseek_listen_port;
#endif
#ifdef PROTO_IRC
    uint8_t irc_number_of_port;
#endif
#ifdef PROTO_OSCAR
    uint8_t oscar_ssl_session_id[33];
#endif
#ifdef PROTO_GADUGADU
    uint8_t gg_call_id[2][7];
    uint8_t gg_fmnumber[8];
#endif
#ifdef PROTO_UNENCRYPED_JABBER
    uint8_t jabber_voice_stun_used_ports;
#endif
#ifdef PROTO_SIP
#ifdef PROTO_YAHOO
    uint32_t yahoo_video_lan_dir : 1;
#endif
#endif
#ifdef PROTO_YAHOO
    uint32_t yahoo_conf_logged_in : 1;
    uint32_t yahoo_voice_conf_logged_in : 1;
#endif
#ifdef PROTO_FTP
    uint32_t ftp_timer_set : 1;
#endif
#ifdef PROTO_GADUGADU
    uint32_t gadu_gadu_ft_direction : 1;
    uint32_t gadu_gadu_voice : 1;
    uint32_t gg_next_id : 1;
#endif
#ifdef PROTO_RTSP
    uint32_t rtsp_ts_set : 1;
#endif
#ifdef PROTO_PPLIVE
    uint32_t pplive_last_packet_time_set : 1;
#endif
} mmt_internal_tcpip_id_struct;

struct mmt_internal_tcp_session_struct {
    struct timeval rtt;

#ifdef PROTO_FLASH
    uint16_t flash_bytes;
#endif
#ifdef PROTO_SMTP
    uint16_t smtp_command_bitmask;
#endif
#ifdef PROTO_POP
    uint16_t pop_command_bitmask;
#endif
#ifdef PROTO_QQ
    uint16_t qq_nxt_len;
#endif
#ifdef PROTO_TDS
    uint8_t tds_login_version;
#endif
#ifdef PROTO_PPLIVE
    uint8_t pplive_next_packet_size[2];
#endif
#ifdef PROTO_IRC
    uint8_t irc_stage;
    uint8_t irc_port;
#endif
#ifdef PROTO_GNUTELLA
    uint8_t gnutella_msg_id[3];
#endif
#ifdef PROTO_EDONKEY
    uint32_t edk_ext : 1;
#endif
#ifdef PROTO_IRC
    uint32_t irc_3a_counter : 3;
    uint32_t irc_stage2 : 5;
    uint32_t irc_direction : 2;
    uint32_t irc_0x1000_full : 1;
#endif
#ifdef PROTO_WINMX
    uint32_t winmx_stage : 1; // 0-1
#endif
#ifdef PROTO_SOULSEEK
    uint32_t soulseek_stage : 2;
#endif
#ifdef PROTO_FILETOPIA
    uint32_t filetopia_stage : 2;
#endif
#ifdef PROTO_MANOLITO
    uint32_t manolito_stage : 4;
#endif
#ifdef PROTO_TDS
    uint32_t tds_stage : 3;
#endif
#ifdef PROTO_GADUGADU
    uint32_t gadugadu_stage : 2;
#endif
#ifdef PROTO_USENET
    uint32_t usenet_stage : 2;
#endif
#ifdef PROTO_IMESH
    uint32_t imesh_stage : 4;
#endif
#ifdef PROTO_FTP
    // WORKING HERE for FTP session
    uint32_t ftp_codes_seen:5;
    uint32_t ftp_client_direction : 1;
#endif
#ifdef PROTO_HTTP
    uint32_t http_setup_dir : 2;
    uint32_t http_stage : 2;
    uint32_t http_data_direction : 1;
    uint32_t http_empty_line_seen : 1;
    uint32_t http_wait_for_retransmission : 1;
#endif							// PROTO_HTTP
#ifdef PROTO_FLASH
    uint32_t flash_stage : 3;
#endif
#ifdef PROTO_GNUTELLA
    uint32_t gnutella_stage : 2; //0-2
#endif
#ifdef PROTO_MMS
    uint32_t mms_stage : 2;
#endif
#ifdef PROTO_YAHOO
    uint32_t yahoo_sip_comm : 1;
    uint32_t yahoo_http_proxy_stage : 2;
#endif
#ifdef PROTO_MSN
    uint32_t msn_stage : 3;
    uint32_t msn_ssl_ft : 2;
#endif
#ifdef PROTO_SSH
    uint32_t ssh_stage : 3;
#endif
#ifdef PROTO_VNC
    uint32_t vnc_stage : 2; //0 - 3
#endif
#ifdef PROTO_STEAM
    uint32_t steam_stage : 2; //0 - 3
#endif
#ifdef PROTO_TELNET
    uint32_t telnet_stage : 2; //0 - 2
#endif
#ifdef PROTO_SSL
    uint32_t ssl_stage : 2; //0 - 3
#endif
#ifdef PROTO_WHATSAPP
    uint32_t whatsapp_conn_stage : 3; //0 - 16
    uint32_t whatsapp_stage : 3; //0 - 16
#endif
#ifdef PROTO_POSTGRES
    uint32_t postgres_stage : 3;
#endif
#ifdef PROTO_DIRECT_DOWNLOAD_LINK
    uint32_t ddlink_server_direction : 1;
#endif
    uint32_t seen_syn : 1;
    uint32_t seen_syn_ack : 1;
    uint32_t seen_ack : 1;
    uint32_t seen_fin : 1;
    uint32_t seen_fin_ack : 1;
    uint32_t seen_close : 1;
#ifdef PROTO_ICECAST
    uint32_t icecast_stage : 1;
#endif
#ifdef PROTO_DOFUS
    uint32_t dofus_stage : 1;
#endif
#ifdef PROTO_FIESTA
    uint32_t fiesta_stage : 2;
#endif
#ifdef PROTO_WORLDOFWARCRAFT
    uint32_t wow_stage : 2;
#endif
#ifdef PROTO_HTTP_APPLICATION_VEOHTV
    uint32_t veoh_tv_stage : 2;
#endif
#ifdef PROTO_SHOUTCAST
    uint32_t shoutcast_stage : 2;
#endif
#ifdef PROTO_RTP
    uint32_t rtp_special_packets_seen : 1;
#endif
#ifdef PROTO_POP
    uint32_t mail_pop_stage : 2;
#endif
#ifdef PROTO_IMAP
    uint32_t mail_imap_stage : 3;
#endif

#ifdef PROTO_SKYPE
    uint8_t skype_packet_id;
    uint8_t skype_like_packet; //BW: follow the nb of packets that seems to be Skype (small packets, etc.)
#endif

#ifdef PROTO_CITRIX
    uint8_t citrix_packet_id;
#endif

#ifdef PROTO_TEAMVIEWER
    uint8_t teamviewer_stage;
#endif
#ifdef PROTO_SPOTIFY
    uint8_t spotify_like_packet; //BW: follow the nb of packets that seems to be spotify
    uint8_t spotify_stage;
#endif
}

#if !(defined(WIN32))
__attribute__((__packed__))
#endif
;

struct mmt_internal_udp_session_struct {
#ifdef PROTO_BATTLEFIELD
    uint32_t battlefield_msg_id;
#endif
#ifdef PROTO_SNMP
    uint32_t snmp_msg_id;
#endif
#ifdef PROTO_BATTLEFIELD
    uint32_t battlefield_stage : 3;
#endif
#ifdef PROTO_SNMP
    uint32_t snmp_stage : 2;
#endif
#ifdef PROTO_PPSTREAM
    uint32_t ppstream_stage : 3; // 0-7
#endif
#ifdef PROTO_FEIDIAN
    uint32_t feidian_stage : 1; // 0-7
#endif
#ifdef PROTO_HALFLIFE2
    uint32_t halflife2_stage : 2; // 0 - 2
#endif
#ifdef PROTO_TFTP
    uint32_t tftp_stage : 1;
#endif
#ifdef PROTO_AIMINI
    uint32_t aimini_stage : 5;
#endif
#ifdef PROTO_XBOX
    uint32_t xbox_stage : 1;
#endif
#ifdef PROTO_WINUPDATE
    uint32_t wsus_stage : 1;
#endif
#ifdef PROTO_SKYPE
    uint8_t skype_packet_id;
    uint8_t skype_like_packet; //BW: follow the nb of packets that seems to be Skype (small packets, etc.)
#endif
#ifdef PROTO_TEAMVIEWER
    uint8_t teamviewer_stage;
#endif
#ifdef PROTO_TANGO
    uint8_t tango_like_packet;
#endif
}

#if !(defined(WIN32))
__attribute__((__packed__))
#endif
;

typedef struct mmt_internal_tcpip_session_struct {
    // uint16_t packet_counter;             // can be 0 - 65000
    // uint16_t packet_direction_counter[2];
    // uint16_t byte_counter[2];
    uint16_t detected_protocol_stack[PROTOCOL_HISTORY_SIZE];
#if PROTOCOL_HISTORY_SIZE > 1
#if PROTOCOL_HISTORY_SIZE > 5
#error protocol stack size not supported
#endif

    struct {
        uint8_t entry_is_real_protocol : 5;
        uint8_t current_stack_size_minus_one : 3;
    }

#if !(defined(WIN32))
    __attribute__((__packed__))
#endif
    protocol_stack_info;
#endif

    /* the tcp / udp / other l4 value union
     * this is used to reduce the number of bytes for tcp or udp protocol states
     * */
    union {
        struct mmt_internal_tcp_session_struct tcp;
        struct mmt_internal_udp_session_struct udp;
    } l4;


    /* ALL protocol specific 64 bit variables here */

    /* protocols which have marked a connection as this connection cannot be protocol XXX, multiple u64 */
    MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;

#ifdef PROTO_RTP
    uint32_t rtp_ssid[2];
#endif
#ifdef PROTO_I23V5
    uint32_t i23v5_len1;
    uint32_t i23v5_len2;
    uint32_t i23v5_len3;
#endif
#ifdef PROTO_RTP
    uint16_t rtp_seqnum[2]; /* current highest sequence number (only goes forwards, is not decreased by retransmissions) */
#endif
#ifdef PROTO_RTP
    /* tcp and udp */
    uint8_t rtp_payload_type[2];
#endif

#ifdef PROTO_BITTORRENT
    uint8_t bittorrent_stage; // can be 0-255
#endif
#ifdef PROTO_RTP
    uint32_t rtp_stage1 : 2; //0-3
    uint32_t rtp_stage2 : 2;
#endif
#ifdef PROTO_EDONKEY
    uint32_t edk_stage : 5; // 0-17
#endif
#ifdef PROTO_DIRECTCONNECT
    uint32_t directconnect_stage : 2; // 0-1
#endif
#ifdef PROTO_SIP
#ifdef PROTO_YAHOO
    uint32_t sip_yahoo_voice : 1;
#endif
#endif
#ifdef PROTO_HTTP
    uint32_t http_detected : 1;
#endif	// PROTO_HTTP
#ifdef PROTO_RTSP
    uint32_t rtsprdt_stage : 2;
    uint32_t rtsp_control_flow : 1;
#endif

#ifdef PROTO_YAHOO
    uint32_t yahoo_detection_finished : 2;
#endif
#ifdef PROTO_PPLIVE
    uint32_t pplive_stage : 3; // 0-7
#endif

#ifdef PROTO_ZATTOO
    uint32_t zattoo_stage : 3;
#endif
#ifdef PROTO_QQ
    uint32_t qq_stage : 3;
#endif
#ifdef PROTO_THUNDER
    uint32_t thunder_stage : 2; // 0-3
#endif
#ifdef PROTO_OSCAR
    uint32_t oscar_ssl_voice_stage : 3;
    uint32_t oscar_video_voice : 1;
#endif
#ifdef PROTO_FLORENSIA
    uint32_t florensia_stage : 1;
#endif
#ifdef PROTO_REDIS
  uint8_t redis_s2d_first_char, redis_d2s_first_char;
  uint32_t redis_packet_count:3;
#endif
// #ifdef PROTO_FTP_CONTROL
//   uint32_t ftp_control_stage:2;
// #endif
} mmt_internal_tcpip_session_t;

typedef struct mmt_classify_me_function_element_struct {
    uint32_t priority;
    MMT_PROTOCOL_BITMASK detection_bitmask;
    MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
    MMT_SELECTION_BITMASK_PROTOCOL_SIZE mmt_selection_bitmask;
    void (*func) (ipacket_t * ipacket, int index);
    uint8_t detection_feature;
} mmt_classify_me_function_element_t;

typedef struct mmt_call_function_struct {
    mmt_classify_me_function_element_t * classify_me;
    struct mmt_call_function_struct * next;
    struct mmt_call_function_struct * previous;
} mmt_call_function_struct_t;

typedef struct mmt_int_one_line_struct {
    const uint8_t *ptr;
    uint16_t len;
} mmt_int_one_line_struct_t;

struct mmt_tcpip_internal_packet_struct {
    struct mmt_internal_tcpip_session_struct *flow;
    struct mmt_internal_tcpip_id_struct *src;
    struct mmt_internal_tcpip_id_struct *dst;

    const struct iphdr *iph;
#ifdef MMT_SUPPORT_IPV6
    const struct mmt_ipv6hdr *iphv6;
#endif
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    //const uint8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
    const uint8_t *payload;

    MMT_INTERNAL_TIMESTAMP_TYPE tick_timestamp;


    uint16_t detected_protocol_stack[PROTOCOL_HISTORY_SIZE];
    uint8_t detected_subprotocol_stack[PROTOCOL_HISTORY_SIZE];

    /* this is for simple read-only access to the real protocol
     * used for the main loop */
    uint16_t real_protocol_read_only;


#if PROTOCOL_HISTORY_SIZE > 1
#if PROTOCOL_HISTORY_SIZE > 5
#error protocol stack size not supported
#endif

    struct {
        uint8_t entry_is_real_protocol : 5;
        uint8_t current_stack_size_minus_one : 3;
    }
#if !(defined(WIN32))
    __attribute__((__packed__))
#endif
    protocol_stack_info;
#endif

    /* BW: MMT content type */
    struct {
        uint16_t content_class;
        uint16_t content_type;
    } content_info;

    struct mmt_int_one_line_struct https_server_name;

    struct mmt_int_one_line_struct line[MMT_MAX_PARSE_LINES_PER_PACKET];
    struct mmt_int_one_line_struct unix_line[MMT_MAX_PARSE_LINES_PER_PACKET];
    struct mmt_int_one_line_struct host_line;
    struct mmt_int_one_line_struct referer_line;
    struct mmt_int_one_line_struct content_line;
    struct mmt_int_one_line_struct accept_line;
    struct mmt_int_one_line_struct user_agent_line;
    struct mmt_int_one_line_struct upgrade_line; // LN: To extract upgrade line
    struct mmt_int_one_line_struct connection_line; // LN: To extract Connection line
    struct mmt_int_one_line_struct http_url_name;
    struct mmt_int_one_line_struct http_encoding;
    struct mmt_int_one_line_struct http_transfer_encoding;
    struct mmt_int_one_line_struct http_contentlen;
    struct mmt_int_one_line_struct http_cookie;
    struct mmt_int_one_line_struct http_x_session_type;
    struct mmt_int_one_line_struct server_line;
    struct mmt_int_one_line_struct http_method;
    struct mmt_int_one_line_struct http_response;

    MMT_PROTOCOL_BITMASK detection_bitmask;
    MMT_SELECTION_BITMASK_PROTOCOL_SIZE mmt_selection_packet;
    uint16_t l3_packet_len;
    /* BW: In the packet structure add the length of the truncated packet */
    uint16_t l3_captured_packet_len;
    uint16_t l4_packet_len;
    uint16_t payload_packet_len;
    uint16_t actual_payload_len;
    uint16_t num_retried_bytes;
    uint16_t parsed_lines;
    uint16_t parsed_unix_lines;
    uint16_t empty_line_position;
    uint8_t tcp_retransmission;
    uint8_t l4_protocol;
    uint8_t has_x_cdn_hdr;

    uint8_t packet_lines_parsed_complete;
    uint8_t packet_unix_lines_parsed_complete;
    uint8_t empty_line_position_set;
    
    //TODO: BW temporary solution waiting the TCP segmentation 
    uint32_t tcp_outoforder;
    
    // uint8_t packet_direction:1;
    uint64_t packet_id;

};

#endif	/* __MMT_TCPIP_PLUGIN_STRUCTS__ */
