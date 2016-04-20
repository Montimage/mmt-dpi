#ifndef MMT_TCPIP_ATTRIBUTES
#define MMT_TCPIP_ATTRIBUTES

#ifdef __cplusplus
extern "C" {
#endif

#include "mmt_contents_defs.h"

    enum {
        ETH_PROTOCOL = 1,
        ETH_DST,
        ETH_SRC,
    };

#define ETHERNET_ATTRIBUTES_NB ETH_SRC

#define ETH_PROTOCOL_ALIAS      "proto"
#define ETH_SRC_ALIAS           "src"
#define ETH_DST_ALIAS           "dst"

    enum ip_attributes {
        IP_VERSION = 1,
        IP_HEADER_LEN,
        IP_PROTO_TOS,
        IP_TOT_LEN,
        IP_IDENTIFICATION,
        IP_DF_FLAG,
        IP_MF_FLAG,
        IP_FRAG_OFFSET,
        IP_PROTO_TTL,
        IP_PROTO_ID,
        IP_CHECKSUM,
        IP_SRC,
        IP_DST,
        IP_OPTS,
        IP_RTT,
        IP_CLIENT_ADDR,
        IP_SERVER_ADDR,
        IP_CLIENT_PORT,
        IP_SERVER_PORT,
        IP_ATTRIBUTES_NB = IP_SERVER_PORT,
    };

#define IP_SRC_ALIAS            "src"
#define IP_DST_ALIAS            "dst"
#define IP_PROTO_ID_ALIAS       "proto_id"
#define IP_PROTO_TOS_ALIAS      "proto_tos"
#define IP_PROTO_TTL_ALIAS      "proto_ttl"
#define IP_TOT_LEN_ALIAS        "tot_len"
#define IP_DF_FLAG_ALIAS        "df_flag"
#define IP_MF_FLAG_ALIAS        "mf_flag"
#define IP_FRAG_OFFSET_ALIAS    "frag_offset"
#define IP_IDENTIFICATION_ALIAS "identification"
#define IP_HEADER_LEN_ALIAS     "header_len"
#define IP_VERSION_ALIAS        "version"
#define IP_OPTS_ALIAS        "options"
#define IP_RTT_ALIAS        "ip_rtt"
#define IP_CHECKSUM_ALIAS       "checksum"
#define IP_CLIENT_ADDR_ALIAS    "client_addr"
#define IP_SERVER_ADDR_ALIAS    "server_addr"
#define IP_CLIENT_PORT_ALIAS    "client_port"
#define IP_SERVER_PORT_ALIAS    "server_port"

    enum ip6_attributes {
        IP6_VERSION = 1,
        IP6_TRAFFIC_CLASS,
        IP6_FLOW_LABEL,
        IP6_PAYLOAD_LEN,
        IP6_NEXT_HEADER,
        IP6_NEXT_PROTO,
        IP6_HOP_LIMIT,
        IP6_SRC,
        IP6_DST,
        IP6_CLIENT_ADDR,
        IP6_SERVER_ADDR,
        IP6_CLIENT_PORT,
        IP6_SERVER_PORT,
        IP6_ATTRIBUTES_NB = IP6_SERVER_PORT,
    };
    /*
     * Hop by hop attribute
     * routing header
     * Fragement
     * authentication header
     * ESP header
     */
#define IP6_VERSION_ALIAS "version"
#define IP6_TRAFFIC_CLASS_ALIAS "TC"
#define IP6_FLOW_LABEL_ALIAS "flow_label"
#define IP6_PAYLOAD_LEN_ALIAS "len"
#define IP6_NEXT_HEADER_ALIAS "next_hdr"
#define IP6_NEXT_PROTO_ALIAS "next_proto"
#define IP6_HOP_LIMIT_ALIAS "hop_limit"
#define  IP6_SRC_ALIAS "src"
#define  IP6_DST_ALIAS "dst"
#define IP6_CLIENT_ADDR_ALIAS    "client_addr"
#define IP6_SERVER_ADDR_ALIAS    "server_addr"
#define IP6_CLIENT_PORT_ALIAS    "client_port"
#define IP6_SERVER_PORT_ALIAS    "server_port"

    enum {
        TCP_SRC_PORT = 1,
        TCP_DEST_PORT,
        TCP_SEQ_NB,
        TCP_ACK_NB,
        TCP_DATA_OFF, //tcp data offset
        TCP_FLAGS,
        TCP_FIN,
        TCP_SYN,
        TCP_RST,
        TCP_PSH,
        TCP_ACK,
        TCP_URG,
        TCP_ECE,
        TCP_CWR,
        TCP_WINDOW,
        TCP_CHECKSUM,
        TCP_URG_PTR,
        TCP_RTT,
        TCP_SYN_RCV,
        TCP_RETRANSMISSION,
        TCP_OUTOFORDER,
        TCP_SESSION_RETRANSMISSION,
        // TCP_SESSION_OUTOFORDER,
        TCP_PAYLOAD_LEN,
        TCP_CONN_ESTABLISHED,
    };

#define TCP_ATTRIBUTES_NB    TCP_CONN_ESTABLISHED

#define TCP_SRC_PORT_ALIAS    "src_port"
#define TCP_DEST_PORT_ALIAS   "dest_port"
#define TCP_SEQ_NB_ALIAS      "seq_nb"
#define TCP_ACK_NB_ALIAS      "ack_nb"
#define TCP_DATA_OFF_ALIAS    "data_offset"
#define TCP_FLAGS_ALIAS       "flags"
#define TCP_FIN_ALIAS         "fin"
#define TCP_SYN_ALIAS         "syn"
#define TCP_RST_ALIAS         "rst"
#define TCP_PSH_ALIAS         "psh"
#define TCP_ACK_ALIAS         "ack"
#define TCP_URG_ALIAS         "urg"
#define TCP_ECE_ALIAS         "ece"
#define TCP_CWR_ALIAS         "cwr"
#define TCP_WINDOW_ALIAS      "window"
#define TCP_CHECKSUM_ALIAS    "checksum"
#define TCP_URG_PTR_ALIAS     "urg_pointer"
#define TCP_RTT_ALIAS         "rtt"
#define TCP_SYN_RCV_ALIAS     "syn_received"
#define TCP_RETRANSMISSION_ALIAS     "retransmission"
#define TCP_OUTOFORDER_ALIAS     "outoforder"
#define TCP_SESSION_RETRANSMISSION_ALIAS     "session_retransmission"
// #define TCP_SESSION_OUTOFORDER_ALIAS     "session_outoforder"
#define TCP_PAYLOAD_LEN_ALIAS     "payload_len"
#define TCP_CONN_ESTABLISHED_ALIAS "established"
    //TODO: addition of the tcp options

    enum {
        UDP_SRC_PORT = 1,
        UDP_DEST_PORT,
        UDP_LEN,
        UDP_CHECKSUM,
    };

#define UDP_ATTRIBUTES_NB UDP_CHECKSUM

#define UDP_SRC_PORT_ALIAS      "src_port"
#define UDP_DEST_PORT_ALIAS     "dest_port"
#define UDP_LEN_ALIAS           "len"
#define UDP_CHECKSUM_ALIAS      "checksum"

    enum rfc2822_attributes {
        RFC2822_METHOD = 1,
        RFC2822_RESPONSE,
        RFC2822_HOST,
        RFC2822_URI,
        RFC2822_REFERER,
        RFC2822_CONTENT_TYPE,
        RFC2822_USER_AGENT,
        RFC2822_CONTENT_LEN,
        RFC2822_SERVER,
        RFC2822_XCDN_SEEN,
        HTTP_MESSAGE_START, // Beginning of an HTTP message
        HTTP_HEADER, // Generic HTTP header
        HTTP_HEADERS_END, // End of an HTTP message headers
        HTTP_DATA, // HTTP data chunk
        HTTP_MESSAGE_END, // End of an HTTP message
    };

#define RFC2822_ATTRIBUTES_NB HTTP_MESSAGE_END

#define RFC2822_HOST_ALIAS "host"
#define RFC2822_METHOD_ALIAS "method"
#define RFC2822_RESPONSE_ALIAS "response"
#define RFC2822_URI_ALIAS "uri"
#define RFC2822_REFERER_ALIAS "referer"
#define RFC2822_CONTENT_TYPE_ALIAS "content_type"
#define RFC2822_USER_AGENT_ALIAS "user_agent"
#define RFC2822_CONTENT_LEN_ALIAS "content_len"
#define RFC2822_SERVER_ALIAS "server"
#define RFC2822_XCDN_SEEN_ALIAS "xcdn_seen"
#define HTTP_MESSAGE_START_ALIAS "msg_start"
#define HTTP_HEADER_ALIAS "header"
#define HTTP_HEADERS_END_ALIAS "headers_end"
#define HTTP_DATA_ALIAS "data"
#define HTTP_MESSAGE_END_ALIAS "msg_end"

    enum arp_attributes {
        ARP_AR_HRD = 1,
        ARP_AR_PRO,
        ARP_AR_HLN,
        ARP_AR_PLN,
        ARP_AR_OP,
        ARP_AR_SHA,
        ARP_AR_SIP,
        ARP_AR_THA,
        ARP_AR_TIP,
        ARP_SRC_HARD,
        ARP_SRC_PROTO,
        ARP_DST_HARD,
        ARP_DST_PROTO,
        ARP_ATTRIBUTES_NB = ARP_DST_PROTO,
    };


#define ARP_AR_HRD_ALIAS "ar_hrd"
#define ARP_AR_PRO_ALIAS "ar_pro"
#define ARP_AR_HLN_ALIAS "ar_hln"
#define ARP_AR_PLN_ALIAS "ar_pln"
#define ARP_AR_OP_ALIAS "ar_op"
#define ARP_AR_SHA_ALIAS "ar_sha"
#define ARP_AR_SIP_ALIAS "ar_sip"
#define ARP_AR_THA_ALIAS "ar_tha"
#define ARP_AR_TIP_ALIAS "ar_tip"
#define ARP_SRC_HARD_ALIAS "src_hard"
#define ARP_SRC_PROTO_ALIAS "src_proto"
#define ARP_DST_HARD_ALIAS "dst_hard"
#define ARP_DST_PROTO_ALIAS "dst_proto"

    /**
     * GRE protocol: extraction of ann of the protocol fields.
     * <p>
     * TODO: Link sequence numbers and Keys to extract attributes like: out of sequence, in sequence, sequence gap, loss.
     */

    enum gre_attributes {
        GRE_PROTOCOL = 1,
        GRE_FLAGS,
        GRE_CHECKSUM,
        GRE_KEY,
        GRE_SEQ_NB,
        GRE_C_FLAG,
        GRE_K_FLAG,
        GRE_S_FLAG,
        GRE_OUT_SEQENCE, //TODO
        GRE_IN_SEQENCE, //TODO
        GRE_SEQENCE_GAP, //TODO
        GRE_LOSS, //TODO
    };

#define GRE_ATTRIBUTES_NB GRE_LOSS

#define GRE_PROTOCOL_ALIAS "proto"
#define GRE_FLAGS_ALIAS "flags"
#define GRE_CHECKSUM_ALIAS "checksum"
#define GRE_KEY_ALIAS "key"
#define GRE_SEQ_NB_ALIAS "seqnb"
#define GRE_C_FLAG_ALIAS "cflag"
#define GRE_K_FLAG_ALIAS "kflag"
#define GRE_S_FLAG_ALIAS "sflag"
#define GRE_OUT_SEQENCE_ALIAS "seq_out"
#define GRE_IN_SEQENCE_ALIAS "seq_in"
#define GRE_SEQENCE_GAP_ALIAS "seq_gap"
#define GRE_LOSS_ALIAS "loss"

    enum {
        ICMP_TYPE = 1,
        ICMP_CODE,
        ICMP_CHECKSUM,
        ICMP_IDENTIFIER,
        ICMP_SEQUENCE_NB,
        ICMP_GATEWAY,
        ICMP_DATA,
    };

#define ICMP_ATTRIBUTES_NB ICMP_DATA

#define ICMP_TYPE_ALIAS         "type"
#define ICMP_CODE_ALIAS         "code"
#define ICMP_CHECKSUM_ALIAS     "checksum"
#define ICMP_IDENTIFIER_ALIAS   "identifier"
#define ICMP_SEQUENCE_NB_ALIAS  "seq_nb"
#define ICMP_GATEWAY_ALIAS      "gateway"
#define ICMP_DATA_ALIAS         "data"

    enum {
        ICMP6_TYPE = 1,
        ICMP6_CODE,
        ICMP6_CHECKSUM,
    };

#define ICMP6_ATTRIBUTES_NB ICMP6_CHECKSUM

#define ICMP6_TYPE_ALIAS         "type"
#define ICMP6_CODE_ALIAS         "code"
#define ICMP6_CHECKSUM_ALIAS     "checksum"

    enum {
        OSPF_VERSION = 1,
        OSPF_TYPE,
        OSPF_PACKET_LENGTH,
        OSPF_ROUTER_ID,
        OSPF_AREA_ID,
        OSPF_CHECKSUM,
        OSPF_INSTANCE_ID,
        OSPF_ATTRIBUTES_NB = OSPF_INSTANCE_ID,
    };

#define  OSPF_VERSION_ALIAS "version"
#define  OSPF_TYPE_ALIAS "type"
#define  OSPF_PACKET_LENGTH_ALIAS "len"
#define  OSPF_ROUTER_ID_ALIAS "router_id"
#define  OSPF_AREA_ID_ALIAS "area_id"
#define  OSPF_CHECKSUM_ALIAS "checksum"
#define  OSPF_INSTANCE_ID_ALIAS "instance_id"

    enum {
        RTP_IGNORE = 0,
        RTP_VERSION,
        RTP_PADDING,
        RTP_EXTENSION,
        RTP_CSRCCOUNT,
        RTP_MARKER,
        RTP_PAYLOADTYPE,
        RTP_SEQNB,
        RTP_TIMESTAMP,
        RTP_SSRC,
        RTP_CSRC,
        RTP_QUALITY_INDEX,
        RTP_JITTER,
        RTP_INTER_ARRIVAL_JITTER, //TODO
        RTP_INTER_DELAY, //TODO
        RTP_LOSS,
        RTP_BURST_LOSS,
        RTP_UNORDER,
        RTP_DUPLICATE,
        RTP_ERROR_ORDER,
    };
#define RTP_ATTRIBUTES_NB RTP_ERROR_ORDER

#define RTP_VERSION_LABEL "VERSION"
#define RTP_PADDING_LABEL "PADDING"
#define RTP_EXTENSION_LABEL "EXTENSION"
#define RTP_CSRCCOUNT_LABEL "CSRC_COUNT"
#define RTP_MARKER_LABEL "MARKER"
#define RTP_PAYLOADTYPE_LABEL "PAYLOAD_TYPE"
#define RTP_SEQNB_LABEL "SEQUENCE_NUMBER"
#define RTP_TIMESTAMP_LABEL "TIMESTAMP"
#define RTP_SSRC_LABEL "SYNCHRONIZATION_SOURCE"
#define RTP_CSRC_LABEL "CONTRIBUTING_SOURCE"
#define RTP_QUALITY_INDEX_LABEL "QUALITY"
#define RTP_JITTER_LABEL "JITTER"
#define RTP_INTER_ARRIVAL_JITTER_LABEL "INTER_JITTER"
#define RTP_INTER_DELAY_LABEL "INTER_DELAY"
#define RTP_LOSS_LABEL "PACKET_LOSS"
#define RTP_BURST_LOSS_LABEL "PACKET_BURST_LOSS"
#define RTP_UNORDER_LABEL "UNORDER"
#define RTP_ERROR_ORDER_LABEL "ORDER_ERROR"
#define RTP_DUPLICATE_LABEL "DUPLICATE"

#define RTP_VERSION_SHORT_LABEL "version"
#define RTP_PADDING_SHORT_LABEL "pad"
#define RTP_EXTENSION_SHORT_LABEL "ext"
#define RTP_CSRCCOUNT_SHORT_LABEL "cc"
#define RTP_MARKER_SHORT_LABEL "mark"
#define RTP_PAYLOADTYPE_SHORT_LABEL "type"
#define RTP_SEQNB_SHORT_LABEL "seqnb"
#define RTP_TIMESTAMP_SHORT_LABEL "timestamp"
#define RTP_SSRC_SHORT_LABEL "ssrc"
#define RTP_CSRC_SHORT_LABEL "csrc"
#define RTP_QUALITY_INDEX_SHORT_LABEL "quality"
#define RTP_JITTER_SHORT_LABEL "jitter"
#define RTP_INTER_ARRIVAL_JITTER_SHORT_LABEL "inter_jitter"
#define RTP_INTER_DELAY_SHORT_LABEL "inter_delay"
#define RTP_LOSS_SHORT_LABEL "loss"
#define RTP_BURST_LOSS_SHORT_LABEL "burst_loss"
#define RTP_UNORDER_SHORT_LABEL "unorder"
#define RTP_ERROR_ORDER_SHORT_LABEL "order_err"
#define RTP_DUPLICATE_SHORT_LABEL "duplicate"

    enum ssl_attributes {
        SSL_SERVER_NAME = 1,
        SSL_ATTRIBUTES_NB = SSL_SERVER_NAME,
    };

#define SSL_SERVER_NAME_ALIAS "server_name"

    enum radius_attributes {
        RADIUS_CODE = 1,
        RADIUS_RID,
        RADIUS_RLEN,
        RADIUS_AUTHENTICATOR,
        RADIUS_USER_NAME,
        RADIUS_USER_PASSWORD,
        RADIUS_CHAP_PASSWORD,
        RADIUS_NAS_IP_ADDRESS,
        RADIUS_NAS_PORT,
        RADIUS_SERVICE_TYPE,
        RADIUS_FRAMED_PROTOCOL,
        RADIUS_FRAMED_IP_ADDRESS,
        RADIUS_FRAMED_IP_NETMASK,
        RADIUS_FRAMED_MTU,
        RADIUS_CALLBACK_NUMBER,
        RADIUS_CALLBACK_ID,
        RADIUS_STATE,
        RADIUS_CLASS,
        RADIUS_SESSION_TIMEOUT,
        RADIUS_IDLE_TIMEOUT,
        RADIUS_CALLED_STATION_ID,
        RADIUS_CALLING_STATION_ID,
        RADIUS_NAS_IDENTIFIER,
        RADIUS_ACCT_STATUS_TYPE,
        RADIUS_ACCT_DELAY_TIME,
        RADIUS_ACCT_INPUT_OCTETS,
        RADIUS_ACCT_OUTPUT_OCTETS,
        RADIUS_ACCT_SESSION_ID,
        RADIUS_ACCT_AUTHENTIC,
        RADIUS_ACCT_SESSION_TIME,
        RADIUS_ACCT_INPUT_PACKETS,
        RADIUS_ACCT_OUTPUT_PACKETS,
        RADIUS_ACCT_TERMINATE_CAUSE,
        RADIUS_EVENT_TIMESTAMP,
        RADIUS_NAS_PORT_TYPE,
        RADIUS_MESSAGE_AUTHENTICATOR,
        RADIUS_NAS_PORT_ID,
        RADIUS_NAS_IPV6_ADDRESS,
        RADIUS_FRAMED_INTERFACE_ID,
        RADIUS_FRAMED_IPV6_PREFIX,
        RADIUS_FRAMED_IPV6_POOL,
        RADIUS_3GPP_IMSI,
        RADIUS_3GPP_CHARGING_ID,
        RADIUS_3GPP_PDP_TYPE,
        RADIUS_3GPP_CG_ADDRESS,
        RADIUS_3GPP_QOS_PROFILE,
        RADIUS_3GPP_SGSN_ADDRESS,
        RADIUS_3GPP_GGSN_ADDRESS,
        RADIUS_3GPP_IMSI_MCCMNC,
        RADIUS_3GPP_GGSN_MCCMNC,
        RADIUS_3GPP_NSAPI,
        RADIUS_3GPP_SESSION_STOP_IND,
        RADIUS_3GPP_SELECTION_MODE,
        RADIUS_3GPP_CHARGIN_CHARACT,
        RADIUS_3GPP_CG_IPV6,
        RADIUS_3GPP_SGSN_IPV6,
        RADIUS_3GPP_GGSN_IPV6,
        RADIUS_3GPP_DNS_IPV6,
        RADIUS_3GPP_SGSN_MCCMNC,
        RADIUS_3GPP_TEARDOWN_IND,
        RADIUS_3GPP_IMEISV,
        RADIUS_3GPP_RAT_TYPE,
        RADIUS_3GPP_USER_LOCATION,
        RADIUS_3GPP_TIMEZONE,
        RADIUS_3GPP_CAMELCHARGING,
        RADIUS_3GPP_PACKET_FILTER,
        RADIUS_3GPP_NEG_DSCP,
        RADIUS_3GPP_ALLOC_IP_TYPE,
        RADIUS_AVP1,
        RADIUS_AVP2,
        RADIUS_AVP3,
        RADIUS_AVP4,
        RADIUS_AVP5,
        RADIUS_AVP6,
        RADIUS_AVP7,
        RADIUS_AVP8,
        RADIUS_AVP9,
        RADIUS_AVP10,
        RADIUS_AVP11,
        RADIUS_AVP12,
        RADIUS_AVP13,
        RADIUS_AVP14,
        RADIUS_AVP15,
        RADIUS_AVP16,
        RADIUS_AVP17,
        RADIUS_AVP18,
        RADIUS_AVP19,
        RADIUS_AVP20,
        RADIUS_AVP21,
        RADIUS_AVP22,
        RADIUS_AVP23,
        RADIUS_AVP24,
        RADIUS_AVP25,
        RADIUS_AVP26,
        RADIUS_AVP27,
        RADIUS_AVP28,
        RADIUS_AVP29,
        RADIUS_AVP30,
        RADIUS_AVP31,
        RADIUS_AVP32,
        RADIUS_AVP33,
        RADIUS_AVP34,
        RADIUS_AVP35,
        RADIUS_AVP36,
        RADIUS_AVP37,
        RADIUS_AVP38,
        RADIUS_AVP39,
        RADIUS_AVP40,
        RADIUS_AVP41,
        RADIUS_AVP42,
        RADIUS_AVP43,
        RADIUS_AVP44,
        RADIUS_AVP45,
        RADIUS_AVP46,
        RADIUS_AVP47,
        RADIUS_AVP48,
        RADIUS_AVP49,
        RADIUS_AVP50,
        RADIUS_AVP51,
        RADIUS_AVP52,
        RADIUS_AVP53,
        RADIUS_AVP54,
        RADIUS_AVP55,
        RADIUS_AVP56,
        RADIUS_AVP57,
        RADIUS_AVP58,
        RADIUS_AVP59,
        RADIUS_AVP60,
        RADIUS_AVP61,
        RADIUS_AVP62,
        RADIUS_AVP63,
        RADIUS_AVP64,
        RADIUS_AVP65,
        RADIUS_AVP66,
        RADIUS_AVP67,
        RADIUS_AVP68,
        RADIUS_AVP69,
        RADIUS_AVP70,
        RADIUS_AVP71,
        RADIUS_AVP72,
        RADIUS_AVP73,
        RADIUS_AVP74,
        RADIUS_AVP75,
        RADIUS_AVP76,
        RADIUS_AVP77,
        RADIUS_AVP78,
        RADIUS_AVP79,
        RADIUS_AVP80,
        RADIUS_AVP81,
        RADIUS_AVP82,
        RADIUS_AVP83,
        RADIUS_AVP84,
        RADIUS_AVP85,
        RADIUS_AVP86,
        RADIUS_AVP87,
        RADIUS_AVP88,
        RADIUS_AVP89,
        RADIUS_AVP90,
        RADIUS_AVP91,
        RADIUS_AVP92,
        RADIUS_AVP93,
        RADIUS_AVP94,
        RADIUS_AVP95,
        RADIUS_AVP96,
        RADIUS_AVP97,
        RADIUS_AVP98,
        RADIUS_AVP99,
        RADIUS_AVP100,
        RADIUS_AVP101,
        RADIUS_AVP102,
        RADIUS_AVP224,
        RADIUS_AVP225,
        RADIUS_AVP226,
        RADIUS_AVP227,
        RADIUS_AVP228,
        RADIUS_AVP229,
        RADIUS_AVP230,
        RADIUS_AVP231,
        RADIUS_AVP232,
        RADIUS_AVP233,
        RADIUS_AVP234,
        RADIUS_AVP235,
        RADIUS_AVP236,
        RADIUS_AVP237,
        RADIUS_AVP238,
        RADIUS_AVP239,
        RADIUS_AVP240,
        RADIUS_ATTRIBUTES_NB = RADIUS_AVP240,
    };

#define RADIUS_CODE_ALIAS "code"
#define RADIUS_RID_ALIAS "id"
#define RADIUS_RLEN_ALIAS "len"
#define RADIUS_AUTHENTICATOR_ALIAS "authenticator"
#define RADIUS_USER_NAME_ALIAS "user_name"
#define RADIUS_USER_PASSWORD_ALIAS "user_password"
#define RADIUS_CHAP_PASSWORD_ALIAS "chap_password"
#define RADIUS_NAS_IP_ADDRESS_ALIAS "nas_ip_address"
#define RADIUS_NAS_PORT_ALIAS "nas_port"
#define RADIUS_SERVICE_TYPE_ALIAS "service_type"
#define RADIUS_FRAMED_PROTOCOL_ALIAS "framed_protocol"
#define RADIUS_FRAMED_IP_ADDRESS_ALIAS "framed_ip_address"
#define RADIUS_FRAMED_IP_NETMASK_ALIAS "framed_ip_netmask"
#define RADIUS_FRAMED_MTU_ALIAS "framed_mtu"
#define RADIUS_CALLBACK_NUMBER_ALIAS "callback_number"
#define RADIUS_CALLBACK_ID_ALIAS "callback_id"
#define RADIUS_STATE_ALIAS "state"
#define RADIUS_CLASS_ALIAS "class"
#define RADIUS_SESSION_TIMEOUT_ALIAS "session_timeout"
#define RADIUS_IDLE_TIMEOUT_ALIAS "idle_timeout"
#define RADIUS_CALLED_STATION_ID_ALIAS "called_station_id"
#define RADIUS_CALLING_STATION_ID_ALIAS "calling_station_id"
#define RADIUS_NAS_IDENTIFIER_ALIAS "nas_identifier"
#define RADIUS_ACCT_STATUS_TYPE_ALIAS "acct_status_type"
#define RADIUS_ACCT_DELAY_TIME_ALIAS "acct_delay_time"
#define RADIUS_ACCT_INPUT_OCTETS_ALIAS "acct_input_octets"
#define RADIUS_ACCT_OUTPUT_OCTETS_ALIAS "acct_output_octets"
#define RADIUS_ACCT_SESSION_ID_ALIAS "acct_session_id"
#define RADIUS_ACCT_AUTHENTIC_ALIAS "acct_authentic"
#define RADIUS_ACCT_SESSION_TIME_ALIAS "acct_session_time"
#define RADIUS_ACCT_INPUT_PACKETS_ALIAS "acct_input_packets"
#define RADIUS_ACCT_OUTPUT_PACKETS_ALIAS "acct_output_packets"
#define RADIUS_ACCT_TERMINATE_CAUSE_ALIAS "acct_terminate_cause"
#define RADIUS_EVENT_TIMESTAMP_ALIAS "event_timestamp"
#define RADIUS_NAS_PORT_TYPE_ALIAS "nas_port_type"
#define RADIUS_MESSAGE_AUTHENTICATOR_ALIAS "message_authenticator"
#define RADIUS_NAS_PORT_ID_ALIAS "nas_port_id"
#define RADIUS_NAS_IPV6_ADDRESS_ALIAS "nas_ipv6_address"
#define RADIUS_FRAMED_INTERFACE_ID_ALIAS "framed_interface_id"
#define RADIUS_FRAMED_IPV6_PREFIX_ALIAS "framed_ipv6_prefix"
#define RADIUS_FRAMED_IPV6_POOL_ALIAS "framed_ipv6_pool"
#define RADIUS_3GPP_IMSI_ALIAS "imsi"
#define RADIUS_3GPP_CHARGING_ID_ALIAS "charg_id"
#define RADIUS_3GPP_PDP_TYPE_ALIAS "pdp_type"
#define RADIUS_3GPP_CG_ADDRESS_ALIAS "cg_ip"
#define RADIUS_3GPP_QOS_PROFILE_ALIAS "qos_prof"
#define RADIUS_3GPP_SGSN_ADDRESS_ALIAS "sgsn_ip"
#define RADIUS_3GPP_GGSN_ADDRESS_ALIAS "ggsn_ip"
#define RADIUS_3GPP_IMSI_MCCMNC_ALIAS "imsi_mccmnc"
#define RADIUS_3GPP_GGSN_MCCMNC_ALIAS "ggsn_mccmnc"
#define RADIUS_3GPP_NSAPI_ALIAS "nsapi"
#define RADIUS_3GPP_SESSION_STOP_IND_ALIAS "sess_stop_ind"
#define RADIUS_3GPP_SELECTION_MODE_ALIAS "select_mode"
#define RADIUS_3GPP_CHARGIN_CHARACT_ALIAS "charg_charact"
#define RADIUS_3GPP_CG_IPV6_ALIAS "cg_ipv6"
#define RADIUS_3GPP_SGSN_IPV6_ALIAS "sgsn_ipv6"
#define RADIUS_3GPP_GGSN_IPV6_ALIAS "ggsn_ipv6"
#define RADIUS_3GPP_DNS_IPV6_ALIAS "dns_ipv6"
#define RADIUS_3GPP_SGSN_MCCMNC_ALIAS "sgsn_mccmnc"
#define RADIUS_3GPP_TEARDOWN_IND_ALIAS "teardown_ind"
#define RADIUS_3GPP_IMEISV_ALIAS "imei"
#define RADIUS_3GPP_RAT_TYPE_ALIAS "rat_type"
#define RADIUS_3GPP_USER_LOCATION_ALIAS "user_loc"
#define RADIUS_3GPP_TIMEZONE_ALIAS "timezone"
#define RADIUS_3GPP_CAMELCHARGING_ALIAS "camel_charg"
#define RADIUS_3GPP_PACKET_FILTER_ALIAS "pkt_filter"
#define RADIUS_3GPP_NEG_DSCP_ALIAS "neg_dscp"
#define RADIUS_3GPP_ALLOC_IP_TYPE_ALIAS "alloc_ip_type"
#define RADIUS_AVP1_ALIAS  "avp1"
#define RADIUS_AVP2_ALIAS  "avp2"
#define RADIUS_AVP3_ALIAS  "avp3"
#define RADIUS_AVP4_ALIAS  "avp4"
#define RADIUS_AVP5_ALIAS  "avp5"
#define RADIUS_AVP6_ALIAS  "avp6"
#define RADIUS_AVP7_ALIAS  "avp7"
#define RADIUS_AVP8_ALIAS  "avp8"
#define RADIUS_AVP9_ALIAS  "avp9"
#define RADIUS_AVP10_ALIAS  "avp10"
#define RADIUS_AVP11_ALIAS  "avp11"
#define RADIUS_AVP12_ALIAS  "avp12"
#define RADIUS_AVP13_ALIAS  "avp13"
#define RADIUS_AVP14_ALIAS  "avp14"
#define RADIUS_AVP15_ALIAS  "avp15"
#define RADIUS_AVP16_ALIAS  "avp16"
#define RADIUS_AVP17_ALIAS  "avp17"
#define RADIUS_AVP18_ALIAS  "avp18"
#define RADIUS_AVP19_ALIAS  "avp19"
#define RADIUS_AVP20_ALIAS  "avp20"
#define RADIUS_AVP21_ALIAS  "avp21"
#define RADIUS_AVP22_ALIAS  "avp22"
#define RADIUS_AVP23_ALIAS  "avp23"
#define RADIUS_AVP24_ALIAS  "avp24"
#define RADIUS_AVP25_ALIAS  "avp25"
#define RADIUS_AVP26_ALIAS  "avp26"
#define RADIUS_AVP27_ALIAS  "avp27"
#define RADIUS_AVP28_ALIAS  "avp28"
#define RADIUS_AVP29_ALIAS  "avp29"
#define RADIUS_AVP30_ALIAS  "avp30"
#define RADIUS_AVP31_ALIAS  "avp31"
#define RADIUS_AVP32_ALIAS  "avp32"
#define RADIUS_AVP33_ALIAS  "avp33"
#define RADIUS_AVP34_ALIAS  "avp34"
#define RADIUS_AVP35_ALIAS  "avp35"
#define RADIUS_AVP36_ALIAS  "avp36"
#define RADIUS_AVP37_ALIAS  "avp37"
#define RADIUS_AVP38_ALIAS  "avp38"
#define RADIUS_AVP39_ALIAS  "avp39"
#define RADIUS_AVP40_ALIAS  "avp40"
#define RADIUS_AVP41_ALIAS  "avp41"
#define RADIUS_AVP42_ALIAS  "avp42"
#define RADIUS_AVP43_ALIAS  "avp43"
#define RADIUS_AVP44_ALIAS  "avp44"
#define RADIUS_AVP45_ALIAS  "avp45"
#define RADIUS_AVP46_ALIAS  "avp46"
#define RADIUS_AVP47_ALIAS  "avp47"
#define RADIUS_AVP48_ALIAS  "avp48"
#define RADIUS_AVP49_ALIAS  "avp49"
#define RADIUS_AVP50_ALIAS  "avp50"
#define RADIUS_AVP51_ALIAS  "avp51"
#define RADIUS_AVP52_ALIAS  "avp52"
#define RADIUS_AVP53_ALIAS  "avp53"
#define RADIUS_AVP54_ALIAS  "avp54"
#define RADIUS_AVP55_ALIAS  "avp55"
#define RADIUS_AVP56_ALIAS  "avp56"
#define RADIUS_AVP57_ALIAS  "avp57"
#define RADIUS_AVP58_ALIAS  "avp58"
#define RADIUS_AVP59_ALIAS  "avp59"
#define RADIUS_AVP60_ALIAS  "avp60"
#define RADIUS_AVP61_ALIAS  "avp61"
#define RADIUS_AVP62_ALIAS  "avp62"
#define RADIUS_AVP63_ALIAS  "avp63"
#define RADIUS_AVP64_ALIAS  "avp64"
#define RADIUS_AVP65_ALIAS  "avp65"
#define RADIUS_AVP66_ALIAS  "avp66"
#define RADIUS_AVP67_ALIAS  "avp67"
#define RADIUS_AVP68_ALIAS  "avp68"
#define RADIUS_AVP69_ALIAS  "avp69"
#define RADIUS_AVP70_ALIAS  "avp70"
#define RADIUS_AVP71_ALIAS  "avp71"
#define RADIUS_AVP72_ALIAS  "avp72"
#define RADIUS_AVP73_ALIAS  "avp73"
#define RADIUS_AVP74_ALIAS  "avp74"
#define RADIUS_AVP75_ALIAS  "avp75"
#define RADIUS_AVP76_ALIAS  "avp76"
#define RADIUS_AVP77_ALIAS  "avp77"
#define RADIUS_AVP78_ALIAS  "avp78"
#define RADIUS_AVP79_ALIAS  "avp79"
#define RADIUS_AVP80_ALIAS  "avp80"
#define RADIUS_AVP81_ALIAS  "avp81"
#define RADIUS_AVP82_ALIAS  "avp82"
#define RADIUS_AVP83_ALIAS  "avp83"
#define RADIUS_AVP84_ALIAS  "avp84"
#define RADIUS_AVP85_ALIAS  "avp85"
#define RADIUS_AVP86_ALIAS  "avp86"
#define RADIUS_AVP87_ALIAS  "avp87"
#define RADIUS_AVP88_ALIAS  "avp88"
#define RADIUS_AVP89_ALIAS  "avp89"
#define RADIUS_AVP90_ALIAS  "avp90"
#define RADIUS_AVP91_ALIAS  "avp91"
#define RADIUS_AVP92_ALIAS  "avp92"
#define RADIUS_AVP93_ALIAS  "avp93"
#define RADIUS_AVP94_ALIAS  "avp94"
#define RADIUS_AVP95_ALIAS  "avp95"
#define RADIUS_AVP96_ALIAS  "avp96"
#define RADIUS_AVP97_ALIAS  "avp97"
#define RADIUS_AVP98_ALIAS  "avp98"
#define RADIUS_AVP99_ALIAS  "avp99"
#define RADIUS_AVP100_ALIAS  "avp100"
#define RADIUS_AVP101_ALIAS  "avp101"
#define RADIUS_AVP102_ALIAS  "avp102"
#define RADIUS_AVP224_ALIAS  "avp224"
#define RADIUS_AVP225_ALIAS  "avp225"
#define RADIUS_AVP226_ALIAS  "avp226"
#define RADIUS_AVP227_ALIAS  "avp227"
#define RADIUS_AVP228_ALIAS  "avp228"
#define RADIUS_AVP229_ALIAS  "avp229"
#define RADIUS_AVP230_ALIAS  "avp230"
#define RADIUS_AVP231_ALIAS  "avp231"
#define RADIUS_AVP232_ALIAS  "avp232"
#define RADIUS_AVP233_ALIAS  "avp233"
#define RADIUS_AVP234_ALIAS  "avp234"
#define RADIUS_AVP235_ALIAS  "avp235"
#define RADIUS_AVP236_ALIAS  "avp236"
#define RADIUS_AVP237_ALIAS  "avp237"
#define RADIUS_AVP238_ALIAS  "avp238"
#define RADIUS_AVP239_ALIAS  "avp239"
#define RADIUS_AVP240_ALIAS  "avp240"

    enum dns_attributes {
        DNS_TID = 1,
        DNS_QR,
        DNS_OPCODE,
        DNS_AA,
        DNS_TC,
        DNS_RD,
        DNS_RA,
        DNS_Z,
        DNS_ANS_AUTH,
        DNS_DATA_AUTH,
        DNS_RCODE,
        DNS_QDCOUNT,
        DNS_ANCOUNT,
        DNS_NSCOUNT,
        DNS_ARCOUNT,
        DNS_ATTRIBUTES_NB = DNS_ARCOUNT,
    };

#define DNS_TID_ALIAS "tid"
#define DNS_QR_ALIAS "qr"
#define DNS_OPCODE_ALIAS "opcode"
#define DNS_AA_ALIAS "aa"
#define DNS_TC_ALIAS "tc"
#define DNS_RD_ALIAS "rd"
#define DNS_RA_ALIAS "ra"
#define DNS_Z_ALIAS "z"
#define DNS_ANS_AUTH_ALIAS "ans_auth"
#define DNS_DATA_AUTH_ALIAS "data_auth"
#define DNS_RCODE_ALIAS "rcode"
#define DNS_QDCOUNT_ALIAS "qdcount"
#define DNS_ANCOUNT_ALIAS "ancount"
#define DNS_NSCOUNT_ALIAS "nscount"
#define DNS_ARCOUNT_ALIAS "arcount"

    enum sll_attributes {
        SLL_PKTTYPE = 1,
        SLL_HATYPE,
        SLL_HALEN,
        SLL_ADDR,
        SLL_ADDR2,
        SLL_PROTOCOL,
        SLL_ATTRIBUTES_NB = SLL_PROTOCOL,
    };


#define SLL_PKTTYPE_ALIAS  "pkttype"
#define SLL_HATYPE_ALIAS   "hatype"
#define SLL_HALEN_ALIAS    "halen"
#define SLL_ADDR_ALIAS     "addr"
#define SLL_PROTOCOL_ALIAS "protocol"

/////////////////////////////// FTP ATTRIBUTES //////////////////////////////////////////
    // FTP protocol attribute
    enum ftp_attributes{
        /*--- SESSION ATTRIBUTES --- */
        FTP_SESSION_CONN_TYPE=1,// CONTROL or DATA connection
        /* CONTROL CONNECTION */
        FTP_SERVER_CONT_ADDR,
        FTP_SERVER_CONT_PORT, // Alway 21
        FTP_CLIENT_CONT_ADDR,
        FTP_CLIENT_CONT_PORT,
        // ACCOUNT
        FTP_USERNAME,
        FTP_PASSWORD,
        // OTHER
        FTP_SESSION_FEATURES,
        FTP_SYST,//
        FTP_STATUS,
        FTP_LAST_COMMAND,
        FTP_LAST_RESPONSE_CODE,
        FTP_CURRENT_DIR,
        /* DATA CONNECTION */
        FTP_SERVER_DATA_ADDR,
        FTP_SERVER_DATA_PORT,
        FTP_CLIENT_DATA_ADDR,
        FTP_CLIENT_DATA_PORT,
        FTP_DATA_TYPE, // FTP_LIST_DIRECTORY, FTP_FILE_TRANSFER
        FTP_DATA_TRANSFER_TYPE,// ASCII, IMAGE, EBCDIC, LOCAL
        FTP_DATA_MODE,// PASSIVE or ACTIVE
        FTP_DATA_DIRECTION,
        // FILE ATTRIBUTE - ONLY for FTP_FILE_TRANSFER
        FTP_FILE_NAME,
        FTP_FILE_SIZE,
        FTP_FILE_LAST_MODIFIED,
        /*--- Packet attributes ---*/
        FTP_PACKET_TYPE, // DATA, REQUEST, RESPONSE - WITH PACKET_TYPE WE CAN KNOW WHO IS THE SERVER AND WHO IS THE CLIENT
        FTP_PACKET_REQUEST, // ONLY REQUEST PACKET
        FTP_PACKET_REQUEST_PARAMETER, // ONLY REQUEST PACKET
        FTP_PACKET_RESPONSE_CODE, // ONLY RESPONSE PACKET
        FTP_PACKET_RESPONSE_VALUE, // ONLY RESPONSE PACKET
        FTP_PACKET_DATA_LEN,// ONLY DATA PACKET 
        FTP_ATTRIBUTES_NB = FTP_PACKET_DATA_LEN
    };

#define FTP_SESSION_CONN_TYPE_ALIAS    "session_connection_type"
// Control connection
#define FTP_SERVER_CONT_ADDR_ALIAS  "server_control_addr"
#define FTP_SERVER_CONT_PORT_ALIAS  "server_control_port"
#define FTP_CLIENT_CONT_ADDR_ALIAS  "data_control_addr"
#define FTP_CLIENT_CONT_PORT_ALIAS  "data_control_port"
// USER ATTRIBUTE
#define FTP_USERNAME_ALIAS          "user_name"
#define FTP_PASSWORD_ALIAS          "password"
#define FTP_SESSION_FEATURES_ALIAS  "session_features"
#define FTP_SYST_ALIAS              "ftp_server_system"//
#define FTP_STATUS_ALIAS            "ftp_status"
#define FTP_LAST_COMMAND_ALIAS      "last_command"
#define FTP_LAST_RESPONSE_CODE_ALIAS      "last_response_code"
#define FTP_CURRENT_DIR_ALIAS       "current_directory"
// Data connection
#define FTP_SERVER_DATA_ADDR_ALIAS  "server_data_addr"
#define FTP_SERVER_DATA_PORT_ALIAS  "server_data_port"
#define FTP_CLIENT_DATA_ADDR_ALIAS  "client_data_addr"
#define FTP_CLIENT_DATA_PORT_ALIAS  "client_data_port"
#define FTP_DATA_TYPE_ALIAS         "data_type" //
#define FTP_DATA_TRANSFER_TYPE_ALIAS "transfer_type"
#define FTP_DATA_MODE_ALIAS      "ftp_session_mode"// PASSIVE or ACTIVE
#define FTP_DATA_DIRECTION_ALIAS    "data_direction" // Upload, download
// FILE ATTRIBUTE
#define FTP_FILE_NAME_ALIAS         "file_name"
#define FTP_FILE_SIZE_ALIAS         "file_size"
#define FTP_FILE_LAST_MODIFIED_ALIAS "file_last_modified"
/*--- Packet attributes ---*/
#define FTP_PACKET_TYPE_ALIAS       "packet_type"  // DATA_ALIAS REQUEST_ALIAS RESPONSE
#define FTP_PACKET_REQUEST_ALIAS    "packet_request"// ONLY REQUEST PACKET
#define FTP_PACKET_REQUEST_PARAMETER_ALIAS "packet_request_parameter"// ONLY REQUEST PACKET
#define FTP_PACKET_RESPONSE_CODE_ALIAS "packet_response_code"// ONLY RESPONSE PACKET
#define FTP_PACKET_RESPONSE_VALUE_ALIAS "packet_reponse_value"// ONLY RESPONSE PACKET
#define FTP_PACKET_DATA_LEN_ALIAS "packet_payload_len"// ONLY DATA PACKET 

/////////////////////////////// END OF FTP ATTRIBUTES ///////////////////////////////////

//////////////////////////////// NDN ATTRIBUTES ////////////////////////
// Type of ndn - do not change the order
enum 
{
    // Packet type
    NDN_IMPLICIT_SHA256_DIGEST_COMPONENT = 1,
    NDN_PACKET_TYPE,
    NDN_PACKET_LENGTH,
    // Common field
    NDN_UNKNOWN_PACKET,
    NDN_INTEREST_PACKET,
    NDN_DATA_PACKET,
    NDN_COMMON_NAME,
    NDN_NAME_COMPONENTS,
    // Interest packet
    NDN_INTEREST_SELECTORS,
    NDN_INTEREST_NONCE,
    NDN_INTEREST_LIFETIME = 12,
    // Interest/selectors
    NDN_INTEREST_MIN_SUFFIX_COMPONENT,
    NDN_INTEREST_MAX_SUFFIX_COMPONENT,
    NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR,
    NDN_INTEREST_EXCLUDE,
    NDN_INTEREST_CHILD_SELECTOR,
    NDN_INTEREST_MUST_BE_FRESH,
    NDN_INTEREST_ANY,
    // Data packet
    NDN_DATA_METAINFO,
    NDN_DATA_CONTENT,
    NDN_DATA_SIGNATURE_INFO,
    NDN_DATA_SIGNATURE_VALUE,
    // data/metainfo
    NDN_DATA_CONTENT_TYPE,
    NDN_DATA_FRESHNESS_PERIOD,
    NDN_DATA_FINAL_BLOCK_ID,
    // Data/signature
    NDN_DATA_SIGNATURE_TYPE,
    NDN_DATA_KEY_LOCATOR,
    NDN_DATA_KEY_DIGEST,
    NDN_LIST_SESSIONS,
    NDN_ATTRIBUTES_NB,
};


#define NDN_IMPLICIT_SHA256_DIGEST_COMPONENT_ALIAS  "implicitSHA256DigestComponent"
#define NDN_PACKET_TYPE_ALIAS                       "packet_type"
#define NDN_PACKET_LENGTH_ALIAS                     "packet_length"
    // Common field
#define NDN_COMMON_NAME_ALIAS                       "common_name"
#define NDN_NAME_COMPONENTS_ALIAS                   "name_components"
    // Interest packet
#define NDN_INTEREST_NONCE_ALIAS                    "nonce"
#define NDN_INTEREST_LIFETIME_ALIAS                 "life_time"
    // Interest/selectors
#define NDN_INTEREST_MIN_SUFFIX_COMPONENT_ALIAS     "min_suffix"
#define NDN_INTEREST_MAX_SUFFIX_COMPONENT_ALIAS     "max_suffix"
#define NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR_ALIAS  "publisher_publickey_locator"
#define NDN_INTEREST_EXCLUDE_ALIAS                  "exclude"
#define NDN_INTEREST_CHILD_SELECTOR_ALIAS           "child_selector"
#define NDN_INTEREST_MUST_BE_FRESH_ALIAS            "must_be_fresh"
#define NDN_INTEREST_ANY_ALIAS                      "any"
    // Data packet
#define NDN_DATA_CONTENT_ALIAS                      "content"
#define NDN_DATA_SIGNATURE_VALUE_ALIAS              "signature_value"
    // data/metainfo
#define NDN_DATA_CONTENT_TYPE_ALIAS                 "content_type"
#define NDN_DATA_FRESHNESS_PERIOD_ALIAS             "fresh_period"
#define NDN_DATA_FINAL_BLOCK_ID_ALIAS               "final_block_id"
    // Data/signature
#define NDN_DATA_SIGNATURE_TYPE_ALIAS               "signature_type"
#define NDN_DATA_KEY_LOCATOR_ALIAS                  "key_locator"
#define NDN_DATA_KEY_DIGEST_ALIAS                   "key_digest"
#define NDN_LIST_SESSIONS_ALIAS                     "list_sessions"
////////////////// END OF NDN ATTRIBUTES ////////////////////

#ifdef __cplusplus
}
#endif
#endif //MMT_TCPIP_ATTRIBUTES
