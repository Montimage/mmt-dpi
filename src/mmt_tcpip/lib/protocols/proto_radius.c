#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#define VENDOR_3GPP_ID 10415
#define VENDOR_3GPP_MAX_TLV_TYPE 27

typedef struct vendor_tlv_struct {
    uint32_t vendor_id;
    uint8_t type;
    uint8_t len;
    uint8_t val;
} vendor_tlv_t;

typedef struct tlv_struct {
    uint8_t type;
    uint8_t len;
    uint8_t val;
} tlv_t;

struct radius_header {
    uint8_t code;
    uint8_t packet_id;
    uint16_t len;
};

/*
 * Issue #59: this header overlays the byte-aligned packet->payload; reading
 * (and writing) len through a strict cast is a misaligned access (UB, aborts
 * under BUILD=asan -fsanitize=alignment). This view lowers the alignment
 * requirement to 1 for alignment-safe single-load access. Mirrors PR #58 (#57).
 */
typedef struct radius_header __attribute__((aligned(1))) mmt_una_radius_header_t;

/* Issue #530: one slot per value of the 8-bit TLV type (0..255); 0xFF slots
 * left type 255 writing one element past the array. */
#define RADIUS_TLV_SLOTS 0x100

typedef struct radius_session_context_struct {
    int tlv_count;
    tlv_t * packet_tlvs[RADIUS_TLV_SLOTS]; // This will hold the different TLVs found in the last packet.
    tlv_t * vendor_3gpp_tlvs[VENDOR_3GPP_MAX_TLV_TYPE + 1]; // This will hold the different TLVs found in the last packet.
} radius_session_context_t;

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static inline uint32_t
read_be32( const uint8_t *x )
{ return ((uint32_t)x[0] << 24) | ((uint32_t)x[1] << 16) | ((uint32_t)x[2] << 8) | (uint32_t)x[3]; }

/*
 * RADIUS data extraction routines.
 *
 * Issue #543: apart from the authenticator (a fixed header field), every
 * attribute reads one TLV of the last packet — a packet attribute
 * (packet_tlvs[type]) or a 3GPP vendor sub-attribute
 * (vendor_3gpp_tlvs[type], filled by radius_vendor_specific_fields_analysis)
 * — and copies it in one of a few shapes. radius_tlv_desc[] names the TLV
 * and the shape of each such attribute; radius_tlv_extraction() finds the
 * entry through extracted_data->field_id, which the core sets on every
 * registered attribute (packet_registry_attr.c, register_extraction_attribute).
 * The length guards are those of the per-attribute functions this table
 * replaced (#128, #205, #331): the copy never reads past the TLV, which the
 * parser stored only when it lay inside the capture.
 * tests/radius_hardening/radius_extraction.golden pins the output of every
 * attribute.
 */
static int radius_authenticator_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if (ipacket == NULL || ipacket->p_hdr == NULL || ipacket->data == NULL) return 0;
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);

    /* Get the attribute offset (relative the to protocol) */
    int attribute_offset = sizeof (struct radius_header);

    int attribute_length = 16; /* Length of the authenticator field */
    if (proto_offset < 0) return 0;
    if ((size_t)proto_offset + (size_t)attribute_offset + (size_t)attribute_length > ipacket->p_hdr->caplen) return 0;

    *((unsigned int *) extracted_data->data) = attribute_length;
    memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & ipacket->data[proto_offset + attribute_offset], attribute_length);

    return 1;
}

/* How a TLV value is copied into the attribute. */
enum radius_copy {
    RADIUS_COPY_NONE = 0, /* no table entry: never reported */
    RADIUS_COPY_BIN64,    /* MMT_BINARY_DATA: 4-byte length + value clamped to 64 bytes */
    RADIUS_COPY_STR63,    /* MMT_BINARY_DATA: 4-byte length + value clamped to 63 bytes, NUL-terminated */
    RADIUS_COPY_BE32,     /* MMT_U32_DATA: the first 4 value bytes, big-endian */
    RADIUS_COPY_U8,       /* MMT_U8_DATA: the first value byte */
    RADIUS_COPY_FIXED,    /* the first `size` value bytes, as they are */
};

typedef struct radius_tlv_desc_struct {
    uint8_t vendor_3gpp; /* 0: packet_tlvs[type]; 1: vendor_3gpp_tlvs[type] */
    uint8_t type;        /* RADIUS attribute or 3GPP sub-attribute type */
    uint8_t copy;        /* enum radius_copy */
    uint8_t size;        /* RADIUS_COPY_FIXED: bytes copied (the value must hold them) */
} radius_tlv_desc_t;

#define RADIUS_PKT(type, copy, size)  { 0, (type), (copy), (size) }
#define RADIUS_3GPP(type, copy, size) { 1, (type), (copy), (size) }

/* Indexed by attribute id; ids with no entry are not TLV attributes. */
static const radius_tlv_desc_t radius_tlv_desc[RADIUS_ATTRIBUTES_NB + 1] = {
    [RADIUS_USER_NAME]             = RADIUS_PKT(1, RADIUS_COPY_BIN64, 0),
    [RADIUS_USER_PASSWORD]         = RADIUS_PKT(2, RADIUS_COPY_BIN64, 0),
    [RADIUS_CHAP_PASSWORD]         = RADIUS_PKT(3, RADIUS_COPY_BIN64, 0),
    [RADIUS_NAS_IP_ADDRESS]        = RADIUS_PKT(4, RADIUS_COPY_BE32, 0),
    [RADIUS_NAS_PORT]              = RADIUS_PKT(5, RADIUS_COPY_BE32, 0),
    [RADIUS_SERVICE_TYPE]          = RADIUS_PKT(6, RADIUS_COPY_BE32, 0),
    [RADIUS_FRAMED_PROTOCOL]       = RADIUS_PKT(7, RADIUS_COPY_BE32, 0),
    [RADIUS_FRAMED_IP_ADDRESS]     = RADIUS_PKT(8, RADIUS_COPY_BE32, 0),
    [RADIUS_FRAMED_IP_NETMASK]     = RADIUS_PKT(9, RADIUS_COPY_BE32, 0),
    [RADIUS_FRAMED_MTU]            = RADIUS_PKT(12, RADIUS_COPY_BE32, 0),
    [RADIUS_CALLBACK_NUMBER]       = RADIUS_PKT(19, RADIUS_COPY_BIN64, 0),
    [RADIUS_CALLBACK_ID]           = RADIUS_PKT(20, RADIUS_COPY_BIN64, 0),
    [RADIUS_STATE]                 = RADIUS_PKT(24, RADIUS_COPY_BIN64, 0),
    [RADIUS_CLASS]                 = RADIUS_PKT(25, RADIUS_COPY_BIN64, 0),
    [RADIUS_SESSION_TIMEOUT]       = RADIUS_PKT(27, RADIUS_COPY_BE32, 0),
    [RADIUS_IDLE_TIMEOUT]          = RADIUS_PKT(28, RADIUS_COPY_BE32, 0),
    [RADIUS_CALLED_STATION_ID]     = RADIUS_PKT(30, RADIUS_COPY_STR63, 0),
    [RADIUS_CALLING_STATION_ID]    = RADIUS_PKT(31, RADIUS_COPY_STR63, 0),
    [RADIUS_NAS_IDENTIFIER]        = RADIUS_PKT(32, RADIUS_COPY_BIN64, 0),
    [RADIUS_ACCT_STATUS_TYPE]      = RADIUS_PKT(40, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_DELAY_TIME]       = RADIUS_PKT(41, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_INPUT_OCTETS]     = RADIUS_PKT(42, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_OUTPUT_OCTETS]    = RADIUS_PKT(43, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_SESSION_ID]       = RADIUS_PKT(44, RADIUS_COPY_STR63, 0),
    [RADIUS_ACCT_AUTHENTIC]        = RADIUS_PKT(45, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_SESSION_TIME]     = RADIUS_PKT(46, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_INPUT_PACKETS]    = RADIUS_PKT(47, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_OUTPUT_PACKETS]   = RADIUS_PKT(48, RADIUS_COPY_BE32, 0),
    [RADIUS_ACCT_TERMINATE_CAUSE]  = RADIUS_PKT(49, RADIUS_COPY_BE32, 0),
    [RADIUS_EVENT_TIMESTAMP]       = RADIUS_PKT(55, RADIUS_COPY_BE32, 0),
    [RADIUS_NAS_PORT_TYPE]         = RADIUS_PKT(61, RADIUS_COPY_BE32, 0),
    [RADIUS_MESSAGE_AUTHENTICATOR] = RADIUS_PKT(80, RADIUS_COPY_BIN64, 0),
    [RADIUS_NAS_PORT_ID]           = RADIUS_PKT(87, RADIUS_COPY_BIN64, 0),
    [RADIUS_NAS_IPV6_ADDRESS]      = RADIUS_PKT(95, RADIUS_COPY_FIXED, IPv6_ALEN),
    [RADIUS_FRAMED_INTERFACE_ID]   = RADIUS_PKT(96, RADIUS_COPY_FIXED, 8),
    [RADIUS_FRAMED_IPV6_PREFIX]    = RADIUS_PKT(97, RADIUS_COPY_BIN64, 0),
    [RADIUS_FRAMED_IPV6_POOL]      = RADIUS_PKT(100, RADIUS_COPY_BIN64, 0),
    [RADIUS_3GPP_IMSI]             = RADIUS_3GPP(1, RADIUS_COPY_STR63, 0),
    [RADIUS_3GPP_SGSN_ADDRESS]     = RADIUS_3GPP(6, RADIUS_COPY_BE32, 0),
    [RADIUS_3GPP_GGSN_ADDRESS]     = RADIUS_3GPP(7, RADIUS_COPY_BE32, 0),
    [RADIUS_3GPP_CHARGIN_CHARACT]  = RADIUS_3GPP(13, RADIUS_COPY_STR63, 0),
    [RADIUS_3GPP_SGSN_IPV6]        = RADIUS_3GPP(15, RADIUS_COPY_FIXED, IPv6_ALEN),
    [RADIUS_3GPP_GGSN_IPV6]        = RADIUS_3GPP(16, RADIUS_COPY_FIXED, IPv6_ALEN),
    [RADIUS_3GPP_DNS_IPV6]         = RADIUS_3GPP(17, RADIUS_COPY_FIXED, IPv6_ALEN), /* #331: the first (primary) server */
    [RADIUS_3GPP_SGSN_MCCMNC]      = RADIUS_3GPP(18, RADIUS_COPY_STR63, 0),
    [RADIUS_3GPP_IMEISV]           = RADIUS_3GPP(20, RADIUS_COPY_STR63, 0),
    [RADIUS_3GPP_RAT_TYPE]         = RADIUS_3GPP(21, RADIUS_COPY_U8, 0),
    [RADIUS_3GPP_USER_LOCATION]    = RADIUS_3GPP(22, RADIUS_COPY_STR63, 0),
};

static int radius_tlv_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    if (extracted_data->field_id > RADIUS_ATTRIBUTES_NB) return 0;
    const radius_tlv_desc_t * desc = &radius_tlv_desc[extracted_data->field_id];
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data == NULL || desc->copy == RADIUS_COPY_NONE) return 0;
    const tlv_t * tlv = desc->vendor_3gpp ? radius_session_data->vendor_3gpp_tlvs[desc->type]
                                          : radius_session_data->packet_tlvs[desc->type];
    if (tlv == NULL) return 0;
    u_char * out = (u_char *) extracted_data->data;
    size_t vlen;
    switch (desc->copy) {
    case RADIUS_COPY_BIN64:
        if (tlv->len < 2) return 0;
        vlen = (size_t)tlv->len - 2;
        if (vlen > BINARY_64DATA_LEN) vlen = BINARY_64DATA_LEN;
        *((unsigned int *) out) = (unsigned int)vlen;
        memcpy(& out[sizeof (int) ], & tlv->val, vlen);
        return 1;
    case RADIUS_COPY_STR63:
        if (tlv->len < 2) return 0;
        vlen = (size_t)tlv->len - 2;
        if (vlen >= BINARY_64DATA_LEN) vlen = BINARY_64DATA_LEN - 1;
        *((unsigned int *) out) = (unsigned int)vlen;
        memcpy(& out[sizeof (int) ], & tlv->val, vlen);
        out[sizeof (int) +vlen] = '\0';
        return 1;
    case RADIUS_COPY_BE32:
        if (tlv->len < 6) return 0;
        *((unsigned int *) out) = read_be32( & tlv->val );
        return 1;
    case RADIUS_COPY_U8:
        if (tlv->len < 3) return 0;
        *((uint8_t *) out) = tlv->val;
        return 1;
    case RADIUS_COPY_FIXED:
        if (tlv->len < 2 + desc->size) return 0;
        memcpy(out, & tlv->val, desc->size);
        return 1;
    default:
        return 0;
    }
}

/* RADIUS_AVP1..RADIUS_AVP102 and RADIUS_AVP224..RADIUS_AVP240
 * (MMT_DATA_POINTER): a pointer to the whole TLV of that type. */
_Static_assert(RADIUS_AVP102 - RADIUS_AVP1 == 101 && RADIUS_AVP224 == RADIUS_AVP102 + 1
        && RADIUS_AVP240 - RADIUS_AVP224 == 16, "RADIUS_AVP ids must stay contiguous");

static int radius_avp_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    uint32_t id = extracted_data->field_id;
    unsigned type;
    if (id >= RADIUS_AVP1 && id <= RADIUS_AVP102) type = 1 + (id - RADIUS_AVP1);
    else if (id >= RADIUS_AVP224 && id <= RADIUS_AVP240) type = 224 + (id - RADIUS_AVP224);
    else return 0;
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[type]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[type];
        return 1;
    }
    return 0;
}

/* 3GPP attributes declared in the attribute list but never decoded. */
static int radius_unsupported_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    (void) ipacket; (void) proto_index; (void) extracted_data;
    return 0;
}

/* RADIUS packet codes a flow may start with: RFC 2865/2866 (1-5, 11-13)
 * and the RFC 5176 dynamic-authorization codes (40-45). */
static int mmt_radius_code_is_valid(uint8_t code) {
    return (code >= 1 && code <= 5) || (code >= 11 && code <= 13)
            || (code >= 40 && code <= 45);
}

int mmt_check_radius(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_RADIUS, MMT_LOG_DEBUG, "radius detection...\n");

        uint32_t payload_len = packet->payload_packet_len;

        mmt_una_radius_header_t *h = (mmt_una_radius_header_t*) packet->payload;

        /* The length field is read only once the payload is known to hold
         * the whole header; a RADIUS packet is at least 20 bytes (code,
         * identifier, length and the 16-byte authenticator, RFC 2865 §3). */
        if ((payload_len >= 20)
                && mmt_radius_code_is_valid(h->code)
                && (ntohs(h->len) == payload_len)) {
            MMT_LOG(PROTO_RADIUS, MMT_LOG_DEBUG, "Found radius.\n");
            mmt_internal_add_connection(ipacket, PROTO_RADIUS, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RADIUS);
    }
    return 0;
}

void radius_vendor_specific_fields_analysis(ipacket_t * ipacket, uint8_t * v_field, size_t v_remaining, unsigned index) {
    if (v_remaining < 6) return; // need 4-byte vendor ID + 2-byte sub-TLV header
    /* Issue #205 (F-BUG-074): read the vendor ID byte-wise — the field is
     * not 4-byte aligned in the packet, so the uint32_t cast was UB. */
    if (read_be32(v_field) != VENDOR_3GPP_ID) return;
    radius_session_context_t * radius_session_data = ipacket->session->session_data[index];
    if (radius_session_data == NULL) return;
    tlv_t * tlv = (tlv_t *) & v_field[4]; //Offset the vendor id (4 bytes)
    size_t sub_remaining = v_remaining - 4;
    if (sub_remaining < 2) return;
    if (tlv->len < 2) return;
    if ((size_t)tlv->len > sub_remaining) return;
    if (tlv->type > VENDOR_3GPP_MAX_TLV_TYPE) return;
    // keep >= VENDOR_3GPP_MAX_TLV_TYPE check for verification: reject if tlv->type >= VENDOR_3GPP_MAX_TLV_TYPE+1
    if (tlv->type >= VENDOR_3GPP_MAX_TLV_TYPE+1) return;
    radius_session_data->vendor_3gpp_tlvs[tlv->type] = tlv;
}

void radius_session_data_init(ipacket_t * ipacket, unsigned index) {
    /*
     * Issue #23: RADIUS parser state is stored per-session (allocated into the
     * session context) rather than in a __thread global. This prevents
     * concurrent RADIUS flows on the same thread from clobbering each other's
     * TLV state.
     */
    radius_session_context_t * radius_session_data = (radius_session_context_t *) mmt_malloc(sizeof (radius_session_context_t));
    memset(radius_session_data, 0, sizeof (radius_session_context_t));
    ipacket->session->session_data[index] = radius_session_data;
}

void radius_session_data_cleanup(mmt_session_t * session, unsigned index) {
    if (session->session_data[index] != NULL) {
        mmt_free(session->session_data[index]);
    }
}

int radius_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    radius_session_context_t * radius_session_data;
    radius_session_data = ipacket->session->session_data[index];
    if (radius_session_data) {
        int count;
        for (count = 0; count < RADIUS_TLV_SLOTS; count++) {
            radius_session_data->packet_tlvs[count] = NULL;
        }
        for (count = 0; count <= VENDOR_3GPP_MAX_TLV_TYPE; count++) {
            radius_session_data->vendor_3gpp_tlvs[count] = NULL;
        }
        radius_session_data->tlv_count = 0;
        /* Get the protocol offset */
        int proto_offset = get_packet_offset_at_index(ipacket, index);
        if (proto_offset < 0) return MMT_CONTINUE;
        if (ipacket->p_hdr == NULL || ipacket->data == NULL) return MMT_CONTINUE;
        int tlv_offset = proto_offset + 20 /* header = 4 octets + 16 for authenticator field */;
        while ((size_t)ipacket->p_hdr->caplen > (size_t)tlv_offset + 2 /* to guarantee we have access to the type and len of the next tlv */) {
            tlv_t * current_tlv = (tlv_t *) & ipacket->data[tlv_offset];
            if (current_tlv->len < 2) break; /* F-BUG-102: reject TLVs with len<2 */
            if ((size_t)tlv_offset + (size_t)current_tlv->len > (size_t)ipacket->p_hdr->caplen) break; /* truncated */
            /* The current tlv is completely in the available packet data! */
            radius_session_data->packet_tlvs[current_tlv->type] = current_tlv;
            if (current_tlv->type == 26) {
                size_t v_remaining = (size_t)current_tlv->len - 2;
                radius_vendor_specific_fields_analysis(ipacket, (uint8_t *) & current_tlv->val, v_remaining, index);
            }
            radius_session_data->tlv_count += 1;
            tlv_offset += current_tlv->len;
        }
    }
    return MMT_CONTINUE;
}

static attribute_metadata_t radius_attributes_metadata[RADIUS_ATTRIBUTES_NB] = {
    {RADIUS_CODE, RADIUS_CODE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, general_char_extraction},
    {RADIUS_RID, RADIUS_RID_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 1, SCOPE_PACKET, general_char_extraction},
    {RADIUS_RLEN, RADIUS_RLEN_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {RADIUS_AUTHENTICATOR, RADIUS_AUTHENTICATOR_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_authenticator_extraction},
    {RADIUS_USER_NAME, RADIUS_USER_NAME_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_USER_PASSWORD, RADIUS_USER_PASSWORD_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_CHAP_PASSWORD, RADIUS_CHAP_PASSWORD_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_NAS_IP_ADDRESS, RADIUS_NAS_IP_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_NAS_PORT, RADIUS_NAS_PORT_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_SERVICE_TYPE, RADIUS_SERVICE_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_FRAMED_PROTOCOL, RADIUS_FRAMED_PROTOCOL_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_FRAMED_IP_ADDRESS, RADIUS_FRAMED_IP_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_FRAMED_IP_NETMASK, RADIUS_FRAMED_IP_NETMASK_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_FRAMED_MTU, RADIUS_FRAMED_MTU_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_CALLBACK_NUMBER, RADIUS_CALLBACK_NUMBER_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_CALLBACK_ID, RADIUS_CALLBACK_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_STATE, RADIUS_STATE_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_CLASS, RADIUS_CLASS_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_SESSION_TIMEOUT, RADIUS_SESSION_TIMEOUT_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_IDLE_TIMEOUT, RADIUS_IDLE_TIMEOUT_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_CALLED_STATION_ID, RADIUS_CALLED_STATION_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_CALLING_STATION_ID, RADIUS_CALLING_STATION_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_NAS_IDENTIFIER, RADIUS_NAS_IDENTIFIER_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_STATUS_TYPE, RADIUS_ACCT_STATUS_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_DELAY_TIME, RADIUS_ACCT_DELAY_TIME_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_INPUT_OCTETS, RADIUS_ACCT_INPUT_OCTETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_OUTPUT_OCTETS, RADIUS_ACCT_OUTPUT_OCTETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_SESSION_ID, RADIUS_ACCT_SESSION_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_AUTHENTIC, RADIUS_ACCT_AUTHENTIC_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_SESSION_TIME, RADIUS_ACCT_SESSION_TIME_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_INPUT_PACKETS, RADIUS_ACCT_INPUT_PACKETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_OUTPUT_PACKETS, RADIUS_ACCT_OUTPUT_PACKETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_ACCT_TERMINATE_CAUSE, RADIUS_ACCT_TERMINATE_CAUSE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_EVENT_TIMESTAMP, RADIUS_EVENT_TIMESTAMP_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_NAS_PORT_TYPE, RADIUS_NAS_PORT_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_MESSAGE_AUTHENTICATOR, RADIUS_MESSAGE_AUTHENTICATOR_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_NAS_PORT_ID, RADIUS_NAS_PORT_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_NAS_IPV6_ADDRESS, RADIUS_NAS_IPV6_ADDRESS_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_FRAMED_INTERFACE_ID, RADIUS_FRAMED_INTERFACE_ID_ALIAS, MMT_U64_DATA, sizeof (uint64_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_FRAMED_IPV6_PREFIX, RADIUS_FRAMED_IPV6_PREFIX_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_FRAMED_IPV6_POOL, RADIUS_FRAMED_IPV6_POOL_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},

    {RADIUS_3GPP_IMSI, RADIUS_3GPP_IMSI_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_CHARGING_ID, RADIUS_3GPP_CHARGING_ID_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_PDP_TYPE, RADIUS_3GPP_PDP_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_CG_ADDRESS, RADIUS_3GPP_CG_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_QOS_PROFILE, RADIUS_3GPP_QOS_PROFILE_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_SGSN_ADDRESS, RADIUS_3GPP_SGSN_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_GGSN_ADDRESS, RADIUS_3GPP_GGSN_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_IMSI_MCCMNC, RADIUS_3GPP_IMSI_MCCMNC_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_GGSN_MCCMNC, RADIUS_3GPP_GGSN_MCCMNC_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_NSAPI, RADIUS_3GPP_NSAPI_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_SESSION_STOP_IND, RADIUS_3GPP_SESSION_STOP_IND_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_SELECTION_MODE, RADIUS_3GPP_SELECTION_MODE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_CHARGIN_CHARACT, RADIUS_3GPP_CHARGIN_CHARACT_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_CG_IPV6, RADIUS_3GPP_CG_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_SGSN_IPV6, RADIUS_3GPP_SGSN_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_GGSN_IPV6, RADIUS_3GPP_GGSN_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_DNS_IPV6, RADIUS_3GPP_DNS_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_SGSN_MCCMNC, RADIUS_3GPP_SGSN_MCCMNC_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_TEARDOWN_IND, RADIUS_3GPP_TEARDOWN_IND_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_IMEISV, RADIUS_3GPP_IMEISV_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_RAT_TYPE, RADIUS_3GPP_RAT_TYPE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_USER_LOCATION, RADIUS_3GPP_USER_LOCATION_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_tlv_extraction},
    {RADIUS_3GPP_TIMEZONE, RADIUS_3GPP_TIMEZONE_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_CAMELCHARGING, RADIUS_3GPP_CAMELCHARGING_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_PACKET_FILTER, RADIUS_3GPP_PACKET_FILTER_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_NEG_DSCP, RADIUS_3GPP_NEG_DSCP_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_unsupported_extraction},
    {RADIUS_3GPP_ALLOC_IP_TYPE, RADIUS_3GPP_ALLOC_IP_TYPE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_unsupported_extraction},

    {RADIUS_AVP1, RADIUS_AVP1_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP2, RADIUS_AVP2_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP3, RADIUS_AVP3_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP4, RADIUS_AVP4_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP5, RADIUS_AVP5_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP6, RADIUS_AVP6_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP7, RADIUS_AVP7_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP8, RADIUS_AVP8_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP9, RADIUS_AVP9_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP10, RADIUS_AVP10_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP11, RADIUS_AVP11_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP12, RADIUS_AVP12_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP13, RADIUS_AVP13_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP14, RADIUS_AVP14_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP15, RADIUS_AVP15_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP16, RADIUS_AVP16_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP17, RADIUS_AVP17_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP18, RADIUS_AVP18_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP19, RADIUS_AVP19_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP20, RADIUS_AVP20_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP21, RADIUS_AVP21_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP22, RADIUS_AVP22_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP23, RADIUS_AVP23_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP24, RADIUS_AVP24_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP25, RADIUS_AVP25_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP26, RADIUS_AVP26_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP27, RADIUS_AVP27_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP28, RADIUS_AVP28_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP29, RADIUS_AVP29_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP30, RADIUS_AVP30_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP31, RADIUS_AVP31_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP32, RADIUS_AVP32_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP33, RADIUS_AVP33_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP34, RADIUS_AVP34_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP35, RADIUS_AVP35_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP36, RADIUS_AVP36_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP37, RADIUS_AVP37_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP38, RADIUS_AVP38_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP39, RADIUS_AVP39_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP40, RADIUS_AVP40_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP41, RADIUS_AVP41_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP42, RADIUS_AVP42_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP43, RADIUS_AVP43_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP44, RADIUS_AVP44_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP45, RADIUS_AVP45_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP46, RADIUS_AVP46_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP47, RADIUS_AVP47_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP48, RADIUS_AVP48_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP49, RADIUS_AVP49_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP50, RADIUS_AVP50_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP51, RADIUS_AVP51_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP52, RADIUS_AVP52_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP53, RADIUS_AVP53_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP54, RADIUS_AVP54_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP55, RADIUS_AVP55_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP56, RADIUS_AVP56_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP57, RADIUS_AVP57_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP58, RADIUS_AVP58_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP59, RADIUS_AVP59_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP60, RADIUS_AVP60_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP61, RADIUS_AVP61_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP62, RADIUS_AVP62_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP63, RADIUS_AVP63_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP64, RADIUS_AVP64_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP65, RADIUS_AVP65_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP66, RADIUS_AVP66_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP67, RADIUS_AVP67_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP68, RADIUS_AVP68_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP69, RADIUS_AVP69_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP70, RADIUS_AVP70_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP71, RADIUS_AVP71_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP72, RADIUS_AVP72_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP73, RADIUS_AVP73_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP74, RADIUS_AVP74_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP75, RADIUS_AVP75_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP76, RADIUS_AVP76_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP77, RADIUS_AVP77_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP78, RADIUS_AVP78_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP79, RADIUS_AVP79_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP80, RADIUS_AVP80_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP81, RADIUS_AVP81_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP82, RADIUS_AVP82_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP83, RADIUS_AVP83_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP84, RADIUS_AVP84_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP85, RADIUS_AVP85_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP86, RADIUS_AVP86_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP87, RADIUS_AVP87_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP88, RADIUS_AVP88_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP89, RADIUS_AVP89_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP90, RADIUS_AVP90_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP91, RADIUS_AVP91_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP92, RADIUS_AVP92_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP93, RADIUS_AVP93_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP94, RADIUS_AVP94_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP95, RADIUS_AVP95_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP96, RADIUS_AVP96_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP97, RADIUS_AVP97_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP98, RADIUS_AVP98_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP99, RADIUS_AVP99_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP100, RADIUS_AVP100_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP101, RADIUS_AVP101_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP102, RADIUS_AVP102_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP224, RADIUS_AVP224_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP225, RADIUS_AVP225_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP226, RADIUS_AVP226_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP227, RADIUS_AVP227_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP228, RADIUS_AVP228_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP229, RADIUS_AVP229_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP230, RADIUS_AVP230_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP231, RADIUS_AVP231_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP232, RADIUS_AVP232_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP233, RADIUS_AVP233_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP234, RADIUS_AVP234_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP235, RADIUS_AVP235_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP236, RADIUS_AVP236_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP237, RADIUS_AVP237_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP238, RADIUS_AVP238_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP239, RADIUS_AVP239_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
    {RADIUS_AVP240, RADIUS_AVP240_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp_extraction},
};
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_radius_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RADIUS, PROTO_RADIUS_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < RADIUS_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &radius_attributes_metadata[i]);
        }

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                PROTO_UNKNOWN, PROTO_RADIUS);
        register_session_data_initialization_function(protocol_struct, radius_session_data_init);
        register_session_data_cleanup_function(protocol_struct, radius_session_data_cleanup);
        register_session_data_analysis_function(protocol_struct, radius_session_data_analysis);
        return register_protocol(protocol_struct, PROTO_RADIUS);
    } else {
        return 0;
    }
}
