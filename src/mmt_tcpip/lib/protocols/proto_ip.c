
#include <string.h> // memcpy()
#include <stddef.h> // offsetof()

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "packet_processing.h" /* mmt_have_bytes() — issue #202 caplen prologues */
#include "mmt_common_internal_include.h"

#include "ip.h"
#include "ip_session_id_management.h"
#include "proto_ip_dgram.h"
/* Shared IPv4/IPv6 L4-protocol dispatch table — emits the file-local
 * `static const uint16_t mmt_ip_l4_proto_table[256]` (issue #238). */
#include "ip_l4_proto_table.inc"
#define _STDC_FORMAT_MARCROS
#include <inttypes.h>

/*
 * Issue #57: the mmt_una_iphdr_t / mmt_una_tcphdr_t / mmt_una_udphdr_t
 * alignment-safe header views used below are defined centrally in
 * mmt_tcpip_internal_defs_macros.h (included via mmt_common_internal_include.h).
 */

/**
 * IP protocol references:
 * - IP parameters value: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
 * - IP packet structure: http://www.freesoft.org/CIE/Course/Section3/7.htm
 * -
 */

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

bool ip_session_comp(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    if (l_session->ip_type != r_session->ip_type) return (l_session->ip_type < r_session->ip_type);

    // both flows of the same type
    int comp_val = mmt_memcmp(&l_session->next_proto, &r_session->next_proto, 5);
    if (comp_val == 0) {
        if (l_session->ip_type == 4) {
            comp_val = mmt_memcmp(l_session->lower_ip, r_session->lower_ip, IPv4_ALEN);
            if (comp_val == 0) {
                comp_val = mmt_memcmp(l_session->higher_ip, r_session->higher_ip, IPv4_ALEN);
            }
        } else {
            comp_val = mmt_memcmp(l_session->lower_ip, r_session->lower_ip, IPv6_ALEN);
            if (comp_val == 0) {
                comp_val = mmt_memcmp(l_session->higher_ip, r_session->higher_ip, IPv6_ALEN);
            }
        }
    }
    return comp_val < 0;
}


bool ipv4_session_comp(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    int comp_val;
    comp_val = l_session->next_proto - r_session->next_proto;

    if( comp_val == 0 )
   	 comp_val = l_session->lower_ip_port - r_session->lower_ip_port;

    if( comp_val == 0 )
   	 comp_val = l_session->higher_ip_port - r_session->higher_ip_port;
    char * l_session_higher_ip = (char *)l_session->higher_ip;
    char * r_session_higher_ip = (char *)r_session->higher_ip;

    if( comp_val == 0 )
   	 comp_val = l_session_higher_ip[0] - r_session_higher_ip[0];
    if( comp_val == 0 )
   	 comp_val = l_session_higher_ip[1] - r_session_higher_ip[1];
    if( comp_val == 0 )
   	 comp_val = l_session_higher_ip[2] - r_session_higher_ip[2];
    if( comp_val == 0 )
   	 comp_val = l_session_higher_ip[3] - r_session_higher_ip[3];

    char * l_session_lower_ip = (char *)l_session->lower_ip;
    char * r_session_lower_ip = (char *)r_session->lower_ip;

    if( comp_val == 0 )
   	 comp_val = l_session_lower_ip[0] - r_session_lower_ip[0];
    if( comp_val == 0 )
   	 comp_val = l_session_lower_ip[1] - r_session_lower_ip[1];
    if( comp_val == 0 )
   	 comp_val = l_session_lower_ip[2] - r_session_lower_ip[2];
    if( comp_val == 0 )
   	 comp_val = l_session_lower_ip[3] - r_session_lower_ip[3];

    return comp_val < 0;
}

/**
 * Issue #253 (F-PERF-008): one-call equality predicate for IPv4 session keys.
 * True iff the same fields ipv4_session_comp distinguishes agree — next_proto,
 * both ports and the 4 bytes of each interned IP — equivalent to the old
 * `!comp(a,b) && !comp(b,a)` probe but evaluated in a single pass.
 */
bool ipv4_session_equal(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    return l_session->next_proto == r_session->next_proto
        && l_session->lower_ip_port == r_session->lower_ip_port
        && l_session->higher_ip_port == r_session->higher_ip_port
        && mmt_memcmp(l_session->higher_ip, r_session->higher_ip, IPv4_ALEN) == 0
        && mmt_memcmp(l_session->lower_ip, r_session->lower_ip, IPv4_ALEN) == 0;
}

/**
 * Hash of an IPv4 session key, consistent with ipv4_session_equal/
 * ipv4_session_comp: it mixes exactly the fields equality distinguishes —
 * next_proto, both ports and the 4 bytes of each interned IP address — so
 * that any two keys that compare equal hash to the same value.
 *
 * Dependent-multiply count (asserted by tools/phase0/tests/
 * session_lookup_perf_test.sh): FNV-1a over the 13 key bytes ran 13
 * serially-dependent multiplies; the three multiplies below are INDEPENDENT
 * (the CPU overlaps them in one multiply-latency window) and the finalizer
 * adds one dependent step — a chain 2 multiplies deep before the table's
 * inlined fmix64, versus ~16 before.
 */
uint64_t ipv4_session_hash(void * key) {
    mmt_session_key_t * s = (mmt_session_key_t *) key;
    uint32_t lip, hip;
    /* Same unaligned-read precaution as ipv4_addr_comp: the key may point
     * into the byte-aligned packet buffer (build_ipv4_session_key stores raw
     * header pointers; interned keys point at mmt_ip4_id_t.ip, offset 0). */
    memcpy(&lip, s->lower_ip, sizeof(lip));
    memcpy(&hip, s->higher_ip, sizeof(hip));
    /* tuple word: next_proto(8b) | lower_ip_port(16b) | higher_ip_port(16b) */
    uint64_t w = (uint64_t) s->next_proto
               | ((uint64_t) s->lower_ip_port << 8)
               | ((uint64_t) s->higher_ip_port << 24);
    uint64_t h = w * 0x9E3779B97F4A7C15ULL
               ^ (uint64_t) lip * 0xC2B2AE3D27D4EB4FULL
               ^ (uint64_t) hip * 0x165667B19E3779F9ULL;
    h *= 0xD6E8FEB86659FD93ULL;
    h ^= h >> 29;
    return h;
}
/*
 * IP data extraction routines
 */

int ip_version_extraction(const ipacket_t * packet, unsigned proto_index,
                          attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — every packet byte this
     * callback dereferences must lie inside the captured data. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint8_t))) return 0;

    mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) (& packet->data[proto_offset]);
    *((unsigned char *) extracted_data->data) = ip_hdr->version;
    return 1;
}

int ip_ihl_extraction(const ipacket_t * packet, unsigned proto_index,
                      attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see ip_version_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint8_t))) return 0;

    mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) (& packet->data[proto_offset]);
    *((unsigned char *) extracted_data->data) = ip_hdr->ihl * 4;
    return 1;
}

int ip_rf_extraction(const ipacket_t * packet, unsigned proto_index,
                     attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see ip_version_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + (size_t) attribute_offset, sizeof(uint8_t))) return 0;

    if (*((unsigned char *) & packet->data[proto_offset + attribute_offset]) & 0x80) {
        *((unsigned char *) extracted_data->data) = 1;
    } else {
        *((unsigned char *) extracted_data->data) = 0;
    }
    return 1;
}

int ip_df_extraction(const ipacket_t * packet, unsigned proto_index,
                     attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see ip_version_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + (size_t) attribute_offset, sizeof(uint8_t))) return 0;

    if (*((unsigned char *) & packet->data[proto_offset + attribute_offset]) & 0x40) {
        *((unsigned char *) extracted_data->data) = 1;
    } else {
        *((unsigned char *) extracted_data->data) = 0;
    }
    return 1;
}


int ip_mf_extraction(const ipacket_t * packet, unsigned proto_index,
                     attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see ip_version_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + (size_t) attribute_offset, sizeof(uint8_t))) return 0;

    if (*((unsigned char *) & packet->data[proto_offset + attribute_offset]) & 0x20) {
        *((unsigned char *) extracted_data->data) = 1;
    } else {
        *((unsigned char *) extracted_data->data) = 0;
    }
    return 1;
}

int ip_frag_offset_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see ip_version_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;
    //int attr_data_len = protocol_struct->get_attribute_length(extracted_data->proto_id, extracted_data->field_id);
    if (proto_offset < 0 || attribute_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset + (size_t) attribute_offset, sizeof(uint16_t))) return 0;

    /* Issue #202: the capture buffer is byte-aligned — memcpy is the
     * alignment-safe u16 load (UBSan aborts on a strict-cast load at an odd
     * offset); mirrors the issue #59 fixes. */
    uint16_t frag_word;
    memcpy(&frag_word, &packet->data[proto_offset + attribute_offset], sizeof(frag_word));
    *((unsigned short *) extracted_data->data) = (ntohs(frag_word) & 0x1fff)<<3;
    return 1;
}

int ip_client_port_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): uniform caplen prologue — this extractor reads
     * no packet bytes; the floor still validates the capture plumbing. */
    if (!mmt_have_bytes(packet, 0, 0) || extracted_data == NULL) return 0;
    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client) ? s_key->lower_ip_port : s_key->higher_ip_port;
        return 1;
    }
    return 0;
}

int ip_server_port_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * ip_client_port_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(packet, 0, 0) || extracted_data == NULL) return 0;
    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client) ? s_key->higher_ip_port : s_key->lower_ip_port;
        return 1;
    }
    return 0;
}

int ip_client_addr_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * ip_client_port_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(packet, 0, 0) || extracted_data == NULL) return 0;
    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned int *) extracted_data->data) = (s_key->is_lower_client) ? ((mmt_ip4_id_t *) s_key->lower_ip)->ip : ((mmt_ip4_id_t *) s_key->higher_ip)->ip;
        return 1;
    }
    return 0;
}

int ip_server_addr_extraction(const ipacket_t * packet, unsigned proto_index,
                              attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): uniform caplen prologue — see
     * ip_client_port_extraction (no packet bytes are read). */
    if (!mmt_have_bytes(packet, 0, 0) || extracted_data == NULL) return 0;
    if (packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned int *) extracted_data->data) = (s_key->is_lower_client) ? ((mmt_ip4_id_t *) s_key->higher_ip)->ip : ((mmt_ip4_id_t *) s_key->lower_ip)->ip;
        return 1;
    }
    return 0;
}

/*
 * IP options extraction routines
 */

int ip_options_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see ip_version_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint8_t))) return 0;

    mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) (& packet->data[proto_offset]);
    int ihl = ip_hdr->ihl;
    extracted_data->data = NULL;
    if (ihl > 5) {
        /* The returned pointer exposes (ihl-5)*4 option bytes — refuse when
         * that whole area is not captured (ihl is 4 bits, so <= 40 bytes). */
        if (!mmt_have_bytes(packet, (size_t) proto_offset + 5 * 4, (size_t) (ihl - 5) * 4)) return 0;
        extracted_data->data = (unsigned char *) (& packet->data[proto_offset + 5 * 4]);
        return 1;
    }
    return 0;
}


int ip_opts_type_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): caplen prologue — see ip_version_extraction. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(uint8_t))) return 0;

    mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) (& packet->data[proto_offset]);
    int ihl = ip_hdr->ihl;
    if (ihl > 5) {
        /* Propagate the delegate's verdict: a refused extraction must not be
         * reported as a set attribute. */
        return general_byte_to_byte_extraction(packet, proto_index, extracted_data);
    }
    return 0;
}

int ip_padding_check_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data) {

    /* Issue #202 (F-BUG-033): route every bounds check through the shared
     * caplen helper so the coverage stays greppable. */
    if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    if (proto_offset < 0) return 0;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, sizeof(struct iphdr))) return 0;
    mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) (& packet->data[proto_offset]);
    int ihl = ip_hdr->ihl;
    if (ihl <= 5 || ihl > 15) return 0;
    int ihl_bytes = ihl * 4;
    if (!mmt_have_bytes(packet, (size_t) proto_offset, (size_t) ihl_bytes)) return 0;
    int total_opt_len = (ihl - 5) * 4;
    if (total_opt_len <= 0 || total_opt_len > 40) return 0;
    int checked_len = 0;
    while (checked_len < total_opt_len){
        if (!mmt_have_bytes(packet, (size_t) proto_offset + 5*4 + checked_len, 1)) return 0;
        uint8_t kind = packet->data[proto_offset + 5*4 + checked_len];
        if (kind == 0x00){
            // EOL presents
            checked_len++;
            if (checked_len == total_opt_len){
                return 0;
            } else {
                for (int i = checked_len; i < total_opt_len; i++){
                    if (packet->data[proto_offset + 5*4 + i] != 0x00){
                       *((uint8_t *) extracted_data->data) = 1;
                       return 1;
                    }
                }
                *((uint8_t *) extracted_data->data) = 0;
                return 1;
            }
        } else if (kind == 0x01) {
            // NOP is single-byte padding
            checked_len += 1;
        } else {
            if (checked_len + 1 >= total_opt_len) return 0;
            if (!mmt_have_bytes(packet, (size_t) proto_offset + 5*4 + checked_len, 2)) return 0;
            uint8_t opt_len = packet->data[proto_offset + 5*4 + 1 + checked_len];
            if (opt_len < 2) return 0;
            if (opt_len > total_opt_len - checked_len) return 0;
            if (proto_offset + 5*4 + checked_len + opt_len > proto_offset + ihl_bytes) return 0;
            checked_len += opt_len;
        }
    }
    return 0;
}

//HN: extract L4S metrics

/* we store drops in 5 bits */
#define DROPS_M 2
#define DROPS_E 3

/* we store queue length in 11 bits */
#define QDELAY_M 7
#define QDELAY_E 4

/* Decode float value
 *
 * fl: Float value
 * m_b: Number of mantissa bits
 * e_b: Number of exponent bits
 */
static inline uint32_t fl2int(uint32_t fl, uint32_t m_b, uint32_t e_b)
{
	const uint32_t m_max = 1 << m_b;

	fl &= ((m_max << e_b) - 1);

	if (fl < (m_max << 1)) {
		return fl;
	} else {
		return (((fl & (m_max - 1)) + m_max) << ((fl >> m_b) - 1));
	}
}
static int _extract_l4s_metrics(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data) {

	/* Issue #202 (F-BUG-033): caplen prologue — this callback dereferences
	 * the ihl/tos/id fields, i.e. the IP header up through the id field. */
	if (packet == NULL || packet->p_hdr == NULL || packet->data == NULL || extracted_data == NULL) return 0;
	int proto_offset = get_packet_offset_at_index(packet, proto_index);
	if (proto_offset < 0) return 0;
	if (!mmt_have_bytes(packet, (size_t) proto_offset, offsetof(struct iphdr, id) + sizeof(uint16_t))) return 0;

	mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) (& packet->data[proto_offset]);
	int ihl = ip_hdr->ihl;

	if (ihl < 5)
		return 0;

	uint8_t ecn_val = (ip_hdr->tos & 0x3);
	uint16_t id     = ntohs(ip_hdr->id);
	//drops = decodeDrops(id >> 11); // drops stored in 5 bits MSB
	// We don't decode queueing delay here as we need to store it in a table,
	// so defer this to the actual serialization of the table to file
	//qdelay_encoded = id & 2047; // 2047 = 0b0000011111111111
	switch( extracted_data->field_id ){
	case IP_L4S_NB_DROPS:
		*(uint16_t *)extracted_data->data = fl2int(id >> 11, DROPS_M, DROPS_E); //( id >> 11 );
		break;
	case IP_L4S_QUEUE_DELAY:
		*(float *)extracted_data->data = (id & 2047); //fl2int( (id & 2047), QDELAY_M, QDELAY_E );
		break;
	case IP_ECN:
		//when ecn_val == 0 => Value does not exist
		if( ecn_val == 0 )
			return 0;
		*(uint8_t *)extracted_data->data = ecn_val;
		break;
	case IP_L4S_MARKED:
		//when ecn_val == 0 => Value does not exist
		if( ecn_val != 0x3 )
			return 0;
		*(uint8_t *)extracted_data->data = 1;
		break;
	default:
		return 0;
	}
	return 1;
}

int _extract_jitter(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data) {

	/* Issue #202 (F-BUG-033): uniform caplen prologue — this extractor reads
	 * no packet bytes; the floor still validates the capture plumbing. */
	if (!mmt_have_bytes(packet, 0, 0) || extracted_data == NULL) return 0;

	//no session => no jitter
	if (packet->session == NULL)
		return 0;
	int dir = packet->session->last_packet_direction;
	struct timeval last_ts = packet->session->s_last_data_packet_time[dir];
	struct timeval *ts = (struct timeval *) extracted_data->data;
	if( last_ts.tv_sec != 0 || last_ts.tv_usec != 0 ){

		ts->tv_sec = packet->p_hdr->ts.tv_sec - last_ts.tv_sec;
		ts->tv_usec = packet->p_hdr->ts.tv_usec - last_ts.tv_usec;

		if (ts->tv_usec < 0) {
			ts->tv_usec += 1000000;
			ts->tv_sec -= 1;
		}
	} else
		ts->tv_sec = ts->tv_usec = 0;


	return 1;
}

/*
 * End of IP data extraction routines
 */


uint8_t build_ipv4_session_key(u_char * ip_packet, unsigned ip_packet_len, mmt_session_key_t * ipv4_session) {
    uint8_t retval;
    uint16_t sport = 0, dport = 0;
    mmt_una_iphdr_t * iph = (mmt_una_iphdr_t *) ip_packet;
    ipv4_session->next_proto = iph->protocol;
    /* tcp / udp detection — only read the L4 source/dest ports when the
     * captured data actually holds the 4 port octets that follow the IP
     * header. ihl is a 4-bit field (max 60 bytes), so the header offset plus
     * the 4 port octets must fit within ip_packet_len; otherwise the ports
     * default to 0 (no out-of-bounds read on a truncated capture). */
    unsigned l4_off = (unsigned) iph->ihl * 4;
    if (ipv4_session->next_proto == 6) {
        if (l4_off + 4u <= ip_packet_len) {
            const mmt_una_tcphdr_t *tcph = (mmt_una_tcphdr_t *) & ip_packet[l4_off];
            sport = ntohs(tcph->source);
            dport = ntohs(tcph->dest);
        }
    } else if (ipv4_session->next_proto == 17) {
        if (l4_off + 4u <= ip_packet_len) {
            const mmt_una_udphdr_t *udph = (mmt_una_udphdr_t *) & ip_packet[l4_off];
            sport = ntohs(udph->source);
            dport = ntohs(udph->dest);
        }
    }
    // ipv4_session->lower_ip = (void*)mmt_malloc(sizeof(iph->saddr));
    // ipv4_session->higher_ip = (void*)mmt_malloc(sizeof(iph->daddr));
    if (iph->saddr < iph->daddr) {
        // memcpy(ipv4_session->lower_ip,&iph->saddr,sizeof(iph->saddr));
        // memcpy(ipv4_session->higher_ip,&iph->daddr,sizeof(iph->daddr));
        ipv4_session->lower_ip = &iph->saddr;
        ipv4_session->higher_ip = &iph->daddr;

        ipv4_session->lower_ip_port = sport;
        ipv4_session->higher_ip_port = dport;

        ipv4_session->is_lower_initiator = L2H_DIRECTION;
        ipv4_session->is_lower_client = L2H_DIRECTION;
        retval = L2H_DIRECTION;
    } else if (iph->saddr == iph->daddr) {
        if (sport < dport) {
            // memcpy(ipv4_session->lower_ip,&iph->saddr,sizeof(iph->saddr));
            // memcpy(ipv4_session->higher_ip,&iph->daddr,sizeof(iph->daddr));
            ipv4_session->lower_ip = &iph->saddr;
            ipv4_session->higher_ip = &iph->daddr;
            ipv4_session->lower_ip_port = sport;
            ipv4_session->higher_ip_port = dport;
            ipv4_session->is_lower_initiator = L2H_DIRECTION;
            ipv4_session->is_lower_client = L2H_DIRECTION;
            retval = L2H_DIRECTION;
        } else {
            // memcpy(ipv4_session->lower_ip,&iph->daddr,sizeof(iph->daddr));
            // memcpy(ipv4_session->higher_ip,&iph->saddr,sizeof(iph->saddr));
            ipv4_session->lower_ip = &iph->daddr;
            ipv4_session->higher_ip = &iph->saddr;
            ipv4_session->lower_ip_port = dport;
            ipv4_session->higher_ip_port = sport;
            ipv4_session->is_lower_initiator = H2L_DIRECTION;
            ipv4_session->is_lower_client = H2L_DIRECTION;
            retval = H2L_DIRECTION;
        }
    } else {
        // memcpy(ipv4_session->lower_ip,&iph->daddr,sizeof(iph->daddr));
        // memcpy(ipv4_session->higher_ip,&iph->saddr,sizeof(iph->saddr));
        ipv4_session->lower_ip = &iph->daddr;
        ipv4_session->higher_ip = &iph->saddr;
        ipv4_session->lower_ip_port = dport;
        ipv4_session->higher_ip_port = sport;
        ipv4_session->is_lower_initiator = H2L_DIRECTION;
        ipv4_session->is_lower_client = H2L_DIRECTION;
        retval = H2L_DIRECTION;
    }

    ipv4_session->ip_type = 4;

    return retval;
}

int ip_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    /* If we get here, then the packet is not fragmented. */
    int offset = get_packet_offset_at_index(ipacket, index);
    const mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) & ipacket->data[offset];

    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    /* L4 protocol number -> PROTO_* dispatch (issue #238, F-CLEAN-005): the
     * mapping below used to be a ~800-line switch duplicated almost verbatim
     * in ip6_classify_next_proto(); it now lives once in the shared
     * ip_l4_proto_table.inc table (included at the top of this file). */
    retval.proto_id = mmt_ip_l4_proto_table[ip_hdr->protocol];
    retval.offset = (ip_hdr->ihl * 4);
    retval.status = Classified;
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

int ip_session_cleanup_on_timeout(void * protocol_context, mmt_session_t * timedout_session, void * args) {
    //Remove the session from the sessions hash
    /* Issue #327: a failed delete leaves a map entry pointing at memory that
     * free_session_data() is about to release — log it; the cleanup must
     * still proceed because the session's owned memory is freed here. */
    if (delete_session_from_protocol_context(protocol_context, timedout_session->session_key) == 0) {
        mmt_debug_log( "[error] ip_session_cleanup_on_timeout - delete_session_from_protocol_context failed\n");
    }

    // free session allocated memory. be careful about multiple free of the same data.
    // In the closup some session data are freed. These should not be the same as here.
    free_session_data(timedout_session->session_key, timedout_session, ((protocol_instance_t *) protocol_context)->args);
    return 0;
}

/* Compute the IPv4 fragment-reassembly hash key from the source/destination
 * addresses and the IP identification field. All three are mixed into the
 * 64-bit key without discarding any of them: the previous formulation shifted
 * the key left by 32 bits a second time after folding in daddr, which silently
 * dropped saddr entirely (so unrelated datagrams sharing a daddr and id would
 * collide on the same reassembly entry). */
mmt_key_t ip_fragment_key(const struct iphdr *ip)
{
    /*
     * Issue #57: ip may point into the byte-aligned packet buffer, so read the
     * 32-/16-bit header fields with memcpy rather than dereferencing the struct
     * directly (a misaligned multi-byte load is UB and aborts under
     * -fsanitize=alignment). memcpy of a fixed small size lowers to a single
     * load on architectures with native unaligned access — no hot-path cost.
     */
    const uint8_t *raw = (const uint8_t *) ip;
    uint32_t saddr, daddr;
    uint16_t id;
    memcpy(&saddr, raw + offsetof(struct iphdr, saddr), sizeof(saddr));
    memcpy(&daddr, raw + offsetof(struct iphdr, daddr), sizeof(daddr));
    memcpy(&id,    raw + offsetof(struct iphdr, id),    sizeof(id));
    mmt_key_t key = ((mmt_key_t) saddr << 32) | (mmt_key_t) daddr;
    key ^= (mmt_key_t) id;
    return key;
}

static inline int ip_process_fragment( ipacket_t *ipacket, unsigned index )
{
    mmt_handler_t *mmt = ipacket->mmt_handler;
    mmt_hashmap_t *map = mmt->ip_streams;
    mmt_key_t     key;
    ip_dgram_t    *dg;

    if (map == NULL) return 0;

    /* Issue #201 (F-BUG-020): arm the fragment-map maintenance hooks the first
     * time a fragment is seen. The sweep runs from the existing session-expiry
     * timer pass (process_timedout_sessions) and the drain runs from
     * mmt_close_handler, so no datagram can outlive its handler or sit in the
     * map forever. */
    if (mmt->frag_map_sweep_fct == NULL) {
        mmt->frag_map_sweep_fct = mmt_ip_frag_map_sweep;
    }

    /* Issue #201 (F-BUG-017): `off` comes from the protocol path and `len` is
     * derived from the CAPTURED length — validate both before touching the
     * header. The old code computed `caplen - off` without checking off <=
     * caplen, so a stale offset could wrap `len` to a huge value. */
    int off = get_packet_offset_at_index( ipacket, index );
    if (off < 0 || (unsigned) off >= ipacket->p_hdr->caplen)
        return 0;
    unsigned len = ipacket->p_hdr->caplen - (unsigned) off;

    if ( len < sizeof( struct iphdr )) {
        /* Issue #212 (F-BUG-042): this printf ran in the packet hot path, so a
         * remote sender could flood stdout with one malformed datagram each.
         * Routed through the (default-off) MMT_LOG macro like every other
         * diagnostic in this file's peers. */
        MMT_LOG(PROTO_IP, MMT_LOG_DEBUG, "*** Warning: malformed packet (not enough data): %"PRIu64"\n", ipacket->packet_id );
        return 0;
    }

    const mmt_una_iphdr_t *ip = (mmt_una_iphdr_t *)(ipacket->data + off);

    key = ip_fragment_key( (const struct iphdr *) ip );
    if ( !hashmap_get( map, key, (void**)&dg )) {
        /* Issue #201 (F-BUG-020): bound the map BEFORE allocating a new
         * datagram — at the ceiling, evict the least recently updated entry
         * (O(1) list head, issue #383) instead of growing without bound. */
        if (!mmt_ip_frag_map_make_room(map, &mmt->ip_streams_lru))
            return 0; /* nothing evictable left — refuse to grow */
        dg = ip_dgram_alloc();
        if (dg == NULL)
            return 0; /* OOM: treat like an incomplete datagram — drop the fragment */
        hashmap_insert_kv( map, key, dg );
        /* hashmap_insert_kv() is void and drops silently on OOM — verify the
         * datagram actually landed, else it would be orphaned (issue #216). */
        void *check = NULL;
        hashmap_get( map, key, &check );
        if (check != dg) {
            ip_dgram_free( dg );
            return 0;
        }
        /* The handler owns the map, we own the value type: hand over the
         * destructor once so mmt_close_handler() can drain datagrams that
         * never completed (issue #216). */
        mmt->ip_streams_value_free = (void (*)(void *)) ip_dgram_free;
    }
    int dgram_update_result = ip_dgram_update( dg, ip, len , ipacket->p_hdr->caplen);
    if (dgram_update_result == 1) {
        /* Issue #201 (F-BUG-017): malformed fragment — never park it in the
         * map. A failed update may have left its hole list partially mutated,
         * and it must never reach is_complete in that state. */
        hashmap_remove( map, key );
        ip_dgram_free( dg );
        return 0;
    }
    /* Track the most recent fragment for the age-based sweep. */
    dg->last_activity = (uint32_t) ipacket->p_hdr->ts.tv_sec;
    /* Issue #383: move to the recency-list tail (eviction order). */
    mmt_ip_frag_lru_touch( &mmt->ip_streams_lru, &dg->lru, key );
    if(dgram_update_result == 2 || dgram_update_result == 6 ){
        fire_evasion_event(ipacket,PROTO_IP,index,EVA_IP_FRAGMENT_DUPLICATED,(void*)&(dgram_update_result));
    }else if (dgram_update_result > 0 ) {
        // There are some overlapping
        fire_evasion_event(ipacket,PROTO_IP,index,EVA_IP_FRAGMENT_OVERLAPPED,(void*)&(dgram_update_result));
    }
    // Check timed-out for all data gram

    // Detect too many fragment in one packet
    if (ipacket->mmt_handler->fragment_in_packet > 0
        && (dg->nb_packets % ipacket->mmt_handler->fragment_in_packet) == 0){
        fire_evasion_event(ipacket,PROTO_IP,index,EVA_IP_FRAGMENT_PACKET,(void*)&(dg->nb_packets));
    }
    if ( !ip_dgram_is_complete( dg )) {
        // debug("Fragmented packet is incompleted: %lu\n", ipacket->packet_id);
        // fire_evasion_event(ipacket,PROTO_IP,index,1,(void*)NULL);
        return 0;
    }
    // At this point, dg is a fully reassembled datagram.
    // -> reconstruct ipacket from dg, and pass it along

    unsigned ioff = (unsigned) off + ( ip->ihl << 2 );
    /* Issue #201: unchecked mmt_malloc — on failure the datagram must leave
     * the map with its buffer, not stay half-assembled. */
    uint8_t *x = (uint8_t*)mmt_malloc( ioff + dg->len );
    /* Issue #201: unchecked mmt_malloc. Issue #216: on OOM the datagram stays
     * in the map — still consistent — and drains at close via
     * ip_streams_value_free. */
    if (x == NULL)
        return 0;
    // copy the original ipacket data + IP header
    (void)memcpy( x,        ipacket->data, ioff );
    // copy the IP payload
    (void)memcpy( x + ioff, dg->x,         dg->len );
    ipacket->data = x;
    ipacket->p_hdr->len    = ioff + dg->len;
    ipacket->p_hdr->caplen = ioff + dg->len;
    ipacket->total_caplen  = dg->caplen;
    ipacket->nb_reassembled_packets[index] = dg->nb_packets;
    // debug("Total captured packet: %d\n", dg->nb_packets);
    //hexdump( x, ioff + dg->len );
    hashmap_remove( map, key );
    ip_dgram_free( dg );
    return 1;
}

static inline int mmt_iph_is_fragmented(const mmt_una_iphdr_t *iph)
{
    //#ifdef REQUIRE_FULL_PACKETS
    unsigned ip_off = (ntohs( iph->frag_off ) & IP_OFFSET) << 3;
    unsigned ip_mf  =  ntohs( iph->frag_off ) & IP_MF;
    if (ip_mf != 0) return 1;
    if (ip_off > 0) return 1;
    //#endif
    return 0;
}

void * ip_sessionizer(void * protocol_context, ipacket_t * ipacket, unsigned index, int * is_new_session)
{
    int offset = get_packet_offset_at_index(ipacket, index);
    /* Issue #201 (F-BUG-017): the fixed IPv4 header must be captured before
     * frag_off/ihl are read below — the sessionizer is invoked with no
     * offset-vs-caplen guarantee. */
    if (offset < 0 || (uint64_t) offset + sizeof(struct iphdr) > ipacket->p_hdr->caplen) {
        *is_new_session = 0;
        return NULL;
    }
    const mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) & ipacket->data[offset];
    mmt_session_key_t ipv4_session_key;
    // ipv4_session_key.lower_ip = NULL;
    // ipv4_session_key.higher_ip = NULL;
    uint8_t packet_direction;

    // uint16_t ip_offset = ntohs(ip_hdr->frag_off);
    // handle fragmented datagrams
    // Check if the packet is a fragment or not
    if (mmt_iph_is_fragmented(ip_hdr)) {
        ipacket->is_fragment[index] = 1;
        if (ipacket->session) {
            ipacket->session->is_fragmenting = 1;
        }
        // debug("Fragmented packet: %lu\n", ipacket->packet_id);
        if ( !ip_process_fragment( ipacket, index )) {
            *is_new_session = 0;
            return NULL;
        }
    }

    ipacket->is_completed[index] = 1;
    if (ipacket->session) {
        ipacket->session->is_fragmenting = 0;
    }
    // re-point to the reassempled IP header if reassembly took place
    // points to the same pointer if no fragmentation
    ip_hdr = (mmt_una_iphdr_t *) & ipacket->data[offset];

    // Get the session of this packet and set it to the packet's session
    packet_direction = build_ipv4_session_key((u_char *) ip_hdr,
            ipacket->p_hdr->caplen - (unsigned) offset, &ipv4_session_key);

    mmt_session_t * session = get_session(protocol_context, & ipv4_session_key, ipacket, is_new_session);
    if (session) {
        /* Issue #327: fragmented-packet accounting — when this packet was
         * reassembled from more than one fragment, update the session's
         * fragmented-packet and fragment counters and fire the threshold
         * evasion events. */
        if(ipacket->nb_reassembled_packets[index] > 1){
            session->fragmented_packet_count++;
            session->fragment_count += ipacket->nb_reassembled_packets[index];
            // Detect too many fragmented packet in one session
            if ( ipacket->mmt_handler->fragmented_packet_in_session > 0
                && (session->fragmented_packet_count % ipacket->mmt_handler->fragmented_packet_in_session) == 0 ){
                fire_evasion_event(ipacket,PROTO_IP,index,EVA_IP_FRAGMENTED_PACKET_SESSION,(void*)&session->fragmented_packet_count);
            }
            // Detect too many fragments in one session
            if ( ipacket->mmt_handler->fragment_in_session > 0
                && (session->fragment_count % ipacket->mmt_handler->fragment_in_session) == 0 ){
                fire_evasion_event(ipacket,PROTO_IP,index,EVA_IP_FRAGMENT_SESSION,(void*)&session->fragment_count);
            }
        }
        if (session->last_packet_direction != packet_direction && session->packet_count > 0) {
            ip_rtt_t ip_rtt;
            ip_rtt.direction = session->last_packet_direction;
            ip_rtt.session   = session;
            ip_rtt.rtt.tv_sec = ipacket->p_hdr->ts.tv_sec - session->s_last_activity_time.tv_sec;
            ip_rtt.rtt.tv_usec = ipacket->p_hdr->ts.tv_usec - session->s_last_activity_time.tv_usec;
            if ((int) ip_rtt.rtt.tv_usec < 0) {
                ip_rtt.rtt.tv_usec += 1000000;
                ip_rtt.rtt.tv_sec -= 1;
            }
            fire_attribute_event(ipacket, PROTO_IP, IP_RTT, index, (void *) & (ip_rtt));
        }


        // Fix proto_path , only fix til IP
        /* Issue #327: the splice below already keeps all three session paths
         * in sync — proto_path, proto_headers_offset and proto_classif_status
         * are copied together; the ipacket's pointers are re-pointed at the
         * session's arrays by proto_session_management(). */
        if (session->proto_path.proto_path[index] != PROTO_IP) {
            // debug("[IP] Fixing proto_path of session: %lu", session->session_id);
            // Get PROTO_IP index in current proto_path
            int j, ip_index = 0;
            for (j = 0; j < session->proto_path.len; j++) {
                if (session->proto_path.proto_path[j] == PROTO_IP) {
                    ip_index = j;
                    // break; - to make sure it go for the last one - in case of IP - TCP - GRE - IP - TCP - GRE - IP - TCP - HTTP
                }
            }

            // debug("[IP] Current index of PROTO_IP: %d / (packet)%d", ip_index, index);
            if (ip_index != 0) {
                if (ip_index > index) {
                    // debug("[IP] Current protocol_path need to remove some protocol");
                    int pre_path = 0, post_path = ip_index + 1;

                    for (pre_path = 0; pre_path <= index; pre_path++)
                    {
                        session->proto_path.proto_path[pre_path] = ipacket->proto_hierarchy->proto_path[pre_path];
                        session->proto_headers_offset.proto_path[pre_path] = ipacket->proto_headers_offset->proto_path[pre_path];
                        session->proto_classif_status.proto_path[pre_path] = ipacket->proto_classif_status->proto_path[pre_path];
                    }
                    for (post_path = ip_index + 1; post_path < session->proto_path.len; post_path++, pre_path++) {
                        session->proto_path.proto_path[pre_path] = session->proto_path.proto_path[post_path];
                        session->proto_headers_offset.proto_path[pre_path] = session->proto_headers_offset.proto_path[post_path];
                        session->proto_classif_status.proto_path[pre_path] = session->proto_classif_status.proto_path[post_path];
                    }
                    session->proto_path.len = pre_path;
                    session->proto_headers_offset.len = pre_path;
                    session->proto_classif_status.len = pre_path;
                    // debug("[IP] New protocol_path len %d", pre_path);
                } else {
                    // debug("[IP] Current protocol_path need to add some protocol from packet hierarchy");
                    int delta = index - ip_index;
                    int new_len = session->proto_path.len + delta;
                    int pre_path = 0, post_path = new_len - 1;

                    for (post_path = new_len - 1; post_path > ip_index; post_path--) {
                        session->proto_path.proto_path[post_path] = session->proto_path.proto_path[post_path - delta];
                        session->proto_headers_offset.proto_path[post_path] = session->proto_headers_offset.proto_path[post_path - delta];
                        session->proto_classif_status.proto_path[post_path] = session->proto_classif_status.proto_path[post_path - delta];
                    }

                    for (pre_path = 0; pre_path <= index; pre_path++)
                    {
                        session->proto_path.proto_path[pre_path] = ipacket->proto_hierarchy->proto_path[pre_path];
                        session->proto_headers_offset.proto_path[pre_path] = ipacket->proto_headers_offset->proto_path[pre_path];
                        session->proto_classif_status.proto_path[pre_path] = ipacket->proto_classif_status->proto_path[pre_path];
                    }

                    session->proto_path.len = new_len;
                    session->proto_headers_offset.len = new_len;
                    session->proto_classif_status.len = new_len;
                    // debug("[IP] New protocol_path len %d", new_len);
                }
                // Issue #19: the session offset path was rewritten in place; if
                // the packet shares this buffer the memoized cache is now stale.
                invalidate_packet_offset_cache(ipacket);
                /* Issue #252 (F-PERF-002): the splice moved path entries
                 * between indices, so the recorded per-layer winning checkers
                 * no longer line up with proto_path — drop them all. Affected
                 * layers re-walk the full chain (and re-record) instead of
                 * dispatching a stale engine. */
                memset(session->proto_checkers, 0, sizeof(session->proto_checkers));
            }

        }

        session->last_packet_direction = packet_direction;

    }
    return (void *) session;
}

void ip_context_cleanup(void * proto_context, void * args) {
    close_session_lists(proto_context);
    cleanup_ipv4_internal_context(((protocol_instance_t *) proto_context)->args);
    close_ipv4_internal_context(proto_context);
}

void * setup_ip_context(void * proto_context, void * args) {
    return (void *) setup_ipv4_internal_context();
}

static attribute_metadata_t ip_attributes_metadata[IP_ATTRIBUTES_NB] = {
    {IP_VERSION, IP_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip_version_extraction},
    {IP_HEADER_LEN, IP_HEADER_LEN_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip_ihl_extraction},
    {IP_PROTO_TOS, IP_PROTO_TOS_ALIAS, MMT_U8_DATA, sizeof (char), 1, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP_TOT_LEN, IP_TOT_LEN_ALIAS, MMT_U16_DATA, sizeof (short), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP_IDENTIFICATION, IP_IDENTIFICATION_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP_RF_FLAG, IP_RF_FLAG_ALIAS, MMT_U8_DATA, sizeof (char), 6, SCOPE_PACKET, ip_rf_extraction},
    {IP_DF_FLAG, IP_DF_FLAG_ALIAS, MMT_U8_DATA, sizeof (char), 6, SCOPE_PACKET, ip_df_extraction},
    {IP_MF_FLAG, IP_MF_FLAG_ALIAS, MMT_U8_DATA, sizeof (char), 6, SCOPE_PACKET, ip_mf_extraction},
    {IP_FRAG_OFFSET, IP_FRAG_OFFSET_ALIAS, MMT_U16_DATA, sizeof (short), 6, SCOPE_PACKET, ip_frag_offset_extraction},
    {IP_PROTO_TTL, IP_PROTO_TTL_ALIAS, MMT_U8_DATA, sizeof (char), 8, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP_PROTO_ID, IP_PROTO_ID_ALIAS, MMT_U8_DATA, sizeof (char), 9, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP_CHECKSUM_MMT, IP_CHECKSUM_MMT_ALIAS, MMT_U16_DATA, sizeof (short), 10, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP_SRC, IP_SRC_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), 12, SCOPE_PACKET, general_int_extraction},
    {IP_DST, IP_DST_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), 16, SCOPE_PACKET, general_int_extraction},
    {IP_OPTS, IP_OPTS_ALIAS, MMT_DATA_POINTER,  sizeof (void *), -2, SCOPE_PACKET, ip_options_extraction},
    {IP_OPTS_TYPE, IP_OPTS_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 20, SCOPE_PACKET, ip_opts_type_extraction},
    {IP_PADDING_CHECK, IP_PADDING_CHECK_ALIAS, MMT_U8_DATA,  sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_padding_check_extraction},
    {IP_CLIENT_ADDR, IP_CLIENT_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_client_addr_extraction},
    {IP_SERVER_ADDR, IP_SERVER_ADDR_ALIAS, MMT_DATA_IP_ADDR, sizeof (int), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_server_addr_extraction},
    {IP_CLIENT_PORT, IP_CLIENT_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_client_port_extraction},
    {IP_SERVER_PORT, IP_SERVER_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip_server_port_extraction},
    // LN: Those are IP protocol attributes, they should go to IP protocol
    {IP_FRAG_PACKET_COUNT, IP_FRAG_PACKET_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_frag_packet_count_extraction},
    {IP_FRAG_DATA_VOLUME, IP_FRAG_DATA_VOLUME_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_frag_data_volume_extraction},
    {IP_DF_PACKET_COUNT, IP_DF_PACKET_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_df_packet_count_extraction},
    {IP_DF_DATA_VOLUME, IP_DF_DATA_VOLUME_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_df_data_volume_extraction},
    {IP_SESSIONS_COUNT, IP_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_sessions_count_extraction},
    {IP_ACTIVE_SESSIONS_COUNT, IP_ACTIVE_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_active_sessions_count_extraction},
    {IP_TIMEDOUT_SESSIONS_COUNT, IP_TIMEDOUT_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_timedout_sessions_count_extraction},
    // End of LN
	//HN
	{IP_JITTER, IP_JITTER_ALIAS, MMT_DATA_TIMEVAL, sizeof (struct timeval), POSITION_NOT_KNOWN, SCOPE_PACKET, _extract_jitter},
	{IP_ECN, IP_ECN_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, _extract_l4s_metrics},
	{IP_L4S_MARKED, IP_L4S_MARKED_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, _extract_l4s_metrics},
	{IP_L4S_QUEUE_DELAY, IP_L4S_QUEUE_DELAY_ALIAS, MMT_DATA_FLOAT, sizeof (float), POSITION_NOT_KNOWN, SCOPE_PACKET, _extract_l4s_metrics},
	{IP_L4S_NB_DROPS, IP_L4S_NB_DROPS_ALIAS, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET,  _extract_l4s_metrics},
};

int ip_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    /* IP is a flow based protocol. If at this level the flow associated to this packet is null
     * stop the classification procedure by returning zero. This can happen if the packet is fragmented.
     */
    if (ipacket->session == NULL) {
        return MMT_CLASSIFY_SKIP;
    }
    return MMT_CLASSIFY_CONTINUE;
}

int ip_post_classification_function(ipacket_t * ipacket, unsigned index) {
    mmt_session_t * session = ipacket->session;
    /* Issue #245 (F-PERF-003): reuse the shared per-protocol context packet
     * in reassembly mode too — the ~6.7 KB mmt_tcpip_internal_packet_t was
     * allocated + zeroed for every packet. The scalar scratch fields are
     * reset here so no stale per-packet value survives reuse — including on
     * the early-return paths below (fragmented datagrams, malformed ihl),
     * where the old memset-0 packet reported zeroed fields instead. */
    ipacket->internal_packet = &((internal_ip_proto_context_t *) ((protocol_instance_t *) session->protocol_container_context)->args)->packet;
    mmt_reset_internal_packet_scalars(ipacket->internal_packet);
    ipacket->internal_packet->packet_id = ipacket->packet_id;
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;

    int ip_offset = get_packet_offset_at_index(ipacket, index);
    if (ip_offset < 0 || (unsigned)ip_offset > ipacket->p_hdr->caplen) return 0;
    if (ipacket->p_hdr->caplen < (unsigned)(ip_offset + (int)sizeof(struct iphdr))) return 0;
    const mmt_una_iphdr_t * ip_hdr = (mmt_una_iphdr_t *) & ipacket->data[ip_offset];

    uint32_t time = ((uint64_t) ipacket->p_hdr->ts.tv_sec) * MMT_MICRO_IN_SEC + ipacket->p_hdr->ts.tv_usec;
    packet->tick_timestamp = time;

    struct mmt_internal_tcpip_id_struct * src = NULL;
    struct mmt_internal_tcpip_id_struct * dst = NULL;

    // only handle unfragmented packets
    if (mmt_iph_is_fragmented(ip_hdr) && !ipacket->is_completed[index]) {
        return 0;
    }

    packet->iph = ip_hdr;
    packet->iphv6 = NULL;
    uint32_t ihl_bytes = (uint32_t)ip_hdr->ihl * 4;
    if (ihl_bytes < sizeof(struct iphdr) || ihl_bytes > 60) return 0;
    if ((unsigned)(ip_offset + (int)ihl_bytes) > ipacket->p_hdr->caplen) return 0;
    uint16_t tot_len = ntohs(ip_hdr->tot_len);
    // Validate tot_len to prevent underflow: forged tot_len < header len would underflow l4 length huge
    if (tot_len != 0 && tot_len < ihl_bytes) {
        tot_len = 0; // treat as TSO/unknown, fallback to captured length below
    }
    packet->l3_packet_len = tot_len;
    /* BW: add the length of the truncated packet as well */
    if ((unsigned)ip_offset <= ipacket->p_hdr->caplen)
        packet->l3_captured_packet_len = (ipacket->p_hdr->caplen - (unsigned)ip_offset);
    else
        packet->l3_captured_packet_len = 0;
    //HN: IP->tot_len = 0 will cause error when calculating packet->l4_packet_len (thus segementation faut)
    //Wireshark shows this when tot_len==0: [Total Length: 2930 bytes (reported as 0, presumed to be because of "TCP segmentation offload" (TSO))]
    if( packet->l3_packet_len == 0 && packet->l3_captured_packet_len > 0 )
        packet->l3_packet_len = packet->l3_captured_packet_len;

    /* Issue #327: padding/truncation handling — l3_captured_packet_len may
     * differ from l3_packet_len (link-layer padding adds bytes, capture
     * truncation removes them). The usable bound below already clamps the
     * L4 length to MIN(declared, captured), so padded and truncated packets
     * both stay safe; distinguishing padding *types* has no consumer in the
     * engine and is not required. */
    //packet->l4_packet_len = packet->l3_packet_len - (ip_hdr->ihl * 4); //For IPv6 this is done in tcp and udp
    // packet->l4_packet_len = packet->l3_packet_len - (ip_hdr->ihl * 4); //For IPv6 this is done in tcp and udp
    /* Issue #192 (F-BUG-016): l3_packet_len derives from the attacker-
     * controlled IPv4 tot_len and may exceed what was actually captured, so
     * bound the L4 length by the captured length on every branch — not only
     * on the reassembled one. usable = MIN(l3_packet_len, l3_captured_packet_len). */
    uint32_t usable = packet->l3_packet_len;
    if (packet->l3_captured_packet_len < usable)
        usable = packet->l3_captured_packet_len;
    if (usable < ihl_bytes) {
        packet->l4_packet_len = 0;
    } else {
        packet->l4_packet_len = usable - ihl_bytes;
    }

    if (mmt_memcmp(&((mmt_ip4_id_t *) ((mmt_session_key_t *) session->session_key)->higher_ip)->ip, &ip_hdr->saddr, IPv4_ALEN) == 0) {
        src = &((mmt_ip4_id_t *) ((mmt_session_key_t *) session->session_key)->higher_ip)->id_internal_context;
        dst = &((mmt_ip4_id_t *) ((mmt_session_key_t *) session->session_key)->lower_ip)->id_internal_context;
    } else {
        dst = &((mmt_ip4_id_t *) ((mmt_session_key_t *) session->session_key)->higher_ip)->id_internal_context;
        src = &((mmt_ip4_id_t *) ((mmt_session_key_t *) session->session_key)->lower_ip)->id_internal_context;
    }

    packet->flow = session->internal_data;
    packet->src = src;
    packet->dst = dst;

    /* build selction packet bitmask */
    packet->mmt_selection_packet = MMT_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
    packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_IP | MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

    // Update session statistics
    session->packet_cap_count_direction[session->last_packet_direction] += ipacket->nb_reassembled_packets[index];
    session->data_cap_volume_direction[session->last_packet_direction] += ipacket->total_caplen;
    session->packet_count_direction[session->last_packet_direction]++;
    session->data_volume_direction[session->last_packet_direction] += ipacket->p_hdr->len;
    mmt_session_t *p_session = session->parent_session;
    while (p_session)
    {
        /* Issue #255: children counters live in the lazily-allocated
         * tunnel-parent extension (NULL under OOM -> update skipped). */
        mmt_session_children_stats_t *cs = mmt_session_get_children_stats(p_session);
        if (cs != NULL) {
            uint8_t direction = p_session->last_packet_direction ;
            cs->sub_packet_cap_count_direction[direction] += ipacket->nb_reassembled_packets[index];
            cs->sub_data_cap_volume_direction[direction] += ipacket->total_caplen;
            cs->sub_packet_count_direction[direction]++;
            cs->sub_data_volume_direction[direction] += ipacket->p_hdr->len;
        }
        p_session = p_session->parent_session;
    }

    return 1;
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ip_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IP, PROTO_IP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < IP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ip_attributes_metadata[i]);
        }

        register_classification_function(protocol_struct, ip_classify_next_proto);
        register_pre_post_classification_functions(protocol_struct, ip_pre_classification_function, ip_post_classification_function);

        register_sessionizer_function(protocol_struct, ip_sessionizer, ip_session_cleanup_on_timeout, ipv4_session_comp);
        register_session_hash_function(protocol_struct, ipv4_session_hash);
        register_session_equal_function(protocol_struct, ipv4_session_equal);

        register_proto_context_init_cleanup_function(protocol_struct, setup_ip_context, ip_context_cleanup, NULL);
        return register_protocol(protocol_struct, PROTO_IP);
    } else {
        return 0;
    }
}
