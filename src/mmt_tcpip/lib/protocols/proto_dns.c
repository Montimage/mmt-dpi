#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#define MMT_DNS_SESSION_TIMEOUT_DELAY 15 /**< The DNS session timeout delay */

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/* dns header
           0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                      ID                       |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    QDCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ANCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    NSCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ARCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct qropcodeaatcrdrazans_authdata_authrcode {
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t rd : 1, tc : 1, aa : 1, opcode : 4, qr : 1;
    uint8_t rcode : 4, data_auth : 1, ans_auth : 1, z : 1, ra : 1;
#elif BYTE_ORDER == BIG_ENDIAN
    uint8_t qr : 1, opcode : 4, aa : 1, tc : 1, rd : 1;
    uint8_t ra : 1, z : 1, ans_auth : 1, data_auth : 1, rcode : 4;
#else
#error "BYTE_ORDER must be defined"
#endif
};

struct dnshdr {
    uint16_t tid;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

static attribute_metadata_t dns_attributes_metadata[DNS_ATTRIBUTES_NB];

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/*
 * DNS data extraction routines
 */
int dns_qr_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[1].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[1].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;
    *((uint16_t *) extracted_data->data) = (flags & 0x8000)?1:0;
    return 1;
}

int dns_opcode_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[2].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[2].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;
    *((uint16_t *) extracted_data->data) = (flags & 0x7800) >> 11;
    return 1;
}

int dns_aa_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[3].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[3].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;
    if (flags & 0x8000) {
        *((uint16_t *) extracted_data->data) = (flags & 0x0400)?1:0;
        return 1;
    }
    return 0;
}

int dns_tc_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[4].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[4].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;
    *((uint16_t *) extracted_data->data) = (flags & 0x0200)?1:0;
    return 1;
}

int dns_rd_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[5].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[5].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;
    *((uint16_t *) extracted_data->data) = (flags & 0x0100)?1:0;
    return 1;
}

int dns_ra_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[6].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[6].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;

    if (flags & 0x8000) {
        *((uint16_t *) extracted_data->data) = (flags & 0x0080)?1:0;
        return 1;
    }
    return 0;
}

int dns_z_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[7].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[7].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;
    *((uint16_t *) extracted_data->data) = (flags & 0x0040)?1:0;
    return 1;
}

int dns_ans_auth_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[8].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[8].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;

    if (flags & 0x8000) {
        *((uint16_t *) extracted_data->data) = (flags & 0x0020)?1:0;
        return 1;
    }
    return 0;
}

int dns_data_auth_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[9].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[9].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;

    if (flags & 0x8000) {
        *((uint16_t *) extracted_data->data) = (flags & 0x0010)?1:0;
        return 1;
    }
    return 0;
}

int dns_rcode_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);
    int attribute_offset = dns_attributes_metadata[10].position_in_packet;
    /* unused
    int attribute_length = dns_attributes_metadata[10].data_len;
    */
    uint16_t flags = ntohs(*(uint16_t *) & ipacket->data[proto_offset + attribute_offset]);
    //struct qropcodeaatcrdrazans_authdata_authrcode * temp_qropcodeaatcrdrazans_authdata_authrcode = (struct qropcodeaatcrdrazans_authdata_authrcode *) & flags;

    if (flags & 0x8000) {
        *((uint16_t *) extracted_data->data) = flags & 0x000F;
        return 1;
    }
    return 0;
}

static attribute_metadata_t dns_attributes_metadata[DNS_ATTRIBUTES_NB] = {
    {DNS_TID, DNS_TID_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 0, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {DNS_QR, DNS_QR_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_qr_extraction},
    {DNS_OPCODE, DNS_OPCODE_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_opcode_extraction},
    {DNS_AA, DNS_AA_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_aa_extraction},
    {DNS_TC, DNS_TC_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_tc_extraction},
    {DNS_RD, DNS_RD_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_rd_extraction},
    {DNS_RA, DNS_RA_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_ra_extraction},
    {DNS_Z, DNS_Z_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_z_extraction},
    {DNS_ANS_AUTH, DNS_ANS_AUTH_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_ans_auth_extraction},
    {DNS_DATA_AUTH, DNS_DATA_AUTH_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_data_auth_extraction},
    {DNS_RCODE, DNS_RCODE_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, dns_rcode_extraction},
    {DNS_QDCOUNT, DNS_QDCOUNT_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {DNS_ANCOUNT, DNS_ANCOUNT_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 6, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {DNS_NSCOUNT, DNS_NSCOUNT_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 8, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {DNS_ARCOUNT, DNS_ARCOUNT_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 10, SCOPE_PACKET, general_short_extraction_with_ordering_change},
};

void dns_session_data_init(ipacket_t * ipacket, unsigned index) {
    /* User specific code goes here */
}

void dns_session_data_cleanup(mmt_session_t * session, unsigned index) {
    /* User specific code goes here */
}

int dns_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    /* User specific code goes here */
    return MMT_CONTINUE;
}

static void mmt_int_dns_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_DNS, MMT_REAL_PROTOCOL);
    set_session_timeout_delay(ipacket->session, MMT_DNS_SESSION_TIMEOUT_DELAY);
}

void mmt_classify_me_dns(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;


    uint16_t dport = 0;

#define IPOQUE_MAX_DNS_REQUESTS			16

    MMT_LOG(PROTO_DNS, MMT_LOG_DEBUG, "search DNS.\n");


    if (packet->udp != NULL) {
        //      const u16 sport=ntohs(packet->udp->source);
        dport = ntohs(packet->udp->dest);
        MMT_LOG(PROTO_DNS, MMT_LOG_DEBUG, "calculated dport over UDP.\n");
    }
    if (packet->tcp != NULL) {
        //      const u16 sport=ntohs(packet->tcp->source);
        dport = ntohs(packet->tcp->dest);
        MMT_LOG(PROTO_DNS, MMT_LOG_DEBUG, "calculated dport over tcp.\n");
    }

    /*check standard DNS to port 53 */
    if (dport == 53 && packet->payload_packet_len >= 12) {

        MMT_LOG(PROTO_DNS, MMT_LOG_DEBUG, "dport==53, packet-payload-packet-len>=12.\n");

        /* dns header
           0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                      ID                       |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    QDCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ANCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    NSCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ARCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         *
         * dns query check: query: QR set, ancount = 0, nscount = 0, QDCOUNT < MAX_DNS, ARCOUNT < MAX_DNS
         *
         */

        if (((packet->payload[2] & 0x80) == 0 &&
                ntohs(get_u16(packet->payload, 4)) <= IPOQUE_MAX_DNS_REQUESTS &&
                ntohs(get_u16(packet->payload, 4)) != 0 &&
                ntohs(get_u16(packet->payload, 6)) == 0 &&
                ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) <= IPOQUE_MAX_DNS_REQUESTS)
                ||
                ((ntohs(get_u16(packet->payload, 0)) == packet->payload_packet_len - 2) &&
                (packet->payload[4] & 0x80) == 0 &&
                ntohs(get_u16(packet->payload, 6)) <= IPOQUE_MAX_DNS_REQUESTS &&
                ntohs(get_u16(packet->payload, 6)) != 0 &&
                ntohs(get_u16(packet->payload, 8)) == 0 &&
                ntohs(get_u16(packet->payload, 10)) == 0 &&
                packet->payload_packet_len >= 14 && ntohs(get_u16(packet->payload, 12)) <= IPOQUE_MAX_DNS_REQUESTS)) {

            MMT_LOG(PROTO_DNS, MMT_LOG_DEBUG, "found DNS.\n");

            mmt_int_dns_add_connection(ipacket);
            return;
        }
    }

    MMT_LOG(PROTO_DNS, MMT_LOG_DEBUG, "exclude DNS.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DNS);

}

int mmt_check_dns(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_dns(ipacket, index);
    }
    return 1;
}

void mmt_init_classify_me_dns() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_DNS);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dns_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DNS, PROTO_DNS_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < DNS_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &dns_attributes_metadata[i]);
        }

        mmt_init_classify_me_dns();

        /* Session context specific initializations */
        register_session_data_initialization_function(protocol_struct, dns_session_data_init);
        register_session_data_cleanup_function(protocol_struct, dns_session_data_cleanup);
        register_session_data_analysis_function(protocol_struct, dns_session_data_analysis);

        return register_protocol(protocol_struct, PROTO_DNS);
    } else {
        return 0;
    }
}


