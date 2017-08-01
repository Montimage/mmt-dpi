#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#define RADIUS_SESSION_DATA_PERSISTANCE 0 //0 means global persistance (per thread) non zero means session persistance (allocated into the session context)

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

typedef struct radius_session_context_struct {
    int tlv_count;
    tlv_t * packet_tlvs[0xFF]; // This will hold the different TLVs found in the last packet.
    tlv_t * vendor_3gpp_tlvs[VENDOR_3GPP_MAX_TLV_TYPE + 1]; // This will hold the different TLVs found in the last packet.
} radius_session_context_t;

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

//Radius session struct per thread!
static __thread radius_session_context_t r_session_data = {0};

static inline uint32_t
read_be32( const uint8_t *x )
{ return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]; }

/*
 * RADIUS data extraction routines
 */
int radius_authenticator_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(ipacket, proto_index);

    /* Get the attribute offset (relative the to protocol) */
    int attribute_offset = sizeof (struct radius_header);

    int attribute_length = 16; /* Length of the authenticator field */

    *((unsigned int *) extracted_data->data) = attribute_length;
    memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & ipacket->data[proto_offset + attribute_offset], attribute_length);

    return 1;
}

int radius_user_name_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[1]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[1]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[1]->val, radius_session_data->packet_tlvs[1]->len - 2);
        return 1;
    }
    return 0;
}

int radius_user_password_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[2]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[2]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[2]->val, radius_session_data->packet_tlvs[2]->len - 2);
        return 1;
    }
    return 0;
}

int radius_chap_password_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[3]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[3]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[3]->val, radius_session_data->packet_tlvs[3]->len - 2);
        return 1;
    }
    return 0;
}

int radius_nas_ip_address_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[4]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[4]->val );
        return 1;
    }
    return 0;
}

int radius_nas_port_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[5]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[5]->val );
        return 1;
    }
    return 0;
}

int radius_service_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[6]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[6]->val );
        return 1;
    }
    return 0;
}

int radius_framed_protocol_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[7]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[7]->val );
        return 1;
    }
    return 0;
}

int radius_framed_ip_address_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[8]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[8]->val );
        return 1;
    }
    return 0;
}

int radius_framed_ip_netmask_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[9]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[9]->val );
        return 1;
    }
    return 0;
}

int radius_framed_mtu_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[12]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[12]->val );
        return 1;
    }
    return 0;
}

int radius_callback_number_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[19]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[19]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[19]->val, radius_session_data->packet_tlvs[19]->len - 2);
        return 1;
    }
    return 0;
}

int radius_callback_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[20]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[20]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[20]->val, radius_session_data->packet_tlvs[20]->len - 2);
        return 1;
    }
    return 0;
}

int radius_state_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[24]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[24]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[24]->val, radius_session_data->packet_tlvs[24]->len - 2);
        return 1;
    }
    return 0;
}

int radius_class_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[25]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[25]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[25]->val, radius_session_data->packet_tlvs[25]->len - 2);
        return 1;
    }
    return 0;
}

int radius_session_timeout_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[27]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[27]->val );
        return 1;
    }
    return 0;
}

int radius_idle_timeout_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[28]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[28]->val );
        return 1;
    }
    return 0;
}

int radius_called_station_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[30]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[30]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[30]->val, radius_session_data->packet_tlvs[30]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->packet_tlvs[30]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_calling_station_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[31]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[31]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[31]->val, radius_session_data->packet_tlvs[31]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->packet_tlvs[31]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_nas_identifier_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[32]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[32]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[32]->val, radius_session_data->packet_tlvs[32]->len - 2);
        return 1;
    }
    return 0;
}

int radius_acct_status_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[40]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[40]->val );
        return 1;
    }
    return 0;
}

int radius_acct_delay_time_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[41]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[41]->val );
        return 1;
    }
    return 0;
}

int radius_acct_input_octets_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[42]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[42]->val );
        return 1;
    }
    return 0;
}

int radius_acct_output_octets_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[43]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[43]->val );
        return 1;
    }
    return 0;
}

int radius_acct_session_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[44]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[44]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[44]->val, radius_session_data->packet_tlvs[44]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->packet_tlvs[44]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_acct_authentic_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[45]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[45]->val );
        return 1;
    }
    return 0;
}

int radius_acct_session_time_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[46]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[46]->val );
        return 1;
    }
    return 0;
}

int radius_acct_input_packets_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[47]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[47]->val );
        return 1;
    }
    return 0;
}

int radius_acct_output_packets_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[48]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[48]->val );
        return 1;
    }
    return 0;
}

int radius_acct_terminate_cause_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[49]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[49]->val );
        return 1;
    }
    return 0;
}

int radius_event_timestamp_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[55]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[55]->val );
        return 1;
    }
    return 0;
}

int radius_nas_port_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[61]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->packet_tlvs[61]->val );
        return 1;
    }
    return 0;
}

int radius_message_authenticator_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[80]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[80]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[80]->val, radius_session_data->packet_tlvs[80]->len - 2);
        return 1;
    }
    return 0;
}

int radius_nas_port_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[87]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[87]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[87]->val, radius_session_data->packet_tlvs[87]->len - 2);
        return 1;
    }
    return 0;
}

int radius_nas_ipv6_address_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[95]) {
        memcpy((u_char *) extracted_data->data, & radius_session_data->packet_tlvs[95]->val, IPv6_ALEN);
        return 1;
    }
    return 0;
}

int radius_framed_interface_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[96]) {
        //The length of the framed interface id is 8Bytes.
        memcpy((u_char *) extracted_data->data, & radius_session_data->packet_tlvs[96]->val, 8);
        return 1;
    }
    return 0;
}

int radius_framed_ipv6_prefix_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[97]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[97]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[97]->val, radius_session_data->packet_tlvs[97]->len - 2);
        return 1;
    }
    return 0;
}

int radius_framed_ipv6_pool_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[100]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->packet_tlvs[100]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->packet_tlvs[100]->val, radius_session_data->packet_tlvs[100]->len - 2);
        return 1;
    }
    return 0;
}

int radius_avp1_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[1]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[1];
        return 1;
    }
    return 0;
}

int radius_avp2_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[2]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[2];
        return 1;
    }
    return 0;
}

int radius_avp3_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[3]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[3];
        return 1;
    }
    return 0;
}

int radius_avp4_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[4]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[4];
        return 1;
    }
    return 0;
}

int radius_avp5_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[5]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[5];
        return 1;
    }
    return 0;
}

int radius_avp6_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[6]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[6];
        return 1;
    }
    return 0;
}

int radius_avp7_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[7]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[7];
        return 1;
    }
    return 0;
}

int radius_avp8_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[8]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[8];
        return 1;
    }
    return 0;
}

int radius_avp9_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[9]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[9];
        return 1;
    }
    return 0;
}

int radius_avp10_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[10]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[10];
        return 1;
    }
    return 0;
}

int radius_avp11_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[11]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[11];
        return 1;
    }
    return 0;
}

int radius_avp12_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[12]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[12];
        return 1;
    }
    return 0;
}

int radius_avp13_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[13]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[13];
        return 1;
    }
    return 0;
}

int radius_avp14_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[14]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[14];
        return 1;
    }
    return 0;
}

int radius_avp15_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[15]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[15];
        return 1;
    }
    return 0;
}

int radius_avp16_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[16]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[16];
        return 1;
    }
    return 0;
}

int radius_avp17_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[17]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[17];
        return 1;
    }
    return 0;
}

int radius_avp18_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[18]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[18];
        return 1;
    }
    return 0;
}

int radius_avp19_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[19]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[19];
        return 1;
    }
    return 0;
}

int radius_avp20_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[20]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[20];
        return 1;
    }
    return 0;
}

int radius_avp21_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[21]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[21];
        return 1;
    }
    return 0;
}

int radius_avp22_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[22]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[22];
        return 1;
    }
    return 0;
}

int radius_avp23_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[23]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[23];
        return 1;
    }
    return 0;
}

int radius_avp24_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[24]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[24];
        return 1;
    }
    return 0;
}

int radius_avp25_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[25]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[25];
        return 1;
    }
    return 0;
}

int radius_avp26_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[26]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[26];
        return 1;
    }
    return 0;
}

int radius_avp27_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[27]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[27];
        return 1;
    }
    return 0;
}

int radius_avp28_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[28]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[28];
        return 1;
    }
    return 0;
}

int radius_avp29_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[29]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[29];
        return 1;
    }
    return 0;
}

int radius_avp30_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[30]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[30];
        return 1;
    }
    return 0;
}

int radius_avp31_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[31]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[31];
        return 1;
    }
    return 0;
}

int radius_avp32_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[32]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[32];
        return 1;
    }
    return 0;
}

int radius_avp33_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[33]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[33];
        return 1;
    }
    return 0;
}

int radius_avp34_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[34]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[34];
        return 1;
    }
    return 0;
}

int radius_avp35_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[35]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[35];
        return 1;
    }
    return 0;
}

int radius_avp36_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[36]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[36];
        return 1;
    }
    return 0;
}

int radius_avp37_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[37]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[37];
        return 1;
    }
    return 0;
}

int radius_avp38_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[38]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[38];
        return 1;
    }
    return 0;
}

int radius_avp39_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[39]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[39];
        return 1;
    }
    return 0;
}

int radius_avp40_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[40]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[40];
        return 1;
    }
    return 0;
}

int radius_avp41_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[41]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[41];
        return 1;
    }
    return 0;
}

int radius_avp42_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[42]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[42];
        return 1;
    }
    return 0;
}

int radius_avp43_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[43]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[43];
        return 1;
    }
    return 0;
}

int radius_avp44_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[44]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[44];
        return 1;
    }
    return 0;
}

int radius_avp45_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[45]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[45];
        return 1;
    }
    return 0;
}

int radius_avp46_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[46]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[46];
        return 1;
    }
    return 0;
}

int radius_avp47_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[47]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[47];
        return 1;
    }
    return 0;
}

int radius_avp48_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[48]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[48];
        return 1;
    }
    return 0;
}

int radius_avp49_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[49]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[49];
        return 1;
    }
    return 0;
}

int radius_avp50_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[50]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[50];
        return 1;
    }
    return 0;
}

int radius_avp51_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[51]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[51];
        return 1;
    }
    return 0;
}

int radius_avp52_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[52]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[52];
        return 1;
    }
    return 0;
}

int radius_avp53_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[53]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[53];
        return 1;
    }
    return 0;
}

int radius_avp54_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[54]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[54];
        return 1;
    }
    return 0;
}

int radius_avp55_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[55]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[55];
        return 1;
    }
    return 0;
}

int radius_avp56_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[56]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[56];
        return 1;
    }
    return 0;
}

int radius_avp57_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[57]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[57];
        return 1;
    }
    return 0;
}

int radius_avp58_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[58]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[58];
        return 1;
    }
    return 0;
}

int radius_avp59_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[59]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[59];
        return 1;
    }
    return 0;
}

int radius_avp60_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[60]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[60];
        return 1;
    }
    return 0;
}

int radius_avp61_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[61]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[61];
        return 1;
    }
    return 0;
}

int radius_avp62_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[62]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[62];
        return 1;
    }
    return 0;
}

int radius_avp63_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[63]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[63];
        return 1;
    }
    return 0;
}

int radius_avp64_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[64]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[64];
        return 1;
    }
    return 0;
}

int radius_avp65_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[65]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[65];
        return 1;
    }
    return 0;
}

int radius_avp66_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[66]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[66];
        return 1;
    }
    return 0;
}

int radius_avp67_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[67]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[67];
        return 1;
    }
    return 0;
}

int radius_avp68_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[68]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[68];
        return 1;
    }
    return 0;
}

int radius_avp69_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[69]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[69];
        return 1;
    }
    return 0;
}

int radius_avp70_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[70]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[70];
        return 1;
    }
    return 0;
}

int radius_avp71_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[71]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[71];
        return 1;
    }
    return 0;
}

int radius_avp72_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[72]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[72];
        return 1;
    }
    return 0;
}

int radius_avp73_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[73]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[73];
        return 1;
    }
    return 0;
}

int radius_avp74_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[74]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[74];
        return 1;
    }
    return 0;
}

int radius_avp75_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[75]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[75];
        return 1;
    }
    return 0;
}

int radius_avp76_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[76]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[76];
        return 1;
    }
    return 0;
}

int radius_avp77_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[77]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[77];
        return 1;
    }
    return 0;
}

int radius_avp78_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[78]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[78];
        return 1;
    }
    return 0;
}

int radius_avp79_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[79]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[79];
        return 1;
    }
    return 0;
}

int radius_avp80_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[80]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[80];
        return 1;
    }
    return 0;
}

int radius_avp81_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[81]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[81];
        return 1;
    }
    return 0;
}

int radius_avp82_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[82]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[82];
        return 1;
    }
    return 0;
}

int radius_avp83_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[83]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[83];
        return 1;
    }
    return 0;
}

int radius_avp84_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[84]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[84];
        return 1;
    }
    return 0;
}

int radius_avp85_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[85]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[85];
        return 1;
    }
    return 0;
}

int radius_avp86_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[86]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[86];
        return 1;
    }
    return 0;
}

int radius_avp87_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[87]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[87];
        return 1;
    }
    return 0;
}

int radius_avp88_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[88]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[88];
        return 1;
    }
    return 0;
}

int radius_avp89_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[89]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[89];
        return 1;
    }
    return 0;
}

int radius_avp90_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[90]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[90];
        return 1;
    }
    return 0;
}

int radius_avp91_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[91]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[91];
        return 1;
    }
    return 0;
}

int radius_avp92_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[92]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[92];
        return 1;
    }
    return 0;
}

int radius_avp93_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[93]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[93];
        return 1;
    }
    return 0;
}

int radius_avp94_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[94]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[94];
        return 1;
    }
    return 0;
}

int radius_avp95_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[95]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[95];
        return 1;
    }
    return 0;
}

int radius_avp96_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[96]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[96];
        return 1;
    }
    return 0;
}

int radius_avp97_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[97]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[97];
        return 1;
    }
    return 0;
}

int radius_avp98_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[98]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[98];
        return 1;
    }
    return 0;
}

int radius_avp99_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[99]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[99];
        return 1;
    }
    return 0;
}

int radius_avp100_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[100]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[100];
        return 1;
    }
    return 0;
}

int radius_avp101_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[101]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[101];
        return 1;
    }
    return 0;
}

int radius_avp102_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[102]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[102];
        return 1;
    }
    return 0;
}

int radius_avp224_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[224]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[224];
        return 1;
    }
    return 0;
}

int radius_avp225_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[225]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[225];
        return 1;
    }
    return 0;
}

int radius_avp226_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[226]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[226];
        return 1;
    }
    return 0;
}

int radius_avp227_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[227]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[227];
        return 1;
    }
    return 0;
}

int radius_avp228_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[228]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[228];
        return 1;
    }
    return 0;
}

int radius_avp229_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[229]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[229];
        return 1;
    }
    return 0;
}

int radius_avp230_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[230]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[230];
        return 1;
    }
    return 0;
}

int radius_avp231_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[231]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[231];
        return 1;
    }
    return 0;
}

int radius_avp232_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[232]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[232];
        return 1;
    }
    return 0;
}

int radius_avp233_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[233]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[233];
        return 1;
    }
    return 0;
}

int radius_avp234_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[234]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[234];
        return 1;
    }
    return 0;
}

int radius_avp235_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[235]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[235];
        return 1;
    }
    return 0;
}

int radius_avp236_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[236]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[236];
        return 1;
    }
    return 0;
}

int radius_avp237_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[237]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[237];
        return 1;
    }
    return 0;
}

int radius_avp238_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[238]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[238];
        return 1;
    }
    return 0;
}

int radius_avp239_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[239]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[239];
        return 1;
    }
    return 0;
}

int radius_avp240_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->packet_tlvs[240]) {
        extracted_data->data = (void *) radius_session_data->packet_tlvs[240];
        return 1;
    }
    return 0;
}

int radius_imsi_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[1]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->vendor_3gpp_tlvs[1]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->vendor_3gpp_tlvs[1]->val, radius_session_data->vendor_3gpp_tlvs[1]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->vendor_3gpp_tlvs[1]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_sgsn_ip_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[6]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->vendor_3gpp_tlvs[6]->val );
        return 1;
    }
    return 0;
}

int radius_ggsn_ip_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[7]) {
        *((unsigned int *) extracted_data->data) = read_be32( &radius_session_data->vendor_3gpp_tlvs[7]->val );
        return 1;
    }
    return 0;
}

int radius_charging_charact_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[13]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->vendor_3gpp_tlvs[13]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->vendor_3gpp_tlvs[13]->val, radius_session_data->vendor_3gpp_tlvs[13]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->vendor_3gpp_tlvs[13]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_sgsn_ipv6_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[15]) {
        memcpy((u_char *) extracted_data->data, & radius_session_data->vendor_3gpp_tlvs[15]->val, IPv6_ALEN);
        return 1;
    }
    return 0;
}

int radius_ggsn_ipv6_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[16]) {
        memcpy((u_char *) extracted_data->data, & radius_session_data->vendor_3gpp_tlvs[16]->val, IPv6_ALEN);
        return 1;
    }
    return 0;
}

int radius_sgsn_mccmnc_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[18]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->vendor_3gpp_tlvs[18]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->vendor_3gpp_tlvs[18]->val, radius_session_data->vendor_3gpp_tlvs[18]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->vendor_3gpp_tlvs[18]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_imei_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[20]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->vendor_3gpp_tlvs[20]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->vendor_3gpp_tlvs[20]->val, radius_session_data->vendor_3gpp_tlvs[20]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->vendor_3gpp_tlvs[20]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_rat_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[21]) {
        *((uint8_t *) extracted_data->data) = *((uint8_t *) & radius_session_data->vendor_3gpp_tlvs[21]->val);
        return 1;
    }
    return 0;
}

int radius_charging_id_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_pdp_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_cg_ip_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_qos_profile_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_imsi_mccmnc_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_ggsn_mccmnc_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_nsapi_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_session_stop_ind_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_select_mode_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_cgipv6_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_dns_ipv6_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_teardown_ind_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_user_loc_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    radius_session_context_t * radius_session_data = ipacket->session->session_data[proto_index];
    if (radius_session_data != NULL && radius_session_data->vendor_3gpp_tlvs[22]) {
        *((unsigned int *) extracted_data->data) = radius_session_data->vendor_3gpp_tlvs[22]->len - 2 /* tlv len accounts also for the type and len fields */;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & radius_session_data->vendor_3gpp_tlvs[22]->val, radius_session_data->vendor_3gpp_tlvs[22]->len - 2);
        ((u_char *) extracted_data->data)[sizeof (int) +radius_session_data->vendor_3gpp_tlvs[22]->len - 2] = '\0';
        return 1;
    }
    return 0;
}

int radius_timezone_change(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_camelcharging_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_packet_filter_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_neg_dscp_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

int radius_alloc_ip_type_extraction(const ipacket_t * ipacket, unsigned proto_index,
        attribute_t * extracted_data) {
    return 0;
}

void mmt_classify_me_radius(ipacket_t * ipacket, unsigned index) {

    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    MMT_LOG(PROTO_RADIUS, MMT_LOG_DEBUG, "radius detection...\n");

    /* skip marked packets */
    if (packet->detected_protocol_stack[0] != PROTO_RADIUS) {
        /* unused
        const uint8_t *packet_payload = packet->payload;
        */
        uint32_t payload_len = packet->payload_packet_len;

        if (packet->udp != NULL) {
            struct radius_header *h = (struct radius_header*) packet->payload;

            uint32_t h_len = ntohs(h->len);

            if ((payload_len > sizeof (struct radius_header))
                    && (h->code <= 5)
                    && (h_len == payload_len)) {
                h->len = ntohs(h->len);
                MMT_LOG(PROTO_RADIUS, MMT_LOG_DEBUG, "Found radius.\n");
                mmt_internal_add_connection(ipacket, PROTO_RADIUS, MMT_REAL_PROTOCOL);

                return;
            }

            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RADIUS);
            return;
        }
    }
}

int mmt_check_radius(ipacket_t * ipacket, unsigned index) { //BW: TODO: check this out
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        MMT_LOG(PROTO_RADIUS, MMT_LOG_DEBUG, "radius detection...\n");

        uint32_t payload_len = packet->payload_packet_len;

        struct radius_header *h = (struct radius_header*) packet->payload;

        uint32_t h_len = ntohs(h->len);

        if ((payload_len > sizeof (struct radius_header))
                && (h->code <= 5)
                && (h_len == payload_len)) {
            h->len = ntohs(h->len);
            MMT_LOG(PROTO_RADIUS, MMT_LOG_DEBUG, "Found radius.\n");
            mmt_internal_add_connection(ipacket, PROTO_RADIUS, MMT_REAL_PROTOCOL);
            return 1;
        }

        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RADIUS);
    }
    return 0;
}

void radius_vendor_specific_fields_analysis(ipacket_t * ipacket, uint8_t * v_field, unsigned index) {
    vendor_tlv_t * v_tlv = (vendor_tlv_t *) v_field;
    if (ntohl(v_tlv->vendor_id) == VENDOR_3GPP_ID) {
        radius_session_context_t * radius_session_data = ipacket->session->session_data[index];
        tlv_t * tlv = (tlv_t *) & v_field[4]; //Offset the vendor id (4 bytes)
        if (tlv->type <= VENDOR_3GPP_MAX_TLV_TYPE) {
            radius_session_data->vendor_3gpp_tlvs[tlv->type] = tlv;
        }
    }
}

void mmt_init_classify_me_radius() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_RADIUS);
}

void radius_session_data_init(ipacket_t * ipacket, unsigned index) {
    if (RADIUS_SESSION_DATA_PERSISTANCE) {
        radius_session_context_t * radius_session_data = (radius_session_context_t *) mmt_malloc(sizeof (radius_session_context_t));
        memset(radius_session_data, 0, sizeof (radius_session_context_t));
        ipacket->session->session_data[index] = radius_session_data;
    } else {
        ipacket->session->session_data[index] = &r_session_data; //Global persistance.
    }
}

void radius_session_data_cleanup(mmt_session_t * session, unsigned index) {
    if (RADIUS_SESSION_DATA_PERSISTANCE) {
        if (session->session_data[index] != NULL) {
            mmt_free(session->session_data[index]);
        }
    }
}

int radius_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    radius_session_context_t * radius_session_data;
    radius_session_data = ipacket->session->session_data[index];
    if (radius_session_data) {
        int count;
        for (count = 0; count < 0xFF; count++) {
            radius_session_data->packet_tlvs[count] = NULL;
        }
        for (count = 0; count < VENDOR_3GPP_MAX_TLV_TYPE; count++) {
            radius_session_data->vendor_3gpp_tlvs[count] = NULL;
        }
        radius_session_data->tlv_count = 0;
        /* Get the protocol offset */
        int proto_offset = get_packet_offset_at_index(ipacket, index);
        int tlv_offset = proto_offset + 20 /* header = 4 octets + 16 for authenticator field */;
        while (ipacket->p_hdr->caplen > tlv_offset + 2 /* to guarantee we have access to the type and len of the next tlv */) {
            tlv_t * current_tlv = (tlv_t *) & ipacket->data[tlv_offset];
            if((int) current_tlv->len > 0) {
                tlv_offset += current_tlv->len;
            }else {
                for (count = 0; count < 0xFF; count++) {
                    radius_session_data->packet_tlvs[count] = NULL;
                }
                for (count = 0; count < VENDOR_3GPP_MAX_TLV_TYPE; count++) {
                    radius_session_data->vendor_3gpp_tlvs[count] = NULL;
                }
                break;
            }
            if (tlv_offset <= ipacket->p_hdr->caplen) {
                /* The current tlv is completely in the available packet data! */
                radius_session_data->packet_tlvs[current_tlv->type] = current_tlv;
                if (current_tlv->type == 26) {
                    radius_vendor_specific_fields_analysis(ipacket, (uint8_t *) & current_tlv->val, index);
                }
                radius_session_data->tlv_count += 1;
            }
        }
    }
    return MMT_CONTINUE;
}

static attribute_metadata_t radius_attributes_metadata[RADIUS_ATTRIBUTES_NB] = {
    {RADIUS_CODE, RADIUS_CODE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, general_char_extraction},
    {RADIUS_RID, RADIUS_RID_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 1, SCOPE_PACKET, general_char_extraction},
    {RADIUS_RLEN, RADIUS_RLEN_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {RADIUS_AUTHENTICATOR, RADIUS_AUTHENTICATOR_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_authenticator_extraction},
    {RADIUS_USER_NAME, RADIUS_USER_NAME_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_user_name_extraction},
    {RADIUS_USER_PASSWORD, RADIUS_USER_PASSWORD_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_user_password_extraction},
    {RADIUS_CHAP_PASSWORD, RADIUS_CHAP_PASSWORD_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_chap_password_extraction},
    {RADIUS_NAS_IP_ADDRESS, RADIUS_NAS_IP_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_nas_ip_address_extraction},
    {RADIUS_NAS_PORT, RADIUS_NAS_PORT_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_nas_port_extraction},
    {RADIUS_SERVICE_TYPE, RADIUS_SERVICE_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_service_type_extraction},
    {RADIUS_FRAMED_PROTOCOL, RADIUS_FRAMED_PROTOCOL_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_framed_protocol_extraction},
    {RADIUS_FRAMED_IP_ADDRESS, RADIUS_FRAMED_IP_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_framed_ip_address_extraction},
    {RADIUS_FRAMED_IP_NETMASK, RADIUS_FRAMED_IP_NETMASK_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_framed_ip_netmask_extraction},
    {RADIUS_FRAMED_MTU, RADIUS_FRAMED_MTU_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_framed_mtu_extraction},
    {RADIUS_CALLBACK_NUMBER, RADIUS_CALLBACK_NUMBER_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_callback_number_extraction},
    {RADIUS_CALLBACK_ID, RADIUS_CALLBACK_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_callback_id_extraction},
    {RADIUS_STATE, RADIUS_STATE_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_state_extraction},
    {RADIUS_CLASS, RADIUS_CLASS_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_class_extraction},
    {RADIUS_SESSION_TIMEOUT, RADIUS_SESSION_TIMEOUT_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_session_timeout_extraction},
    {RADIUS_IDLE_TIMEOUT, RADIUS_IDLE_TIMEOUT_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_idle_timeout_extraction},
    {RADIUS_CALLED_STATION_ID, RADIUS_CALLED_STATION_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_called_station_id_extraction},
    {RADIUS_CALLING_STATION_ID, RADIUS_CALLING_STATION_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_calling_station_id_extraction},
    {RADIUS_NAS_IDENTIFIER, RADIUS_NAS_IDENTIFIER_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_nas_identifier_extraction},
    {RADIUS_ACCT_STATUS_TYPE, RADIUS_ACCT_STATUS_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_status_type_extraction},
    {RADIUS_ACCT_DELAY_TIME, RADIUS_ACCT_DELAY_TIME_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_delay_time_extraction},
    {RADIUS_ACCT_INPUT_OCTETS, RADIUS_ACCT_INPUT_OCTETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_input_octets_extraction},
    {RADIUS_ACCT_OUTPUT_OCTETS, RADIUS_ACCT_OUTPUT_OCTETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_output_octets_extraction},
    {RADIUS_ACCT_SESSION_ID, RADIUS_ACCT_SESSION_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_acct_session_id_extraction},
    {RADIUS_ACCT_AUTHENTIC, RADIUS_ACCT_AUTHENTIC_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_authentic_extraction},
    {RADIUS_ACCT_SESSION_TIME, RADIUS_ACCT_SESSION_TIME_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_session_time_extraction},
    {RADIUS_ACCT_INPUT_PACKETS, RADIUS_ACCT_INPUT_PACKETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_input_packets_extraction},
    {RADIUS_ACCT_OUTPUT_PACKETS, RADIUS_ACCT_OUTPUT_PACKETS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_output_packets_extraction},
    {RADIUS_ACCT_TERMINATE_CAUSE, RADIUS_ACCT_TERMINATE_CAUSE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_acct_terminate_cause_extraction},
    {RADIUS_EVENT_TIMESTAMP, RADIUS_EVENT_TIMESTAMP_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_event_timestamp_extraction},
    {RADIUS_NAS_PORT_TYPE, RADIUS_NAS_PORT_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_nas_port_type_extraction},
    {RADIUS_MESSAGE_AUTHENTICATOR, RADIUS_MESSAGE_AUTHENTICATOR_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_message_authenticator_extraction},
    {RADIUS_NAS_PORT_ID, RADIUS_NAS_PORT_ID_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_nas_port_id_extraction},
    {RADIUS_NAS_IPV6_ADDRESS, RADIUS_NAS_IPV6_ADDRESS_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_nas_ipv6_address_extraction},
    {RADIUS_FRAMED_INTERFACE_ID, RADIUS_FRAMED_INTERFACE_ID_ALIAS, MMT_U64_DATA, sizeof (uint64_t), -2, SCOPE_PACKET, radius_framed_interface_id_extraction},
    {RADIUS_FRAMED_IPV6_PREFIX, RADIUS_FRAMED_IPV6_PREFIX_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_framed_ipv6_prefix_extraction},
    {RADIUS_FRAMED_IPV6_POOL, RADIUS_FRAMED_IPV6_POOL_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_framed_ipv6_pool_extraction},

    {RADIUS_3GPP_IMSI, RADIUS_3GPP_IMSI_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_imsi_extraction},
    {RADIUS_3GPP_CHARGING_ID, RADIUS_3GPP_CHARGING_ID_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_charging_id_extraction},
    {RADIUS_3GPP_PDP_TYPE, RADIUS_3GPP_PDP_TYPE_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_pdp_type_extraction},
    {RADIUS_3GPP_CG_ADDRESS, RADIUS_3GPP_CG_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_cg_ip_extraction},
    {RADIUS_3GPP_QOS_PROFILE, RADIUS_3GPP_QOS_PROFILE_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_qos_profile_extraction},
    {RADIUS_3GPP_SGSN_ADDRESS, RADIUS_3GPP_SGSN_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_sgsn_ip_extraction},
    {RADIUS_3GPP_GGSN_ADDRESS, RADIUS_3GPP_GGSN_ADDRESS_ALIAS, MMT_U32_DATA, sizeof (uint32_t), -2, SCOPE_PACKET, radius_ggsn_ip_extraction},
    {RADIUS_3GPP_IMSI_MCCMNC, RADIUS_3GPP_IMSI_MCCMNC_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_imsi_mccmnc_extraction},
    {RADIUS_3GPP_GGSN_MCCMNC, RADIUS_3GPP_GGSN_MCCMNC_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_ggsn_mccmnc_extraction},
    {RADIUS_3GPP_NSAPI, RADIUS_3GPP_NSAPI_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_nsapi_extraction},
    {RADIUS_3GPP_SESSION_STOP_IND, RADIUS_3GPP_SESSION_STOP_IND_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_session_stop_ind_extraction},
    {RADIUS_3GPP_SELECTION_MODE, RADIUS_3GPP_SELECTION_MODE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_select_mode_extraction},
    {RADIUS_3GPP_CHARGIN_CHARACT, RADIUS_3GPP_CHARGIN_CHARACT_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_charging_charact_extraction},
    {RADIUS_3GPP_CG_IPV6, RADIUS_3GPP_CG_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_cgipv6_extraction},
    {RADIUS_3GPP_SGSN_IPV6, RADIUS_3GPP_SGSN_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_sgsn_ipv6_extraction},
    {RADIUS_3GPP_GGSN_IPV6, RADIUS_3GPP_GGSN_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_ggsn_ipv6_extraction},
    {RADIUS_3GPP_DNS_IPV6, RADIUS_3GPP_DNS_IPV6_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, -2, SCOPE_PACKET, radius_dns_ipv6_extraction}, //TODO: binary 256 needed
    {RADIUS_3GPP_SGSN_MCCMNC, RADIUS_3GPP_SGSN_MCCMNC_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_sgsn_mccmnc_extraction},
    {RADIUS_3GPP_TEARDOWN_IND, RADIUS_3GPP_TEARDOWN_IND_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_teardown_ind_extraction},
    {RADIUS_3GPP_IMEISV, RADIUS_3GPP_IMEISV_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_imei_extraction},
    {RADIUS_3GPP_RAT_TYPE, RADIUS_3GPP_RAT_TYPE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_rat_type_extraction},
    {RADIUS_3GPP_USER_LOCATION, RADIUS_3GPP_USER_LOCATION_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_user_loc_extraction},
    {RADIUS_3GPP_TIMEZONE, RADIUS_3GPP_TIMEZONE_ALIAS, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, radius_timezone_change},
    {RADIUS_3GPP_CAMELCHARGING, RADIUS_3GPP_CAMELCHARGING_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_camelcharging_extraction},
    {RADIUS_3GPP_PACKET_FILTER, RADIUS_3GPP_PACKET_FILTER_ALIAS, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, -2, SCOPE_PACKET, radius_packet_filter_extraction},
    {RADIUS_3GPP_NEG_DSCP, RADIUS_3GPP_NEG_DSCP_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_neg_dscp_extraction},
    {RADIUS_3GPP_ALLOC_IP_TYPE, RADIUS_3GPP_ALLOC_IP_TYPE_ALIAS, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, radius_alloc_ip_type_extraction},

    {RADIUS_AVP1, RADIUS_AVP1_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp1_extraction},
    {RADIUS_AVP2, RADIUS_AVP2_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp2_extraction},
    {RADIUS_AVP3, RADIUS_AVP3_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp3_extraction},
    {RADIUS_AVP4, RADIUS_AVP4_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp4_extraction},
    {RADIUS_AVP5, RADIUS_AVP5_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp5_extraction},
    {RADIUS_AVP6, RADIUS_AVP6_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp6_extraction},
    {RADIUS_AVP7, RADIUS_AVP7_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp7_extraction},
    {RADIUS_AVP8, RADIUS_AVP8_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp8_extraction},
    {RADIUS_AVP9, RADIUS_AVP9_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp9_extraction},
    {RADIUS_AVP10, RADIUS_AVP10_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp10_extraction},
    {RADIUS_AVP11, RADIUS_AVP11_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp11_extraction},
    {RADIUS_AVP12, RADIUS_AVP12_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp12_extraction},
    {RADIUS_AVP13, RADIUS_AVP13_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp13_extraction},
    {RADIUS_AVP14, RADIUS_AVP14_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp14_extraction},
    {RADIUS_AVP15, RADIUS_AVP15_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp15_extraction},
    {RADIUS_AVP16, RADIUS_AVP16_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp16_extraction},
    {RADIUS_AVP17, RADIUS_AVP17_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp17_extraction},
    {RADIUS_AVP18, RADIUS_AVP18_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp18_extraction},
    {RADIUS_AVP19, RADIUS_AVP19_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp19_extraction},
    {RADIUS_AVP20, RADIUS_AVP20_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp20_extraction},
    {RADIUS_AVP21, RADIUS_AVP21_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp21_extraction},
    {RADIUS_AVP22, RADIUS_AVP22_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp22_extraction},
    {RADIUS_AVP23, RADIUS_AVP23_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp23_extraction},
    {RADIUS_AVP24, RADIUS_AVP24_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp24_extraction},
    {RADIUS_AVP25, RADIUS_AVP25_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp25_extraction},
    {RADIUS_AVP26, RADIUS_AVP26_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp26_extraction},
    {RADIUS_AVP27, RADIUS_AVP27_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp27_extraction},
    {RADIUS_AVP28, RADIUS_AVP28_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp28_extraction},
    {RADIUS_AVP29, RADIUS_AVP29_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp29_extraction},
    {RADIUS_AVP30, RADIUS_AVP30_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp30_extraction},
    {RADIUS_AVP31, RADIUS_AVP31_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp31_extraction},
    {RADIUS_AVP32, RADIUS_AVP32_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp32_extraction},
    {RADIUS_AVP33, RADIUS_AVP33_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp33_extraction},
    {RADIUS_AVP34, RADIUS_AVP34_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp34_extraction},
    {RADIUS_AVP35, RADIUS_AVP35_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp35_extraction},
    {RADIUS_AVP36, RADIUS_AVP36_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp36_extraction},
    {RADIUS_AVP37, RADIUS_AVP37_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp37_extraction},
    {RADIUS_AVP38, RADIUS_AVP38_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp38_extraction},
    {RADIUS_AVP39, RADIUS_AVP39_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp39_extraction},
    {RADIUS_AVP40, RADIUS_AVP40_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp40_extraction},
    {RADIUS_AVP41, RADIUS_AVP41_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp41_extraction},
    {RADIUS_AVP42, RADIUS_AVP42_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp42_extraction},
    {RADIUS_AVP43, RADIUS_AVP43_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp43_extraction},
    {RADIUS_AVP44, RADIUS_AVP44_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp44_extraction},
    {RADIUS_AVP45, RADIUS_AVP45_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp45_extraction},
    {RADIUS_AVP46, RADIUS_AVP46_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp46_extraction},
    {RADIUS_AVP47, RADIUS_AVP47_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp47_extraction},
    {RADIUS_AVP48, RADIUS_AVP48_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp48_extraction},
    {RADIUS_AVP49, RADIUS_AVP49_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp49_extraction},
    {RADIUS_AVP50, RADIUS_AVP50_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp50_extraction},
    {RADIUS_AVP51, RADIUS_AVP51_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp51_extraction},
    {RADIUS_AVP52, RADIUS_AVP52_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp52_extraction},
    {RADIUS_AVP53, RADIUS_AVP53_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp53_extraction},
    {RADIUS_AVP54, RADIUS_AVP54_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp54_extraction},
    {RADIUS_AVP55, RADIUS_AVP55_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp55_extraction},
    {RADIUS_AVP56, RADIUS_AVP56_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp56_extraction},
    {RADIUS_AVP57, RADIUS_AVP57_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp57_extraction},
    {RADIUS_AVP58, RADIUS_AVP58_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp58_extraction},
    {RADIUS_AVP59, RADIUS_AVP59_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp59_extraction},
    {RADIUS_AVP60, RADIUS_AVP60_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp60_extraction},
    {RADIUS_AVP61, RADIUS_AVP61_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp61_extraction},
    {RADIUS_AVP62, RADIUS_AVP62_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp62_extraction},
    {RADIUS_AVP63, RADIUS_AVP63_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp63_extraction},
    {RADIUS_AVP64, RADIUS_AVP64_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp64_extraction},
    {RADIUS_AVP65, RADIUS_AVP65_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp65_extraction},
    {RADIUS_AVP66, RADIUS_AVP66_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp66_extraction},
    {RADIUS_AVP67, RADIUS_AVP67_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp67_extraction},
    {RADIUS_AVP68, RADIUS_AVP68_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp68_extraction},
    {RADIUS_AVP69, RADIUS_AVP69_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp69_extraction},
    {RADIUS_AVP70, RADIUS_AVP70_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp70_extraction},
    {RADIUS_AVP71, RADIUS_AVP71_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp71_extraction},
    {RADIUS_AVP72, RADIUS_AVP72_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp72_extraction},
    {RADIUS_AVP73, RADIUS_AVP73_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp73_extraction},
    {RADIUS_AVP74, RADIUS_AVP74_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp74_extraction},
    {RADIUS_AVP75, RADIUS_AVP75_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp75_extraction},
    {RADIUS_AVP76, RADIUS_AVP76_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp76_extraction},
    {RADIUS_AVP77, RADIUS_AVP77_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp77_extraction},
    {RADIUS_AVP78, RADIUS_AVP78_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp78_extraction},
    {RADIUS_AVP79, RADIUS_AVP79_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp79_extraction},
    {RADIUS_AVP80, RADIUS_AVP80_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp80_extraction},
    {RADIUS_AVP81, RADIUS_AVP81_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp81_extraction},
    {RADIUS_AVP82, RADIUS_AVP82_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp82_extraction},
    {RADIUS_AVP83, RADIUS_AVP83_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp83_extraction},
    {RADIUS_AVP84, RADIUS_AVP84_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp84_extraction},
    {RADIUS_AVP85, RADIUS_AVP85_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp85_extraction},
    {RADIUS_AVP86, RADIUS_AVP86_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp86_extraction},
    {RADIUS_AVP87, RADIUS_AVP87_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp87_extraction},
    {RADIUS_AVP88, RADIUS_AVP88_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp88_extraction},
    {RADIUS_AVP89, RADIUS_AVP89_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp89_extraction},
    {RADIUS_AVP90, RADIUS_AVP90_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp90_extraction},
    {RADIUS_AVP91, RADIUS_AVP91_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp91_extraction},
    {RADIUS_AVP92, RADIUS_AVP92_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp92_extraction},
    {RADIUS_AVP93, RADIUS_AVP93_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp93_extraction},
    {RADIUS_AVP94, RADIUS_AVP94_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp94_extraction},
    {RADIUS_AVP95, RADIUS_AVP95_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp95_extraction},
    {RADIUS_AVP96, RADIUS_AVP96_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp96_extraction},
    {RADIUS_AVP97, RADIUS_AVP97_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp97_extraction},
    {RADIUS_AVP98, RADIUS_AVP98_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp98_extraction},
    {RADIUS_AVP99, RADIUS_AVP99_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp99_extraction},
    {RADIUS_AVP100, RADIUS_AVP100_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp100_extraction},
    {RADIUS_AVP101, RADIUS_AVP101_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp101_extraction},
    {RADIUS_AVP102, RADIUS_AVP102_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp102_extraction},
    {RADIUS_AVP224, RADIUS_AVP224_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp224_extraction},
    {RADIUS_AVP225, RADIUS_AVP225_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp225_extraction},
    {RADIUS_AVP226, RADIUS_AVP226_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp226_extraction},
    {RADIUS_AVP227, RADIUS_AVP227_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp227_extraction},
    {RADIUS_AVP228, RADIUS_AVP228_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp228_extraction},
    {RADIUS_AVP229, RADIUS_AVP229_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp229_extraction},
    {RADIUS_AVP230, RADIUS_AVP230_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp230_extraction},
    {RADIUS_AVP231, RADIUS_AVP231_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp231_extraction},
    {RADIUS_AVP232, RADIUS_AVP232_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp232_extraction},
    {RADIUS_AVP233, RADIUS_AVP233_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp233_extraction},
    {RADIUS_AVP234, RADIUS_AVP234_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp234_extraction},
    {RADIUS_AVP235, RADIUS_AVP235_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp235_extraction},
    {RADIUS_AVP236, RADIUS_AVP236_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp236_extraction},
    {RADIUS_AVP237, RADIUS_AVP237_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp237_extraction},
    {RADIUS_AVP238, RADIUS_AVP238_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp238_extraction},
    {RADIUS_AVP239, RADIUS_AVP239_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp239_extraction},
    {RADIUS_AVP240, RADIUS_AVP240_ALIAS, MMT_DATA_POINTER, sizeof (void *), -2, SCOPE_PACKET, radius_avp240_extraction},
};
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_radius_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RADIUS, PROTO_RADIUS_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < RADIUS_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &radius_attributes_metadata[i]);
        }

        mmt_init_classify_me_radius();
        register_session_data_initialization_function(protocol_struct, radius_session_data_init);
        register_session_data_cleanup_function(protocol_struct, radius_session_data_cleanup);
        register_session_data_analysis_function(protocol_struct, radius_session_data_analysis);
        return register_protocol(protocol_struct, PROTO_RADIUS);
    } else {
        return 0;
    }
}
