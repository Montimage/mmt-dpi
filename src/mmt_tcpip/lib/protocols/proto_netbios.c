#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/*
http://www.networksorcery.com/enp/rfc/rfc1002.txt

DIRECT_UNIQUE, DIRECT_GROUP, & BROADCAST DATAGRAM
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           SOURCE_IP                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          SOURCE_PORT          |          DGM_LENGTH           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         PACKET_OFFSET         |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   |                                                               |
   /                          SOURCE_NAME                          /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                       DESTINATION_NAME                        /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                           USER_DATA                           /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

DATAGRAM ERROR PACKET
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           SOURCE_IP                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          SOURCE_PORT          |  ERROR_CODE   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
ERROR_CODE values (in hexidecimal):

           82 -  DESTINATION NAME NOT PRESENT
           83 -  INVALID SOURCE NAME FORMAT
           84 -  INVALID DESTINATION NAME FORMAT

DATAGRAM QUERY REQUEST
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           SOURCE_IP                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          SOURCE_PORT          |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   |                                                               |
   /                       DESTINATION_NAME                        /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

DATAGRAM POSITIVE AND NEGATIVE QUERY RESPONSE
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           SOURCE_IP                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          SOURCE_PORT          |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   |                                                               |
   /                       DESTINATION_NAME                        /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

MSG_TYPE values (in hexidecimal):

           10 -  DIRECT_UNIQUE DATAGRAM
           11 -  DIRECT_GROUP DATAGRAM
           12 -  BROADCAST DATAGRAM
           13 -  DATAGRAM ERROR
           14 -  DATAGRAM QUERY REQUEST
           15 -  DATAGRAM POSITIVE QUERY RESPONSE
           16 -  DATAGRAM NEGATIVE QUERY RESPONSE

*/

#define NB_MSG_DIRECT_UNIQUE 16
#define NB_MSG_DIRECT_GROUP 17
#define NB_MSG_BROADCAST_DATAGRAM 18
#define NB_MSG_ERROR 19
#define NB_MSG_QUERY_REQUEST 20
#define NB_MSG_POSITIVE_QUERY_RESPONSE 21
#define NB_MSG_NEGATIVE_QUERY_RESPONSE 22

struct mmt_netbios_header_struct {
  uint8_t msg_type;
  uint8_t flags;
  uint16_t datagram_id;
  uint32_t source_ip;
  uint16_t source_port;
  uint8_t * data;
};

static void mmt_int_netbios_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_NETBIOS, MMT_REAL_PROTOCOL);
}

int mmt_check_netbios_tcp(ipacket_t * ipacket, unsigned index) {
    // debug("NETBIOS: mmt_check_netbios_tcp of ipacket: %lu",ipacket->packet_id);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint16_t dport;
        dport = ntohs(packet->tcp->dest);

        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG, "netbios tcp start\n");

        /* destination port must be 139 */
        if (dport == 139) {
            MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG, "found netbios with destination port 139\n");
            /* payload_packet_len must be 72 */
            if (packet->payload_packet_len == 72) {
                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG, "found netbios with payload_packen_len = 72. \n");

                if (packet->payload[0] == 0x81 && packet->payload[1] == 0 && ntohs(get_u16(packet->payload, 2)) == 68) {
                    MMT_LOG(PROTO_NETBIOS,
                            MMT_LOG_DEBUG,
                            "found netbios with session request = 81, flags=0 and length od following bytes = 68. \n");

                    mmt_int_netbios_add_connection(ipacket);
                    return 1;
                }
            }
        }

        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG, "exclude netbios\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_NETBIOS);
    }
    return 0;
}

int mmt_check_netbios_udp(ipacket_t * ipacket, unsigned index) {
    // debug("NETBIOS: mmt_check_netbios_udp of ipacket: %lu",ipacket->packet_id);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct * flow = packet->flow;

        uint16_t dport;
        dport = ntohs(packet->udp->dest);

        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG, "netbios udp start\n");

        /*check standard NETBIOS over udp to port 137 */
        if (dport == 137 && packet->payload_packet_len >= 50) {
            MMT_LOG(PROTO_NETBIOS,
                    MMT_LOG_DEBUG, "found netbios port 137 and payload_packet_len 50\n");

            if (ntohs(get_u16(packet->payload, 2)) == 0 &&
                    ntohs(get_u16(packet->payload, 4)) == 1 &&
                    ntohs(get_u16(packet->payload, 6)) == 0 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 0) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG, "found netbios with questions = 1 and answers = 0, authority = 0  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }
            if (packet->payload[2] == 0x80 &&
                    ntohs(get_u16(packet->payload, 4)) == 1 &&
                    ntohs(get_u16(packet->payload, 6)) == 0 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 1) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG, "found netbios with questions = 1 and answers, authority, additional = 0  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }
            if (ntohs(get_u16(packet->payload, 2)) == 0x4000 &&
                    ntohs(get_u16(packet->payload, 4)) == 1 &&
                    ntohs(get_u16(packet->payload, 6)) == 0 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 1) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG, "found netbios with questions = 1 and answers = 0, authority = 0  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }
            if (ntohs(get_u16(packet->payload, 2)) == 0x8400 &&
                    ntohs(get_u16(packet->payload, 4)) == 0 &&
                    ntohs(get_u16(packet->payload, 6)) == 1 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 0) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG,
                        "found netbios with flag 8400 questions = 0 and answers = 1, authority, additional = 0  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }
            if (ntohs(get_u16(packet->payload, 2)) == 0x8500 &&
                    ntohs(get_u16(packet->payload, 4)) == 0 &&
                    ntohs(get_u16(packet->payload, 6)) == 1 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 0) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG,
                        "found netbios with flag 8500 questions = 0 and answers = 1, authority, additional = 0  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }
            if (ntohs(get_u16(packet->payload, 2)) == 0x2910 &&
                    ntohs(get_u16(packet->payload, 4)) == 1 &&
                    ntohs(get_u16(packet->payload, 6)) == 0 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 1) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG,
                        "found netbios with flag 2910, questions = 1 and answers, authority=0, additional = 1  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }
            if (ntohs(get_u16(packet->payload, 2)) == 0xAD86 &&
                    ntohs(get_u16(packet->payload, 4)) == 0 &&
                    ntohs(get_u16(packet->payload, 6)) == 1 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 0) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG,
                        "found netbios with flag ad86 questions = 0 and answers = 1, authority, additional = 0  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }
            if (ntohs(get_u16(packet->payload, 2)) == 0x0110 &&
                    ntohs(get_u16(packet->payload, 4)) == 1 &&
                    ntohs(get_u16(packet->payload, 6)) == 0 &&
                    ntohs(get_u16(packet->payload, 8)) == 0 && ntohs(get_u16(packet->payload, 10)) == 0) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG,
                        "found netbios with flag 0110 questions = 1 and answers = 0, authority, additional = 0  \n");

                mmt_int_netbios_add_connection(ipacket);
                return 1;
            }

            if ((ntohs(get_u16(packet->payload, 2)) & 0xf800) == 0) {

                MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG, "possible netbios name query request\n");

                if (get_u16(packet->payload, 4) == htons(1) &&
                        get_u16(packet->payload, 6) == 0 &&
                        get_u16(packet->payload, 8) == 0 && get_u16(packet->payload, 10) == 0) {

                    /* name is encoded as described in rfc883 */
                    uint8_t name_length = packet->payload[12];

                    MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                            "possible netbios name query request, one question\n");

                    if (packet->payload_packet_len == 12 + 1 + name_length + 1 + 2 + 2) {

                        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                "possible netbios name query request, length matches\n");

                        /* null terminated? */
                        if (packet->payload[12 + name_length + 1] == 0 &&
                                get_u16(packet->payload, 12 + name_length + 2) == htons(0x0020) &&
                                get_u16(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

                            MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                    "found netbios name query request\n");
                            mmt_int_netbios_add_connection(ipacket);
                            return 1;
                        }
                    }
                }
            } else if ((ntohs(get_u16(packet->payload, 2)) & 0xf800) == 0x8000) {

                MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                        "possible netbios name query response\n");

                if (get_u16(packet->payload, 4) == 0 &&
                        get_u16(packet->payload, 6) == htons(1) &&
                        get_u16(packet->payload, 8) == 0 && get_u16(packet->payload, 10) == 0) {

                    /* name is encoded as described in rfc883 */
                    uint8_t name_length = packet->payload[12];

                    MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                            "possible netbios positive name query response, one answer\n");

                    if (packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

                        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                "possible netbios name query response, length matches\n");

                        /* null terminated? */
                        if (packet->payload[12 + name_length + 1] == 0 &&
                                get_u16(packet->payload, 12 + name_length + 2) == htons(0x0020) &&
                                get_u16(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

                            MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                    "found netbios name query response\n");
                            mmt_int_netbios_add_connection(ipacket);
                            return 1;
                        }
                    }
                } else if (get_u16(packet->payload, 4) == 0 &&
                        get_u16(packet->payload, 6) == 0 &&
                        get_u16(packet->payload, 8) == 0 && get_u16(packet->payload, 10) == 0) {

                    /* name is encoded as described in rfc883 */
                    uint8_t name_length = packet->payload[12];

                    MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                            "possible netbios negative name query response, one answer\n");

                    if (packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

                        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                "possible netbios name query response, length matches\n");

                        /* null terminated? */
                        if (packet->payload[12 + name_length + 1] == 0 &&
                                get_u16(packet->payload, 12 + name_length + 2) == htons(0x000A) &&
                                get_u16(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

                            MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                    "found netbios name query response\n");
                            mmt_int_netbios_add_connection(ipacket);
                            return 1;
                        }
                    }
                } else if (get_u16(packet->payload, 4) == 0 &&
                        get_u16(packet->payload, 6) == 0 &&
                        get_u16(packet->payload, 8) == htons(1) && get_u16(packet->payload, 10) == htons(1)) {

                    /* name is encoded as described in rfc883 */
                    uint8_t name_length = packet->payload[12];

                    MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                            "possible netbios redirect name query response, one answer\n");

                    if (packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

                        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                "possible netbios name query response, length matches\n");

                        /* null terminated? */
                        if (packet->payload[12 + name_length + 1] == 0 &&
                                get_u16(packet->payload, 12 + name_length + 2) == htons(0x0002) &&
                                get_u16(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

                            MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG,
                                    "found netbios name query response\n");
                            mmt_int_netbios_add_connection(ipacket);
                            return 1;
                        }
                    }
                }
            }
            /* TODO: extend according to rfc1002 */
        }

        /*check standard NETBIOS over udp to port 138 */
        /*netbios header token from http://www.protocolbase.net/protocols/protocol_NBDGM.php */
        if (dport == 138 &&
                packet->payload_packet_len >= 14 &&
                ntohs(get_u16(packet->payload, 10)) == packet->payload_packet_len - 14) {

            MMT_LOG(PROTO_NETBIOS,
                    MMT_LOG_DEBUG, "found netbios port 138 and payload length >= 112 \n");


            if (packet->payload[0] >= 0x11 && packet->payload[0] <= 0x16) {

                MMT_LOG(PROTO_NETBIOS,
                        MMT_LOG_DEBUG, "found netbios with MSG-type 0x11,0x12,0x13,0x14,0x15 or 0x16\n");

                if (ntohl(get_u32(packet->payload, 4)) == ntohl(packet->iph->saddr)) {
                    MMT_LOG(PROTO_NETBIOS,
                            MMT_LOG_DEBUG, "found netbios with checked ip-address.\n");

                    mmt_int_netbios_add_connection(ipacket);
                    return 1;
                }
            }
        }

        MMT_LOG(PROTO_NETBIOS, MMT_LOG_DEBUG, "exclude netbios\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_NETBIOS);
    }
    return 0;
}

void mmt_init_classify_me_netbios() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_NETBIOS);
}
/*
DIRECT_UNIQUE, DIRECT_GROUP, & BROADCAST DATAGRAM
*/
int netbios_classify_next_proto(ipacket_t * ipacket, unsigned index) {
    int offset = get_packet_offset_at_index(ipacket, index);
    // uint8_t * netbios_type = (uint8_t *) & ipacket->data[offset];
    // printf("Message type: %d\n", *netbios_type);
    struct mmt_netbios_header_struct * netbios_header = (struct mmt_netbios_header_struct *) & ipacket->data[offset];
    classified_proto_t retval;
    // Classify base on port number
    if (ntohs(netbios_header->source_port) == 138) {
      retval.proto_id = PROTO_SMB;
    }
    retval.status = Classified;
    retval.offset = -1;
    printf("Message type: %d\n", netbios_header->msg_type);
    switch(netbios_header->msg_type){
      case NB_MSG_DIRECT_UNIQUE:
      case NB_MSG_DIRECT_GROUP:
      case NB_MSG_BROADCAST_DATAGRAM:
        retval.offset = 64;
        break;
      case NB_MSG_ERROR:
        retval.offset = 11;
        break;
      case NB_MSG_QUERY_REQUEST:
      case NB_MSG_POSITIVE_QUERY_RESPONSE:
      case NB_MSG_NEGATIVE_QUERY_RESPONSE:
        retval.offset = 44;
        break;
      default:
        return 0;
    }
    // return 0;
    return set_classified_proto(ipacket, index + 1, retval);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_netbios_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_NETBIOS, PROTO_NETBIOS_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_netbios();
        register_classification_function(protocol_struct, netbios_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_NETBIOS);
    } else {
        return 0;
    }
}


