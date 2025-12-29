#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

// struct mmt_mqtt_header_struct {
//   uint8_t msg_type;
//   uint8_t flags;
//   uint16_t datagram_id;
//   uint32_t source_ip;
//   uint16_t source_port;
//   uint8_t * data;
// };

static void mmt_int_mqtt_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MQTT, MMT_REAL_PROTOCOL);
}

int mmt_check_mqtt(ipacket_t * ipacket, unsigned index) {
    // debug("mqtt: mmt_check_mqtt of ipacket: %lu",ipacket->packet_id);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        uint16_t dport;
        dport = ntohs(packet->tcp->dest);

        MMT_LOG(PROTO_MQTT, MMT_LOG_DEBUG, "mqtt tcp start\n");

        /* destination port must be 1883 or 8883 - ports reserved for MQTT http://mqtt.org/faq */
        if (dport == 1883 || dport == 8883) {
            // TODO: Check the header length: > 2 bytes and < 5 bytes
            MMT_LOG(PROTO_MQTT, MMT_LOG_DEBUG, "found mqtt with destination port 139\n");
            mmt_int_mqtt_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_MQTT, MMT_LOG_DEBUG, "exclude mqtt\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MQTT);
    }
    return 0;
}

void mmt_init_classify_me_mqtt() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_MQTT);
}
/*
DIRECT_UNIQUE, DIRECT_GROUP, & BROADCAST DATAGRAM
*/
// int mqtt_classify_next_proto(ipacket_t * ipacket, unsigned index) {
//     int offset = get_packet_offset_at_index(ipacket, index);
//     // uint8_t * mqtt_type = (uint8_t *) & ipacket->data[offset];
//     // printf("Message type: %d\n", *mqtt_type);
//     struct mmt_mqtt_header_struct * mqtt_header = (struct mmt_mqtt_header_struct *) & ipacket->data[offset];
//     classified_proto_t retval;
//     // Classify base on port number
//     if (ntohs(mqtt_header->source_port) == 138 || ntohs(mqtt_header->source_port) == 445) {
//       retval.proto_id = PROTO_SMB;
//     }
//     retval.status = Classified;
//     retval.offset = -1;
//     switch(mqtt_header->msg_type){
//       case NB_MSG_SESSION_MESSAGE:
//         retval.offset = 4;
//         break;
//       case NB_MSG_DIRECT_UNIQUE:
//       case NB_MSG_DIRECT_GROUP:
//       case NB_MSG_BROADCAST_DATAGRAM:
//         retval.offset = 82;
//         break;
//       case NB_MSG_ERROR:
//         retval.offset = 11;
//         break;
//       case NB_MSG_QUERY_REQUEST:
//       case NB_MSG_POSITIVE_QUERY_RESPONSE:
//       case NB_MSG_NEGATIVE_QUERY_RESPONSE:
//         retval.offset = 44;
//         break;
//       default:
//         return 0;
//     }
//     // return 0;
//     return set_classified_proto(ipacket, index + 1, retval);
// }

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mqtt_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MQTT, PROTO_MQTT_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_mqtt();
        // register_classification_function(protocol_struct, mqtt_classify_next_proto);
        return register_protocol(protocol_struct, PROTO_MQTT);
    } else {
        return 0;
    }
}
