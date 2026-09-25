#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mqtt_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_MQTT, MMT_REAL_PROTOCOL);
}

/* An MQTT control packet starts with a 2..5-byte fixed header: a packet-type
 * nibble (0 is reserved) and a Remaining Length varint of 1..4 bytes whose
 * last byte has the continuation bit clear. Returns 1 when the payload starts
 * with such a header, 0 otherwise. */
static int mmt_mqtt_fixed_header_ok(const uint8_t *payload, uint32_t len) {
    uint32_t i;
    if (len < 2 || (payload[0] >> 4) == 0)
        return 0;
    for (i = 1; i < len && i <= 4; i++) {
        if ((payload[i] & 0x80) == 0)
            return 1;
    }
    return 0;
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

        /* destination port must be 1883 or 8883 - ports reserved for MQTT http://mqtt.org/faq
         * On 1883 (plain MQTT) the payload must also start with a well-formed
         * fixed header; 8883 carries MQTT over TLS, whose bytes are encrypted. */
        if ((dport == 1883 && mmt_mqtt_fixed_header_ok(packet->payload, packet->payload_packet_len))
                || dport == 8883) {
            MMT_LOG(PROTO_MQTT, MMT_LOG_DEBUG, "found mqtt with destination port %u\n", dport);
            mmt_int_mqtt_add_connection(ipacket);
            return 1;
        }

        MMT_LOG(PROTO_MQTT, MMT_LOG_DEBUG, "exclude mqtt\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_MQTT);
    }
    return 0;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_mqtt_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_MQTT, PROTO_MQTT_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                PROTO_UNKNOWN, PROTO_MQTT);
        return register_protocol(protocol_struct, PROTO_MQTT);
    } else {
        return 0;
    }
}


