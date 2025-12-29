#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_dropbox_add_connection(ipacket_t * ipacket, uint8_t due_to_correlation)
{
    mmt_internal_add_connection(ipacket,
            PROTO_DROPBOX,
            due_to_correlation ? MMT_CORRELATED_PROTOCOL : MMT_REAL_PROTOCOL);
}

void mmt_classify_me_dropbox(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* skip marked packets */
    if (packet->detected_protocol_stack[0] != PROTO_DROPBOX) {
        if (packet->tcp_retransmission == 0) {
            /* unused
            const uint8_t *packet_payload = packet->payload;
            */
            uint32_t payload_len = packet->payload_packet_len;

            if (packet->udp != NULL) {
                uint16_t dropbox_port = htons(17500);

                if ((packet->udp->source == dropbox_port)
                        && (packet->udp->dest == dropbox_port)) {
                    if (payload_len > 2) {
                        if (strncmp((const char*)packet->payload, "{\"", 2) == 0) {
                            MMT_LOG(PROTO_DROPBOX, MMT_LOG_DEBUG, "Found dropbox.\n");
                            mmt_int_dropbox_add_connection(ipacket, 0);
                            return;
                        }
                    }
                }
            }

            MMT_LOG(PROTO_DROPBOX, MMT_LOG_DEBUG, "exclude dropbox.\n");
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DROPBOX);
        }
    }
}

//BW: TODO: add dropbox classification for TCP traffic

int mmt_check_dropbox_udp(ipacket_t * ipacket, unsigned index)
{
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* skip marked packets */
        if (packet->detected_protocol_stack[0] != PROTO_DROPBOX) {
            if (packet->tcp_retransmission == 0) {
                /* unused
                const uint8_t *packet_payload = packet->payload;
                */
                uint32_t payload_len = packet->payload_packet_len;

                if (packet->udp != NULL) {
                    uint16_t dropbox_port = htons(17500);

                    if ((packet->udp->source == dropbox_port)
                            && (packet->udp->dest == dropbox_port)) {
                        if (payload_len > 2) {
                            if (strncmp((const char*)packet->payload, "{\"", 2) == 0) {
                                MMT_LOG(PROTO_DROPBOX, MMT_LOG_DEBUG, "Found dropbox.\n");
                                mmt_int_dropbox_add_connection(ipacket, 0);
                                return 1;
                            }
                        }
                    }
                }

                MMT_LOG(PROTO_DROPBOX, MMT_LOG_DEBUG, "exclude dropbox.\n");
                MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_DROPBOX);
            }
        }
    }
    return 0;
}

void mmt_init_classify_me_dropbox()
{
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_DROPBOX);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_DROPBOX);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_dropbox_struct()
{
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_DROPBOX, PROTO_DROPBOX_ALIAS);
    if (protocol_struct != NULL) {
        mmt_init_classify_me_dropbox();
        return register_protocol(protocol_struct, PROTO_DROPBOX);
    } else {
        return 0;
    }
}
