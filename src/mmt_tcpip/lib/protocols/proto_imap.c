#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_mail_imap_add_connection(ipacket_t * ipacket)
{
	mmt_internal_add_connection(ipacket, PROTO_IMAP, MMT_REAL_PROTOCOL);
}

void mmt_classify_me_imap(ipacket_t * ipacket, unsigned index)
{
   struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
   struct mmt_internal_tcpip_session_struct *flow = packet->flow;

	uint16_t i = 0;
	uint16_t space_pos = 0;
	uint16_t command_start = 0;
	uint8_t saw_command = 0;
	/* unused
	const uint8_t *command = 0;
	*/

	MMT_LOG(PROTO_IMAP, MMT_LOG_DEBUG, "search IMAP.\n");



	if (packet->payload_packet_len >= 4 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
		// the DONE command appears without a tag
		if (packet->payload_packet_len == 6 && ((packet->payload[0] == 'D' || packet->payload[0] == 'd')
												&& (packet->payload[1] == 'O' || packet->payload[1] == 'o')
												&& (packet->payload[2] == 'N' || packet->payload[2] == 'n')
												&& (packet->payload[3] == 'E' || packet->payload[3] == 'e'))) {
			flow->l4.tcp.mail_imap_stage += 1;
			saw_command = 1;
		} else {

			if (flow->l4.tcp.mail_imap_stage < 4) {
				// search for the first space character (end of the tag)
				while (i < 20 && i < packet->payload_packet_len) {
					if (i > 0 && packet->payload[i] == ' ') {
						space_pos = i;
						break;
					}
					if (!((packet->payload[i] >= 'a' && packet->payload[i] <= 'z') ||
						  (packet->payload[i] >= 'A' && packet->payload[i] <= 'Z') ||
						  (packet->payload[i] >= '0' && packet->payload[i] <= '9') || packet->payload[i] == '*')) {
						goto imap_excluded;
					}
					i++;
				}
				if (space_pos == 0 || space_pos == (packet->payload_packet_len - 1)) {
					goto imap_excluded;
				}
				// now walk over a possible mail number to the next space
				i++;
				if (i < packet->payload_packet_len && (packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
					while (i < 20 && i < packet->payload_packet_len) {
						if (i > 0 && packet->payload[i] == ' ') {
							space_pos = i;
							break;
						}
						if (!(packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
							goto imap_excluded;
						}
						i++;
					}
					if (space_pos == 0 || space_pos == (packet->payload_packet_len - 1)) {
						goto imap_excluded;
					}
				}
				command_start = space_pos + 1;
				/* unused
				command = &(packet->payload[command_start]);
				*/
			} else {
				command_start = 0;
				/* unused
				command = &(packet->payload[command_start]);
				*/
			}

			if ((command_start + 3) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'O' || packet->payload[command_start] == 'o')
					&& (packet->payload[command_start + 1] == 'K' || packet->payload[command_start + 1] == 'k')
					&& packet->payload[command_start + 2] == ' ') {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'U' || packet->payload[command_start] == 'u')
						   && (packet->payload[command_start + 1] == 'I' || packet->payload[command_start + 1] == 'i')
						   && (packet->payload[command_start + 2] == 'D' || packet->payload[command_start + 2] == 'd')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 10) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'C' || packet->payload[command_start] == 'c')
					&& (packet->payload[command_start + 1] == 'A' || packet->payload[command_start + 1] == 'a')
					&& (packet->payload[command_start + 2] == 'P' || packet->payload[command_start + 2] == 'p')
					&& (packet->payload[command_start + 3] == 'A' || packet->payload[command_start + 3] == 'a')
					&& (packet->payload[command_start + 4] == 'B' || packet->payload[command_start + 4] == 'b')
					&& (packet->payload[command_start + 5] == 'I' || packet->payload[command_start + 5] == 'i')
					&& (packet->payload[command_start + 6] == 'L' || packet->payload[command_start + 6] == 'l')
					&& (packet->payload[command_start + 7] == 'I' || packet->payload[command_start + 7] == 'i')
					&& (packet->payload[command_start + 8] == 'T' || packet->payload[command_start + 8] == 't')
					&& (packet->payload[command_start + 9] == 'Y' || packet->payload[command_start + 9] == 'y')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 8) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'S' || packet->payload[command_start] == 's')
					&& (packet->payload[command_start + 1] == 'T' || packet->payload[command_start + 1] == 't')
					&& (packet->payload[command_start + 2] == 'A' || packet->payload[command_start + 2] == 'a')
					&& (packet->payload[command_start + 3] == 'R' || packet->payload[command_start + 3] == 'r')
					&& (packet->payload[command_start + 4] == 'T' || packet->payload[command_start + 4] == 't')
					&& (packet->payload[command_start + 5] == 'T' || packet->payload[command_start + 5] == 't')
					&& (packet->payload[command_start + 6] == 'L' || packet->payload[command_start + 6] == 'l')
					&& (packet->payload[command_start + 7] == 'S' || packet->payload[command_start + 7] == 's')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 5) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'L' || packet->payload[command_start] == 'l')
					&& (packet->payload[command_start + 1] == 'O' || packet->payload[command_start + 1] == 'o')
					&& (packet->payload[command_start + 2] == 'G' || packet->payload[command_start + 2] == 'g')
					&& (packet->payload[command_start + 3] == 'I' || packet->payload[command_start + 3] == 'i')
					&& (packet->payload[command_start + 4] == 'N' || packet->payload[command_start + 4] == 'n')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'F' || packet->payload[command_start] == 'f')
						   && (packet->payload[command_start + 1] == 'E' || packet->payload[command_start + 1] == 'e')
						   && (packet->payload[command_start + 2] == 'T' || packet->payload[command_start + 2] == 't')
						   && (packet->payload[command_start + 3] == 'C' || packet->payload[command_start + 3] == 'c')
						   && (packet->payload[command_start + 4] == 'H' || packet->payload[command_start + 4] == 'h')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'F' || packet->payload[command_start] == 'f')
						   && (packet->payload[command_start + 1] == 'L' || packet->payload[command_start + 1] == 'l')
						   && (packet->payload[command_start + 2] == 'A' || packet->payload[command_start + 2] == 'a')
						   && (packet->payload[command_start + 3] == 'G' || packet->payload[command_start + 3] == 'g')
						   && (packet->payload[command_start + 4] == 'S' || packet->payload[command_start + 4] == 's')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'C' || packet->payload[command_start] == 'c')
						   && (packet->payload[command_start + 1] == 'H' || packet->payload[command_start + 1] == 'h')
						   && (packet->payload[command_start + 2] == 'E' || packet->payload[command_start + 2] == 'e')
						   && (packet->payload[command_start + 3] == 'C' || packet->payload[command_start + 3] == 'c')
						   && (packet->payload[command_start + 4] == 'K' || packet->payload[command_start + 4] == 'k')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'S' || packet->payload[command_start] == 's')
						   && (packet->payload[command_start + 1] == 'T' || packet->payload[command_start + 1] == 't')
						   && (packet->payload[command_start + 2] == 'O' || packet->payload[command_start + 2] == 'o')
						   && (packet->payload[command_start + 3] == 'R' || packet->payload[command_start + 3] == 'r')
						   && (packet->payload[command_start + 4] == 'E' || packet->payload[command_start + 4] == 'e')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 12) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'A' || packet->payload[command_start] == 'a')
					&& (packet->payload[command_start + 1] == 'U' || packet->payload[command_start + 1] == 'u')
					&& (packet->payload[command_start + 2] == 'T' || packet->payload[command_start + 2] == 't')
					&& (packet->payload[command_start + 3] == 'H' || packet->payload[command_start + 3] == 'h')
					&& (packet->payload[command_start + 4] == 'E' || packet->payload[command_start + 4] == 'e')
					&& (packet->payload[command_start + 5] == 'N' || packet->payload[command_start + 5] == 'n')
					&& (packet->payload[command_start + 6] == 'T' || packet->payload[command_start + 6] == 't')
					&& (packet->payload[command_start + 7] == 'I' || packet->payload[command_start + 7] == 'i')
					&& (packet->payload[command_start + 8] == 'C' || packet->payload[command_start + 8] == 'c')
					&& (packet->payload[command_start + 9] == 'A' || packet->payload[command_start + 9] == 'a')
					&& (packet->payload[command_start + 10] == 'T' || packet->payload[command_start + 10] == 't')
					&& (packet->payload[command_start + 11] == 'E' || packet->payload[command_start + 11] == 'e')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 9) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'N' || packet->payload[command_start] == 'n')
					&& (packet->payload[command_start + 1] == 'A' || packet->payload[command_start + 1] == 'a')
					&& (packet->payload[command_start + 2] == 'M' || packet->payload[command_start + 2] == 'm')
					&& (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')
					&& (packet->payload[command_start + 4] == 'S' || packet->payload[command_start + 4] == 's')
					&& (packet->payload[command_start + 5] == 'P' || packet->payload[command_start + 5] == 'p')
					&& (packet->payload[command_start + 6] == 'A' || packet->payload[command_start + 6] == 'a')
					&& (packet->payload[command_start + 7] == 'C' || packet->payload[command_start + 7] == 'c')
					&& (packet->payload[command_start + 8] == 'E' || packet->payload[command_start + 8] == 'e')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 4) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'L' || packet->payload[command_start] == 'l')
					&& (packet->payload[command_start + 1] == 'S' || packet->payload[command_start + 1] == 's')
					&& (packet->payload[command_start + 2] == 'U' || packet->payload[command_start + 2] == 'u')
					&& (packet->payload[command_start + 3] == 'B' || packet->payload[command_start + 3] == 'b')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'L' || packet->payload[command_start] == 'l')
						   && (packet->payload[command_start + 1] == 'I' || packet->payload[command_start + 1] == 'i')
						   && (packet->payload[command_start + 2] == 'S' || packet->payload[command_start + 2] == 's')
						   && (packet->payload[command_start + 3] == 'T' || packet->payload[command_start + 3] == 't')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'N' || packet->payload[command_start] == 'n')
						   && (packet->payload[command_start + 1] == 'O' || packet->payload[command_start + 1] == 'o')
						   && (packet->payload[command_start + 2] == 'O' || packet->payload[command_start + 2] == 'o')
						   && (packet->payload[command_start + 3] == 'P' || packet->payload[command_start + 3] == 'p')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'I' || packet->payload[command_start] == 'i')
						   && (packet->payload[command_start + 1] == 'D' || packet->payload[command_start + 1] == 'd')
						   && (packet->payload[command_start + 2] == 'L' || packet->payload[command_start + 2] == 'l')
						   && (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 6) < packet->payload_packet_len) {
				if ((packet->payload[command_start] == 'S' || packet->payload[command_start] == 's')
					&& (packet->payload[command_start + 1] == 'E' || packet->payload[command_start + 1] == 'e')
					&& (packet->payload[command_start + 2] == 'L' || packet->payload[command_start + 2] == 'l')
					&& (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')
					&& (packet->payload[command_start + 4] == 'C' || packet->payload[command_start + 4] == 'c')
					&& (packet->payload[command_start + 5] == 'T' || packet->payload[command_start + 5] == 't')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'E' || packet->payload[command_start] == 'e')
						   && (packet->payload[command_start + 1] == 'X' || packet->payload[command_start + 1] == 'x')
						   && (packet->payload[command_start + 2] == 'I' || packet->payload[command_start + 2] == 'i')
						   && (packet->payload[command_start + 3] == 'S' || packet->payload[command_start + 3] == 's')
						   && (packet->payload[command_start + 4] == 'T' || packet->payload[command_start + 4] == 't')
						   && (packet->payload[command_start + 5] == 'S' || packet->payload[command_start + 5] == 's')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				} else if ((packet->payload[command_start] == 'A' || packet->payload[command_start] == 'a')
						   && (packet->payload[command_start + 1] == 'P' || packet->payload[command_start + 1] == 'p')
						   && (packet->payload[command_start + 2] == 'P' || packet->payload[command_start + 2] == 'p')
						   && (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')
						   && (packet->payload[command_start + 4] == 'N' || packet->payload[command_start + 4] == 'n')
						   && (packet->payload[command_start + 5] == 'D' || packet->payload[command_start + 5] == 'd')) {
					flow->l4.tcp.mail_imap_stage += 1;
					saw_command = 1;
				}
			}

		}

		if (saw_command == 1) {
			if (flow->l4.tcp.mail_imap_stage == 3 || flow->l4.tcp.mail_imap_stage == 5) {
				MMT_LOG(PROTO_IMAP, MMT_LOG_DEBUG, "mail imap identified\n");
				mmt_int_mail_imap_add_connection(ipacket);
				return;
			}
		}
	}

	if (packet->payload_packet_len > 1 && packet->payload[packet->payload_packet_len - 1] == ' ') {
		MMT_LOG(PROTO_IMAP, MMT_LOG_DEBUG,
				"maybe a split imap command -> need next packet and imap_stage is set to 4.\n");
		flow->l4.tcp.mail_imap_stage = 4;
		return;
	}

  imap_excluded:

	// skip over possible authentication hashes etc. that cannot be identified as imap commands or responses
	// if the packet count is low enough and at least one command or response was seen before
	if ((packet->payload_packet_len >= 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
		&& ipacket->session->data_packet_count < 6 && flow->l4.tcp.mail_imap_stage >= 1) {
		MMT_LOG(PROTO_IMAP, MMT_LOG_DEBUG,
				"no imap command or response but packet count < 6 and imap stage >= 1 -> skip\n");
		return;
	}

	MMT_LOG(PROTO_IMAP, MMT_LOG_DEBUG, "exclude IMAP.\n");
	MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_IMAP);
}

int mmt_check_imap(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_classify_me_imap(ipacket, index);
    }
    return 4;
}

void mmt_init_classify_me_imap() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_IMAP);
}
/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_imap_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IMAP, PROTO_IMAP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_imap();
        
        return register_protocol(protocol_struct, PROTO_IMAP);
    } else {
        return 0;
    }
}


