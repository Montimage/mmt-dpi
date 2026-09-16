#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

#define QUIC_NO_V_RES_RSV 0xC3  // 1100 0011

#define QUIC_CID_MASK 0x0C      // 0000 1100
#define QUIC_VER_MASK 0x01      // 0000 0001
#define QUIC_SEQ_MASK 0x30      // 0011 0000

#define CID_LEN_8 0x0C          // 0000 1100
#define CID_LEN_4 0x08          // 0000 1000
#define CID_LEN_1 0x04          // 0000 0100
#define CID_LEN_0 0x00          // 0000 0000

#define SEQ_LEN_6 0x30          // 0011 0000
#define SEQ_LEN_4 0x20          // 0010 0000
#define SEQ_LEN_2 0x10          // 0001 0000
#define SEQ_LEN_1 0x00          // 0000 0000

#define SEQ_CONV(ARR) (ARR[0] | ARR[1] | ARR[2] | ARR[3] | ARR[4] | ARR[5] << 8)

/*
 * Minimum number of payload bytes the QUIC public-header classifier may touch.
 *
 * The detection path reads, in the worst case:
 *   - payload[0] and payload[1]                 (public flags + first byte)
 *   - sequence():  connect_id() returns up to 9 (CID_LEN_8 + 1), then the SEQ
 *                  loop reads payload[cid_offs + i] for i in 0..seq_lens-1 with
 *                  seq_lens up to 6 -> highest index 9 + 5 = 14 (15 bytes).
 *   - version path: connect_id() up to 9, then payload[ver_offs..ver_offs+3]
 *                   -> highest index 9 + 3 = 12 (13 bytes).
 *
 * 15 bytes covers every access. The UDP-with-payload selection mask only
 * guarantees a single payload byte, so without this gate a 1..14 byte UDP
 * datagram on port 80/443 over-reads past the captured payload (issue #6, H3).
 */
#define QUIC_MIN_PAYLOAD_LEN 15


#ifdef PROTO_QUIC

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_quic_add_connection(ipacket_t * ipacket) {

    mmt_internal_add_connection(ipacket, PROTO_QUIC, MMT_REAL_PROTOCOL);
}

static int connect_id(const unsigned char pflags)
{
    u_int cid_len;

        // Check CID length.
        switch (pflags & QUIC_CID_MASK)
        {
           case CID_LEN_8: cid_len = 8; break;
           case CID_LEN_4: cid_len = 4; break;
           case CID_LEN_1: cid_len = 1; break;
           case CID_LEN_0: cid_len = 0; break;
           default:
               return -1;

        }
        // Return offset.
        return cid_len + 1;
}

static int sequence(const unsigned char *payload, int payload_len)
{
    unsigned char conv[6] = {0};
    u_int seq_value = -1;
    int seq_lens;
    int cid_offs;
    int i;

        // Need at least the public-flags byte to derive SEQ/CID lengths.
        if (payload_len < 1)
            return -1;

        // Search SEQ bytes length.
        switch (payload[0] & QUIC_SEQ_MASK)
        {
           case SEQ_LEN_6: seq_lens = 6; break;
           case SEQ_LEN_4: seq_lens = 4; break;
           case SEQ_LEN_2: seq_lens = 2; break;
           case SEQ_LEN_1: seq_lens = 1; break;
           default:
               return -1;
        }
        // Retrieve SEQ offset.
        cid_offs = connect_id(payload[0]);

        // Re-check the remaining length before walking the SEQ bytes: the loop
        // reads payload[cid_offs .. cid_offs + seq_lens - 1], so that highest
        // index must stay inside the captured payload (issue #6, H3).
        if (cid_offs >= 0 && seq_lens > 0 && cid_offs + seq_lens <= payload_len)
        {
            for (i = 0; i < seq_lens; i++)
                conv[i] = payload[cid_offs + i];

        seq_value = SEQ_CONV(conv);
        }

        // Return SEQ dec value;
        return seq_value;
}

int mmt_check_quic(ipacket_t * ipacket, unsigned index)
{
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	int ver_offs;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {
    	struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        if(packet->udp != NULL){
        	uint16_t sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
        	// debug("QUIC: Calculating QUIC over UDP");
        	if((((sport == 80) || (dport == 80) || (sport == 443) || (dport == 443))))
			    {
			     MMT_LOG(PROTO_QUIC,MMT_LOG_DEBUG, "exclude quic.\n");
			     MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QUIC);
				// Minimum-length gate: the public-header reads below touch up to
				// QUIC_MIN_PAYLOAD_LEN bytes, but the selection mask only guarantees
				// one payload byte. Bail out on short datagrams before any multi-byte
				// read so a truncated/crafted packet cannot over-read (issue #6, H3).
			     if (packet->payload_packet_len < QUIC_MIN_PAYLOAD_LEN)
			     {
			       MMT_LOG(PROTO_QUIC,MMT_LOG_DEBUG, "exclude quic.\n");
			       return 0;
			     }
				// Settings without version. First check if PUBLIC FLAGS & SEQ bytes are 0x0. SEQ must be 1 at least.
			     if ((packet->payload[0] == 0x00 && packet->payload[1] != 0x00) || ((packet->payload[0] & QUIC_NO_V_RES_RSV) == 0))
			     {
			       if (sequence(packet->payload, packet->payload_packet_len) < 1)
			       {
			         
			         MMT_LOG(PROTO_QUIC,MMT_LOG_DEBUG, "exclude quic.\n");
			         MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QUIC);
			       }

			       MMT_LOG(PROTO_QUIC,MMT_LOG_DEBUG, "found quic.\n");
			       // debug("QUIC: Found QUIC");
			       mmt_int_quic_add_connection(ipacket);
                   return 1;
			     }

				// Check if version, than the CID length.
			     else if (packet->payload[0] & QUIC_VER_MASK)
			     {
				  // Skip CID length.
			       ver_offs = connect_id(packet->payload[0]);

			       // Re-check remaining length: the version match below reads
			       // payload[ver_offs .. ver_offs + 3], so those 4 bytes must stay
			       // inside the captured payload (issue #6, H3).
			       if (ver_offs >= 0 && ver_offs + 4 <= packet->payload_packet_len)
			       {
			         unsigned char vers[] = {packet->payload[ver_offs], packet->payload[ver_offs + 1],
			          packet->payload[ver_offs + 2], packet->payload[ver_offs + 3]};
			          
				    // Version Match.
			          if ((vers[0] == 'Q' && vers[1] == '0') &&
			            ((vers[2] == '2' && (vers[3] == '5' || vers[3] == '4' || vers[3] == '3' || vers[3] == '2' ||
			             vers[3] == '1' || vers[3] == '0')) ||
			            (vers[2] == '1' && (vers[3] == '9' || vers[3] == '8' || vers[3] == '7' || vers[3] == '6' ||
			             vers[3] == '5' || vers[3] == '4' || vers[3] == '3' || vers[3] == '2' ||
			             vers[3] == '1' || vers[3] == '0')) ||
			            (vers[2] == '0' && vers[3] == '9')))
			           
			          {
			           MMT_LOG(PROTO_QUIC,MMT_LOG_DEBUG, "found quic.\n");
			           // debug("QUIC: Found QUIC");
			       		mmt_int_quic_add_connection(ipacket);
			           return 1;
			         }
			       }
			     }
			   } 
			   else
			   {
			     MMT_LOG(PROTO_QUIC,MMT_LOG_DEBUG, "exclude quic.\n");
			     MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QUIC);
			   }
        }
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_QUIC);
        MMT_LOG(PROTO_QUIC, MMT_LOG_DEBUG, "exclude quic.\n");
        return 0;

    }
    return 0;
}


int init_proto_quic_struct() {
    
    // debug("QUIC: init_proto_quic_struct");

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_QUIC, PROTO_QUIC_ALIAS);
    if (protocol_struct != NULL) {
        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask, MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                PROTO_QUIC, PROTO_QUIC);

        return register_protocol(protocol_struct, PROTO_QUIC);
    } else {
        return 0;
    }
}
#endif