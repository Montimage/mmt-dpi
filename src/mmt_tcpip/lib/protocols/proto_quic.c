#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"


/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

#define QUIC_CID_MASK 0x0C      // 0000 1100
#define QUIC_VER_MASK 0x01      // 0000 0001

#define CID_LEN_8 0x0C          // 0000 1100
#define CID_LEN_4 0x08          // 0000 1000
#define CID_LEN_1 0x04          // 0000 0100
#define CID_LEN_0 0x00          // 0000 0000

/*
 * Minimum number of payload bytes the QUIC public-header classifier may touch.
 *
 * The detection path reads, in the worst case:
 *   - payload[0]                                (public flags)
 *   - version path: connect_id() up to 9, then payload[ver_offs..ver_offs+3]
 *                   -> highest index 9 + 3 = 12 (13 bytes).
 *
 * 15 bytes covers every access (it was sized for the version-less
 * sequence-number walk issue #564 removed, and is kept). The
 * UDP-with-payload selection mask only
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

int mmt_check_quic(ipacket_t * ipacket, unsigned index)
{
	struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
	int ver_offs;
    { /* guard evaluated by the classifier walk (issue #561) */
    	struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        if(packet->udp != NULL){
        	uint16_t sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
        	// debug("QUIC: Calculating QUIC over UDP");
        	if((((sport == 80) || (dport == 80) || (sport == 443) || (dport == 443))))
			    {
			     MMT_EXCLUDE_PROTOCOL(flow, PROTO_QUIC);
				// Minimum-length gate: the public-header reads below touch up to
				// QUIC_MIN_PAYLOAD_LEN bytes, but the selection mask only guarantees
				// one payload byte. Bail out on short datagrams before any multi-byte
				// read so a truncated/crafted packet cannot over-read (issue #6, H3).
			     if (packet->payload_packet_len < QUIC_MIN_PAYLOAD_LEN)
			     {
			       return 0;
			     }
				// Issue #564 (F-BUG-303): only a public header that carries a
				// known gQUIC version (Q009..Q025) claims the flow. The
				// version-less branch accepted any datagram whose first byte
				// has the 0xC3 bits clear -- about one random byte in sixteen --
				// and ran ahead of STUN and IETF QUIC on UDP/80 and UDP/443.
			     if (packet->payload[0] & QUIC_VER_MASK)
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
			           // debug("QUIC: Found QUIC");
			       		mmt_int_quic_add_connection(ipacket);
			           return 1;
			         }
			       }
			     }
			   } 
			   else
			   {
			     MMT_EXCLUDE_PROTOCOL(flow, PROTO_QUIC);
			   }
        }
        MMT_EXCLUDE_PROTOCOL(flow, PROTO_QUIC);
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