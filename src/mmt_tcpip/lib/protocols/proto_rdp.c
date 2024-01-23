#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include <inttypes.h>


/*
    TPKT HEADER: (4 bytes)
        version -> 3
        reserved -> 0
        length -> >7
    +--------+--------+----------------+-----------....---------------+
    |version |reserved| packet length  |             TPDU             |
    +----------------------------------------------....---------------+
    <8 bits> <8 bits> <   16 bits    > <       variable length       >


    X.224CRQ: (7 bytes)

    1               2               3      4               5         6               7
    LI            CR CDT             DST-REF                 SRC-REF            CLASS OPTION
                1110 xxxx       0000 0000 0000 0000
    
    a) CR – Connection request code: 1110. Bits 8 to 5 of octet 2.
    b) CDT – Initial credit allocation (set to 0000 in classes 0 and 1 when specified as preferred class). Bits 4 to
        1 of octet 2.
    c) DST-REF – Set to zero.
    d) SRC-REF – Reference selected by the transport entity initiating the CR-TPDU to identify the requested
        transport connection.
    e) CLASS OPTION – Bits 8 to 5 of octet 7 define the preferred transport protocol class to be operated over
        the requested transport connection. When operating over CONS, this field shall take one of the following
        values:
            – 0000 Class 0;
            – 0001 Class 1;
            – 0010 Class 2;
            – 0011 Class 3;
            – 0100 Class 4.
        When operating over CLNS, this field shall take the value 0100 to indicate class 4.
        Bits 4 to 1 of octet 7 define options to be used on the requested transport connection as follows:
            bit 4: 0 always
            bit 3: 0 always
            bit 2: 0 | 1
            bit 1: 0 | 1

*/

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
/* BW: Remote Desktop protocol */
static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

static void mmt_int_rdp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_RDP, MMT_REAL_PROTOCOL);
}


int mmt_check_rdp(ipacket_t * ipacket, unsigned index) {
    const uint8_t *pdata;
    uint16_t tpkt_length;
    //
    // [ETH - IP -] TCP -- PAYLOAD
    //   we are here -----^
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        
        struct mmt_internal_tcpip_session_struct *flow = packet->flow;
        uint32_t payload_len = ipacket->internal_packet->payload_packet_len;

        if (payload_len == 0) {
            printf("length=0\n");
            goto _not_found_rdp;
        }
        //for TPKT header, we should check other header types
        pdata = packet->payload;
        //1. first byte must be 00000011: T-Rect ;;;
        if( pdata[0] != 0b00000011 )
           goto _not_found_rdp;

        //2. reserve should be 0
        if( pdata[1] != 0 )
            goto _not_found_rdp;
        //3. TPKT length:
        tpkt_length = ntohs( *(uint16_t *) &pdata[2] );
        if( !(tpkt_length > 7) )
          goto _not_found_rdp;
          

        //X.224CRQ checks
        //The length is indicated by a binary number, with a maximum value of 254 (1111 1110)
        if(!(pdata[4]<254)){
            printf("lenght too big");
            goto _not_found_rdp;
        }
            
        uint8_t cr = (pdata[5] >> 4) & 0x0F;
        uint8_t cdt = (pdata[5]) & 0x0F;
        // printf("cr e' %" PRIu8 " e cdt e'%" PRIu8"\n", cr, cdt);
        if(cr != 13){
            printf("Wrong CR\n");
            goto _not_found_rdp;
        }
                
        if(!(cdt == 0 || cdt == 1)){
            printf("Wrong CDT\n");
            goto _not_found_rdp;
        }
        uint16_t dst_ref = ntohs( *(uint16_t *) &pdata[6] );
        if (dst_ref!=0){
            printf("dst_ref wrong\n");
            goto _not_found_rdp;
        }
            
        uint8_t class_option_msb = (pdata[7] >> 4) & 0x0F;
        uint8_t class_option_lsb = (pdata[7]) & 0x0F;
        
        if (!(class_option_msb<4)){
            printf("class_option_msb wrong\n");
            goto _not_found_rdp;
        }
            
        if (!(class_option_lsb<3)){
            printf("class_option_lsb wrong\n");
            goto _not_found_rdp;
        }
        if (ntohs(packet->tcp->dest) != 3389 && ntohs(packet->tcp->source) != 3389)
            goto _not_found_rdp;
        printf("packet id = %"PRIu64"  TPKT length = %d\n", ipacket->packet_id, tpkt_length );
        printf("RDP detected\n");    
        //check other signatures
        MMT_LOG(PROTO_RDP, MMT_LOG_DEBUG, "RDP detected.\n");
        mmt_int_rdp_add_connection(ipacket);
        return 1;


        _not_found_rdp:
		MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RDP);
    }
    MMT_ADD_PROTOCOL_TO_BITMASK(packet->flow->excluded_protocol_bitmask, PROTO_RDP);
    return 0;
}

void mmt_init_classify_me_rdp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_RDP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_rdp_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RDP, PROTO_RDP_ALIAS);
    if (protocol_struct != NULL) {

        mmt_init_classify_me_rdp();

        return register_protocol(protocol_struct, PROTO_RDP);
    } else {
        return 0;
    }
}


