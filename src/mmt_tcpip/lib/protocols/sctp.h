/*
 * File:   sctp.h
 * Author: JP
 *
 * Created on 27 avril 2012, 16:15
 */

#ifndef SCTP_H
#define	SCTP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

    struct sctphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t vtag;
        uint32_t checksum;
        uint8_t type;
        uint8_t flags;
        uint16_t length;
    };

    struct sctp_chunkhdr {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
    };

    struct sctp_datahdr {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t tsn;
        uint16_t stream;
        uint16_t ssn;
        uint32_t ppid;
        //uint8_t payload[0];
    };
 /*
 typedef struct sctp_gap_ack_block {
 uint16_t start;
 uint16_t end;
 struct sctp_gap_ack_block * next;
 };

 typedef uint32_t sctp_dup_tsn_t;

 typedef struct sctp_sack_variable{
        sctp_gap_ack_block    * gab;
        sctp_dup_tsn_t        * dup;
        struct sctp_sack_variable * next;
 };
*/
 struct sctp_sackhdr {
 uint8_t type;
 uint8_t flags;
 uint16_t length;
 uint32_t cum_tsn_ack;
 uint32_t a_rwnd;
 uint16_t num_gap_ack_blocks;
 uint16_t num_dup_tsns;
 //sctp_sack_variable * variable;
 };
 struct sctp_inithdr {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t init_tag;
        uint32_t a_rwnd;
        uint16_t num_outbound_streams;
        uint16_t num_inbound_streams;
        uint32_t initial_tsn;
 };

   //int init_sctp_proto_struct();
   //int init_sctp_data_proto_struct();
   int init_sctp_protos();
   //int init_proto_sctp_data();
#ifndef SCTP_DATA
#define SCTP_DATA        0x00          /* sctp data packet   */
#endif

#ifndef SCTP_SACK
#define SCTP_SACK        0x03          /* sctp sack packet    */
#endif

#ifndef SCTP_INIT
#define SCTP_INIT        0x01          /* sctp sack packet    */
#endif
#ifdef	__cplusplus
}
#endif

#endif	/* SCTP_H */

