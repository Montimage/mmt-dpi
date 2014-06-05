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

#define PROTO_SCTP_DATA 207
#define PROTO_SCTP_DATA_ALIAS "sctp_data"

#define PROTO_SCTP_SACK 208
#define PROTO_SCTP_SACK_ALIAS "sctp_sack"

#define PROTO_SCTP_INIT 209
#define PROTO_SCTP_INIT_ALIAS "sctp_init"

    enum {
        SCTP_SCR_PORT = 1,
        SCTP_DEST_PORT,
        SCTP_VERIF_TAG,
        SCTP_CHECKSUM,
        SCTP_CH_TYPE,
        SCTP_CH_FLAGS,
        SCTP_CH_LENGTH,
        //SCTP_NUM_CH, //TODO:delete this later
       // SCTP_DATA_TSN,
        //SCTP_DATA_STREAM,
        //SCTP_DATA_SSN,
       // SCTP_DATA_PPID,
        
    } sctp_attributes;

    /*
     * Chunk type
     * Chunk flags
     * Chunk length
     * Number of chunks in the packet
     */
    //The attributes nb MUST be updated when new attributes are added
#define SCTP_ATTRIBUTES_NB SCTP_CH_LENGTH

#define SCTP_SCR_PORT_ALIAS     "src_port"
#define SCTP_DEST_PORT_ALIAS    "dest_port"
#define SCTP_VERIF_TAG_ALIAS    "verif_tag"
#define SCTP_CHECKSUM_ALIAS     "checksum"
#define SCTP_CH_TYPE_ALIAS      "ch_type"
#define SCTP_CH_FLAGS_ALIAS     "ch_flags"
#define SCTP_CH_LENGTH_ALIAS    "ch_length"
//#define SCTP_NUM_CH_ALIAS       "numchunk" //TODO:delete this later
//#define SCTP_DATA_TSN_ALIAS     "data_tsn"
//#define SCTP_DATA_STREAM_ALIAS  "data_stream"
//#define SCTP_DATA_SSN_ALIAS     "data_ssn"
//#define SCTP_DATA_PPID_ALIAS    "data_ppid"

    enum {
        SCTP_DATA_CH_TYPE = 1,
        SCTP_DATA_CH_FLAGS,
        SCTP_DATA_CH_LENGTH,
        SCTP_DATA_TSN,
        SCTP_DATA_STREAM,
        SCTP_DATA_SSN,
        SCTP_DATA_PPID,

    } sctp_data_attributes;
    
#define SCTP_DATA_ATTRIBUTES_NB  SCTP_DATA_PPID
#define SCTP_DATA_CH_TYPE_ALIAS      "ch_type"
#define SCTP_DATA_CH_FLAGS_ALIAS     "ch_flags"
#define SCTP_DATA_CH_LENGTH_ALIAS    "ch_length"
#define SCTP_DATA_TSN_ALIAS          "data_tsn"
#define SCTP_DATA_STREAM_ALIAS       "data_stream"
#define SCTP_DATA_SSN_ALIAS          "data_ssn"
#define SCTP_DATA_PPID_ALIAS         "data_ppid"
    
 enum {
        SCTP_SACK_CH_TYPE = 1,
        SCTP_SACK_CH_FLAGS,
        SCTP_SACK_CH_LENGTH,
        SCTP_SACK_CUM_TSN_ACK,
        SCTP_SACK_A_RWND,
        SCTP_SACK_NUM_GAP_BLOCKS,
        SCTP_SACK_NUM_DUP_TSN,

    } sctp_sack_attributes;

#define SCTP_SACK_ATTRIBUTES_NB    SCTP_SACK_NUM_DUP_TSN
#define SCTP_SACK_CH_TYPE_ALIAS             "ch_type"
#define SCTP_SACK_CH_FLAGS_ALIAS            "ch_flags"
#define SCTP_SACK_CH_LENGTH_ALIAS           "ch_length"
#define SCTP_SACK_CUM_TSN_ACK_ALIAS         "sack_cum_tsn"
#define SCTP_SACK_A_RWND_ALIAS              "sack_a_rwnd"
#define SCTP_SACK_NUM_GAP_BLOCKS_ALIAS      "sack_num_gap_blocks"
#define SCTP_SACK_NUM_DUP_TSN_ALIAS         "sack_num_dup_tsn"

     enum {
        SCTP_INIT_CH_TYPE = 1,
        SCTP_INIT_CH_FLAGS,
        SCTP_INIT_CH_LENGTH,
        SCTP_INIT_INI_TAG,
        SCTP_INIT_A_RWND,
        SCTP_INIT_NUM_OUT_STREAMS,
        SCTP_INIT_NUM_IN_STREAMS,
        SCTP_INIT_INI_TSN,
    } sctp_init_attributes;

#define SCTP_INIT_ATTRIBUTES_NB             SCTP_INIT_INI_TSN
#define SCTP_INIT_CH_TYPE_ALIAS             "ch_type"
#define SCTP_INIT_CH_FLAGS_ALIAS            "ch_flags"
#define SCTP_INIT_CH_LENGTH_ALIAS           "ch_length"
#define  SCTP_INIT_INI_TAG_ALIAS            "init_ini_tag"
#define SCTP_INIT_A_RWND_ALIAS              "init_a_rwnd"
#define SCTP_INIT_NUM_OUT_STREAMS_ALIAS     "init_num_out_streams"
#define SCTP_INIT_NUM_IN_STREAMS_ALIAS      "init_num_in_streams"
#define SCTP_INIT_INI_TSN_ALIAS             "init_ini_tsn"

    struct sctphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t vtag;
        uint32_t checksum;
        uint8_t type;
        uint8_t flags;
        uint16_t length;
    };

    enum {
        SCTP_CID_DATA = 0,
        SCTP_CID_INIT = 1,
        SCTP_CID_INIT_ACK = 2,
        SCTP_CID_SACK = 3,
        SCTP_CID_HEARTBEAT = 4,
        SCTP_CID_HEARTBEAT_ACK = 5,
        SCTP_CID_ABORT = 6,
        SCTP_CID_SHUTDOWN = 7,
        SCTP_CID_SHUTDOWN_ACK = 8,
        SCTP_CID_ERROR = 9,
        SCTP_CID_COOKIE_ECHO = 10,
        SCTP_CID_COOKIE_ACK = 11,
        SCTP_CID_ECN_ECNE = 12,
        SCTP_CID_ECN_CWR = 13,
        SCTP_CID_SHUTDOWN_COMPLETE = 14,

        /* AUTH Extension Section 4.1 */
        SCTP_CID_AUTH = 0x0F,

        /* PR-SCTP Sec 3.2 */
        SCTP_CID_FWD_TSN = 0xC0,

        /* Use hex, as defined in ADDIP sec. 3.1 */
        SCTP_CID_ASCONF = 0xC1,
        SCTP_CID_ASCONF_ACK = 0x80,
    } sctp_cid_t; /* enum */

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

