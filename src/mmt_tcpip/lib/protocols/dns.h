/* Generated with MMT Plugin Generator */

#ifndef DNS_H
#define DNS_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#define MMT_DNS_SESSION_TIMEOUT_DELAY 15 /**< The DNS session timeout delay */

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

/* dns header
           0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                      ID                       |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    QDCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ANCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    NSCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ARCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct qropcodeaatcrdrazans_authdata_authrcode {
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t rd : 1, tc : 1, aa : 1, opcode : 4, qr : 1;
    uint8_t rcode : 4, data_auth : 1, ans_auth : 1, z : 1, ra : 1;
#elif BYTE_ORDER == BIG_ENDIAN
    uint8_t qr : 1, opcode : 4, aa : 1, tc : 1, rd : 1;
    uint8_t ra : 1, z : 1, ans_auth : 1, data_auth : 1, rcode : 4;
#else
#error "BYTE_ORDER must be defined"
#endif
};

static attribute_metadata_t dns_attributes_metadata[DNS_ATTRIBUTES_NB];

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;


struct dnshdr {
    uint16_t tid;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

typedef struct dns_name_struct{
    char *value; // Value of the name
    uint16_t length;// Length of the name
    uint8_t is_ref; // Is reference name
    uint16_t real_length; // real length of name in packet
    struct dns_name_struct *next;
} dns_name_t;

typedef struct dns_query_struct{
    char *name;
    uint16_t type;
    uint16_t qclass;
    uint16_t qlength;
    struct dns_query_struct *next;
}dns_query_t;

typedef struct dns_answer_mx_struct{
    uint16_t mx_pref;
    char * mx_server;
}dns_answer_mx_t;



typedef struct dns_answer_soa_struct{
    char * soa_pri_server;
    char * soa_mail_box;
    uint64_t soa_serial_number;
    uint64_t soa_refresh_interval;
    uint64_t soa_retry_interval;
    uint64_t soa_expire_limit;
    uint64_t soa_min_ttl;
}dns_answer_soa_t;


typedef struct dns_answer_struct{
    char *name;
    uint16_t type;
    uint16_t aclass;
    uint64_t a_ttl;
    uint16_t a_length;
    uint16_t data_length;
    void * data;
    struct dns_answer_struct *next;
}dns_answer_t;



#ifdef	__cplusplus
}
#endif
#endif	/* DNS_H */


