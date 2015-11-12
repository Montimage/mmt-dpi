/* 
 * File:   http.h
 * Author: montimage
 *
 * Created on 20 septembre 2011, 14:09
 */

#ifndef MMT_NDN_H
#define MMT_NDN_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"
enum ndn_content_type
{
	NDN_CONTENT_TYPE_BLOB=0,
	NDN_CONTENT_TYPE_LINK,
	NDN_CONTENT_TYPE_KEY,
};

enum signature_type
{
	DigestSha256 = 0,
	SignatureSha256WithRsa,
	SignatureSha256WithEcdsa = 3,
	SignatureHmacWithSha256,
	ReservedForFutureAssignments = 5,
	Unassigned = 200,
};

// Type of ndn - do not change the order
enum 
{
	// Packet type
	NDN_IMPLICIT_SHA256_DIGEST_COMPONENT = 1,
	NDN_PACKET_TYPE,
	NDN_PACKET_LENGTH,
	// Common field
	NDN_UNKNOWN_PACKET,
	NDN_INTEREST_PACKET,
	NDN_DATA_PACKET,
	NDN_COMMON_NAME,
	NDN_NAME_COMPONENT,
	// Interest packet
	NDN_INTEREST_SELECTORS,
	NDN_INTEREST_NONCE,
	NDN_INTEREST_LIFETIME = 12,
	// Interest/selectors
	NDN_INTEREST_MIN_SUFFIX_COMPONENT,
	NDN_INTEREST_MAX_SUFFIX_COMPONENT,
	NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR,
	NDN_INTEREST_EXCLUDE,
	NDN_INTEREST_CHILD_SELECTOR,
	NDN_INTEREST_MUST_BE_FRESH,
	NDN_INTEREST_ANY,
	// Data packet
	NDN_DATA_METAINFO,
	NDN_DATA_CONTENT,
	NDN_DATA_SIGNATURE_INFO,
	NDN_DATA_SIGNATURE_VALUE,
	// data/metainfo
	NDN_DATA_CONTENT_TYPE,
	NDN_DATA_FRESHNESS_PERIOD,
	NDN_DATA_FINAL_BLOCK_ID,
	// Data/signature
	NDN_DATA_SIGNATURE_TYPE,
	NDN_DATA_KEY_LOCATOR,
	NDN_DATA_KEY_DIGEST,
	NDN_ATTRIBTUES_NB,
};


#define	NDN_IMPLICIT_SHA256_DIGEST_COMPONENT_ALIAS	"implicitSHA256DigestComponent"
#define	NDN_PACKET_TYPE_ALIAS						"packet_type"
#define	NDN_PACKET_LENGTH_ALIAS						"packet_length"
	// Common field
#define	NDN_COMMON_NAME_ALIAS						"common_name"
#define	NDN_PACKET_NAME_COMPONENT_ALIAS				"name_components"
	// Interest packet
#define	NDN_INTEREST_NONCE_ALIAS					"nonce"
#define	NDN_INTEREST_LIFETIME_ALIAS					"life_time"
	// Interest/selectors
#define	NDN_INTEREST_MIN_SUFFIX_COMPONENT_ALIAS		"min_suffix"
#define	NDN_INTEREST_MAX_SUFFIX_COMPONENT_ALIAS		"max_suffix"
#define	NDN_INTEREST_PUBLISHER_PUBLICKEY_LOCATOR_ALIAS	"publisher_publickey_locator"
#define	NDN_INTEREST_EXCLUDE_ALIAS					"exclude"
#define	NDN_INTEREST_CHILD_SELECTOR_ALIAS			"child_selector"
#define	NDN_INTEREST_MUST_BE_FRESH_ALIAS			"must_be_fresh"
#define	NDN_INTEREST_ANY_ALIAS						"any"
	// Data packet
#define	NDN_DATA_CONTENT_ALIAS 						"content"
#define	NDN_DATA_SIGNATURE_VALUE_ALIAS				"signature_value"
	// data/metainfo
#define	NDN_DATA_CONTENT_TYPE_ALIAS					"content_type"
#define	NDN_DATA_FRESHNESS_PERIOD_ALIAS				"fresh_period"
#define	NDN_DATA_FINAL_BLOCK_ID_ALIAS				"final_block_id"
	// Data/signature
#define	NDN_DATA_SIGNATURE_TYPE_ALIAS				"signature_type"
#define	NDN_DATA_KEY_LOCATOR_ALIAS					"key_locator"
#define	NDN_DATA_KEY_DIGEST_ALIAS					"key_digest"


// #define 

typedef struct ndn_tlv_struct{
	uint16_t type;
	uint8_t nb_octets;
	unsigned long length;
	char *value;
	char *remain_value;
	struct ndn_tlv_struct *next;
}ndn_tlv_t;


/**
 * Check a type value
 * @param  type type value
 * @return      0 if this is node type of NDN node
 *              1 if this is a type of NDN node
 */
int ndn_TLV_check_type(int type);

/**
 * Check type value of a ndn_tlv_struct
 * @param  type 2 character of value
 * @return      0 if the type is not correct:
 *                 type == NULL
 *                 strlen(type)!=2
 *                 smaller than 5 (05)
 *                 bigger than 29 (1d)
 *                 == 0b (there is no 0b)
 *               the value of type 5->29
 */
uint16_t ndn_TLV_get_type(char *type);

/**
 * Initialize a ndn_tlv_t struct
 * @return a pointer to the new ndn_tlv_t struct
 *           type = 0
 *           length = 0
 *           value = NULL
 */
ndn_tlv_t * ndn_TLV_init();

/**
 * Free a ndn TLV node
 */
void ndn_TLV_free(ndn_tlv_t *ndn);

/**
 * Parse a payload to a structure of ndn_tlv_t
 * @param  payload      payload
 * @param  total_length total length of node (not of payload)
 * @return              a pointer to a new node of ndn_tlv_t
 *                      NULL if:
 *                      	payload is NULL
 *                      	type of some node not correct
 *                      	The value of first octet is not correct
 *                      	The value of first octet is 0 but the total length of the node bigger than 4
 *                      	Total length of the node is smaller than the length is calculated:
 *                      		total_length < 4 + 2*nb_octets + length
 */	
ndn_tlv_t * ndn_TLV_parser(char *payload, int total_length);


/**
 * Find a node with input type from a root
 * @param  root      root node contain the node to find
 * @param  node_type type of node
 * @return           NULL if:
 *                        root is NULL
 *                        root value is NULL
 *                        node_type does not exist
 *                        cannot find a node with @node_type in @root
 *                   a pointer to the node with @node_type in @root
 */
ndn_tlv_t * ndn_find_node(ndn_tlv_t *root, int node_type);

/**
 * Check a payload to classify if this packet is a NDN packet or not
 * @param  payload    payload
 * @param  packet_len length of payload
 * @return            0 if this is not an ndn packet
 *                      - Condition 1: The payload must have at least 6 length -> need to confirm
 *                      - Condition 2: The payload must start by '05' or '06'
 *                      - Condition 3: The payload must follow the format : Type - Length - Value (Check for first format: Type(05 or 06) - Lenght - '07')
 *                    1 if this is a ndn interesting packet - the payload start by '05'
 *                    2 if this is a ndn data packet - the payload start by '06'
 */
int mmt_check_ndn_payload(char* payload, int payload_len);

/**
 * Parse all name components to a tree of ndn_tlv_t
 * @param  payload     common field payload
 * @param  payload_len common field payload length
 * @return             NULL if:
 *                          name_com node is NULL
 *                          name_com type is not NDN_PACKET_NAME_COMPONENT
 *                          
 */
ndn_tlv_t * ndn_TLV_parser_name_comp(char* payload, int payload_len);

////////// extraction ///////

/**
 * Get type of packet
 * @param  payload     payload of packet
 * @param  payload_len length of payload
 * @return             NDN_INTEREST_PACKET
 *                     NDN_DATA_PACKET
 *                     NDN_UNKNOWN_PACKET;
 */
uint8_t ndn_packet_type_extraction(char* payload, int payload_len);


/**
 * Get type of packet
 * @param  payload     payload of packet
 * @param  payload_len length of payload
 * @return             NDN_INTEREST_PACKET
 *                     NDN_DATA_PACKET
 *                     NDN_UNKNOWN_PACKET;
 */
uint32_t ndn_packet_length_extraction(char* payload, int payload_len);



////////////////////// EXTRACT COMMON FIELD //////////////////////

/**
 * Get all value of name components of packet
 * @param  payload     packet payload
 * @param  payload_len packet length
 * @return             NULL if:
 *                          It is not NDN packet
 *                          It is an NDN_UNKNOWN_PACKET
 *                          name_node is NULL
 *                          name_node type is not NDN_COMMON_NAME
 *                          name_node value is NULL
 *                          name_com  node is NULL
 *                     value of name components: name1/name2/name3/name4/.../namex
 */
char* ndn_name_components_extraction(char *payload,int payload_len);

////////////////////// EXTRACT INTEREST PACKET //////////////////////


/**
 * Extract nonce from payload of packet
 * @param  payload     packet payload
 * @param  payload_len payload length
 * @return             -1 if:
 *                        nonce node in the packet is NULL
 *                        nonce node in the packet has value is NULL
 *                        The value of nonce node is cannot convert to hexa
 *                     The value unsigned long 
 *                     The combination of nonce and name uniquely identify an interest packet
 */
int ndn_interest_nonce_extraction(char *payload,int payload_len);

/**
 * Extract nonce from payload of packet
 * @param  payload     packet payload
 * @param  payload_len payload length
 * @return             -1 if:
 *                        lifetime node in the packet is NULL
 *                        lifetime node in the packet has value is NULL
 *                        The value of lifetime node is cannot convert to hexa
 *                     The value int 
 */
int ndn_interest_lifetime_extraction(char *payload,int payload_len);

/**
 * [ndn_minSuffixComponents description]
 * @param  payload     [description]
 * @param  payload_len [description]
 * @return             [description]
 */
int ndn_interest_min_suffix_component_extraction(char *payload,int payload_len);

////////////////////// EXTRACT DATA PACKET //////////////////////

char * ndn_data_content_extraction(char *payload,int payload_len);

int ndn_data_content_type_extraction(char *payload,int payload_len);

int ndn_data_freshness_period_extraction(char *payload,int payload_len);



/**
 * Extract signature type
 * @param  payload     [description]
 * @param  payload_len [description]
 * @return             0: DigestSha256
 *                     1: SignatureSha256WithRsa
 *                     3: SignatureSha256WithEcdsa
 *                     4: SignatureHmacWithSha256
 *                     2 or 5->200: ReservedForFutureAssignments
 *                     >=200: Unassigned
 */
int ndn_data_signature_type_extraction(char *payload,int payload_len);

/**
 * Extract key locator of a ndn data packet
 * @param  payload     [description]
 * @param  payload_len [description]
 * @return             [description]
 */
char * ndn_data_key_locator_extraction(char *payload,int payload_len);

/**
 * Signature value of a ndn data packet
 * @param  payload     [description]
 * @param  payload_len [description]
 * @return             [description]
 */
char * ndn_data_signature_value_extraction(char *payload,int payload_len);

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_NDN_H */