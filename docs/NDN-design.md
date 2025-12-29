# NDN design

## ndn_TLV_t struct

```c
/**
 * A NDN TLV node structre
 */
typedef struct ndn_tlv_struct{
 uint16_t type; // Type of node
 uint8_t nb_octets; // number of octets to calculate the length of node
 unsigned long length; // Length of node
 uint16_t node_offset; // data offset of node in packet payload - count from type octet
 uint16_t data_offset;
 struct ndn_tlv_struct *next; // sibling node - same root
}ndn_tlv_t;
```

## NDN attributes

```c
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
 NDN_NAME_COMPONENTS,
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
 NDN_ATTRIBUTES_NB,
};

```

## Signature type value

```c
enum signature_type
{
 DigestSha256 = 0,
 SignatureSha256WithRsa,
 SignatureSha256WithEcdsa = 3,
 SignatureHmacWithSha256,
 ReservedForFutureAssignments = 5,
 Unassigned = 200,
};

```

## Content type

```c
enum ndn_content_type
{
 NDN_CONTENT_TYPE_BLOB=0,
 NDN_CONTENT_TYPE_LINK,
 NDN_CONTENT_TYPE_KEY,
};

```
