/*
 * File:   types_defs.h
 * Author: montimage
 *
 * Created on 27 mai 2011, 15:59
 */

#ifndef TYPES_DEFS_H
#define TYPES_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/time.h>

#ifdef _WIN32
//#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#ifndef false
#define false 0 /**< Code of false value.*/
#endif
#ifndef true
#define true 1 /**< Code of true value. */
#endif

#ifndef ETH_ALEN
#define ETH_ALEN        6 /**< Ethernet MAC address length in bytes.*/
#endif
#ifndef IPv4_ALEN
#define IPv4_ALEN       4 /**< IPv4 address length in bytes. */
#endif

#ifndef IPv6_ALEN
#define IPv6_ALEN       16 /**< IPv6 address length in bytes.*/

#define MAX_PROTO_NAME_SIZE 64 /**< Maximum name size of a protocol.*/
#endif

#ifndef PROTO_PATH_SIZE
#define PROTO_PATH_SIZE         16 /**< Maximum number of protocols in a protocol hierarchy */
#endif


#ifndef BINARY_64DATA_TYPE_LEN
#define BINARY_64DATA_TYPE_LEN      68 /**< Length in bytes of a 64binary data type. A 64binary data type is composed of an int indicating the data length and a char table of 64 bytes. */
#endif

#ifndef BINARY_64DATA_LEN
#define BINARY_64DATA_LEN           64 /**< Length in b bytes of the data part of a 64binary type. */
#endif

#ifndef BINARY_1024DATA_TYPE_LEN
#define BINARY_1024DATA_TYPE_LEN    1028 /**< Length in bytes of a 1024binary data type. A 1024binary data type is composed of an int indicating the data length and a char table of 1024 bytes. */
#endif

#ifndef BINARY_1024DATA_LEN
#define BINARY_1024DATA_LEN         1024 /**< Length in bytes of the data part of a 1024binary type. */
#endif


#ifndef STRING_DATA_TYPE_LEN
#define STRING_DATA_TYPE_LEN        1508 /**< Length in bytes of a string data type. A string data type is composed of an int indicating the data length and a char table of 1504 bytes. */
#endif

#ifndef STRING_DATA_LEN
#define STRING_DATA_LEN             1504 /**< Length in bytes of the data part of a string type. */
#endif

typedef uint8_t mac_addr_t[ETH_ALEN]; /**< Defines a MAC address. */
typedef uint8_t ipv6_addr_t[IPv6_ALEN]; /**< Defines an IPv6 address. */

/** Defines a binary data structure.*/
typedef struct mmt_binary_data_struct {
    /**
     * Length in bytes of binary data
     */
    uint32_t len;

    /**
     * Binary data
     */
    uint8_t data[BINARY_64DATA_LEN];
} mmt_binary_data_t;

/** Defines a binary data structure.*/
typedef struct mmt_binary_var_data_struct {
    /**
     * Length in bytes of binary data
     */
    uint32_t len;

    /**
     * Binary data
     */
    uint8_t data[BINARY_1024DATA_LEN];
} mmt_binary_var_data_t;

/** Defines a string data type */
typedef struct mmt_string_data_struct {
    /**
     * Length in bytes of string data
     */
    uint32_t len;

    /**
     * String data
     */
    uint8_t data[STRING_DATA_LEN];
} mmt_string_data_t;

typedef struct mmt_date {
    uint32_t sec; /**< Second */
    uint32_t min; /**< Minute */
    uint32_t hour; /**< Hour */
    uint32_t mday; /**< Day of month 1..31  */
    uint32_t month; /**< Month of year 0..11 */
    uint32_t year; /**< Year */
    uint32_t wday; /**< Day of Week 0..6 */
} mmt_date_t;

typedef struct mmt_header_line_struct {
    const char * ptr;
    uint16_t len;
}mmt_header_line_t;

/** Defines the different data types that can be used */
enum data_types {
    MMT_UNDEFINED_TYPE, /**< no type constant value */
    MMT_U8_DATA, /**< unsigned 1-byte constant value */
    MMT_U16_DATA, /**< unsigned 2-bytes constant value */
    MMT_U32_DATA, /**< unsigned 4-bytes constant value */
    MMT_U64_DATA, /**< unsigned 8-bytes constant value */
    MMT_DATA_POINTER, /**< pointer constant value (size is void *) */
    MMT_DATA_MAC_ADDR, /**< ethernet mac address constant value */
    MMT_DATA_IP_NET, /**< ip network address constant value */
    MMT_DATA_IP_ADDR, /**< ip address constant value */
    MMT_DATA_IP6_ADDR, /**< ip6 address constant value */
    MMT_DATA_PATH, /**< protocol path constant value */
    MMT_DATA_TIMEVAL, /**< number of seconds and microseconds constant value */
    MMT_DATA_BUFFER, /**< binary buffer content */
    MMT_DATA_CHAR, /**< 1 character constant value */
    MMT_DATA_PORT, /**< tcp/udp port constant value */
    MMT_DATA_POINT, /**< point constant value */
    MMT_DATA_PORT_RANGE, /**< tcp/udp port range constant value */
    MMT_DATA_DATE, /**< date constant value */
    MMT_DATA_TIMEARG, /**< time argument constant value */
    MMT_DATA_STRING_INDEX, /**< string index constant value (an association between a string and an integer) */
    MMT_DATA_FLOAT, /**< float constant value */
    MMT_DATA_LAYERID, /**< Layer ID value */
    MMT_DATA_FILTER_STATE, /**< (filter_id, filter_state) */
    MMT_DATA_PARENT, /**< (filter_id, filter_state) */
    MMT_STATS, /**< pointer to MMT Protocol statistics */
    MMT_BINARY_DATA, /**< binary constant value */
    MMT_BINARY_VAR_DATA, /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */
    MMT_STRING_DATA, /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum BINARY_64DATA_LEN long */
    MMT_STRING_LONG_DATA, /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum STRING_DATA_LEN long */
    MMT_HEADER_LINE, /**< string pointer value with a variable size. The string is not necessary null terminating */
    MMT_STRING_DATA_POINTER, /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */
};

// This should be updated whenever data_types is updated.
#define MMT_HIGHER_VALUED_VALID_DATA_TYPE MMT_STRING_DATA_POINTER + 1/**< Defines the higher valued valid data type.*/

#ifdef	__cplusplus
}
#endif

#endif /* TYPES_DEFS_H */
