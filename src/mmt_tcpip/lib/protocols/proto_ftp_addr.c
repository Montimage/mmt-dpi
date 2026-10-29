/*
 * proto_ftp_addr.c — FTP data-connection addresses: the PORT, EPRT and LPRT
 * command parameters and the 227, 228 and 229 passive-mode replies.
 * Split out of proto_ftp.c by issue #544.
 */
#include "plugin_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ftp.h"

/**
 * Replace a character by another character in all string
 * @param  str string
 * @param  c1  ascii code number of character will be replaced
 * @param  c2  ascii code number of replacing character
 * @return     new string after replacing
 */
inline static char * str_replace_all_char(char *str, int c1, int c2) {
    char *new_str;
    new_str = (char*)malloc(strlen(str) + 1);
    if(new_str == NULL){
        return NULL;
    }
    memcpy(new_str, str, strlen(str));
    new_str[strlen(str)] = '\0';
    int i;
    for (i = 0; i < strlen(str); i++) {
        if ((int)new_str[i] == c1) {
            new_str[i] = (char)c2;
        }
    }
    // free(str);
    return new_str;
}

/* Length-bounded equivalent of the classic subvalue extraction for raw
 * packet buffers: the delimiters are located with str_get_indexes_n(...) so
 * no read ever goes past str_len, and the value between them is returned as
 * a fresh NUL-terminated string (or NULL) — same contract as before (#195).
 * Only the begin != NULL / end != NULL form used by the FTP parsers is
 * implemented. */
static char * ftp_str_subvalue_n(char *str, size_t str_len, char *begin, char *end){
    if(str == NULL || begin == NULL || end == NULL) return NULL;
    if(str_len == 0) return NULL;
    int * b_idx = str_get_indexes_n(str, str_len, begin, strlen(begin));
    if(b_idx == NULL) return NULL;
    int begin_index = b_idx[0];
    free(b_idx);
    int * e_idx = str_get_indexes_n(str, str_len, end, strlen(end));
    if(e_idx == NULL) return NULL;
    int end_index = e_idx[0];
    free(e_idx);
    int start_index = begin_index + (int)strlen(begin);
    if(start_index >= end_index) return NULL;
    return str_sub_n(str, str_len, start_index, end_index - 1);
}

/**
 * Get client address from an EPRT command
 * @param  payload     Payload of command
 * Example: EPRT |1|132.235.1.2|6275|
 * @return             Client IP address
 */
uint32_t ftp_get_data_client_addr_from_EPRT(char * payload, uint32_t payload_len) {
    // Get all the indexes of "|" in payload — bounded by payload_len (#195)
    int * indexes = str_get_indexes_n(payload, payload_len, "|", 1);
    if(indexes == NULL) return 0;
    if(indexes[0] == -1 || indexes[1] == -1 || indexes[2] == -1){
        free(indexes);
        return 0;
    }
    char * str_addr;
    int len = indexes[2] - indexes[1];
    if(len <= 0){
        free(indexes);
        return 0;
    }
    str_addr = (char*)malloc(len);
    if(str_addr == NULL){
        free(indexes);
        return 0;
    }
    memcpy(str_addr, payload + indexes[1] + 1, len - 1);
    str_addr[len - 1] = '\0';

    uint32_t address = inet_addr(str_addr);
    free(str_addr);
    free(indexes);
    return address;
}

/**
 * Get client address IPV6 from an EPRT command
 * @param  payload     Payload of command
 * Example: EPRT |2|2002:5183:4383::5183:4383|1031
 * @return             Client IP address
 */
char * ftp_get_data_client_addr_v6_from_EPRT(char * payload, uint32_t payload_len) {
    // Get all the indexes of "|" in payload — bounded by payload_len (#195)
    int * indexes = str_get_indexes_n(payload, payload_len, "|", 1);
    /* Malformed EPRT (fewer than three "|" delimiters) must not be parsed:
     * str_get_indexes_n(...) returns NULL when no delimiter is present, and a short
     * delimiter list leaves indexes[2] == -1, which would make `len` negative
     * (huge once cast for malloc/memcpy). */
    if(indexes == NULL) return NULL;
    if(indexes[0] == -1 || indexes[1] == -1 || indexes[2] == -1){
        free(indexes);
        return NULL;
    }
    char * str_addr;
    int len = indexes[2] - indexes[1];
    if(len <= 0){
        free(indexes);
        return NULL;
    }
    str_addr = (char*)malloc(len);
    if(str_addr == NULL) {
        free(indexes);
        return NULL;
    }
    memcpy(str_addr, payload + indexes[1] + 1, len - 1);
    str_addr[len - 1] = '\0';
    free(indexes);
    return str_addr;
}

/**
 * Get client address from an EPRT command
 * @param  payload     Payload of command
 * Example: EPRT |1|132.235.1.2|6275|
 * "EPRT |2|2002:5183:4383::5183:4383|1031\r\n"
 * @return             Client port number
 */
uint16_t ftp_get_data_client_port_from_EPRT(char *payload, uint32_t payload_len) {
    // Get all the indexes of "|" in payload — bounded by payload_len (#195)
    int * indexes = str_get_indexes_n(payload, payload_len, "|", 1);
    char * str_addr = NULL;

    /* Malformed EPRT (fewer than three "|" delimiters) must not be parsed:
     * str_get_indexes_n(...) returns NULL when no delimiter is present, and a short
     * delimiter list leaves indexes[2] == -1. Requiring indexes[0..2] to be
     * real positions guarantees the array holds at least four ints, so the
     * indexes[3] read below is in-bounds (it is either the fourth delimiter
     * position or the -1 sentinel). Mirrors the guard in
     * ftp_get_data_client_addr_v6_from_EPRT (issue #8 / K4). */
    if(indexes == NULL) return 0;
    if(indexes[0] == -1 || indexes[1] == -1 || indexes[2] == -1){
        free(indexes);
        return 0;
    }

    if(indexes[3]!=-1){
        int len = indexes[3] - indexes[2];
        if(len <= 0){
            free(indexes);
            return 0;
        }
        str_addr = (char*)malloc(len);
        if (str_addr == NULL)
        {
            free(indexes);
            return 0;
        }
        memcpy(str_addr, payload + indexes[2] + 1, len - 1);
        str_addr[len - 1] = '\0';
    }else{
        /* No fourth "|": the port runs to the end of the command minus the
         * trailing CRLF — bounded by payload_len, never strlen() (#195). */
        int len = (int)payload_len - indexes[2]-2;
        if(len <= 0){
            free(indexes);
            return 0;
        }
        str_addr = (char*)malloc(len);
        if (str_addr == NULL)
        {
            free(indexes);
            return 0;
        }
        memcpy(str_addr, payload + indexes[2] + 1, len - 1);
        str_addr[len - 1] = '\0';
    }
    
    uint16_t c_port = atoi(str_addr);
    free(str_addr);
    free(indexes);
    return c_port;
}

/**
 * Get an address from a string
 * @param  payload     string
 * Example: 192,168,1,2,7,138 -> addr = inet_addr("192.168.1.2")
 * @return             an address
 */
uint32_t ftp_get_addr_from_parameter(char * payload, uint32_t payload_len) {
    // Get all the indexes of "," in payload — bounded by payload_len (#195)
    int * indexes = str_get_indexes_n(payload, payload_len, ",", 1);
    char * str_addr = NULL;

    /* Malformed PORT parameter (fewer than three "," delimiters) must not be
     * parsed: str_get_indexes_n(...) returns NULL when no delimiter is present, and a
     * short delimiter list leaves indexes[2] == -1. Requiring indexes[0..2] to
     * be real positions guarantees the array holds at least four ints, so the
     * indexes[3] read below is in-bounds (it is either the fourth delimiter
     * position or the -1 sentinel). The short-circuit ordering never reads past
     * the first -1. Mirrors the guard in ftp_get_data_client_port_from_EPRT
     * (issue #35 / #8 K4). */
    if(indexes == NULL) return 0;
    if(indexes[0] == -1 || indexes[1] == -1 || indexes[2] == -1){
        free(indexes);
        return 0;
    }
    int len = indexes[3];
    /* indexes[3] is the fourth delimiter's byte offset, or the -1 sentinel when
     * there are exactly three delimiters. A non-positive length is malformed
     * and would otherwise drive malloc(0)/an OOB str_addr[len] write. */
    if(len <= 0){
        free(indexes);
        return 0;
    }
    str_addr = (char*)malloc(len + 1);
    if (str_addr == NULL) {
        free(indexes);
        return 0;
    }
    memcpy(str_addr, payload, len + 1);
    str_addr[len] = '\0';
    // mmt_debug_log("String before replacing: %s\n",str_addr);
    char *new_str_addr = NULL;
    new_str_addr = str_replace_all_char(str_addr, (int)',', (int)'.');
    // mmt_debug_log("String after replacing: %s\n",str_addr);
    if(new_str_addr == NULL) {
        free(str_addr);
        free(indexes);
        return 0;
    }
    uint32_t address = inet_addr(new_str_addr);
    free(str_addr);
    free(new_str_addr);
    free(indexes);
    return address;
}

/**
 * Get an address IPv6 from a string
 *     LPRT <protocol>,<addr-length>,<address...>,<port-length>,<port...>
 *  
 *     LPRT <SP> <long-host-port> <CRLF>
 *     
 *     The <long-host-port> argument is the concatenation of the following
       fields;

       o  an 8-bit <address-family> argument (af)

       o  an 8-bit <host-address-length> argument (hal)

       o  a <host-address> of <host-address-length> (h1, h2, ...)

       o  an 8-bit <port-address-length> (pal)

       o  a <port-address> of <port-address-length> (p1, p2, ...)
 *     LPRT af,hal,h1,h2,h3,h4...,pal,p1,p2...
 * Ref: http://www.networksorcery.com/enp/rfc/rfc1639.txt    
 * @param  payload     string
 * Example: LPRT 6,16,32,2,81,131,67,131,0,0,0,0,0,0,81,131,67,131,2,4,7 -> 
 * address family: 6
 * host address length: 16
 * host address of host address length: 32 (=2x16->20),2(02) ,81(51),131(83), 67(43),131(83), 0,0, 0,0 ,0,0 ,81,131 ,67,131
 * port address length: 2
 * port addres of port address length: 4,7 -> port = 4*16^2 + 7*16^0 = 1031
 * @return             an address
 */
/*
 * Maximum length, in characters, of the textual IPv6 address built from an
 * LPRT/EPRT command. A full IPv6 address is 8 groups of 4 hex digits joined by
 * 7 colons = 39 characters, but this parser emits at most 32 hex characters
 * (it does not separate every group), so the historical 33-byte buffer
 * (32 chars + NUL) is kept. The accumulation below is hard-bounded to this
 * length to make a heap overflow impossible regardless of the input.
 */
#define FTP_V6_ADDR_MAX_LEN 32
/* RFC 1639 IPv6 host-address-length is 16 octets; reject anything larger so a
 * forged length cannot drive unbounded growth of the address string. */
#define FTP_V6_HOST_ADDR_MAX_OCTETS 16
/* A TCP/UDP port is 16 bits: a declared LPRT port-address-length above 2
 * octets is malformed, and would make port_length * 2 overflow int (or loop
 * power_16() for billions of iterations) in ftp_get_data_client_port_from_LPRT
 * (#206, F-BUG-075). */
#define FTP_LPRT_PORT_ADDR_MAX_OCTETS 2

char * ftp_get_data_client_addr_v6_from_LPRT(char * payload, uint32_t payload_len) {
    char * str_addr;

    /* calloc so the buffer is NUL-terminated/zeroed before the first append —
     * the legacy code read the buffer (strstr/strcat) while still uninitialised
     * when the first octet was zero. */
    str_addr = (char*)calloc(FTP_V6_ADDR_MAX_LEN + 1, sizeof(char));
    if(str_addr == NULL) return NULL;
    size_t addr_len = 0; /* current length of str_addr, excluding the NUL */

    /* str_copy() would strlen() the raw, non-NUL-terminated packet buffer;
     * make a bounded NUL-terminated copy instead (#195). */
    char *payload_copy = ( payload_len > 0 && payload_len <= (uint32_t)INT32_MAX )
        ? str_sub_n(payload, payload_len, 0, (int)payload_len - 1) : NULL;
    if(payload_copy == NULL){
        free(str_addr);
        return NULL;
    }
    /* strtok_r: the engine is documented thread-safe, so no shared
     * static tokeniser state (#206, F-BUG-075). */
    char *saveptr = NULL;
    char *temp = strtok_r(payload_copy,",",&saveptr);
    int index = 0;
    int host_address_length = 0;
    int found_address = 0;
    while(temp!=NULL){

        if(index == 1){
            host_address_length = atoi(temp);
            /* Validate the declared host-address length: a negative or
             * oversized value is malformed input — stop and return what we
             * have (an empty string) rather than trusting it as a loop bound. */
            if(host_address_length <= 0 ||
               host_address_length > FTP_V6_HOST_ADDR_MAX_OCTETS){
                free(payload_copy);
                str_addr[0] = '\0';
                return str_addr;
            }
            found_address = 1;
            temp = strtok_r(NULL,",",&saveptr);
            index++;
            continue;
        }

        if(found_address == 1){
            int temp_nb = atoi(temp);
            /* Each address element encodes a single octet: validate 0..255.
             * Anything outside that range is malformed — stop parsing so a
             * huge value cannot overflow the fixed hvalue buffer below. */
            if(temp_nb < 0 || temp_nb > 255){
                free(payload_copy);
                str_addr[addr_len] = '\0';
                return str_addr;
            }
            if(temp_nb!=0){
                /* temp_nb is validated to 0..255 above; mask to a byte so the
                 * value is provably one or two hex digits. "0FF:" (4 chars) is
                 * then the longest rendering — 8 bytes is comfortably bounded
                 * and snprintf can never overrun it. */
                unsigned octet = (unsigned)temp_nb & 0xFFu;
                char hvalue[8];
                if(host_address_length%2==1 && host_address_length!=1){
                    if (octet < 16)
                        snprintf(hvalue, sizeof(hvalue), "0%X:", octet);
                    else
                        snprintf(hvalue, sizeof(hvalue), "%X:", octet);
                }else{
                    if (octet < 16)
                        snprintf(hvalue, sizeof(hvalue), "0%X", octet);
                    else
                        snprintf(hvalue, sizeof(hvalue), "%X", octet);
                }
                /* Bounded accumulation: append only what still fits in the
                 * 32-char window — never an unbounded strcat. */
                size_t hlen = strlen(hvalue);
                if(addr_len + hlen <= FTP_V6_ADDR_MAX_LEN){
                    memcpy(str_addr + addr_len, hvalue, hlen);
                    addr_len += hlen;
                    str_addr[addr_len] = '\0';
                }
            }else{
                if(strstr(str_addr,"::")==NULL){
                    if(addr_len + 1 <= FTP_V6_ADDR_MAX_LEN){
                        str_addr[addr_len++] = ':';
                        str_addr[addr_len] = '\0';
                    }
                }
            }

            host_address_length--;
            debug("[PROTO_FTP] host_address_length: %d",host_address_length);
            if(host_address_length==0){
                str_addr[addr_len]='\0';
                free(payload_copy);
                return str_addr;
            }
            temp = strtok_r(NULL,",",&saveptr);
            index++;
        }else{
            temp = strtok_r(NULL,",",&saveptr);
            index++;
        }
    }
    str_addr[addr_len] = '\0';
    free(payload_copy);
    return str_addr;
}

uint16_t power_16(uint16_t nb, int t){
    int i;
    uint16_t ret = nb;
    for(i = 0; i < t; i++){
        ret = ret * 16;
    }

    return ret;
}

/**
 * Get an address IPv6 from a string
 * @param  payload     string
 * Example: LPRT 6,16,32,2,81,131,67,131,0,0,0,0,0,0,81,131,67,131,2,4,7
 * -> Port number: 4*256+7 = 1031
 * @return             a port number
 */
uint16_t ftp_get_data_client_port_from_LPRT(char * payload, uint32_t payload_len) {
    // Get all the indexes of "|" in payload
    uint16_t port_nb = 0;
    char *temp = NULL;
    /* Bounded NUL-terminated copy — str_copy() would strlen() the raw packet
     * buffer past its end (#195). */
    char *payload_copy = ( payload_len > 0 && payload_len <= (uint32_t)INT32_MAX )
        ? str_sub_n(payload, payload_len, 0, (int)payload_len - 1) : NULL;
    if(payload_copy == NULL) return 0;
    /* strtok_r: the engine is documented thread-safe, so no shared
     * static tokeniser state (#206, F-BUG-075). */
    char *saveptr = NULL;
    temp = strtok_r(payload_copy,",",&saveptr);
    int index = 0;
    int host_address_length = 0;
    int port_length = 0;
    int found_port = 0;
    while(temp!=NULL){
        if(index == 1 ){
            host_address_length = atoi(temp);
            /* Validated as the sibling address parser does: RFC 1639 caps
             * the host address at 16 octets — a forged value would otherwise
             * make host_address_length + 2 below overflow int (#206). */
            if(host_address_length <= 0 ||
               host_address_length > FTP_V6_HOST_ADDR_MAX_OCTETS){
                free(payload_copy);
                return 0;
            }

            temp = strtok_r(NULL,",",&saveptr);
            index++;
            continue;
        }
        if(index == host_address_length + 2){
            port_length = atoi(temp);
            /* A port is 16 bits: at most FTP_LPRT_PORT_ADDR_MAX_OCTETS
             * octets. A forged length would overflow int in port_length * 2
             * below and drive power_16() for billions of iterations (#206). */
            if(port_length <= 0 ||
               port_length > FTP_LPRT_PORT_ADDR_MAX_OCTETS){
                free(payload_copy);
                return 0;
            }
            found_port = 1;

            temp = strtok_r(NULL,",",&saveptr);
            index++;
            continue;
        }
        if(found_port){
            port_length--;
            port_nb += power_16(atoi(temp),(port_length*2));
            if(port_length == 0){
                free(payload_copy);
                return port_nb;
            }
            temp = strtok_r(NULL,",",&saveptr);
            index++;
        }else{
            temp = strtok_r(NULL,",",&saveptr);
            index++;
            continue;
        }
    }
    free(payload_copy);
    return port_nb;
}

/**
 * Get a port number from a string
 * @param  payload     string
 * Example: 192,168,1,2,7,138 -> port_nb = 7*256 + 138
 * @return             port number
 */
uint16_t ftp_get_port_from_parameter(char *payload, uint32_t payload_len) {
    // Get all the indexes of "," in payload — PORT needs 5 commas (6 numbers)
    // Bounded by payload_len so a non-NUL-terminated buffer is safe (#195)
    int * indexes = str_get_indexes_n(payload, payload_len, ",", 1);
    if(indexes == NULL) return 0;
    /* Need at least 5 delimiters; indexes[4] must be a real offset (not -1).
     * This mirrors the guard in ftp_get_addr_from_parameter (above). */
    if(indexes[0] == -1 || indexes[1] == -1 || indexes[2] == -1 || indexes[3] == -1 || indexes[4] == -1){
        free(indexes);
        return 0;
    }

    char * nb1;
    nb1 = str_sub_n(payload, payload_len, indexes[3]+1, indexes[4]-1);
    if(nb1 == NULL){
        free(indexes);
        return 0;
    }

    char * nb2;
    int last_c_number = indexes[4]+1;
    // Remove special character at the end of the commands — bounded by payload_len
    while((uint32_t)last_c_number < payload_len && payload[last_c_number]>='0' && payload[last_c_number]<='9'){
        last_c_number++;
    }

    nb2 = str_sub_n(payload, payload_len, indexes[4]+1, last_c_number-1);
    if(nb2 == NULL){
        free(nb1);
        free(indexes);
        return 0;
    }
    uint16_t port = ntohs(atoi(nb1) * 256 + atoi(nb2));
    free(nb1);
    free(nb2);
    free(indexes);
    return port;
}

/**
 * Get data server port from response code 229
 * Example: Entering Extended Passive Mode (|||port|)
 * @param  payload payload to extract server port
 * @return         server port
 */
uint16_t ftp_get_data_server_port_code_229(char *payload, uint32_t payload_len) {
    char *ret = ftp_str_subvalue_n(payload, payload_len, "(|||", "|)");
    if(ret == NULL) return 0;
    uint16_t s_port = htons(atoi(ret));
    free(ret);
    return s_port;
}

/**
 * Get data server address from value of response code 227
 * @param  payload payload
 * @return         server address
 */
uint32_t ftp_get_data_server_addr_code_227(char * payload, uint32_t payload_len) {
    char * str = ftp_str_subvalue_n(payload, payload_len, "(", ")");
    if(str == NULL) return 0;
    uint32_t len = strlen(str);
    uint32_t address = ftp_get_addr_from_parameter(str, len);
    free(str);
    return address;
}
/**
 * Get data server port number from value of response code 227
 * @param  payload payload
 * @return         server address
 */
uint16_t ftp_get_data_server_port_code_227(char * payload, uint32_t payload_len) {
    char * str = ftp_str_subvalue_n(payload, payload_len, "(", ")");
    if(str == NULL) return 0;
    uint32_t len = strlen(str);
    uint16_t port = ftp_get_port_from_parameter(str, len);
    free(str);
    return port;
}

/**
 * Extract server port from response code 228
 * Example: Entering Long Passive Mode (long address, port).
 * @param  payload Payload to extract
 * @return         port number
 */
uint16_t ftp_get_data_server_port_code_228(char *payload, uint32_t payload_len) {
    char *ret = ftp_str_subvalue_n(payload, payload_len, ", ", ")");
    if(ret == NULL) return 0;
    uint16_t s_addr = htons(atoi(ret));
    free(ret);
    return s_addr;
}

/**
 * Extract serer address from response code 228
 * Example: Entering Long Passive Mode (long address, port).
 * @param  payload payload to extract
 * @return         server address
 */
uint32_t ftp_get_data_server_addr_code_228(char *payload, uint32_t payload_len) {
    char *ret = ftp_str_subvalue_n(payload, payload_len, "(", ",");
    if(ret == NULL) return 0;
    uint32_t s_addr = htons(atoi(ret));
    free(ret);
    return s_addr;
}
