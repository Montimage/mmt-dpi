/* 
 * File:   ip_session_id_management.h
 * Author: montimage
 *
 * Created on 29 février 2012, 16:32
 */

#ifndef IP_SESSION_ID_MANAGEMENT_H
#define	IP_SESSION_ID_MANAGEMENT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "data_defs.h"
#include "hash_utils.h"
#include "ip.h"
#include "mmt_tcpip_plugin_structs.h"

    typedef struct internal_ip_proto_context_struct {
        void * ips_map;
        mmt_tcpip_internal_packet_t packet;
        uint64_t ips_count;
        uint64_t active_ips_count;

        uint64_t sessions_count;
        uint64_t active_sessions_count;
    } internal_ip_proto_context_t;

    /**
     * Defines the internal structure to represent a user identifier (address) for IPv4 protocol
     */
    typedef struct mmt_ip4_id_struct {
        uint32_t ip; /**< IPv4 address */
        uint32_t count; /**< Nb of sessions this user participates in */
        struct mmt_internal_tcpip_id_struct id_internal_context; /**< internal id related classification struct */
    } mmt_ip4_id_t;

    /**
     * Defines the internal structure to represent a user identifier (address) for IPv6 protocol
     */
    typedef struct mmt_ip6_id_struct {
        struct in6_addr ip; /**< IPv6 address */
        uint32_t count; /**< Nb of sessions this user participates in */
        struct mmt_internal_tcpip_id_struct id_internal_context; /**< internal id related classification struct */
    } mmt_ip6_id_t;

    /* Issue #562 (F-PERF-104): one host record per distinct IP address — the
     * cold port cache / IRC DCC table moved to a lazily-allocated extension
     * and the 128 B protocol bitmask became 14 tracked bits (968 B / 984 B
     * before). Pinned so a new per-host field is a deliberate decision. */
#if !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    _Static_assert(sizeof (mmt_ip4_id_t) <= 256, "issue #562: IPv4 host record within 256 B");
    _Static_assert(sizeof (mmt_ip6_id_t) <= 256, "issue #562: IPv6 host record within 256 B");
#endif

    /**
     * Defines the structure of the key of a session.
     */
    typedef struct mmt_session_key_struct {
#if BYTE_ORDER == LITTLE_ENDIAN
        uint8_t is_lower_initiator : 2, is_lower_client : 2, ip_type : 4;
#elif BYTE_ORDER == BIG_ENDIAN
        uint8_t ip_type : 4, is_lower_client : 2, is_lower_initiator : 2;
#else
#error "BYTE_ORDER must be defined"
#endif
        uint8_t next_proto; /**< identifier of the encapsulated protocol (TCP, UDP, etc.) */
        uint16_t lower_ip_port; /**< identifier of the port number with the lower numerical value */
        uint16_t higher_ip_port; /**< identifier of the port number with the higher numerical value */
        void * lower_ip; /**< identifier of the IP address (IPv4 or IPv6) with the lower numerical value */
        void * higher_ip; /**< identifier of the IP address (IPv4 or IPv6) with the higher numerical value */
    } mmt_session_key_t;

    int cleanup_ipv4_internal_context(internal_ip_proto_context_t * tcpip_context);
    int cleanup_ipv6_internal_context(internal_ip_proto_context_t * tcpip_context);
    void close_ipv4_internal_context(protocol_instance_t * proto_context);
    void close_ipv6_internal_context(protocol_instance_t * proto_context);
    internal_ip_proto_context_t * setup_ipv4_internal_context();
    internal_ip_proto_context_t * setup_ipv6_internal_context();
    /**
     * Frees the session data of every session in the protocol context
     * (Issue #327: renamed — it closes the session lists, not "id" lists).
     * @return non zero value upon success, zero on failure.
     */
    int close_session_lists(void * proto_context);

    /**
     * Closes application classification module
     * @return non zero value upon success, zero on failure.
     */
//    int close_application_detection();

    /**
     * Returns an mmt_ip6_id_t pointer for the given IP address
     * @param tcpip_context pointer to the tcpip internal context where to look for the given ip
     * @param ip pointer to the IPv6 address
     * @return an mmt_ip6_id_t pointer for the given IP address
     */
    mmt_ip6_id_t * get_ip6_id(internal_ip_proto_context_t * tcpip_context, struct in6_addr * ip, uint32_t * is_new);

    /**
     * Returns the mmt_session_t pointer corresponding to the given session_key.
     * @param protocol_context pointer to the protocol context
     * @param session_key the key identifier of the session
     * @param ipacket the internal packet structure to update with the session structure
     * @param is_new output variable that indicates if the session corresponding to the given key is new or not
     * @return the mmt_session_t pointer corresponding to the given session_key.
     */
    mmt_session_t * get_session(void * protocol_context, mmt_session_key_t * session_key, ipacket_t * ipacket, int * is_new);

    /**
     * Frees the session data allocated memory
     * @param session the session to be freed
     * @param attr unused attribute
     */
    void free_session_data(void * key, void * value, void * args);

    void free_ipv4_data(void * key, void * value, void * args);

    void free_ipv6_data(void * key, void * value, void * args);


    int insertID6(internal_ip_proto_context_t * tcpip_context, mmt_ip6_id_t * ip_id);
    mmt_ip6_id_t * findID6(internal_ip_proto_context_t * tcpip_context, struct in6_addr * ip);
    int deleteID6(internal_ip_proto_context_t * tcpip_context, struct in6_addr * ip);

// LN: Move from packet_process

int proto_ip_frag_packet_count_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);

int proto_ip_frag_data_volume_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);

int proto_ip_df_packet_count_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);

int proto_ip_df_data_volume_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);

int proto_sessions_count_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);

int proto_active_sessions_count_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);

int proto_timedout_sessions_count_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);

// End of LN

#ifdef	__cplusplus
}
#endif

#endif	/* IP_SESSION_ID_MANAGEMENT_H */

