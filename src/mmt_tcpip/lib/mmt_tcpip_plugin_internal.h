/*
 * File:   mmt_tcpip_plugin_internal.h
 * Author: montimage
 *
 * Created on December 6, 2012, 4:56 PM
 */

#ifndef MMT_TCPIP_PLUGIN_INTERNAL_H
#define MMT_TCPIP_PLUGIN_INTERNAL_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "mmt_core.h"
#include "mmt_tcpip_internal_defs_macros.h"
#include "mmt_tcpip_plugin_structs.h"
#include "protocols/tcp.h"

static int seen = 1;

/**
 * Generic function for setting the content type of a flow.
 * @param ipacket the mmt packet structure
 * @param content_class the detected content class
 * @param content_type the detected content type
 */
void mmt_add_content_type(ipacket_t * ipacket, uint16_t content_class, uint16_t content_type);

/* generic function for setting a protocol for a flow
 *
 * what it does is:
 * 1.call mmt_int_change_protocol
 * 2.set protocol in detected bitmask for src and dst
 */
void mmt_internal_add_connection(ipacket_t * ipacket, uint16_t detected_protocol, mmt_protocol_type_t protocol_type);

/* generic function for changing the flow protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 */
void mmt_change_internal_flow_protocol(ipacket_t * ipacket, uint16_t detected_protocol, mmt_protocol_type_t protocol_type);

/* generic function for changing the packetprotocol
 *
 * what it does is:
 * 1.update the packet protocol stack with the new protocol
 */
void mmt_change_internal_packet_protocol(ipacket_t * ipacket, uint16_t detected_protocol, mmt_protocol_type_t protocol_type);

static inline uint32_t
check_local_proto_by_port_nb(uint16_t portnb, mmt_server_local_proto_t * local_protos) {
    index_t i = local_protos->index;
    int count = 0;
    //while(count < 64 && local_protos->port_proto_mapping[i.index].port != 0) {^M
    while (count < 64) {
        if (local_protos->port_proto_mapping[i.index].port == portnb) {
            return local_protos->port_proto_mapping[i.index].appproto;
        }
        count ++;
        i.index ++;
    }
    return 0;
}

static inline void
insert_to_local_protos(uint16_t portnb, uint32_t appproto, uint16_t l4proto, mmt_server_local_proto_t * local_protos) {
    if (check_local_proto_by_port_nb(portnb, local_protos) == 0) {
        local_protos->port_proto_mapping[local_protos->index.index].port = portnb;
        local_protos->port_proto_mapping[local_protos->index.index].appproto = appproto;
        local_protos->port_proto_mapping[local_protos->index.index].l4proto = l4proto;
        local_protos->index.index ++;
    }
}

static inline void
set_local_conv_proto(ipacket_t * ipacket, uint32_t proto, struct mmt_tcpip_internal_packet_struct * packet) {
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;
    src->conv_proto.last_seen = ipacket->p_hdr->ts;
    src->conv_proto.proto = proto;
    dst->conv_proto.last_seen = ipacket->p_hdr->ts;
    dst->conv_proto.proto = proto;
}

static inline uint32_t
get_local_conv_proto(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = (mmt_tcpip_internal_packet_t *) ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = packet->src;
    struct mmt_internal_tcpip_id_struct *dst = packet->dst;
    uint32_t src_conv_proto = 0;
    uint32_t dest_conv_proto = 0;
    if ((ipacket->p_hdr->ts.tv_sec - src->conv_proto.last_seen.tv_sec) < 20 /* Max time difference is 2 seconds */) src_conv_proto = src->conv_proto.proto;
    if ((ipacket->p_hdr->ts.tv_sec - dst->conv_proto.last_seen.tv_sec) < 20 /* Max time difference is 2 seconds */) dest_conv_proto = dst->conv_proto.proto;
    //We return the proto if:
    //(1) One conv proto is not null while the other is null
    //(2) Both protos are not zero and they are equal
    if ((src_conv_proto | dest_conv_proto) /* Both are not null */ &&
            (((src_conv_proto ^ dest_conv_proto) == 0 /* they are equal */)
             || ((src_conv_proto ^ dest_conv_proto) == (src_conv_proto | dest_conv_proto) /* one is zero the other is not */))) {
        return src_conv_proto | dest_conv_proto; /*If equal Oring them is equal to them, if one is zero Oring them is equal to the non zero */
    }
    return PROTO_UNKNOWN;
}

/* generic function for changing the protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 * 2.update the packet protocol stack with the new protocol
 */
static inline void
mmt_change_internal_flow_packet_protocol(ipacket_t * ipacket, uint16_t detected_protocol, mmt_protocol_type_t protocol_type)
{
    mmt_change_internal_flow_protocol(ipacket, detected_protocol, protocol_type);
    mmt_change_internal_packet_protocol(ipacket, detected_protocol, protocol_type);
}

static inline void
mmt_set_flow_protocol_to_packet(struct mmt_internal_tcpip_session_struct *flow,
                                struct mmt_tcpip_internal_packet_struct *packet) {
    memcpy(&packet->detected_protocol_stack[0],
           &flow->detected_protocol_stack[0], sizeof (packet->detected_protocol_stack));
#if PROTOCOL_HISTORY_SIZE > 1
    memcpy(&packet->protocol_stack_info, &flow->protocol_stack_info, sizeof (packet->protocol_stack_info));
#endif
}

/* turns a packet back to unknown */
static inline void
mmt_reset_internal_packet_protocol(struct mmt_tcpip_internal_packet_struct *packet)
{
    packet->detected_protocol_stack[0] = PROTO_UNKNOWN;

#if PROTOCOL_HISTORY_SIZE > 1
    packet->protocol_stack_info.current_stack_size_minus_one = 0;
    packet->protocol_stack_info.entry_is_real_protocol = 0;
#endif
}

static inline void
mmt_connection_tracking(ipacket_t * ipacket, unsigned index) {
    /* const for gcc code optimisation and cleaner code */
    struct mmt_tcpip_internal_packet_struct *packet = (mmt_tcpip_internal_packet_t *) ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    mmt_session_t * session = ipacket->session;
    if (flow == NULL)
        return;

    // const struct iphdr *iph = packet->iph;

// #ifdef MMT_SUPPORT_IPV6

//     const struct mmt_ipv6hdr *iphv6 = packet->iphv6;

// #endif
    const struct tcphdr *tcph = packet->tcp;
    // const struct udphdr *udph = packet->udp;

    // uint8_t proxy_enabled = 0;

    packet->tcp_retransmission = 0;
    // packet->packet_direction = 0;

    // packet->packet_direction = H2L_DIRECTION;


    // if (iph != NULL && iph->saddr < iph->daddr)
    //         packet->packet_direction = L2H_DIRECTION;

    // #ifdef MMT_SUPPORT_IPV6
    //     if (iphv6 != NULL && MMT_COMPARE_IPV6_ADDRESSES(&iphv6->saddr, &iphv6->daddr) != 0)
    //         packet->packet_direction = L2H_DIRECTION;
    // #endif


    packet->packet_lines_parsed_complete = 0;
    packet->packet_unix_lines_parsed_complete = 0;
    packet->parsed_lines = 0;
    packet->https_server_name.ptr = NULL;
    packet->https_server_name.len = 0;

    // if (flow == NULL)
    //     return;


    // if (ipacket->session->init_finished == 0) {
    //     ipacket->session->init_finished = 1;
    //     ipacket->session->setup_packet_direction = packet->packet_direction;
    // }


    if (tcph != NULL) {
        /* reset retried bytes here before setting it */
        packet->num_retried_bytes = 0;
       struct mmt_internal_tcp_session_struct * flow_l4_tcp = &flow->l4.tcp;
        if(flow_l4_tcp->seen_ack == 0){
            if(tcph->syn != 0 && flow_l4_tcp->seen_syn_ack == 0){
                if(tcph->ack == 0 && flow_l4_tcp->seen_syn == 0){
                    flow_l4_tcp->seen_syn = 1;
                    flow_l4_tcp->rtt.tv_sec = ipacket->p_hdr->ts.tv_sec;
                    flow_l4_tcp->rtt.tv_usec = ipacket->p_hdr->ts.tv_usec;

                    fire_attribute_event(ipacket, PROTO_TCP, TCP_SYN_RCV, index, (void *) &seen);
                }

                if(tcph->ack != 0 && flow_l4_tcp->seen_syn == 1){
                    flow_l4_tcp->seen_syn_ack = 1;
                }
            }

            if (tcph->syn == 0 && tcph->ack == 1 && flow_l4_tcp->seen_syn == 1 && flow_l4_tcp->seen_syn_ack == 1) {
                flow_l4_tcp->seen_ack = 1;

                fire_attribute_event(ipacket, PROTO_TCP, TCP_CONN_ESTABLISHED, index, (void *) &seen);

                if (flow_l4_tcp->rtt.tv_sec != 0) {
                    session->rtt.tv_sec = ipacket->p_hdr->ts.tv_sec - flow_l4_tcp->rtt.tv_sec;
                    session->rtt.tv_usec = ipacket->p_hdr->ts.tv_usec - flow_l4_tcp->rtt.tv_usec;

                    if ((int) session->rtt.tv_usec < 0) {
                        session->rtt.tv_usec += 1000000;
                        session->rtt.tv_sec -= 1;
                    }

                    fire_attribute_event(ipacket, PROTO_TCP, TCP_RTT, index, (void *) &session->rtt);
                }
            }
        }

        // TCP connection closing flags.
        // The order is important
        if (tcph->ack != 0 && flow_l4_tcp->seen_fin != 0 && flow_l4_tcp->seen_fin_ack != 0) {
            flow_l4_tcp->seen_close = 1;
            session->force_timeout = 1;

            fire_attribute_event(ipacket, PROTO_TCP, TCP_CONN_CLOSED, index, (void *) &seen);

        }
        if(tcph->fin != 0){
            if (tcph->ack != 0 && flow_l4_tcp->seen_fin != 0) {
                flow_l4_tcp->seen_fin_ack = 1;
            }
            if (flow_l4_tcp->seen_fin == 0) {
                flow_l4_tcp->seen_fin = 1;

                set_session_timeout_delay(session, ipacket->mmt_handler->default_session_timed_out);

            }
        }

        if (tcph->rst) {
            set_session_timeout_delay(session, ipacket->mmt_handler->short_session_timed_out);
        }

        if ((session->next_tcp_seq_nr[0] == 0 && session->next_tcp_seq_nr[1] == 0)) {
            /* initalize tcp sequence counters */
            /* the ack flag needs to be set to get valid sequence numbers from the other
             * direction. Usually it will catch the second packet syn+ack but it works
             * also for asymmetric traffic where it will use the first data packet
             *
             * if the syn flag is set add one to the sequence number,
             * otherwise use the payload length.
             */
            if (tcph->ack != 0) {
                session->next_tcp_seq_nr[session->last_packet_direction] = ntohl(tcph->seq) + (tcph->syn ? 1 : packet->payload_packet_len);
                session->next_tcp_seq_nr[1 - session->last_packet_direction] = ntohl(tcph->ack_seq);
                    // debug("TCP: set next seq number = %d for ipacket: %lu (seq: %d)", session->next_tcp_seq_nr[session->last_packet_direction], ipacket->packet_id, ntohl(tcph->seq));
            }
            //  ntohs(packet->iph->tot_len) + packet->payload_packet_len + 14 == 60  -> padding packet
        } else if (packet->payload_packet_len > 0 && ( (packet->iph != NULL) && (ntohs(packet->iph->tot_len) + packet->payload_packet_len + 14 != 60))) {
            /* check tcp sequence counters */
            uint32_t next_seq_nb = session->next_tcp_seq_nr[session->last_packet_direction];
            uint32_t temp_seq_number = ((uint32_t) (ntohl(tcph->seq) - next_seq_nb));

            if ( temp_seq_number > 0 && next_seq_nb > 0) {
                packet->tcp_outoforder = 1;
                session->tcp_outoforders += 1;
            } else {
                packet->tcp_outoforder = 0;
            }
            if (temp_seq_number > MMT_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE) {
                // debug("TCP: set tcp_retransmission = 1 for ipacket: %lu", ipacket->packet_id);
                packet->tcp_retransmission = 1;
                session->tcp_retransmissions += 1;

                /*CHECK IF PARTIAL RETRY IS HAPPENENING */
                if ((next_seq_nb - ntohl(tcph->seq) < packet->payload_packet_len)) {
                    /* num_retried_bytes actual_payload_len hold info about the partial retry
                       analyzer which require this info can make use of this info
                       Other analyzer can use packet->payload_packet_len */
                    packet->num_retried_bytes = next_seq_nb - ntohl(tcph->seq);
                    packet->actual_payload_len = packet->payload_packet_len - packet->num_retried_bytes;
                    session->next_tcp_seq_nr[session->last_packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
                    // debug("TCP: set next seq number = %d for ipacket: %lu (seq: %d)", session->next_tcp_seq_nr[session->last_packet_direction], ipacket->packet_id, ntohl(tcph->seq));
                }
            }/*normal path actual_payload_len is initialized to payload_packet_len during tcp header parsing itself. It will be changed only in case of retransmission */
            else {
                packet->num_retried_bytes = 0;
                session->next_tcp_seq_nr[session->last_packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
                // debug("TCP: set next seq number = %d for ipacket: %lu (seq: %d)", session->next_tcp_seq_nr[session->last_packet_direction], ipacket->packet_id, ntohl(tcph->seq));
            }
        }

        if (tcph->rst) {
            session->next_tcp_seq_nr[0] = 0;
            session->next_tcp_seq_nr[1] = 0;
        }
    }

    if (packet->payload_packet_len) {
        // Update session statistics
        session->data_packet_count++;
        session->data_byte_volume += packet->payload_packet_len;
        session->data_packet_count_direction[session->last_packet_direction]++;
        session->data_byte_volume_direction[session->last_packet_direction] += packet->payload_packet_len;
        mmt_session_t * p_session = session->parent_session;
        while (p_session)
        {
            uint8_t direction = p_session->last_packet_direction;
            p_session->sub_data_packet_count++;
            p_session->sub_data_byte_volume += packet->payload_packet_len;
            p_session->sub_data_packet_count_direction[direction]++;
            p_session->sub_data_byte_volume_direction[direction] += packet->payload_packet_len;
            p_session = p_session->parent_session;
        }
        if ((ipacket->internal_packet->iph == NULL) || (ntohs(ipacket->internal_packet->iph->tot_len) + ipacket->internal_packet->payload_packet_len + 14 != 60)) {
            session->s_last_data_packet_time[session->last_packet_direction].tv_sec = ipacket->p_hdr->ts.tv_sec;
            session->s_last_data_packet_time[session->last_packet_direction].tv_usec = ipacket->p_hdr->ts.tv_usec;
        }
        // debug("[DIRECTION] packet: %lu,%u\n",ipacket->packet_id,session->last_packet_direction);
    }
}

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_TCPIP_PLUGIN_INTERNAL_H */

