/**
* MMT_TEST provides some useful testing/debugging function
*
*/

#include "mmt_test.h"

void write_tcp_packet (const ipacket_t* ipacket)
{
    debug("Write data of packet: %lu",ipacket->packet_id);
    int fd=0;
    char path[1024] = {0};
    int len = 0;
    struct ip   *iphdr = 0;
    struct tcphdr       *tcp = 0;
    size_t              size_ip;
    size_t              total_len;
    size_t              size_tcp;
    size_t              size_payload;
    unsigned char       *payload;

    iphdr =(struct ip*)(ipacket->data+14);
    if((size_ip = iphdr->ip_hl * 4)<sizeof(struct ip))  return ;
    if(iphdr->ip_p!=IPPROTO_TCP)        return;
    total_len = ntohs( iphdr->ip_len );
    tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
    if((size_tcp = tcp->th_off * 4)<sizeof(struct tcphdr))      return;
    size_payload = total_len - ( size_ip + size_tcp );
    if(size_payload==0)         return;

    snprintf ( path , sizeof(path) , "%s:%d-" , inet_ntoa(*(struct in_addr*)&(iphdr->ip_src.s_addr)),ntohs(tcp->th_sport));
    len = strlen(path);
    snprintf ( &path[len] , sizeof(path) - len, "%s:%d" , inet_ntoa(*(struct in_addr*)&(iphdr->ip_dst.s_addr)),ntohs(tcp->th_dport));
    if ((fd = open ( strndup ( path , sizeof(path) ), O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 )
    {
        fprintf ( stderr , "\n[e] Error %d writting data to \"%s\": %s" , errno ,strndup (path , sizeof(path)) , strerror( errno ) );
        return;
    }
    payload = (unsigned char *)iphdr + size_ip + size_tcp;
    if(size_payload>0){
        write ( fd , payload , size_payload);
    }
}

