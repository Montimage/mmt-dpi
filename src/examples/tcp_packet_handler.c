/**
 * This example is intended to show a simple packet handler - print out the payload of received tcp packets. That is a callback function that will be called after the processing of every packet by the MMT core
 * 
 * 
 * Compile this example with:
 * 
 * $ gcc -g -o packet_handler packet_handler.c -lmmt_core -ldl -lpcap -lpthread
 * 
 * 
 * And get a data file (.pcap file) by using wireShark application to capture some packet.
 * 
 * Then execute the program:
 * 
 * $ ./packet_handler tcp_plugin_image.pcap
 * 
 * The example output result in the file: packhdler_output.txt
 * 
 * That is it!
 * 
 */

/* Add MMT test for some testing functions*/
// #include "mmt/mmt_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>
/* Add MMT-SDK */
#include "mmt_core.h"

void write_tcp_packet (const ipacket_t* ipacket)
{
	printf("Print payload of packet: %lu bytes\n", ipacket->packet_id);
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
       	printf("Print to file: %zu bytes\n", size_payload);
    }
}


void packet_handler(const ipacket_t * ipacket, void * user_args){
	uint32_t * p_len = (uint32_t *) get_attribute_extracted_data_by_name(ipacket,"META","PACKET_LEN");
	if(p_len){
        printf("Received packet of size %u of packet: %lu\n",*p_len,ipacket->packet_id);
		write_tcp_packet(ipacket);
	}
}

int main(int argc, char ** argv){
	mmt_handler_t *mmt_handler;// MMT handler
	char mmt_errbuf[1024];
	struct pkthdr header; // MMT packet header

	pcap_t *pcap;
	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[1024];

	//Initialize MMT
	init_extraction();

	//Initialize MMT handler
	mmt_handler =mmt_init_handler(DLT_EN10MB,0,mmt_errbuf);
	if(!mmt_handler){
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
		return EXIT_FAILURE;
	}
	//Register the protocol attributes we need
	register_extraction_attribute_by_name(mmt_handler,"META","PACKET_LEN"); //Request packet length. This is a META attribute

	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(mmt_handler,1,packet_handler, NULL);

	pcap = pcap_open_offline(argv[1],errbuf); // open offline trace
	if(!pcap){ /* pcap error? */
		fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
		return;
	}

	while((data=pcap_next(pcap,&p_pkthdr))){
		header.ts = p_pkthdr.ts;
		header.caplen = p_pkthdr.caplen;
		header.len = p_pkthdr.len;
		if(!packet_process(mmt_handler,&header,data)){
			fprintf(stderr, "Packet data extraction failure\n");
		}
	}

	//Close the MMT handler
	mmt_close_handler(mmt_handler);

	//Close MMT
	close_extraction();

	pcap_close(pcap);

	return EXIT_SUCCESS;

}
