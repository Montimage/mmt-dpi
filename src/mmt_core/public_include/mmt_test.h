/**
* MMT_TEST provides some useful testing/debugging function
*
*/
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
#include "data_defs.h" 
/**
 * Print payload field of a tcp packet
 */
void write_tcp_packet(const ipacket_t * ipacket);
