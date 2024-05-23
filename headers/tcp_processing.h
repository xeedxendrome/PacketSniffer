#ifndef TCP_PRO
#define TCP_PRO

#include <pcap.h> 
typedef unsigned char u_char;
void process_packet_tcp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif