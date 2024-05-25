#ifndef UDP_PRO
#define UDP_PRO

#include <pcap.h>

typedef unsigned char u_char;

void process_packet_udp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
// first parameter is same as last parameter in the pcap_loop function,in this specific case it is a file pointer to log file second it header and third is the pointer to the packet passed to it
// it seperates the packet into ethernet header,ip header and udp header and prints the source and destination ip and port and then prints the payload of udp

#endif