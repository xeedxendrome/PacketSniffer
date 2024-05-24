#ifndef TCP_PRO
#define TCP_PRO

#include <pcap.h> 
typedef unsigned char u_char;
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

struct sniff_ethernet {
    u_char dest_mac[ETHER_ADDR_LEN]; 
    u_char src_mac[ETHER_ADDR_LEN]; 
    u_short ether_type; 
};
struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos; 
    u_short ip_len; 
    u_short ip_id; 
    u_short ip_off; 
    u_char ip_ttl; 
    u_char ip_protocol; 
    u_short ip_checksum; 
    struct in_addr ip_src,ip_dst; 
};


struct sniff_udp {
    
    u_short src_port; 
    u_short dest_port; 
    u_short length;
    u_short checksum; 
   
};

void process_packet_tcp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
//first parameter is same as last parameter in the pcap_loop function,in this specific case it is a file pointer to log file second it header and third is the pointer to the packet passed to it
//it seperates the packet into ethernet header,ip header and tcp header and prints the source and destination ip and port and then prints the payload of tcp
#endif