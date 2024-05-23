#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../headers/payload_print.h"


#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)



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


void process_packet_udp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_udp *udp;
    const u_char *payload;
    FILE *FileLog = (FILE *)args;
    int size_ip;
    int size_udp;
    int size_payload;
    printf("\nPacket number %d:\n", count);
    count++;
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        return;
    }
    fprintf(FileLog,"\n\n");
    fprintf(FileLog, "\n");
    fprintf(FileLog, "####################################################### New Packet ###################################################\n");
   
    fprintf(FileLog, "IP address  From: %s\n", inet_ntoa(ip->ip_src));
    fprintf(FileLog, "IP address  To: %s\n", inet_ntoa(ip->ip_dst));
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
    size_udp = sizeof(struct sniff_udp);
    fprintf(FileLog, "\n");
    fprintf(FileLog, "UDP Header\n");
    fprintf(FileLog, "   |-Source Port      : %u\n", ntohs(udp->src_port));
    fprintf(FileLog, "   |-Destination Port : %u\n", ntohs(udp->dest_port));
    fprintf(FileLog, "   |-Checksum       : %d\n", ntohs(udp->checksum));
    fprintf(FileLog, "   |-length : %d\n", ntohs(udp->length));
    fprintf(FileLog, "\n");
    fprintf(FileLog, "                        DATA Dump                         ");
    fprintf(FileLog, "\n");

    
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
    if (size_payload > 0) {
        fprintf(FileLog," Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload, FileLog);
    }
    return;
}