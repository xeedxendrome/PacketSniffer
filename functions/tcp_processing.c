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
#define TH_OFF(th) (((th)->data_offset & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define IP_RF 0x8000 
#define IP_DF 0x4000 
#define IP_MF 0x2000 
#define IP_OFFMASK 0x1fff 


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

typedef u_int tcp_sequence;
struct sniff_tcp {
    
    u_short src_port; 
    u_short dest_port; 
    tcp_sequence sequence_number; 
    tcp_sequence ack_number; 
    u_char data_offset; 
    u_char flags;
  
    u_short window_size; 
    u_short checksum; 
    u_short urgent_pointer; 
};


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const u_char *payload;
    FILE *FileLog = (FILE *)args;
    int size_ip;
    int size_tcp;
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
    fprintf(FileLog, "IP address  From: %s\n", inet_ntoa(ip->ip_src));
    fprintf(FileLog, "IP address  To: %s\n", inet_ntoa(ip->ip_dst));
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    fprintf(FileLog, "\n");
    fprintf(FileLog, "TCP Header\n");
    fprintf(FileLog, "   |-Source Port      : %u\n", ntohs(tcp->src_port));
    fprintf(FileLog, "   |-Destination Port : %u\n", ntohs(tcp->dest_port));
    fprintf(FileLog, "   |-Sequence Number    : %u\n", ntohl(tcp->sequence_number));
    fprintf(FileLog, "   |-Acknowledge Number : %u\n", ntohl(tcp->ack_number));
    fprintf(FileLog, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcp->data_offset, (unsigned int)tcp->data_offset * 4);
    fprintf(FileLog, "   |-Window         : %d\n", ntohs(tcp->window_size));
    fprintf(FileLog, "   |-Checksum       : %d\n", ntohs(tcp->checksum));
    fprintf(FileLog, "   |-Urgent Pointer : %d\n", tcp->urgent_pointer);
    fprintf(FileLog, "\n");
    fprintf(FileLog, "                        DATA Dump                         ");
    fprintf(FileLog, "\n");

    
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0) {
        fprintf(FileLog," Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload, FileLog);
    }
    return;
}