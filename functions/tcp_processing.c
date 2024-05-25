#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>//for in_addr
#include <arpa/inet.h>//for ntohs and inet_ntoa
#include "../headers/payload_print.h"

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)// to extract the header length
#define TH_OFF(th) (((th)->data_offset & 0xf0) >> 4)// to extract the header length of tcp the using mask 11110000 and then shifting it to right by 4 bits



struct sniff_ethernet {
    u_char dest_mac[ETHER_ADDR_LEN]; 
    u_char src_mac[ETHER_ADDR_LEN]; 
    u_short ether_type; //type of protocol like ip4 or ip6
};
struct sniff_ip {
    u_char ip_vhl;//version is first 4 bits and header length is last 4 bits
    u_char ip_tos; 
    u_short ip_len; //datagram size
    u_short ip_id; 
    u_short ip_off; //tells whether the packet is fragmented or not
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
    u_char data_offset; //size of tcp header
    u_char flags;//flags like syn,ack,fin
  
    u_short window_size; 
    u_short checksum; 
    u_short urgent_pointer; //if some data needs to be processed early
};


void process_packet_tcp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
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
    fprintf(FileLog, "Packet number %d:\n", count);
    count++;
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        return;
    }
    // writing tcp header to the logfile
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
    fprintf(FileLog, "                        DATA                        ");
    fprintf(FileLog, "\n\n");

    
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp); //printing the payload
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0) {
        fprintf(FileLog,"Payload (%d bytes):\n", size_payload);
        fprintf(FileLog, "\n");
        print_payload(payload, size_payload, FileLog);
        fprintf(FileLog, "\n\n");
    }
    
    fprintf(FileLog, "####################################################### ------ ###################################################\n\n");

    return;
}