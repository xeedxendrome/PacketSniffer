#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../headers/hex_decimal_payload.h"
#include "../headers/tcp_processing.h"

void process_packet_udp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
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
    fprintf(FileLog, "Packet number %d:\n", count);
    count++;
    ethernet = (struct sniff_ethernet *)(packet);
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20)
    {
        return;
    }

    fprintf(FileLog, "\n\n"); // udp headers being logged to a file
    fprintf(FileLog, "IP address  From: %s\n", inet_ntoa(ip->ip_src));
    fprintf(FileLog, "IP address  To: %s\n", inet_ntoa(ip->ip_dst));
    udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
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

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp); // packets being logged to a file
    size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
    if (size_payload > 0)
    {
        fprintf(FileLog, " Payload (%d bytes):\n", size_payload);
        print_hex_payload(payload, size_payload, FileLog);
        fprintf(FileLog, "\n\n");
    }
    fprintf(FileLog, "####################################################### ------ ###################################################\n\n");
    return;
}