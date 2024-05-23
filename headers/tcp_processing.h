#ifndef TCP_PRO
#define TCP_PRO
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
#endif