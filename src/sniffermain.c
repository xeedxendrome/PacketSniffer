#include <pcap.h>
#include "../headers/payload_print.h"
#include "../headers/udp_processing.h"
#include "../headers/session_creation.h"
#include "../headers/tcp_processing.h"
#include <string.h>

int main(int argc, char *argv[])
{
    char *devname;
    pcap_t *handle;
    FILE *FileLog;
    char filter_exp[10000];
    strcpy(filter_exp, argv[1]);
    devname = argv[2];
    FileLog = fopen("log.txt", "w");
    handle = session_create(devname, filter_exp);
    if (strcmp(argv[1], "udp") == 0)
    {
        pcap_loop(handle, 1000, process_packet_udp, (u_char *)FileLog);
    }
    else
        pcap_loop(handle, 10, process_packet_tcp, (u_char *)FileLog);
    pcap_close(handle);
    return (0);
}
