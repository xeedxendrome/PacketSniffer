#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../headers/payload_print.h"
#include "../headers/udp_processing.h"
#include "../headers/session_creation.h"
#include "../headers/tcp_processing.h"
#include <string.h>


FILE *FileLog;

int main() {
    char *devname;
    pcap_t *handle;
    
    char filter_exp[] = "tcp";
    int filtervalue=get_filter();
    FileLog = fopen("log.txt", "w");
    devname = get_device_name();
    if(filtervalue){
        strcpy(filter_exp, "udp");
    }
    handle = session_create(devname, filter_exp);
    if (filtervalue) {
  
        pcap_loop(handle, 1000, process_packet_udp, (u_char*)FileLog);
    }
    else
    pcap_loop(handle, 1000, process_packet_tcp, (u_char*)FileLog);
    pcap_close(handle);
    return(0);
}
