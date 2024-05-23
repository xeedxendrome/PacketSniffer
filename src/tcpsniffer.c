#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../headers/payload_print.h"
#include "../headers/tcp_processing.h"
#include "../headers/session_creation.h"


FILE *FileLog;

int main() {
    char *devname;
    pcap_t *handle;
    char filter_exp[] = "tcp";
    FileLog = fopen("log.txt", "w");
    devname = get_device_name();
    handle = session_create(devname, filter_exp);
    pcap_loop(handle, 1000, process_packet, (u_char*)FileLog);
    pcap_close(handle);
    return(0);
}
