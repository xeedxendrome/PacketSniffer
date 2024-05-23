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
void filtercompilerandsetter(pcap_t *handle, char *filter_exp, bpf_u_int32 net) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        exit(1);
    }
    return;
}
pcap_t* session_create(char *devname,char *filter_exp) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(devname, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(devname,  65536 , 0, 1000, errbuf);
    
    filtercompilerandsetter(handle, filter_exp, net);
    return handle;
}
char *get_device_name() {
    pcap_if_t *alldevsp , *device;
    char *devname , devs[100][100];
    int count = 1 , n;
    char errbuf[PCAP_ERRBUF_SIZE];
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) ) {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next) {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL) {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];
    return devname;
}