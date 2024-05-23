#ifndef SESS
#define SESS
#include <netinet/in.h> 
#include <stdio.h> 
#include <pcap.h> 

void filtercompilerandsetter(pcap_t *handle, char *filter_exp, bpf_u_int32 net);

pcap_t* session_create(char *devname,char *filter_exp);

char *get_device_name();


#endif 