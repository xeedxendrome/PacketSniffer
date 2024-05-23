#ifndef SESS
#define SESS


void filtercompilerandsetter(pcap_t *handle, char *filter_exp, bpf_u_int32 net);

pcap_t* session_create(char *devname,char *filter_exp);

char *get_device_name();


#endif 