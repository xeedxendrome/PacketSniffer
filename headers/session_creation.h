#ifndef SESS
#define SESS


void filtercompilerandsetter(pcap_t *handle, char *filter_exp, bpf_u_int32 net); // compile and set the filter for the session created by pcap_open_live

pcap_t* session_create(char *devname,char *filter_exp); // create a session for sniffing on the device selected by user by using pcap_open_live

char *get_device_name();// search for available devices to sniff on  and return the name of the device selected by user

int get_filter(); // get the choice of filter from user(tcp or udp)


#endif 