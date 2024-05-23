#ifndef TCPFUNC   
#define TCPFUNC
#include <netinet/in.h> 
#include <stdio.h> 

void print_hex_ascii_line(const u_char *payload, int len, int offset, FILE *FileLog);

void print_payload(const u_char *payload, int len,FILE *FileLog);

#endif 
