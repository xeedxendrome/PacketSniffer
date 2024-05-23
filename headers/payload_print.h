#ifndef PAYLOADFUNC
#define PAYLOADFUNC


void print_hex_ascii_line(const u_char *payload, int len, int offset, FILE *FileLog);

void print_payload(const u_char *payload, int len,FILE *FileLog);

#endif 
