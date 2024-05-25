#ifndef HEXPAYLOADFUNC
#define HEXPAYLOADFUNC

void print_ascii_line(const u_char *payload, int len, int offset, FILE *FileLog);

void print_hex_payload(const u_char *payload, int len,FILE *FileLog);

#endif 