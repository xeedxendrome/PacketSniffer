#ifndef PAYLOADFUNC
#define PAYLOADFUNC


void print_ascii_line(const u_char *payload, int len, int offset, FILE *FileLog , int *line_break);

void print_payload(const u_char *payload, int len,FILE *FileLog);

#endif 
