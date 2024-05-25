#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h> //for isprint
#include <string.h>

void print_hex_line(const u_char *payload, int len, int offset, FILE *FileLog)
{
    int index;
    int gap;
    const u_char *ch;
    ch = payload;
    for (index = 0; index < len; index++)
    {
        fprintf(FileLog, "%02x ", *ch);
        ch++;

        if (index == 7)
            fprintf(FileLog, " ");
    }

    if (len < 8)
        fprintf(FileLog, " ");

    if (len < 16)
    {
        gap = 16 - len;
        for (index = 0; index < gap; index++)
        {
            fprintf(FileLog, "   ");
        }
    }
    fprintf(FileLog, "   ");

    ch = payload;
    for (index = 0; index < len; index++)
    {
        if (isprint(*ch))
            fprintf(FileLog, "%c", *ch);
        else
            fprintf(FileLog, ".");
        ch++;
    }

    fprintf(FileLog, "\n");

    return;
}

void print_hex_payload(const u_char *payload, int len, FILE *FileLog)
{
    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;
    int linebreak = 0;
    if (len <= 0)
        return;
    if (len <= line_width)
    {
        print_hex_line(ch, len, offset, FileLog);
        return;
    }
    for (;;)
    {
        line_len = line_width % len_rem;
        print_hex_line(ch, line_len, offset, FileLog);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_width;
        if (len_rem <= line_width)
        {
            print_hex_line(ch, len_rem, offset, FileLog);
            break;
        }
    }

    return;
}