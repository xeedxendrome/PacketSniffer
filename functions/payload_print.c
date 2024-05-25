#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h> //for isprint
#include <string.h>

void print_ascii_line(const u_char *payload, int len, int offset, FILE *FileLog, int *line_break)
{
    int index;
    int gap;
    const u_char *ch;
    ch = payload;
    int linebr = *line_break;
    for (index = 0; index < len; index++)
    {
        if (isprint(*ch))
        {
            fprintf(FileLog, "%c", *ch);
            linebr = 0;
        }
        else
        {
            linebr++;
            if (linebr == 2)
            {
                fprintf(FileLog, "\n");
                linebr = 0;
            }
        }
        ch++;
    }
    *line_break = linebr;

    return;
}
void print_payload(const u_char *payload, int len, FILE *FileLog)
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
        print_ascii_line(ch, len, offset, FileLog, &linebreak);
        return;
    }
    for (;;)
    {
        line_len = line_width % len_rem;
        print_ascii_line(ch, line_len, offset, FileLog, &linebreak);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_width;
        if (len_rem <= line_width)
        {
            print_ascii_line(ch, len_rem, offset, FileLog, &linebreak);
            break;
        }
    }

    return;
}