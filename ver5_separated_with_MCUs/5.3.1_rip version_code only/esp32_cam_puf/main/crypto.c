// crypto.c — utility helpers (ported from Pi version; no changes needed)
#include "crypto.h"
#include <ctype.h>

void binstr_to_bytes(const char *binstr, unsigned char *keybuf, int keylen)
{
    for (int i = 0; i < keylen; i++) {
        unsigned char b = 0;
        for (int j = 0; j < 8; j++) {
            b <<= 1;
            if (binstr[i * 8 + j] == '1') b |= 1;
        }
        keybuf[i] = b;
    }
}

int hexstr_to_bytes(const char *hexstr, unsigned char *buf, int max_len)
{
    int len = (int)strlen(hexstr);
    if (len % 2 != 0) return -1;
    int byte_len = len / 2;
    if (byte_len > max_len) return -1;

    for (int i = 0; i < byte_len; i++) {
        unsigned char hi = (unsigned char)hexstr[2 * i];
        unsigned char lo = (unsigned char)hexstr[2 * i + 1];

        if      (hi >= '0' && hi <= '9') hi = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hi = hi - 'A' + 10;
        else return -1;

        if      (lo >= '0' && lo <= '9') lo = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lo = lo - 'A' + 10;
        else return -1;

        buf[i] = (unsigned char)((hi << 4) | lo);
    }
    return byte_len;
}

void print_hex(const unsigned char *buf, int len)
{
    for (int i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}
