#include "crypto.h"
#include <ctype.h>

void binstr_to_bytes(const char *binstr, unsigned char *keybuf, int keylen) {
    for(int i=0; i<keylen; i++) {
        unsigned char b = 0;
        for(int j=0; j<8; j++) {
            b <<= 1 ;
            if(binstr[i*8+j] == '1') b |= 1;
        }
        keybuf[i] = b;
    }
}

int hexstr_to_bytes(const char *hexstr, unsigned char *buf, int max_len) {
    int len = strlen(hexstr);
    if(len % 2 != 0) return -1; // odd length error
    int byte_len = len / 2;
    if(byte_len > max_len) return -1;

    for(int i = 0; i < byte_len; i++) {
        sscanf(hexstr + 2*i, "%2hhx", &buf[i]);
    }
    return byte_len;
}

void print_hex(const unsigned char *buf, int len) {
    for(int i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}
