#define _POSIX_C_SOURCE 199309L
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHUNK_SIZE (100*1024*1024) // 100MB
#define TEST_REPEAT_DEFAULT 3
#define FIXED_IV_HEX "0123456789abcdef0123456789abcdef" // 128bit (16B)

long long time_diff_ms(struct timespec start, struct timespec end) {
    long long ms = (end.tv_sec - start.tv_sec) * 1000LL;
    ms += (end.tv_nsec - start.tv_nsec) / 1000000LL;
    return ms;
}
void hex_to_bytes(const char *hexstr, unsigned char *bytes, int len) {
    for (int i = 0; i < len; ++i) {
        sscanf(hexstr + 2*i, "%2hhx", &bytes[i]);
    }
}
int main(int argc, char *argv[]) {
    // [encrypt|decrypt] [filename] [repeat]
    if (argc < 3) {
        printf("usage: %s [encrypt|decrypt] [inputfile] [repeat]\n", argv);
        return 1;
    }
    int do_encrypt = (strcmp(argv[1], "encrypt") == 0);
    int repeat = (argc > 3) ? atoi(argv[3]) : TEST_REPEAT_DEFAULT;
    
    int total_ms = 0;
    for (int n = 0; n < repeat; n++) {
        unsigned char *outbuf = malloc(CHUNK_SIZE + BLOCK_SIZE*2);
        int outlen = 0;
        struct timespec ts1, ts2;
        clock_gettime(CLOCK_MONOTONIC, &ts1);

    FILE *fp = fopen(argv[2], "rb");
    if (!fp) {
        printf("input file open failed\n");
        return 1;
    }

    unsigned char *inbuf = malloc(CHUNK_SIZE);
    if (!inbuf) {
        printf("malloc error\n");
        fclose(fp);
        return 1;
    }
    
    size_t rlen = fread(inbuf, 1, CHUNK_SIZE, fp);
    fclose(fp);
    if (rlen != CHUNK_SIZE) {
        printf("file size error: expected 100MB\n");
        free(inbuf);
        return 1;
    }

    // Key extraction
    uint8_t bits_buffer[1000000];
    int bit_len = extract_bits_from_image("capture.jpg", bits_buffer, sizeof(bits_buffer));
    if (bit_len < KEY_BYTES * 8) {
        printf("Insufficient extracted bits for key.\n");
        return 1;
    }

    // Conversion 0/1 to string
    char bin_key_str[KEY_BYTES * 8 + 1];
    for (int i = 0; i < KEY_BYTES * 8; i++) {
        bin_key_str[i] = bits_buffer[i] ? '1' : '0';
    }
    bin_key_str[KEY_BYTES * 8] = '\0';

    unsigned char key[KEY_BYTES];
    binstr_to_bytes(bin_key_str, key, KEY_BYTES);

    unsigned char iv[IV_BYTES];
    hex_to_bytes(FIXED_IV_HEX, iv, IV_BYTES);


        int ret = 0;
        if (do_encrypt)
            ret = encrypt_aes_192_cbc(key, iv, inbuf, CHUNK_SIZE, outbuf, &outlen);
        else
            ret = decrypt_aes_192_cbc(key, iv, inbuf, CHUNK_SIZE, outbuf, &outlen);

        clock_gettime(CLOCK_MONOTONIC, &ts2);
        free(inbuf);
        
        if (ret != 0) {
            printf("crypto failed at iter %d\n", n+1);
            free(outbuf);
            continue;
        }

        long long ms = time_diff_ms(ts1, ts2);
        printf("[%d] %s time: %lld ms\n", n+1, do_encrypt?"ENCRYPT":"DECRYPT", ms);
        total_ms += ms;
        free(outbuf);
    }
    printf("%s AVG: %.2f ms (%d trials)\n", do_encrypt?"ENCRYPT":"DECRYPT", (double)total_ms/repeat, repeat);
    
    

    return 0;
}
