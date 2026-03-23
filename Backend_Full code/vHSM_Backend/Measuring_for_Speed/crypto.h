#ifdef __cplusplus
extern "C" {
#endif

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define KEY_BYTES 24
#define IV_BYTES 16
#define BLOCK_SIZE 16

#define KEY_NUM 80
#define KEY_STR_LEN (KEY_BYTES * 8)
#define PLAINTEXT_MAX_LEN 1024
#define CIPHERTEXT_MAX_LEN 2048

void binstr_to_bytes(const char *binstr, unsigned char *keybuf, int keylen);
int hexstr_to_bytes(const char *hexstr, unsigned char *buf, int max_len);
void print_hex(const unsigned char *buf, int len);

int encrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *plaintext, int plen,
                        unsigned char *ciphertext, int *ciphertext_len);

int decrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *plaintext, int *plaintext_len);

#endif // CRYPTO_H

#ifdef __cplusplus
}
#endif