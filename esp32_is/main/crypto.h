#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "mbedtls/aes.h"  // replaces openssl/aes.h + openssl/evp.h

#define KEY_BYTES  24   // AES-192: 24 bytes = 192 bits
#define IV_BYTES   16   // AES block size
#define BLOCK_SIZE 16

#define PLAINTEXT_MAX_LEN   1024
#define CIPHERTEXT_MAX_LEN  2048  // plaintext + 1 block of PKCS7 padding

void binstr_to_bytes(const char *binstr, unsigned char *keybuf, int keylen);
int  hexstr_to_bytes(const char *hexstr, unsigned char *buf, int max_len);
void print_hex(const unsigned char *buf, int len);

int encrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *plaintext, int plen,
                        unsigned char *ciphertext, int *ciphertext_len);

int decrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *plaintext, int *plaintext_len);

#endif // CRYPTO_H
