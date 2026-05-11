#include "crypto.h"

int encrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *plaintext, int plen,
                        unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        printf("EVP_CIPHER_CTX_new failure!\n");
        return 1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv)) {
        printf("EVP_EncryptInit_ex failure!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plen)) {
        printf("EVP_EncryptUpdate failure!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    *ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("EVP_EncryptFinal_ex failure!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}