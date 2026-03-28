#include "crypto.h"

int decrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        printf("EVP_CIPHER_CTX_new failure!\n");
        return 1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv)) {
        printf("EVP_DecryptInit_ex failure!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len;

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("EVP_DecryptUpdate failure!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    *plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        printf("EVP_DecryptFinal_ex failure!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
