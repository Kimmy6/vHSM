// aes_crypto.c
// AES-192-CBC encrypt/decrypt using mbedTLS (replaces OpenSSL EVP).
// mbedtls_aes_crypt_cbc does NOT handle padding, so PKCS7 is applied manually.
#include "crypto.h"
#include <string.h>

// ── Encryption ──────────────────────────────────────────────────────────────
int encrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *plaintext, int plen,
                        unsigned char *ciphertext, int *ciphertext_len)
{
    // PKCS7 padding: pad up to next block boundary (minimum 1 byte)
    int pad_len   = BLOCK_SIZE - (plen % BLOCK_SIZE);
    int padded_len = plen + pad_len;

    if (padded_len > CIPHERTEXT_MAX_LEN) {
        printf("encrypt: padded plaintext exceeds CIPHERTEXT_MAX_LEN\n");
        return 1;
    }

    unsigned char padded[CIPHERTEXT_MAX_LEN];
    memcpy(padded, plaintext, plen);
    memset(padded + plen, (unsigned char)pad_len, pad_len);

    // mbedTLS updates the IV buffer in place during CBC — work on a copy
    unsigned char iv_copy[IV_BYTES];
    memcpy(iv_copy, iv, IV_BYTES);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    if (mbedtls_aes_setkey_enc(&ctx, key, KEY_BYTES * 8) != 0) {
        printf("encrypt: mbedtls_aes_setkey_enc failure\n");
        mbedtls_aes_free(&ctx);
        return 1;
    }

    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, padded_len,
                               iv_copy, padded, ciphertext) != 0) {
        printf("encrypt: mbedtls_aes_crypt_cbc failure\n");
        mbedtls_aes_free(&ctx);
        return 1;
    }

    *ciphertext_len = padded_len;
    mbedtls_aes_free(&ctx);
    return 0;
}

// ── Decryption ──────────────────────────────────────────────────────────────
int decrypt_aes_192_cbc(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *plaintext, int *plaintext_len)
{
    if (ciphertext_len <= 0 || ciphertext_len % BLOCK_SIZE != 0) {
        printf("decrypt: ciphertext length not a multiple of block size\n");
        return 1;
    }

    unsigned char iv_copy[IV_BYTES];
    memcpy(iv_copy, iv, IV_BYTES);

    // Decrypt into a temporary buffer before stripping padding
    unsigned char tmp[PLAINTEXT_MAX_LEN + BLOCK_SIZE];
    if (ciphertext_len > (int)sizeof(tmp)) {
        printf("decrypt: ciphertext too large\n");
        return 1;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    if (mbedtls_aes_setkey_dec(&ctx, key, KEY_BYTES * 8) != 0) {
        printf("decrypt: mbedtls_aes_setkey_dec failure\n");
        mbedtls_aes_free(&ctx);
        return 1;
    }

    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, ciphertext_len,
                               iv_copy, ciphertext, tmp) != 0) {
        printf("decrypt: mbedtls_aes_crypt_cbc failure\n");
        mbedtls_aes_free(&ctx);
        return 1;
    }

    mbedtls_aes_free(&ctx);

    // Remove PKCS7 padding — validate ALL padding bytes, not just the last one
    int pad = tmp[ciphertext_len - 1];
    if (pad < 1 || pad > BLOCK_SIZE) {
        printf("decrypt: invalid PKCS7 padding value %d\n", pad);
        return 1;
    }
    for (int i = 1; i < pad; i++) {
        if (tmp[ciphertext_len - 1 - i] != (unsigned char)pad) {
            printf("decrypt: corrupted PKCS7 padding\n");
            return 1;
        }
    }

    *plaintext_len = ciphertext_len - pad;
    memcpy(plaintext, tmp, *plaintext_len);
    return 0;
}
