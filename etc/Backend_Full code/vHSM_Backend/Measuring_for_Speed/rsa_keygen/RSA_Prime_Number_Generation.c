#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// 1. Read entropy bits from file into buffer
int read_entropy(const char *filename, uint8_t *buffer, size_t bit_len) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;
    memset(buffer, 0, (bit_len + 7) / 8);
    size_t bits_read = 0;
    while (bits_read < bit_len) {
        int c = fgetc(f);
        if (c == EOF) {
            fclose(f);
            return 0;
        }
        if (c != '0' && c != '1') continue;  // ignore non-bits
        if (c == '1') buffer[bits_read / 8] |= (1 << (7 - (bits_read % 8)));
        bits_read++;
    }
    fclose(f);
    return 1;
}

// 2. AES-128 CTR_DRBG context and functions
typedef struct {
    AES_KEY aes_key;
    uint8_t V[16];
} CTR_DRBG_CTX;

void increment_counter(uint8_t *ctr) {
    for (int i = 15; i >= 0; i--) {
        if (++ctr[i] != 0) break;
    }
}

void ctr_drbg_instantiate(CTR_DRBG_CTX *ctx, const uint8_t *seed) {
    AES_set_encrypt_key(seed, 128, &ctx->aes_key);
    memset(ctx->V, 0, 16);
    ctx->V[14] = seed[16];
    ctx->V[15] = seed[17];
}

void ctr_drbg_generate(CTR_DRBG_CTX *ctx, uint8_t *out, size_t outlen) {
    uint8_t block[16];
    size_t generated = 0;
    while (generated < outlen) {
        increment_counter(ctx->V);
        AES_encrypt(ctx->V, block, &ctx->aes_key);
        size_t copy_len = (outlen - generated < 16) ? (outlen - generated) : 16;
        memcpy(out + generated, block, copy_len);
        generated += copy_len;
    }
}

// 3. Generate 1024-bit random odd number candidate for prime
void generate_1024bit_random(CTR_DRBG_CTX *ctx, BIGNUM *num) {
    uint8_t buffer[128];
    ctr_drbg_generate(ctx, buffer, 128);
    buffer[0] |= 0x80;   // set MSB for 1024 bits
    buffer[127] |= 0x01; // ensure odd
    BN_bin2bn(buffer, 128, num);
}

// 4. Miller-Rabin primality test wrapper
int is_prime(BIGNUM *num) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;
    int ret = BN_is_prime_ex(num, 20, ctx, NULL);
    BN_CTX_free(ctx);
    return ret == 1;
}

// 5. RSA key generation with error checks, returns 1 on success
int rsa_key_generate(CTR_DRBG_CTX *ctx, BIGNUM **p, BIGNUM **q,
                     BIGNUM **n, BIGNUM **e, BIGNUM **d) {
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) return 0;

    *p = BN_new();
    *q = BN_new();
    *n = BN_new();
    *e = BN_new();
    *d = BN_new();

    if (!(*p && *q && *n && *e && *d)) {
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BN_set_word(*e, 65537);

    do {
        generate_1024bit_random(ctx, *p);
    } while (!is_prime(*p));

    do {
        generate_1024bit_random(ctx, *q);
    } while (!is_prime(*q));

    if (!BN_mul(*n, *p, *q, bn_ctx)) {
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();
    BIGNUM *phi = BN_new();
    if (!p1 || !q1 || !phi) {
        BN_free(p1);
        BN_free(q1);
        BN_free(phi);
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BN_sub(p1, *p, BN_value_one());
    BN_sub(q1, *q, BN_value_one());
    BN_mul(phi, p1, q1, bn_ctx);

    if (!BN_mod_inverse(*d, *e, phi, bn_ctx)) {
        fprintf(stderr, "BN_mod_inverse failed: e not coprime with phi.\n");
        BN_free(p1);
        BN_free(q1);
        BN_free(phi);
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BN_free(p1);
    BN_free(q1);
    BN_free(phi);
    BN_CTX_free(bn_ctx);
    return 1;
}

// 6. Build RSA object and compute CRT parameters
RSA *rsa_build_key(BIGNUM *p, BIGNUM *q, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    RSA *rsa = RSA_new();
    if (!rsa) return NULL;

    if (!RSA_set0_factors(rsa, BN_dup(p), BN_dup(q))) {
        RSA_free(rsa);
        return NULL;
    }
    if (!RSA_set0_key(rsa, BN_dup(n), BN_dup(e), BN_dup(d))) {
        RSA_free(rsa);
        return NULL;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        RSA_free(rsa);
        return NULL;
    }

    BIGNUM *dmp1 = BN_new();
    BIGNUM *dmq1 = BN_new();
    BIGNUM *iqmp = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();

    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());

    BN_mod(dmp1, d, p1, ctx);
    BN_mod(dmq1, d, q1, ctx);
    BN_mod_inverse(iqmp, q, p, ctx);

    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

    BN_free(p1);
    BN_free(q1);
    BN_CTX_free(ctx);

    return rsa;
}

int main() {
    clock_t start = clock();

    uint8_t entropy[18]; // 144 bits
    if (!read_entropy("entropy.txt", entropy, 144)) {
        fprintf(stderr, "Entropy file read error\n");
        return 1;
    }

    printf("Loaded entropy (hex): ");
    for (int i = 0; i < 18; i++) printf("%02X", entropy[i]);
    printf("\n");

    CTR_DRBG_CTX drbg_ctx;
    ctr_drbg_instantiate(&drbg_ctx, entropy);

    BIGNUM *p = NULL, *q = NULL, *n = NULL, *e = NULL, *d = NULL;
    if (!rsa_key_generate(&drbg_ctx, &p, &q, &n, &e, &d)) {
        fprintf(stderr, "RSA key generation failed\n");
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }

    printf("Generated RSA key components:\n");
    printf("p = "); BN_print_fp(stdout, p); printf("\n");
    printf("q = "); BN_print_fp(stdout, q); printf("\n");
    printf("n = "); BN_print_fp(stdout, n); printf("\n");
    printf("e = "); BN_print_fp(stdout, e); printf("\n");
    printf("d = "); BN_print_fp(stdout, d); printf("\n");

    RSA *rsa = rsa_build_key(p, q, n, e, d);
    if (!rsa) {
        fprintf(stderr, "Failed to build RSA key\n");
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }

    FILE *priv_fp = fopen("rsa_private.pem", "wb");
    if (!priv_fp) {
        fprintf(stderr, "Error opening file for private key\n");
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    if (!PEM_write_RSAPrivateKey(priv_fp, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key\n");
        fclose(priv_fp);
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    fclose(priv_fp);

    FILE *pub_fp = fopen("rsa_public.pem", "wb");
    if (!pub_fp) {
        fprintf(stderr, "Error opening file for public key\n");
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    if (!PEM_write_RSA_PUBKEY(pub_fp, rsa)) {
        fprintf(stderr, "Error writing public key\n");
        fclose(pub_fp);
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    fclose(pub_fp);

    printf("RSA key pair saved to rsa_private.pem (private) and rsa_public.pem (public)\n");

    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    RSA_free(rsa);

    double cpu_time_used = (double)(clock() - start) / CLOCKS_PER_SEC;
    printf("Execution time: %f seconds\n", cpu_time_used);

    return 0;
}
