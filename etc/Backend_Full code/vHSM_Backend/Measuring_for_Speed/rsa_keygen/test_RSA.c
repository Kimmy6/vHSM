#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main() {
    EVP_RAND *rand_impl = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    if (!rand_impl) {
        fprintf(stderr, "Failed to fetch RAND\n");
        return 1;
    }

    EVP_RAND_CTX *rand_ctx = EVP_RAND_CTX_new(rand_impl, NULL);
    EVP_RAND_free(rand_impl);
    if (!rand_ctx) {
        fprintf(stderr, "Failed to create RAND_CTX\n");
        return 1;
    }

    unsigned char entropy[32] = {0}; // 임의의 시드 (보통 외부에서 받음)
    
    if (EVP_RAND_instantiate(rand_ctx, 256, 0, entropy, sizeof(entropy)) != 1) {
        fprintf(stderr, "Failed to instantiate DRBG\n");
        EVP_RAND_CTX_free(rand_ctx);
        return 1;
    }

    unsigned char out[16];
    if (EVP_RAND_generate(rand_ctx, out, sizeof(out), 0, NULL, 0) != 1) {
        fprintf(stderr, "Failed to generate random\n");
        EVP_RAND_uninstantiate(rand_ctx);
        EVP_RAND_CTX_free(rand_ctx);
        return 1;
    }

    printf("Random bytes: ");
    for (int i=0; i<sizeof(out); i++) {
        printf("%02X", out[i]);
    }
    printf("\n");

    EVP_RAND_uninstantiate(rand_ctx);
    EVP_RAND_CTX_free(rand_ctx);

    return 0;
}
