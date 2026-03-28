#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

extern int extract_bits_from_image(const char *image_path, uint8_t *out_bits, int max_len);

int main() {
    int mode = 0;
    printf("Select mode: 1) AES-192 encryption 2) AES-192 decryption: ");
    if (scanf("%d", &mode) != 1 || (mode != 1 && mode != 2)) {
        printf("Invalid mode.\n");
        return 1;
    }
    getchar(); // Remove newline

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
    if (!RAND_bytes(iv, IV_BYTES)) {
        printf("IV generation error.\n");
        return 1;
    }

    if (mode == 1) { // Encryption
        char plaintext[PLAINTEXT_MAX_LEN];
        printf("Enter plaintext: ");
        if (!fgets(plaintext, sizeof(plaintext), stdin)) {
            printf("Plaintext input failure.\n");
            return 1;
        }
        size_t plen = strlen(plaintext);
        if (plen > 0 && plaintext[plen - 1] == '\n') {
            plaintext[plen - 1] = '\0';
            plen--;
        }

        unsigned char ciphertext[CIPHERTEXT_MAX_LEN];
        int ciphertext_len = 0;

        if (encrypt_aes_192_cbc(key, iv, (unsigned char *)plaintext, (int)plen, ciphertext, &ciphertext_len) != 0) {
            printf("Encryption failed.\n");
            return 1;
        }

        printf("Ciphertext (HEX): ");
        print_hex(ciphertext, ciphertext_len);
        printf("IV (HEX): ");
        print_hex(iv, IV_BYTES);
    } else { // Decryption
        char hex_ciphertext[CIPHERTEXT_MAX_LEN * 2 + 1];
        char hex_iv[IV_BYTES * 2 + 1];
        printf("Enter ciphertext (hex): ");
        if (!fgets(hex_ciphertext, sizeof(hex_ciphertext), stdin)) {
            printf("Ciphertext input failure.\n");
            return 1;
        }
        size_t clen = strlen(hex_ciphertext);
        if (clen > 0 && hex_ciphertext[clen - 1] == '\n') {
            hex_ciphertext[clen - 1] = '\0';
            clen--;
        }

        printf("Enter IV (hex): ");
        if (!fgets(hex_iv, sizeof(hex_iv), stdin)) {
            printf("IV input failure.\n");
            return 1;
        }
        size_t ivlen = strlen(hex_iv);
        if (ivlen > 0 && hex_iv[ivlen - 1] == '\n') {
            hex_iv[ivlen - 1] = '\0';
            ivlen--;
        }

        unsigned char ciphertext[CIPHERTEXT_MAX_LEN];
        unsigned char iv_from_input[IV_BYTES];
        int ciphertext_len = hexstr_to_bytes(hex_ciphertext, ciphertext, sizeof(ciphertext));
        int iv_len = hexstr_to_bytes(hex_iv, iv_from_input, IV_BYTES);
        if (ciphertext_len < 0 || iv_len != IV_BYTES) {
            printf("Invalid ciphertext or IV length.\n");
            return 1;
        }

        unsigned char decrypted[PLAINTEXT_MAX_LEN];
        int decrypted_len = 0;

        if (decrypt_aes_192_cbc(key, iv_from_input, ciphertext, ciphertext_len, decrypted, &decrypted_len) != 0) {
            printf("Decryption failed.\n");
            return 1;
        }
        decrypted[decrypted_len] = '\0';
        printf("Decrypted plaintext: %s\n", decrypted);
    }

    return 0;
}
