#include "crypto.h"
#include "uart_key.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim_newline(char *s)
{
    size_t len = strlen(s);
    if (len > 0 && s[len - 1] == '\n') {
        s[len - 1] = '\0';
    }
}

int main(int argc, char *argv[])
{
    const char *uart_port = "/dev/ttyUSB0";
    if (argc >= 2) {
        uart_port = argv[1];
    }

    int mode = 0;
    printf("UART port: %s\n", uart_port);
    printf("Select mode: 1) AES-192 encryption 2) AES-192 decryption: ");
    if (scanf("%d", &mode) != 1 || (mode != 1 && mode != 2)) {
        printf("Invalid mode.\n");
        return 1;
    }
    getchar();

    unsigned char key[KEY_BYTES];
    if (receive_key_hex_from_uart(uart_port, key, KEY_BYTES, 30) != 0) {
        printf("Failed to receive key from ESP32.\n");
        return 1;
    }

    printf("Received key (HEX): ");
    print_hex(key, KEY_BYTES);

    if (mode == 1) {
        unsigned char iv[IV_BYTES];
        if (!RAND_bytes(iv, IV_BYTES)) {
            printf("IV generation error.\n");
            return 1;
        }

        char plaintext[PLAINTEXT_MAX_LEN];
        printf("Enter plaintext: ");
        if (!fgets(plaintext, sizeof(plaintext), stdin)) {
            printf("Plaintext input failure.\n");
            return 1;
        }
        trim_newline(plaintext);

        unsigned char ciphertext[CIPHERTEXT_MAX_LEN];
        int ciphertext_len = 0;

        if (encrypt_aes_192_cbc(key, iv,
                                (unsigned char *)plaintext, (int)strlen(plaintext),
                                ciphertext, &ciphertext_len) != 0) {
            printf("Encryption failed.\n");
            return 1;
        }

        printf("Ciphertext (HEX): ");
        print_hex(ciphertext, ciphertext_len);
        printf("IV (HEX): ");
        print_hex(iv, IV_BYTES);
    } else {
        char hex_ciphertext[CIPHERTEXT_MAX_LEN * 2 + 1];
        char hex_iv[IV_BYTES * 2 + 1];

        printf("Enter ciphertext (hex): ");
        if (!fgets(hex_ciphertext, sizeof(hex_ciphertext), stdin)) {
            printf("Ciphertext input failure.\n");
            return 1;
        }
        trim_newline(hex_ciphertext);

        printf("Enter IV (hex): ");
        if (!fgets(hex_iv, sizeof(hex_iv), stdin)) {
            printf("IV input failure.\n");
            return 1;
        }
        trim_newline(hex_iv);

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
        if (decrypt_aes_192_cbc(key, iv_from_input,
                                ciphertext, ciphertext_len,
                                decrypted, &decrypted_len) != 0) {
            printf("Decryption failed.\n");
            return 1;
        }

        decrypted[decrypted_len] = '\0';
        printf("Decrypted plaintext: %s\n", decrypted);
    }

    return 0;
}
