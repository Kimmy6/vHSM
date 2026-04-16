// main.c — ESP32 AES-192-CBC demo with SD-card debug file save

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_heap_caps.h"

#include "crypto.h"
#include "sdcard_storage.h"

#include "driver/gpio.h"

static const char *TAG = "AES192";

#define BITS_BUF_SIZE  307200
#define FLASH_LED_GPIO GPIO_NUM_4

static void flash_led_off(void)
{
    gpio_reset_pin(FLASH_LED_GPIO);
    gpio_set_direction(FLASH_LED_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(FLASH_LED_GPIO, 0);
}

static int uart_readline(char *buf, int max_len)
{
    int idx = 0;

    while (idx < max_len - 1) {
        int c = getchar();
        if (c == EOF || c < 0) {
            continue;
        }

        putchar(c);
        fflush(stdout);

        if (c == '\r' || c == '\n') {
            if (idx == 0) {
                continue;
            }
            break;
        }

        buf[idx++] = (char)c;
    }

    buf[idx] = '\0';
    return idx;
}

extern int extract_bits_from_image(uint8_t *out_bits, int max_len);

void app_main(void)
{
    uint8_t *bits_buf = NULL;
    bool sd_ready = false;

    printf("\r\n=== ESP32 AES-192-CBC Symmetric Key Demo ===\r\n");
    printf("Select mode: 1) AES-192 encryption  2) AES-192 decryption\r\n> ");

    char mode_str[8] = {0};
    uart_readline(mode_str, sizeof(mode_str));
    printf("\r\n");

    char *endptr;
    long mode = strtol(mode_str, &endptr, 10);
    if (endptr == mode_str || (*endptr != '\0' && *endptr != '\r' && *endptr != '\n')) {
        printf("Invalid mode.\r\n");
        goto cleanup;
    }
    if (mode != 1 && mode != 2) {
        printf("Invalid mode.\r\n");
        goto cleanup;
    }

    if (sdcard_init() != ESP_OK) {
        printf("Failed to mount SD card at %s.\r\n", SD_MOUNT_POINT);
        goto cleanup;
    }

    sd_ready = true;

    flash_led_off();

    printf("Image capturing...\r\n");

    bits_buf = (uint8_t *)heap_caps_malloc(BITS_BUF_SIZE,
                                           MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!bits_buf) {
        ESP_LOGE(TAG, "PSRAM allocation failed (%d bytes).", BITS_BUF_SIZE);
        printf("Error: insufficient PSRAM.\r\n");
        goto cleanup;
    }

    int bit_len = extract_bits_from_image(bits_buf, BITS_BUF_SIZE);
    if (bit_len < KEY_BYTES * 8) {
        printf("Insufficient extracted bits for key: got %d, need %d\r\n",
               bit_len, KEY_BYTES * 8);
        goto cleanup;
    }

    char bin_key_str[KEY_BYTES * 8 + 1];
    for (int i = 0; i < KEY_BYTES * 8; i++) {
        bin_key_str[i] = bits_buf[i] ? '1' : '0';
    }
    bin_key_str[KEY_BYTES * 8] = '\0';

    unsigned char key[KEY_BYTES];
    binstr_to_bytes(bin_key_str, key, KEY_BYTES);

    unsigned char iv[IV_BYTES];
    esp_fill_random(iv, IV_BYTES);

    if (mode == 1) {
        printf("Enter plaintext: ");
        char plaintext[PLAINTEXT_MAX_LEN] = {0};
        int plen = uart_readline(plaintext, sizeof(plaintext));
        printf("\r\n");

        if (plen <= 0) {
            printf("Empty plaintext.\r\n");
            goto cleanup;
        }

        unsigned char ciphertext[CIPHERTEXT_MAX_LEN];
        int ciphertext_len = 0;

        if (encrypt_aes_192_cbc(key, iv,
                                (unsigned char *)plaintext, plen,
                                ciphertext, &ciphertext_len) != 0) {
            printf("Encryption failed.\r\n");
            goto cleanup;
        }

        printf("Ciphertext (HEX): ");
        print_hex(ciphertext, ciphertext_len);
        printf("IV (HEX): ");
        print_hex(iv, IV_BYTES);

        if (sdcard_write_hex("ciphertxt.txt", ciphertext, (size_t)ciphertext_len) != ESP_OK) {
            printf("Warning: failed to save ciphertxt.txt\r\n");
        }
        if (sdcard_write_hex("iv.txt", iv, IV_BYTES) != ESP_OK) {
            printf("Warning: failed to save iv.txt\r\n");
        }
    } else {
        printf("Enter ciphertext (hex): ");
        char hex_ct[CIPHERTEXT_MAX_LEN * 2 + 1] = {0};
        uart_readline(hex_ct, sizeof(hex_ct));
        printf("\r\n");

        printf("Enter IV (hex): ");
        char hex_iv[IV_BYTES * 2 + 1] = {0};
        uart_readline(hex_iv, sizeof(hex_iv));
        printf("\r\n");

        unsigned char ciphertext[CIPHERTEXT_MAX_LEN];
        unsigned char iv_from_input[IV_BYTES];

        int ct_len = hexstr_to_bytes(hex_ct, ciphertext, sizeof(ciphertext));
        int iv_len = hexstr_to_bytes(hex_iv, iv_from_input, IV_BYTES);

        if (ct_len < 0 || iv_len != IV_BYTES) {
            printf("Invalid ciphertext or IV length.\r\n");
            goto cleanup;
        }

        unsigned char decrypted[PLAINTEXT_MAX_LEN];
        int decrypted_len = 0;

        if (decrypt_aes_192_cbc(key, iv_from_input,
                                ciphertext, ct_len,
                                decrypted, &decrypted_len) != 0) {
            printf("Decryption failed.\r\n");
            goto cleanup;
        }

        if (decrypted_len >= PLAINTEXT_MAX_LEN) {
            printf("Decrypted data exceeds buffer size.\r\n");
            goto cleanup;
        }
        decrypted[decrypted_len] = '\0';
        printf("Decrypted plaintext: %s\r\n", (char *)decrypted);
    }

cleanup:
    free(bits_buf);
    if (sd_ready) {
        sdcard_deinit();
    }
}