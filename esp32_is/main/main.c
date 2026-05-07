// main.c — Pi4 UART 트리거 → 이미지 캡처 → 192-bit 키 추출 → KEY_HEX 전송

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "driver/gpio.h"

#include "crypto.h"
#include "sdcard_storage.h"

static const char *TAG = "AES192";

#define BITS_BUF_SIZE  307200
#define FLASH_LED_GPIO GPIO_NUM_4

static void flash_led_off(void)
{
    gpio_reset_pin(FLASH_LED_GPIO);
    gpio_set_direction(FLASH_LED_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(FLASH_LED_GPIO, 0);
}

extern int extract_bits_from_image(uint8_t *out_bits, int max_len);

void app_main(void)
{
    bool sd_ready = false;

    if (sdcard_init() == ESP_OK) {
        sd_ready = true;
    }

    flash_led_off();

    while (1) {
    printf("READY\r\n");
    fflush(stdout);

    TickType_t last_ready_tick = xTaskGetTickCount();

    while (1) {
        int c = getchar();

        if (c == EOF || c < 0) {
            vTaskDelay(pdMS_TO_TICKS(10));

            TickType_t now = xTaskGetTickCount();
            if ((now - last_ready_tick) >= pdMS_TO_TICKS(500)) {
                printf("READY\r\n");
                fflush(stdout);
                last_ready_tick = now;
            }
            continue;
        }

        if (c == '\r' || c == '\n') continue;
        if (c == 'G') break;
    }

        uint8_t *bits_buf = (uint8_t *)heap_caps_malloc(
            BITS_BUF_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
        );
        if (!bits_buf) {
            ESP_LOGE(TAG, "PSRAM allocation failed (%d bytes).", BITS_BUF_SIZE);
            printf("ERROR: insufficient PSRAM\r\n");
            fflush(stdout);
            continue;
        }

        int bit_len = extract_bits_from_image(bits_buf, BITS_BUF_SIZE);
        if (bit_len < KEY_BYTES * 8) {
            printf("ERROR: insufficient bits got=%d need=%d\r\n",
                   bit_len, KEY_BYTES * 8);
            fflush(stdout);
            free(bits_buf);
            continue;
        }

        // 앞 192비트 -> AES-192 key
        char bin_key_str[KEY_BYTES * 8 + 1];
        for (int i = 0; i < KEY_BYTES * 8; i++) {
            bin_key_str[i] = bits_buf[i] ? '1' : '0';
        }
        bin_key_str[KEY_BYTES * 8] = '\0';

        unsigned char key[KEY_BYTES];
        binstr_to_bytes(bin_key_str, key, KEY_BYTES);

        // Pi4로 key hex 전송
        printf("KEY_HEX:");
        for (int i = 0; i < KEY_BYTES; i++) {
            printf("%02x", key[i]);
        }
        printf("\r\n");
        printf("DONE\r\n");
        fflush(stdout);

        free(bits_buf);
    }

    if (sd_ready) {
        sdcard_deinit();
    }
}