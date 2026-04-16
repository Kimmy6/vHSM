#ifndef SDCARD_STORAGE_H
#define SDCARD_STORAGE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define SD_MOUNT_POINT "/sdcard"

esp_err_t sdcard_init(void);
void sdcard_deinit(void);
bool sdcard_is_mounted(void);

esp_err_t sdcard_write_binary(const char *filename, const uint8_t *data, size_t len);
esp_err_t sdcard_write_hex(const char *filename, const uint8_t *data, size_t len);
esp_err_t sdcard_write_bits(const char *filename, const uint8_t *bits, size_t len);

#endif // SDCARD_STORAGE_H
