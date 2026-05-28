#include "sdcard_storage.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"
#include "driver/gpio.h"

static const char *TAG = "SDCARD";

static sdmmc_card_t *s_card = NULL;
static bool s_sd_mounted = false;

static void build_path(char *path, size_t path_len, const char *filename)
{
    snprintf(path, path_len, "%s/%s", SD_MOUNT_POINT, filename);
}

bool sdcard_is_mounted(void)
{
    return s_sd_mounted;
}

esp_err_t sdcard_init(void)
{
    if (s_sd_mounted) {
        return ESP_OK;
    }

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024,
    };

    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    host.max_freq_khz = SDMMC_FREQ_DEFAULT;

    sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
    slot_config.width = 1;  // safer on ESP32-CAM: only CLK/CMD/D0 required

    // Helpful pull-ups for 1-bit SD mode on ESP32.
    gpio_set_pull_mode(GPIO_NUM_2, GPIO_PULLUP_ONLY);   // D0
    gpio_set_pull_mode(GPIO_NUM_14, GPIO_PULLUP_ONLY);  // CLK
    gpio_set_pull_mode(GPIO_NUM_15, GPIO_PULLUP_ONLY);  // CMD
    gpio_set_pull_mode(GPIO_NUM_13, GPIO_PULLUP_ONLY);  // D3 / card detect line on many sockets

    esp_err_t ret = esp_vfs_fat_sdmmc_mount(SD_MOUNT_POINT, &host, &slot_config,
                                            &mount_config, &s_card);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount SD card at %s: %s", SD_MOUNT_POINT, esp_err_to_name(ret));
        s_card = NULL;
        s_sd_mounted = false;
        return ret;
    }

    s_sd_mounted = true;
    ESP_LOGI(TAG, "SD card mounted at %s", SD_MOUNT_POINT);
    sdmmc_card_print_info(stdout, s_card);
    return ESP_OK;
}

void sdcard_deinit(void)
{
    if (!s_sd_mounted) {
        return;
    }

    esp_vfs_fat_sdcard_unmount(SD_MOUNT_POINT, s_card);
    ESP_LOGI(TAG, "SD card unmounted from %s", SD_MOUNT_POINT);

    s_card = NULL;
    s_sd_mounted = false;
}

esp_err_t sdcard_write_binary(const char *filename, const uint8_t *data, size_t len)
{
    if (!s_sd_mounted) {
        ESP_LOGE(TAG, "sdcard_write_binary called before sdcard_init");
        return ESP_ERR_INVALID_STATE;
    }

    char path[96];
    build_path(path, sizeof(path), filename);

    FILE *f = fopen(path, "wb");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s for binary write: errno=%d", path, errno);
        return ESP_FAIL;
    }

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    if (written != len) {
        ESP_LOGE(TAG, "Short write to %s (%u/%u bytes)", path,
                 (unsigned)written, (unsigned)len);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Saved %s (%u bytes)", path, (unsigned)len);
    return ESP_OK;
}

esp_err_t sdcard_write_hex(const char *filename, const uint8_t *data, size_t len)
{
    if (!s_sd_mounted) {
        ESP_LOGE(TAG, "sdcard_write_hex called before sdcard_init");
        return ESP_ERR_INVALID_STATE;
    }

    char path[96];
    build_path(path, sizeof(path), filename);

    FILE *f = fopen(path, "w");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s for text write: errno=%d", path, errno);
        return ESP_FAIL;
    }

    for (size_t i = 0; i < len; i++) {
        if (fprintf(f, "%02x", data[i]) < 0) {
            fclose(f);
            ESP_LOGE(TAG, "Failed while writing hex data to %s", path);
            return ESP_FAIL;
        }
    }
    fputc('\n', f);
    fclose(f);

    ESP_LOGI(TAG, "Saved %s", path);
    return ESP_OK;
}

esp_err_t sdcard_write_bits(const char *filename, const uint8_t *bits, size_t len)
{
    if (!s_sd_mounted) {
        ESP_LOGE(TAG, "sdcard_write_bits called before sdcard_init");
        return ESP_ERR_INVALID_STATE;
    }

    char path[96];
    build_path(path, sizeof(path), filename);

    FILE *f = fopen(path, "w");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s for bit write: errno=%d", path, errno);
        return ESP_FAIL;
    }

    char chunk[256];
    size_t chunk_idx = 0;

    for (size_t i = 0; i < len; i++) {
        chunk[chunk_idx++] = bits[i] ? '1' : '0';
        if (chunk_idx == sizeof(chunk)) {
            if (fwrite(chunk, 1, chunk_idx, f) != chunk_idx) {
                fclose(f);
                ESP_LOGE(TAG, "Failed while writing bits to %s", path);
                return ESP_FAIL;
            }
            chunk_idx = 0;
        }
    }

    if (chunk_idx > 0 && fwrite(chunk, 1, chunk_idx, f) != chunk_idx) {
        fclose(f);
        ESP_LOGE(TAG, "Failed while flushing bits to %s", path);
        return ESP_FAIL;
    }

    fputc('\n', f);
    fclose(f);

    ESP_LOGI(TAG, "Saved %s (%u bits)", path, (unsigned)len);
    return ESP_OK;
}
