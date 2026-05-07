// image_capture.c
// 디버깅 저장 플로우:
//   1. JPEG(RGB) UXGA 캡처        → RGBoriginal.jpg
//   2. GRAYSCALE SVGA 캡처        → original.jpg
//   3. 320x240 리사이즈            → resized.jpg
//   4. 임계값 처리                 → threshold.jpg
//   5. Von Neumann 추출 비트 전체  → vn_ext.txt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_camera.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "img_converters.h"

#include "sdcard_storage.h"

static const char *TAG = "IMG_CAP";

// ── AI-Thinker ESP32-CAM 핀 정의 ────────────────────────────────────────────
#define CAM_PIN_PWDN     32
#define CAM_PIN_RESET    -1
#define CAM_PIN_XCLK      0
#define CAM_PIN_SIOD     26
#define CAM_PIN_SIOC     27
#define CAM_PIN_D7       35
#define CAM_PIN_D6       34
#define CAM_PIN_D5       39
#define CAM_PIN_D4       36
#define CAM_PIN_D3       21
#define CAM_PIN_D2       19
#define CAM_PIN_D1       18
#define CAM_PIN_D0        5
#define CAM_PIN_VSYNC    25
#define CAM_PIN_HREF     23
#define CAM_PIN_PCLK     22

#define JPG_QUALITY      99

#define RESIZE_WIDTH     320
#define RESIZE_HEIGHT    240

// ── 공통 핀 설정 ─────────────────────────────────────────────────────────────
#define CAM_PIN_CONFIG                            \
    .pin_pwdn     = CAM_PIN_PWDN,                 \
    .pin_reset    = CAM_PIN_RESET,                \
    .pin_xclk     = CAM_PIN_XCLK,                \
    .pin_sscb_sda = CAM_PIN_SIOD,                \
    .pin_sscb_scl = CAM_PIN_SIOC,                \
    .pin_d7 = CAM_PIN_D7, .pin_d6 = CAM_PIN_D6,  \
    .pin_d5 = CAM_PIN_D5, .pin_d4 = CAM_PIN_D4,  \
    .pin_d3 = CAM_PIN_D3, .pin_d2 = CAM_PIN_D2,  \
    .pin_d1 = CAM_PIN_D1, .pin_d0 = CAM_PIN_D0,  \
    .pin_vsync    = CAM_PIN_VSYNC,               \
    .pin_href     = CAM_PIN_HREF,                \
    .pin_pclk     = CAM_PIN_PCLK,               \
    .xclk_freq_hz = 20000000,                    \
    .ledc_timer   = LEDC_TIMER_0,               \
    .ledc_channel = LEDC_CHANNEL_0,             \
    .fb_count     = 1,                           \
    .fb_location  = CAMERA_FB_IN_PSRAM,         \
    .grab_mode    = CAMERA_GRAB_WHEN_EMPTY

// ── 1단계: RGB JPEG 캡처용 초기화 ───────────────────────────────────────────
static esp_err_t camera_init_jpeg(void)
{
    camera_config_t cfg = {
        CAM_PIN_CONFIG,
        .pixel_format = PIXFORMAT_JPEG,
        .frame_size   = FRAMESIZE_UXGA,
        .jpeg_quality = JPG_QUALITY,
    };
    esp_err_t err = esp_camera_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "camera_init_jpeg failed: 0x%x", err);
        return err;
    }
    ESP_LOGI(TAG, "Camera init: JPEG UXGA");

    sensor_t *s = esp_camera_sensor_get();
    if (s) {
        s->set_whitebal(s, 1);
        s->set_awb_gain(s, 1);
        s->set_wb_mode(s, 3);          // 3 = Office (실내 형광등)
        s->set_gain_ctrl(s, 1);
        s->set_exposure_ctrl(s, 1);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    return ESP_OK;
}

// ── 2단계: 그레이스케일 캡처용 초기화 ───────────────────────────────────────
static esp_err_t camera_init_gray(void)
{
    camera_config_t cfg = {
        CAM_PIN_CONFIG,
        .pixel_format = PIXFORMAT_GRAYSCALE,
        .frame_size   = FRAMESIZE_SVGA,
        .jpeg_quality = 12,
    };
    esp_err_t err = esp_camera_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "camera_init_gray failed: 0x%x", err);
        return err;
    }
    ESP_LOGI(TAG, "Camera init: GRAYSCALE SVGA");
    return ESP_OK;
}

// ── 그레이스케일 nearest-neighbor 리사이즈 ──────────────────────────────────
static void resize_grayscale_nn(const uint8_t *src, int src_w, int src_h,
                                uint8_t *dst, int dst_w, int dst_h)
{
    for (int y = 0; y < dst_h; y++) {
        int src_y = (y * src_h) / dst_h;
        if (src_y >= src_h) src_y = src_h - 1;
        for (int x = 0; x < dst_w; x++) {
            int src_x = (x * src_w) / dst_w;
            if (src_x >= src_w) src_x = src_w - 1;
            dst[y * dst_w + x] = src[src_y * src_w + src_x];
        }
    }
}

// ── 그레이스케일 버퍼 → JPEG → SD 저장 ─────────────────────────────────────
static void save_gray_as_jpeg(const uint8_t *buf, int w, int h, const char *filename)
{
    if (!sdcard_is_mounted()) return;
    uint8_t *jpg_buf = NULL;
    size_t   jpg_len = 0;
    if (fmt2jpg((uint8_t *)buf, (size_t)(w * h), w, h,
                PIXFORMAT_GRAYSCALE, JPG_QUALITY, &jpg_buf, &jpg_len)) {
        if (sdcard_write_binary(filename, jpg_buf, jpg_len) == ESP_OK)
            ESP_LOGI(TAG, "%s 저장 완료 (%zu bytes)", filename, jpg_len);
        else
            ESP_LOGW(TAG, "%s 저장 실패", filename);
        free(jpg_buf);
    } else {
        ESP_LOGW(TAG, "%s JPEG 변환 실패", filename);
    }
}

// ── Von Neumann 디바이싱 ─────────────────────────────────────────────────────
static int vn_pass(const uint8_t *bits, int len, uint8_t *out, int max_out)
{
    int out_idx = 0;
    for (int i = 0; i + 1 < len; i += 2) {
        if (out_idx >= max_out) break;
        if      (bits[i] == 0 && bits[i+1] == 1) out[out_idx++] = 0;
        else if (bits[i] == 1 && bits[i+1] == 0) out[out_idx++] = 1;
    }
    return out_idx;
}

static int two_pass_vonneumann(const uint8_t *bits, int len,
                               uint8_t *out, int max_out)
{
    uint8_t *tmp = (uint8_t *)heap_caps_malloc(max_out,
                       MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!tmp) tmp = (uint8_t *)malloc(max_out);
    if (!tmp) { ESP_LOGE(TAG, "VN alloc failed"); return -1; }
    int pass1_len = vn_pass(bits, len, tmp, max_out);
    int pass2_len = (pass1_len >= 2) ? vn_pass(tmp, pass1_len, out, max_out) : 0;
    free(tmp);
    return pass2_len;
}

// ── 공개 인터페이스 ──────────────────────────────────────────────────────────
int extract_bits_from_image(uint8_t *out_bits, int max_len)
{
    // ════════════════════════════════════════════════════════
    // [1단계] RGB JPEG 캡처 → RGBoriginal.jpg
    // ════════════════════════════════════════════════════════
    if (sdcard_is_mounted()) {
        ESP_LOGI(TAG, "[1/4] RGB JPEG 캡처 (UXGA)...");
        if (camera_init_jpeg() == ESP_OK) {
            camera_fb_t *fb = esp_camera_fb_get();
            if (fb) {
                ESP_LOGI(TAG, "RGB 캡처 완료: %zu bytes", fb->len);
                if (sdcard_write_binary("RGBoriginal.jpg", fb->buf, fb->len) == ESP_OK)
                    ESP_LOGI(TAG, "RGBoriginal.jpg 저장 완료");
                else
                    ESP_LOGW(TAG, "RGBoriginal.jpg 저장 실패");
                esp_camera_fb_return(fb);
            } else {
                ESP_LOGW(TAG, "RGB 프레임 취득 실패");
            }
            esp_camera_deinit();

            // deinit 후 PSRAM 여유 공간 확인
            ESP_LOGI(TAG, "PSRAM free after RGB deinit: %zu bytes",
                     heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
            vTaskDelay(pdMS_TO_TICKS(100));  // 할당자 안정화 대기
        } else {
            ESP_LOGW(TAG, "RGB 초기화 실패, 건너뜀");
        }
    }

    // ════════════════════════════════════════════════════════
    // [2단계] GRAYSCALE 캡처 → original.jpg
    // ════════════════════════════════════════════════════════
    ESP_LOGI(TAG, "[2/4] GRAYSCALE 캡처 (SVGA)...");
    if (camera_init_gray() != ESP_OK) {
        ESP_LOGE(TAG, "GRAYSCALE 초기화 실패");
        return -1;
    }

    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) {
        ESP_LOGE(TAG, "GRAYSCALE 프레임 취득 실패");
        esp_camera_deinit();
        return -1;
    }

    int src_w = fb->width;
    int src_h = fb->height;
    ESP_LOGI(TAG, "GRAYSCALE 캡처 완료: %dx%d", src_w, src_h);

    save_gray_as_jpeg(fb->buf, src_w, src_h, "original.jpg");

    // ════════════════════════════════════════════════════════
    // [3단계] 리사이즈 → resized.jpg
    // ════════════════════════════════════════════════════════
    ESP_LOGI(TAG, "[3/4] 리사이즈 %dx%d → %dx%d...",
             src_w, src_h, RESIZE_WIDTH, RESIZE_HEIGHT);

    int proc_size    = RESIZE_WIDTH * RESIZE_HEIGHT;
    uint8_t *resized_img   = (uint8_t *)heap_caps_malloc(proc_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    uint8_t *raw_bits      = (uint8_t *)heap_caps_malloc(proc_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    uint8_t *threshold_img = (uint8_t *)heap_caps_malloc(proc_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    if (!resized_img || !raw_bits || !threshold_img) {
        ESP_LOGE(TAG, "처리 버퍼 할당 실패");
        free(resized_img); free(raw_bits); free(threshold_img);
        esp_camera_fb_return(fb);
        esp_camera_deinit();
        return -1;
    }

    resize_grayscale_nn(fb->buf, src_w, src_h, resized_img, RESIZE_WIDTH, RESIZE_HEIGHT);
    esp_camera_fb_return(fb);
    esp_camera_deinit();

    save_gray_as_jpeg(resized_img, RESIZE_WIDTH, RESIZE_HEIGHT, "resized.jpg");

    // ════════════════════════════════════════════════════════
    // [4단계] 임계값 처리 → threshold.jpg
    // ════════════════════════════════════════════════════════
    ESP_LOGI(TAG, "[4/4] 임계값 처리...");

    uint8_t max_val = 0;
    for (int i = 0; i < proc_size; i++)
        if (resized_img[i] > max_val) max_val = resized_img[i];

    uint8_t threshold_value = (uint8_t)(max_val * 85 / 100);
    ESP_LOGI(TAG, "임계값: %d (max_val=%d)", threshold_value, max_val);

    for (int i = 0; i < proc_size; i++) {
        uint8_t bit      = (resized_img[i] >= threshold_value) ? 1 : 0;
        raw_bits[i]      = bit;
        threshold_img[i] = bit ? 255 : 0;
    }
    free(resized_img);

    save_gray_as_jpeg(threshold_img, RESIZE_WIDTH, RESIZE_HEIGHT, "threshold.jpg");
    free(threshold_img);

    // ════════════════════════════════════════════════════════
    // Von Neumann 2-pass 디바이싱
    // ════════════════════════════════════════════════════════
    int out_len = two_pass_vonneumann(raw_bits, proc_size, out_bits, max_len);
    free(raw_bits);

    if (out_len < 0) {
        ESP_LOGE(TAG, "Von Neumann 디바이싱 실패");
        return -1;
    }

    // vn_ext.txt — 추출된 비트 전체
    if (sdcard_is_mounted()) {
        if (sdcard_write_bits("vn_ext.txt", out_bits, (size_t)out_len) == ESP_OK)
            ESP_LOGI(TAG, "vn_ext.txt 저장 완료 (%d bits)", out_len);
        else
            ESP_LOGW(TAG, "vn_ext.txt 저장 실패");
    }

    // 통계 출력
    int ones = 0;
    for (int i = 0; i < out_len; i++) if (out_bits[i]) ones++;
    float uniformity = out_len > 0 ? (float)ones / (float)out_len : 0.0f;

    printf("Extracted bits preview (first 10): ");
    for (int i = 0; i < (out_len > 10 ? 10 : out_len); i++) printf("%d", out_bits[i]);
    printf("\nBit uniformity: %.4f\n", uniformity);
    ESP_LOGI(TAG, "총 추출 비트: %d", out_len);

    return out_len;
}