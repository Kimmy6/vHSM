#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <opencv2/opencv.hpp>

#define IMAGE_FILE "capture.jpg"
#define THRESHOLD_IMAGE_FILE "threshold_image.jpg"
#define OUTPUT_FILE "extracted_bits.txt"
#define RESIZED_FILE "resized_image.jpg"

#define THRESHOLD_PERCENT 0.85
#define MAX_TUPLES 1000000 // 최대 출력 튜플 개수 (메모리 고려)
#define RESIZING_V 960
#define RESIZING_H 1280
using namespace cv;

// Speckle 인식 (밝기 임계값 5% 이하 어두운 픽셀 존재 여부)
bool detect_speckle(const Mat &image) {
    int dark_pixel_count = 0;
    int total_pixels = image.rows * image.cols;

    for (int i = 0; i < total_pixels; ++i) {
        Vec3b pix = image.data[i * 3];
        int brightness = (pix[0] + pix[1] + pix[2]) / 3;
        if (brightness < (255 * 0.05)) dark_pixel_count++;
    }
    return (dark_pixel_count > (total_pixels * 0.05)); // 5% 이상 어두운 픽셀 있으면 인식
}

// Thresholding pixel intensity at 85%
void create_threshold_image(const Mat &image, Mat &threshold_img) {
    threshold_img.create(image.rows, image.cols, CV_8UC1);
    int threshold_val = static_cast<int>(255 * THRESHOLD_PERCENT);

    for (int r = 0; r < image.rows; ++r) {
        for (int c = 0; c < image.cols; ++c) {
            Vec3b pix = image.at<Vec3b>(r, c);
            int brightness = (pix[0] + pix[1] + pix[2]) / 3;
            threshold_img.at<uchar>(r, c) = (brightness >= threshold_val) ? 255 : 0;
        }
    }
    imwrite(THRESHOLD_IMAGE_FILE, threshold_img);
}


// 이미지 채널별 비트 배열로 변환 (0 또는 1)
void image_to_bits(const Mat &channel, uint8_t *bits) {
    int size = channel.rows * channel.cols;
    for (int i = 0; i < size; ++i) {
        bits[i] = (channel.data[i] >= 255 * THRESHOLD_PERCENT) ? 1 : 0;
    }
}

// multi-channel tuple-output Von Neumann debiasing (2비트씩 쌍 처리)
int multi_channel_vonneumann(uint8_t *bits_r, uint8_t *bits_g, uint8_t *bits_b, int len,
                             uint8_t *out_bits, int max_out_len) {
    int out_idx = 0;
    for (int i = 0; i < len - 1; i += 2) {
        if (out_idx + 6 > max_out_len) break; // 출력 초과 방지 (2비트 * 3채널)

        uint8_t a_r = bits_r[i], b_r = bits_r[i + 1];
        uint8_t a_g = bits_g[i], b_g = bits_g[i + 1];
        uint8_t a_b = bits_b[i], b_b = bits_b[i + 1];

        if (a_r != b_r) {
            out_bits[out_idx++] = a_r;
            out_bits[out_idx++] = b_r;
        }
        if (a_g != b_g) {
            out_bits[out_idx++] = a_g;
            out_bits[out_idx++] = b_g;
        }
        if (a_b != b_b) {
            out_bits[out_idx++] = a_b;
            out_bits[out_idx++] = b_b;
        }
    }
    return out_idx;
}

// Image resizing
Mat resized_img(const Mat &input_image, int new_width, int new_height) {
    Mat resized_image;
    Size new_size(new_width, new_height);
    resize(input_image, resized_image, new_size, 0, 0, INTER_LINEAR);
    imwrite(RESIZED_FILE, resized_image);
    return resized_image;
}


// Bit uniformity 계산 (0과 1 빈도 비교)
double calculate_uniformity(const uint8_t *bits, int len) {
    if (len == 0) return 0.0;
    int count_ones = 0;
    for (int i = 0; i < len; ++i) {
        if (bits[i]) count_ones++;
    }
    double p = (double)count_ones / len;

    return p;
}

int main() {
    printf("Image capturing...\n");
    int ret = system("rpicam-still -o capture.jpg -n -q 90 --width 3280 --height 2464");
    if (ret != 0) {
        fprintf(stderr, "Image Capture Failure !\n");
        return 1;
    }

    Mat image = imread(IMAGE_FILE, IMREAD_COLOR);
    if (image.empty()) {
        fprintf(stderr, "Image Loading Failure !\n");
        return 1;
    }

    if (!detect_speckle(image)) {
        printf("Speckle Image Recognition Failure !\n");
        return 0;
    }
    printf("Speckle Image is Successfully Recognized.\n");

    // 85% threshold 이미지 생성 및 저장
    Mat threshold_img;
    create_threshold_image(image, threshold_img);
    printf("File generated(%f% Threshold Applied)\n", THRESHOLD_PERCENT * 100);

    // Image resizing
    Mat resized;
    resized_img(threshold_img, RESIZING_H, RESIZING_V);
    printf("File generated(RESIZED by %d x %d)\n", RESIZING_H, RESIZING_V);

    // 채널 분리 및 bits 변환
    std::vector<Mat> channels(3);
    split(image, channels);

    int img_size = image.rows * image.cols;
    uint8_t *bits_r = (uint8_t *)malloc(img_size);
    uint8_t *bits_g = (uint8_t *)malloc(img_size);
    uint8_t *bits_b = (uint8_t *)malloc(img_size);
    if (!bits_r || !bits_g || !bits_b) {
        fprintf(stderr, "메모리 할당 실패\n");
        free(bits_r); free(bits_g); free(bits_b);
        return 1;
    }

    image_to_bits(channels[2], bits_r); // R
    image_to_bits(channels[1], bits_g); // G
    image_to_bits(channels[0], bits_b); // B

    uint8_t *out_bits = (uint8_t *)malloc(MAX_TUPLES * 6);
    if (!out_bits) {
        fprintf(stderr, "메모리 할당 실패\n");
        free(bits_r); free(bits_g); free(bits_b);
        return 1;
    }

    int out_len = multi_channel_vonneumann(bits_r, bits_g, bits_b, img_size, out_bits, MAX_TUPLES * 6);

    // uniformity 출력
    double uniformity = calculate_uniformity(out_bits, out_len);
    printf("추출된 bit 앞 10자리: ");
    for (int i = 0; i < (out_len > 10 ? 10 : out_len); ++i) {
        printf("%d", out_bits[i]);
    }
    printf("\nBit uniformity: %.4f\n", uniformity);

    FILE *fp = fopen(OUTPUT_FILE, "w");
    if (fp) {
        for (int i = 0; i < out_len; i++) {
            fputc(out_bits[i] ? '1' : '0', fp);
        }
        fclose(fp);
        printf("추출된 bit가 %s 에 저장되었습니다.\n", OUTPUT_FILE);
    } else {
        fprintf(stderr, "파일 저장 실패\n");
    }

    free(bits_r);
    free(bits_g);
    free(bits_b);
    free(out_bits);

    return 0;
}
