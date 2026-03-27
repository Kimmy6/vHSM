#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <opencv2/opencv.hpp>

#define IMAGE_FILE "capture"
#define IMAGE_FILE_JPG "capture.tiff"
#define THRESHOLD_IMAGE_FILE "threshold_image.tiff"
#define OUTPUT_FILE "extracted_bits.txt"
#define RESIZED_FILE "resized_image.jpg"
#define THRESHOLD_PERCENT 0.5
#define MAX_TUPLES 1000000
#define RESIZING_V 960
#define RESIZING_H 1280

using namespace cv;

// // Speckle detection: count how many pixels are very dark
// bool detect_speckle(const Mat &image) {
//     int dark_pixel_count = 0;
//     int total_pixels = image.rows * image.cols;

//     for (int i = 0; i < total_pixels; ++i) {
//         // Access grayscale pixel directly
//         uchar pix = image.data[i];
//         if (pix < (255 * 0.05)) dark_pixel_count++;
//     }
//     return (dark_pixel_count > (total_pixels * 0.05)); // at least 5% dark pixels
// }

// Create threshold image from grayscale image
void create_threshold_image(const Mat &gray, Mat &threshold_img) {
    threshold_img.create(gray.rows, gray.cols, CV_8UC1);
    int threshold_val = static_cast<int>(255 * THRESHOLD_PERCENT);
    for (int r = 0; r < gray.rows; ++r) {
        for (int c = 0; c < gray.cols; ++c) {
            int brightness = gray.at<uchar>(r, c);
            threshold_img.at<uchar>(r, c) = (brightness >= threshold_val) ? 255 : 0;
        }
    }
    imwrite(THRESHOLD_IMAGE_FILE, threshold_img);
}

// Convert threshold image (binary) to bit array (0 or 1)
void image_to_bits(const Mat &threshold_img, uint8_t *bits) {
    int size = threshold_img.rows * threshold_img.cols;
    for (int i = 0; i < size; ++i) {
        bits[i] = (threshold_img.data[i] == 255) ? 1 : 0;
    }
}

// Single-pass tuple-output von Neumann debiasing on pairs
int tuple_output_vonneumann_pass(const uint8_t *bits, int len, uint8_t *out_bits, int max_out_len) {
    int out_idx = 0;
    for (int i = 0; i < len - 1; i += 2) {
        if (out_idx + 2 > max_out_len) break;
        if (bits[i] != bits[i + 1]) {
            out_bits[out_idx++] = bits[i];
            out_bits[out_idx++] = bits[i + 1];
        }
    }
    return out_idx;
}

// Two-pass tuple-output von Neumann debiasing for better output and quality
int two_pass_tuple_output_vonneumann(uint8_t *bits, int len, uint8_t *out_bits, int max_out_len) {
    uint8_t *pass1_bits = (uint8_t *)malloc(max_out_len);
    if (!pass1_bits) return -1;

    // First pass
    int pass1_len = tuple_output_vonneumann_pass(bits, len, pass1_bits, max_out_len);
    if (pass1_len < 2) {
        free(pass1_bits);
        return 0;  // Not enough bits for second pass
    }

    // Second pass
    int pass2_len = tuple_output_vonneumann_pass(pass1_bits, pass1_len, out_bits, max_out_len);

    free(pass1_bits);
    return pass2_len;
}

// Calculate uniformity of bit array (proportion of ones)
double calculate_uniformity(const uint8_t *bits, int len) {
    if (len == 0) return 0.0;
    int count_ones = 0;
    for (int i = 0; i < len; ++i) {
        if (bits[i]) count_ones++;
    }
    return (double)count_ones / len;
}

// Resize image and save file
Mat resized_img(const Mat &input_image, int new_width, int new_height) {
    Mat resized_image;
    Size new_size(new_width, new_height);
    resize(input_image, resized_image, new_size, 0, 0, INTER_LINEAR);
    imwrite(RESIZED_FILE, resized_image);
    return resized_image;
}

// Main extraction function accessible via C linkage
extern "C" int extract_bits_from_image(const char *image_path, uint8_t *out_bits, int max_len) {
    // Capture image with fixed white balance gains (disable AWB)
    printf("Image capturing...\n");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rpicam-still --raw --timeout 50 --shutter 1500 --gain 1.0 -o %s\ndcraw -4 -d -T capture.dng", IMAGE_FILE_JPG);

    int ret = system(cmd);


    if (ret != 0) {
        fprintf(stderr, "Image Capture Failure!\n");
        return 1;
    }

    Mat image = imread(IMAGE_FILE_JPG, IMREAD_GRAYSCALE);
    if (image.empty()) {
        fprintf(stderr, "Image Loading Failure!\n");
        return 1;
    }

    // if (!detect_speckle(image)) {
    //     printf("Speckle Image Recognition Failure!\n");
    //     return 0;
    // }
    // printf("Speckle Image is Successfully Recognized.\n");

    Mat resized_image = resized_img(image, RESIZING_H, RESIZING_V);

    Mat threshold_image;
    create_threshold_image(resized_image, threshold_image);

    int img_size = threshold_image.rows * threshold_image.cols;

    uint8_t *raw_bits = (uint8_t *)malloc(img_size);
    if (!raw_bits) {
        fprintf(stderr, "Memory allocation failure!\n");
        return -1;
    }

    image_to_bits(threshold_image, raw_bits);

    int out_len = two_pass_tuple_output_vonneumann(raw_bits, img_size, out_bits, max_len);

    free(raw_bits);

    double uniformity = calculate_uniformity(out_bits, out_len);
    printf("Extracted bit first 10: ");
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
        printf("Extracted bits saved to %s\n", OUTPUT_FILE);
    } else {
        fprintf(stderr, "Failed to save bit file.\n");
    }

    return out_len;
}
