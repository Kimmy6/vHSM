// arduino_entropy_rsa.c
// - Arduino MEGA 2560 시리얼 출력(raw=...)에서 144비트 추출
// - 510.0 ≤ raw < 510.3 -> 0,  raw ≥ 510.3 -> 1 (그 외는 무시)
// - 144비트가 모이면 즉시 RSA 키 생성 및 PEM 저장
//
// Build: gcc -O2 -std=c11 arduino_entropy_rsa.c -o arduino_entropy_rsa -lcrypto
// Usage: ./arduino_entropy_rsa [/dev/ttyACM0]
//
// 참고: 이 CTR_DRBG 구현은 NIST 800-90A 정식 구현이 아닌 단순화 버전입니다.
//       (사용자 제공 코드 로직을 유지)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// -----------------------------
// 1) 시리얼 포트 설정/열기
// -----------------------------
static int set_serial_115200_8n1(int fd) {
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        perror("tcgetattr");
        return -1;
    }

    cfmakeraw(&tty);
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);

    // 8N1, no flow control
    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
    tty.c_cflag &= ~(PARENB | CSTOPB | CRTSCTS);
    tty.c_cflag |= (CLOCAL | CREAD);

    // read timeout: 1.0s (VTIME*0.1s), non-blocking-ish
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 10;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        perror("tcsetattr");
        return -1;
    }
    return 0;
}

static int open_serial(const char *dev) {
    int fd = open(dev, O_RDONLY | O_NOCTTY);
    if (fd < 0) {
        perror("open serial");
        return -1;
    }
    if (set_serial_115200_8n1(fd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// -----------------------------
// 2) 라인 단위 읽기 + raw 파싱
// -----------------------------
static int read_line(int fd, char *buf, size_t bufsz) {
    size_t pos = 0;
    while (1) {
        char ch;
        ssize_t n = read(fd, &ch, 1);
        if (n < 0) {
            if (errno == EAGAIN) continue;
            return -1; // read error
        }
        if (n == 0) {
            // timeout
            return 0;
        }
        if (ch == '\r') continue;
        if (ch == '\n') {
            buf[pos] = '\0';
            return 1;
        }
        if (pos + 1 < bufsz) buf[pos++] = ch;
        else {
            // overflow -> reset buffer
            pos = 0;
        }
    }
}

// "raw=510.23,V=...,R=..." 형태에서 raw 값(double) 추출
static int parse_raw_from_line(const char *line, double *out_raw) {
    const char *p = strstr(line, "raw=");
    if (!p) return 0;
    p += 4; // skip "raw="
    // strtod로 실수 파싱
    char *endptr = NULL;
    double v = strtod(p, &endptr);
    if (endptr == p) return 0; // no number
    *out_raw = v;
    return 1;
}

// -----------------------------
// 3) 144비트 수집
// -----------------------------
static int read_entropy_from_arduino(const char *dev, uint8_t *buffer, size_t bit_len) {
    if (bit_len == 0) return 0;

    int fd = open_serial(dev);
    if (fd < 0) return 0;

    // Arduino는 포트 오픈 시 리셋되는 보드가 있음 -> 잠깐 대기
    usleep(1500 * 1000);

    memset(buffer, 0, (bit_len + 7) / 8);
    size_t bits_read = 0;

    char line[1024];

    fprintf(stderr, "[INFO] Waiting Arduino lines on %s ...\n", dev);
    fprintf(stderr, "[INFO] Rule: 510.0 ≤ raw < 510.3 -> 0,  raw ≥ 510.3 -> 1 (else ignore)\n");

    while (bits_read < bit_len) {
        int rc = read_line(fd, line, sizeof(line));
        if (rc < 0) {
            perror("read_line");
            close(fd);
            return 0;
        }
        if (rc == 0) {
            // timeout -> 계속 대기
            continue;
        }

        if (line[0] == '\0' || line[0] == '#') continue;

        double raw;
        if (!parse_raw_from_line(line, &raw)) {
            // 다른 포맷이면 무시
            continue;
        }

        int bit = -1;
        if (raw == 510.0) bit = 0;
        else if (raw != 510.0) bit = 1;
        else bit = -1; // <510.0 은 무시

        if (bit == 0 || bit == 1) {
            if (bit == 1) {
                buffer[bits_read / 8] |= (1u << (7 - (bits_read % 8)));
            }
            bits_read++;

            // 진행 상황 표시(옵션)
            if (bits_read % 16 == 0) {
                fprintf(stderr, "[INFO] collected %zu / %zu bits\n", bits_read, bit_len);
            }
        }
    }

    close(fd);
    return 1;
}

// -----------------------------
// 4) (사용자 제공) 단순 CTR_DRBG
// -----------------------------
typedef struct {
    AES_KEY aes_key;
    uint8_t V[16];
} CTR_DRBG_CTX;

static void increment_counter(uint8_t *ctr) {
    for (int i = 15; i >= 0; i--) {
        if (++ctr[i] != 0) break;
    }
}

static void ctr_drbg_instantiate(CTR_DRBG_CTX *ctx, const uint8_t *seed /* 18 bytes 기대 */) {
    // AES-128 키는 seed[0..15]만 사용
    AES_set_encrypt_key(seed, 128, &ctx->aes_key);
    memset(ctx->V, 0, 16);
    // 추가 2바이트를 V의 하위 바이트에 반영(사용자 원 코드를 유지)
    ctx->V[14] = seed[16];
    ctx->V[15] = seed[17];
}

static void ctr_drbg_generate(CTR_DRBG_CTX *ctx, uint8_t *out, size_t outlen) {
    uint8_t block[16];
    size_t generated = 0;
    while (generated < outlen) {
        increment_counter(ctx->V);
        AES_encrypt(ctx->V, block, &ctx->aes_key);
        size_t copy_len = (outlen - generated < 16) ? (outlen - generated) : 16;
        memcpy(out + generated, block, copy_len);
        generated += copy_len;
    }
}

// -----------------------------
// 5) RSA 키 생성 (사용자 제공 로직 유지)
// -----------------------------
static void generate_1024bit_random(CTR_DRBG_CTX *ctx, BIGNUM *num) {
    uint8_t buffer[128];
    ctr_drbg_generate(ctx, buffer, 128);
    buffer[0] |= 0x80;   // set MSB for 1024 bits
    buffer[127] |= 0x01; // ensure odd
    BN_bin2bn(buffer, 128, num);
}

static int is_prime_bn(BIGNUM *num) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;
    int ret = BN_is_prime_ex(num, 20, ctx, NULL);
    BN_CTX_free(ctx);
    return ret == 1;
}

static int rsa_key_generate(CTR_DRBG_CTX *ctx, BIGNUM **p, BIGNUM **q,
                            BIGNUM **n, BIGNUM **e, BIGNUM **d) {
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) return 0;

    *p = BN_new(); *q = BN_new(); *n = BN_new(); *e = BN_new(); *d = BN_new();
    if (!(*p && *q && *n && *e && *d)) {
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BN_set_word(*e, 65537);

    do { generate_1024bit_random(ctx, *p); } while (!is_prime_bn(*p));
    do { generate_1024bit_random(ctx, *q); } while (!is_prime_bn(*q));

    if (!BN_mul(*n, *p, *q, bn_ctx)) {
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BIGNUM *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new();
    if (!p1 || !q1 || !phi) {
        BN_free(p1); BN_free(q1); BN_free(phi);
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BN_sub(p1, *p, BN_value_one());
    BN_sub(q1, *q, BN_value_one());
    BN_mul(phi, p1, q1, bn_ctx);

    if (!BN_mod_inverse(*d, *e, phi, bn_ctx)) {
        fprintf(stderr, "BN_mod_inverse failed: e not coprime with phi.\n");
        BN_free(p1); BN_free(q1); BN_free(phi);
        BN_CTX_free(bn_ctx);
        return 0;
    }

    BN_free(p1); BN_free(q1); BN_free(phi);
    BN_CTX_free(bn_ctx);
    return 1;
}

static RSA *rsa_build_key(BIGNUM *p, BIGNUM *q, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    RSA *rsa = RSA_new();
    if (!rsa) return NULL;

    if (!RSA_set0_factors(rsa, BN_dup(p), BN_dup(q))) {
        RSA_free(rsa);
        return NULL;
    }
    if (!RSA_set0_key(rsa, BN_dup(n), BN_dup(e), BN_dup(d))) {
        RSA_free(rsa);
        return NULL;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { RSA_free(rsa); return NULL; }

    BIGNUM *dmp1 = BN_new(), *dmq1 = BN_new(), *iqmp = BN_new();
    BIGNUM *p1 = BN_new(), *q1 = BN_new();
    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());

    BN_mod(dmp1, d, p1, ctx);
    BN_mod(dmq1, d, q1, ctx);
    BN_mod_inverse(iqmp, q, p, ctx);

    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

    BN_free(p1); BN_free(q1);
    BN_CTX_free(ctx);
    return rsa;
}

// -----------------------------
// 6) main
// -----------------------------
int main(int argc, char **argv) {
    const char *serial_dev = (argc >= 2) ? argv[1] : "/dev/ttyACM0";

    clock_t start = clock();

    // 144비트 수집
    uint8_t entropy[18]; // 144 bits = 18 bytes
    if (!read_entropy_from_arduino(serial_dev, entropy, 144)) {
        fprintf(stderr, "Failed to collect 144 bits from Arduino (%s)\n", serial_dev);
        return 1;
    }

    // 수집된 엔트로피 출력(HEX)
    printf("Loaded entropy from Arduino (hex): ");
    for (int i = 0; i < 18; i++) printf("%02X", entropy[i]);
    printf("\n");

    // DRBG 인스턴스 생성
    CTR_DRBG_CTX drbg_ctx;
    ctr_drbg_instantiate(&drbg_ctx, entropy);

    // RSA 키 생성
    BIGNUM *p = NULL, *q = NULL, *n = NULL, *e = NULL, *d = NULL;
    if (!rsa_key_generate(&drbg_ctx, &p, &q, &n, &e, &d)) {
        fprintf(stderr, "RSA key generation failed\n");
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }

    printf("Generated RSA key components:\n");
    printf("p = "); BN_print_fp(stdout, p); printf("\n");
    printf("q = "); BN_print_fp(stdout, q); printf("\n");
    printf("n = "); BN_print_fp(stdout, n); printf("\n");
    printf("e = "); BN_print_fp(stdout, e); printf("\n");
    printf("d = "); BN_print_fp(stdout, d); printf("\n");

    RSA *rsa = rsa_build_key(p, q, n, e, d);
    if (!rsa) {
        fprintf(stderr, "Failed to build RSA key\n");
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }

    FILE *priv_fp = fopen("rsa_private.pem", "wb");
    if (!priv_fp) {
        fprintf(stderr, "Error opening file for private key\n");
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    if (!PEM_write_RSAPrivateKey(priv_fp, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key\n");
        fclose(priv_fp);
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    fclose(priv_fp);

    FILE *pub_fp = fopen("rsa_public.pem", "wb");
    if (!pub_fp) {
        fprintf(stderr, "Error opening file for public key\n");
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    if (!PEM_write_RSA_PUBKEY(pub_fp, rsa)) {
        fprintf(stderr, "Error writing public key\n");
        fclose(pub_fp);
        RSA_free(rsa);
        BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
        return 1;
    }
    fclose(pub_fp);

    printf("RSA key pair saved to rsa_private.pem (private) and rsa_public.pem (public)\n");

    BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
    RSA_free(rsa);

    double cpu_time_used = (double)(clock() - start) / CLOCKS_PER_SEC;
    printf("Execution time: %f seconds\n", cpu_time_used);

    return 0;
}
