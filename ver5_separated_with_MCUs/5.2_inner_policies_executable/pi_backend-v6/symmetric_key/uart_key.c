#include "uart_key.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

static int setup_uart(const char *port)
{
    int fd = open(port, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        perror("open uart");
        return -1;
    }

    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        perror("tcgetattr");
        close(fd);
        return -1;
    }

    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);

    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
    tty.c_cflag |= CLOCAL | CREAD;
    tty.c_cflag &= ~(PARENB | PARODD);
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;

    tty.c_iflag = 0;
    tty.c_oflag = 0;
    tty.c_lflag = 0;

    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 1;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        perror("tcsetattr");
        close(fd);
        return -1;
    }

    tcflush(fd, TCIOFLUSH);
    return fd;
}

static int read_line_with_timeout(int fd, char *buf, int max_len, int timeout_sec)
{
    int idx = 0;

    while (idx < max_len - 1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        int rv = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) {
            perror("select");
            return -1;
        }
        if (rv == 0) {
            return 0;
        }

        char c;
        int n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            perror("read");
            return -1;
        }
        if (n == 0) {
            continue;
        }

        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            if (idx == 0) {
                continue;
            }
            break;
        }

        buf[idx++] = c;
    }

    buf[idx] = '\0';
    return idx;
}

int receive_key_hex_from_uart(const char *port, unsigned char *key, int key_len, int timeout_sec)
{
    int fd = setup_uart(port);
    if (fd < 0) {
        return 1;
    }

    char line[512];
    char key_hex[KEY_BYTES * 2 + 1];
    key_hex[0] = '\0';

    int saw_ready = 0;
    int saw_done = 0;

    while (!saw_done) {
        int len = read_line_with_timeout(fd, line, sizeof(line), timeout_sec);
        if (len < 0) {
            close(fd);
            return 1;
        }
        if (len == 0) {
            fprintf(stderr, "UART timeout while waiting for ESP32 response.\n");
            close(fd);
            return 1;
        }

        printf("[ESP32] %s\n", line);

        if (strcmp(line, "READY") == 0) {
            if (!saw_ready) {
                if (write(fd, "G", 1) != 1) {
                    perror("write trigger");
                    close(fd);
                    return 1;
                }
                tcdrain(fd);
                saw_ready = 1;
                printf("[PI] Sent trigger: G\n");
            }
        } else if (strncmp(line, "KEY_HEX:", 8) == 0) {
            strncpy(key_hex, line + 8, sizeof(key_hex) - 1);
            key_hex[sizeof(key_hex) - 1] = '\0';
        } else if (strcmp(line, "DONE") == 0) {
            saw_done = 1;
        } else if (strncmp(line, "ERROR:", 6) == 0) {
            fprintf(stderr, "ESP32 reported error: %s\n", line);
            close(fd);
            return 1;
        }
    }

    close(fd);

    if ((int)strlen(key_hex) != key_len * 2) {
        fprintf(stderr, "Invalid KEY_HEX length: got %zu, expected %d\n",
                strlen(key_hex), key_len * 2);
        return 1;
    }

    if (hexstr_to_bytes(key_hex, key, key_len) != key_len) {
        fprintf(stderr, "Failed to parse KEY_HEX.\n");
        return 1;
    }

    return 0;
}
