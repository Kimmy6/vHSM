#ifndef UART_KEY_H
#define UART_KEY_H

#include "crypto.h"

int receive_key_hex_from_uart(const char *port, unsigned char *key, int key_len, int timeout_sec);

#endif
