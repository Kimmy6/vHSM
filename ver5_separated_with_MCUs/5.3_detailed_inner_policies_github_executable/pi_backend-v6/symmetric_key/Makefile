CC=gcc
CFLAGS=-O2 -Wall -Wextra
LDFLAGS=-lssl -lcrypto
SRC=main.c crypto.c encryption.c decryption.c uart_key.c
TARGET=aes_uart

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
