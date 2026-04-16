#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <ctype.h>

// Key length define
const int KEY_BYTES = 24;
int IV_BYTES = 16;
int BLOCK_SIZE = 16;

// Key number define
int KEY_NUM = 80;
int KEY_STR_LEN = KEY_BYTES * 8;
int PLAINTEXT_MAX_LEN = 1024;
int CIPHERTEXT_MAX_LEN = 2048;

// Function: Binary code conversion for byte
/* Variable description
const char *binstr: read-only (const), one string type (char), pointer (*binstr)
*binstr: starting address of the varibale 'binstr'.  

unsigned char *keybuf: 0-255 byte data type (unsigned char), pointer (*keybuf)
*keybuf: starting address of the variable 'keybuf'.

int keylen: conversion byte length (AES-192: 24 bytes)
*/

void binstr_to_bytes(const char *binstr, unsigned char *keybuf, int keylen) {
    for(int i=0; i<keylen; i++) {
        unsigned char b = 0;
        for(int j=0; j<8; j++) {
            b <<= 1 ;
            if(binstr[i*8+j] == '1') b |= 1;
        }
        keybuf[i] = b;
    }
}

// Function: Hex-type char conversion for byte
int hexstr_to_bytes(const char *hexstr, unsigned char *buf, int max_len) {
    int len = strlen(hexstr);
    if(len % 2 != 0) return -1; // should even number
    int byte_len = len / 2;
    if(byte_len > max_len) return -1;

    for(int i = 0; i < byte_len; i++) {
        sscanf(hexstr + 2*i, "%2hhx", &buf[i]);
    }
    return byte_len;
}

// Function: Byte array conversion for hex char
void print_hex(const unsigned char *buf, int len) {
    for(int i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    char all_keys[KEY_NUM][KEY_STR_LEN + 1]; // 80 key storage
    unsigned char key[KEY_BYTES]; // 24 byte converted key storage
    unsigned char iv[IV_BYTES]; // 24 byte initialized vector storage
    char plaintext[PLAINTEXT_MAX_LEN]; // input plaintext storage 
    unsigned char ciphertext[CIPHERTEXT_MAX_LEN]; // output ciphertext storage
    int ciphertext_len; // ciphertext length storage

    // 1. Read the key from .txt file
    FILE *fp = fopen("pufkey.txt", "r");
    if(!fp) {
        printf("There is no key file! \n");
        return 1;
    }

    // 2. Load the 80 keys from key file
    for (int i = 0; i < KEY_NUM; i++) {
        if (fread(all_keys[i], 1, KEY_STR_LEN, fp) != KEY_STR_LEN) {
            printf("ERROR occured while read key file!\n");
            fclose(fp);
            return 1;
        }

        all_keys[i][KEY_STR_LEN] = '\0';

        int c;
        while ((c = fgetc(fp)) != EOF && (c == '\n' || c == '\r')) ;
        if (c != EOF) ungetc(c, fp);
    }
    fclose(fp);

    // 3. User input: Key handle
    int key_index;
    printf("Type the key handle: ");
    if(scanf("%d", &key_index) != 1 || key_index < 1 || key_index > KEY_NUM) {
        printf("Invalid Key handle!\n");
        return 1;
    }
    key_index -= 1;

    // 4. User input: Mode for encryption or decryption
    int choice;
    printf("Type the mode: 1) AES-192 encryption 2) AES-192 decryption : ");
    if(scanf("%d", &choice) != 1 || (choice != 1 && choice != 2)) {
        printf("Invalid mode!\n");
        return 1;
    }
    getchar();

    // Binary to byte conversion of key file 
    binstr_to_bytes(all_keys[key_index], key, KEY_BYTES);

    // 5-1. User input for encryption: Plaintext
    if(choice == 1) {
        printf("Type the plaintext: ");
        if(!fgets(plaintext, sizeof(plaintext), stdin)) {
            printf("Plaintext input failure!\n");
            return 1;
        }
        
    size_t plen = strlen(plaintext);
    if (plen > 0 && plaintext[plen - 1] == '\n') {
        plaintext[plen - 1] = '\0';
        plen--;
    }
    
    if (!RAND_bytes(iv, IV_BYTES)) {
        printf("ERROR occured while initialization vector generation!\n");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        printf("EVP_CIPHER_CTX_new failure!\n");
        return 1;
    }
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv)) {
        printf("EVP_EncryptInit_ex failure!\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len;
    
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, (int)plen)) {
            printf("EVP_EncryptUpdate failure!\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
            printf("EVP_EncryptFinal_ex failure!\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext(HEX): ");
    print_hex(ciphertext, ciphertext_len);
    printf("IV(HEX): ");
    print_hex(iv, IV_BYTES);
    }

    else {
        // Decryption
        char hex_ciphertext[CIPHERTEXT_MAX_LEN * 2 + 1];
        char hex_iv[IV_BYTES * 2 + 1];
        printf("Type the ciphertext: ");
        if(!fgets(hex_ciphertext, sizeof(hex_ciphertext), stdin)) {
            printf("Ciphertext input failure!\n");
            return 1;
        }
        size_t clen = strlen(hex_ciphertext);
        if(clen > 0 && hex_ciphertext[clen-1] == '\n') {
            hex_ciphertext[clen-1] = '\0';
            clen--;
        }

        printf("Type the IV(HEX): ");
        if(!fgets(hex_iv, sizeof(hex_iv), stdin)) {
            printf("IV input failure!\n");
            return 1;
        }
        size_t ivlen = strlen(hex_iv);
        if(ivlen > 0 && hex_iv[ivlen-1] == '\n') {
            hex_iv[ivlen-1] = '\0';
            ivlen--;
        }

        // hex -> bytes 변환
        ciphertext_len = hexstr_to_bytes(hex_ciphertext, ciphertext, sizeof(ciphertext));
        if(ciphertext_len < 0) {
            printf("Ciphertext conversion failure!\n");
            return 1;
        }
        if(hexstr_to_bytes(hex_iv, iv, IV_BYTES) != IV_BYTES) {
            printf("IV conversion failure!\n");
            return 1;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(!ctx) {
            printf("EVP_CIPHER_CTX_new failure!\n");
            return 1;
        }
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv)) {
            printf("EVP_DecryptInit_ex failure!\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        unsigned char decrypted[PLAINTEXT_MAX_LEN];
        int len;
        int decrypted_len;

        if(1 != EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len)) {
            printf("EVP_DecryptUpdate failure!\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        decrypted_len = len;

        if(1 != EVP_DecryptFinal_ex(ctx, decrypted + len, &len)) {
            printf("EVP_DecryptFinal_ex failure!\n");
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        decrypted_len += len;

        EVP_CIPHER_CTX_free(ctx);

        decrypted[decrypted_len] = '\0';
        printf("Decrypted Plaintext: %s\n", decrypted);
    }

    return 0;
}