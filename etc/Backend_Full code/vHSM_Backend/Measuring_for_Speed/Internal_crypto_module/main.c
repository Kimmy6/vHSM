#include "crypto.h"
#include <time.h>

int main() {
    clock_t start_time = clock();

    char all_keys[KEY_NUM][KEY_STR_LEN + 1]; // 80 key storage
    unsigned char key[KEY_BYTES]; // 24 byte converted key storage
    unsigned char iv[IV_BYTES]; // 16 byte initialization vector storage
    char plaintext[PLAINTEXT_MAX_LEN]; // input plaintext storage
    unsigned char ciphertext[CIPHERTEXT_MAX_LEN]; // output ciphertext storage
    int ciphertext_len; // ciphertext length storage

    // 1. Read the key from .txt file
    FILE *fp = fopen("pufkey.txt", "r");
    if(!fp) {
        printf("There is no key file!\n");
        return 1;
    }

    // 2. Load the 80 keys from key file
    for (int i = 0; i < KEY_NUM; i++) {
        if (fread(all_keys[i], 1, KEY_STR_LEN, fp) != KEY_STR_LEN) {
            printf("ERROR occurred while reading key file!\n");
            fclose(fp);
            return 1;
        }
        all_keys[i][KEY_STR_LEN] = '\0';

        int c;
        while ((c = fgetc(fp)) != EOF && (c == '\n' || c == '\r'));
        if (c != EOF) ungetc(c, fp);
    }
    fclose(fp);

    // 3. User input: Key handle
int key_index;
while (1) {
    printf("Type the key handle: ");
    if(scanf("%d", &key_index) == 1 && key_index >= 1 && key_index <= KEY_NUM) {
        key_index -= 1;
        break;
    } else {
        printf("Invalid Key handle! Type again!\n");
        while (getchar() != '\n'); // Reset input butffer
    }
}

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

    if(choice == 1) {
        // Encryption mode
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
            printf("ERROR occurred while initialization vector generation!\n");
            return 1;
        }

        if(encrypt_aes_192_cbc(key, iv, (unsigned char*)plaintext, (int)plen, ciphertext, &ciphertext_len) != 0) {
            printf("Encryption failed!\n");
            return 1;
        }

        printf("Ciphertext(HEX): ");
        print_hex(ciphertext, ciphertext_len);

        printf("IV(HEX): ");
        print_hex(iv, IV_BYTES);
    }
    else {
        // Decryption mode
        char hex_ciphertext[CIPHERTEXT_MAX_LEN * 2 + 1];
        char hex_iv[IV_BYTES * 2 + 1];
        int ciphertext_len, input_success = 0;

    unsigned char decrypted[PLAINTEXT_MAX_LEN];
    int decrypted_len;

    while (1) {
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

        ciphertext_len = hexstr_to_bytes(hex_ciphertext, ciphertext, sizeof(ciphertext));
        if(ciphertext_len < 0) {
            printf("Ciphertext conversion failure! Type again!\n");
            continue;
        }
        if(hexstr_to_bytes(hex_iv, iv, IV_BYTES) != IV_BYTES) {
            printf("IV conversion failure! Type again!\n");
            continue;
        }

        
        if(decrypt_aes_192_cbc(key, iv, ciphertext, ciphertext_len, decrypted, &decrypted_len) == 0) {
            
            decrypted[decrypted_len] = '\0';
            printf("Decrypted Plaintext: %s\n", decrypted);
            break;
        } else {
            printf("Decryption Failure! Type again!\n");
        }
    }
}
    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("Elapsed Time: %.6f seconds\n", elapsed_time);
    return 0;
}