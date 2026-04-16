#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SIZE (1024 * 1024)  // 1MB

int main() {
    unsigned char *buffer = (unsigned char *)malloc(SIZE);
    if (!buffer) {
        fprintf(stderr, "메모리 할당 실패\n");
        return 1;
    }

    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < SIZE; i++) {
        buffer[i] = rand() % 256;
    }

    // 텍스트 파일 열기
    FILE *fp = fopen("random_data.txt", "w");
    if (!fp) {
        fprintf(stderr, "파일 열기 실패\n");
        free(buffer);
        return 1;
    }

    // 16진수 형태로 바이트를 텍스트에 저장 (예: "3F", "A0" 식으로)
    for (size_t i = 0; i < SIZE; i++) {
        fprintf(fp, "%02X", buffer[i]);

            fprintf(fp, " "); // 구분자 공백

    }

    fclose(fp);
    free(buffer);

    printf("1MB 난수가 random_data.txt 파일에 저장되었습니다.\n");
    return 0;
}
