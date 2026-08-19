// crypto_demo.c - 加解密识别演示: base64 字母表 + XOR 加密
#include <stdio.h>
#include <string.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void xor_encrypt(char *buf, int len) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= 0x41;   // XOR key 0x41
    }
}

int main() {
    char input[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Enter data: ");
    fgets(input, sizeof(input), stdin);
    xor_encrypt(input, strlen(input));
    printf("Encrypted (base64 would be): %s\n", b64_table);
    return 0;
}
