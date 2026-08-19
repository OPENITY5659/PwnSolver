// ret2win_prompt.c - 非标准提示风格: 自定义提示 + gets 溢出 → ret2win
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *gets(char *s);

void win() {
    printf("You win! FLAG{ret2win_prompt}\n");
    system("/bin/sh");
}

void vuln() {
    char buf[0x30];
    printf("Please enter your name: ");
    fflush(stdout);
    gets(buf);
    printf("Hello, %s!\n", buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("=== Name Service v2.0 ===\n");
    vuln();
    printf("Goodbye!\n");
    return 0;
}
