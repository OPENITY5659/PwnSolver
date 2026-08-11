// rop.c - 简单ROP题目
// 编译: gcc -fno-stack-protector -no-pie -o rop rop.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char *gets(char *s);

void vuln() {
    char buf[64];
    printf("ROP me: ");
    gets(buf);
    puts("Thanks!");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Simple ROP Challenge");
    vuln();
    return 0;
}
