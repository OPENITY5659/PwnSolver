// ret2libc.c - 经典ret2libc题目
// 编译: gcc -fno-stack-protector -no-pie -o ret2libc ret2libc.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char *gets(char *s);

void vuln() {
    char buf[48];
    printf("Welcome! Enter some text: ");
    gets(buf);
    puts(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ret2libc challenge - leak libc and get shell!");
    vuln();
    return 0;
}
