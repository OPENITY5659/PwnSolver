// ret2libc_v2.c - 更现实的ret2libc题目，包含有用gadgets
// 编译: gcc -fno-stack-protector -no-pie -o ret2libc_v2 ret2libc_v2.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char *gets(char *s);

// 提供一个"无害"函数，其中包含有用的gadgets
// 编译器会生成 pop rdi; ret 等gadgets
void helper() {
    // 这些调用会生成有用的gadgets
    asm volatile("nop");
    asm volatile("nop");
}

void vuln() {
    char buf[48];
    printf("Welcome! Enter some text: ");
    gets(buf);
    puts(buf);
    printf("Goodbye!\n");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ret2libc challenge V2 - leak libc and get shell!");
    vuln();
    // 以下代码生成更多gadgets
    helper();
    return 0;
}
