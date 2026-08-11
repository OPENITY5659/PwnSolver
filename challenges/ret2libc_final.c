// ret2libc_final.c - 显式包含gadgets
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
    
    // 这些永远不会执行，但提供ROP gadgets
    // pop rdi; ret -> pops 8 bytes from stack into rdi, then ret
    // pop rsi; pop r15; ret -> useful for setting rsi
    __asm__ volatile(
        ".global gadgets\n"
        "gadgets:\n"
        "    pop %rdi\n"
        "    ret\n"
        "    pop %rsi\n"
        "    pop %r15\n"
        "    ret\n"
        "    ret\n"
    );
    return 0;
}
