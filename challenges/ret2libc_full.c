// ret2libc_full.c - 包含足够代码以生成__libc_csu_init gadgets
// 编译: gcc -fno-stack-protector -no-pie -o ret2libc_full ret2libc_full.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char *gets(char *s);

void init_stuff() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void do_nothing(int a, int b, int c, int d, int e, int f) {
    // 这个函数强制gcc包含__libc_csu_init
    // 用于ret2csu gadgets
    volatile int x = a + b + c + d + e + f;
    (void)x;
}

void vuln() {
    char buf[48];
    printf("Welcome! Enter some text: ");
    gets(buf);
    puts(buf);
    printf("Goodbye!\n");
}

int main(int argc, char **argv) {
    init_stuff();
    puts("ret2libc challenge - leak libc and get shell!");
    vuln();
    do_nothing(1,2,3,4,5,6);
    return 0;
}
