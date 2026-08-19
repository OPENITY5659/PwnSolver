// ret2libc_canary.c - canary 绕过: write 按长度泄露 canary, 循环内二次利用
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[0x30];
    printf("Enter: ");
    fflush(stdout);
    ssize_t n = read(0, buf, 0x100);
    write(1, buf, 0x100);   // 按读入长度输出, 可带出 canary/rbp/ret
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("Canary challenge!");
    for (int i = 0; i < 5; i++) vuln();
    puts("bye");
    return 0;
}
