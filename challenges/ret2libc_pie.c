// ret2libc_pie.c - PIE 绕过: leak 栈返回地址 + libc, 循环可多次利用
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[0x30];
    printf("Enter: ");
    fflush(stdout);
    ssize_t n = read(0, buf, 0x100);
    write(1, buf, 0x100);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("PIE challenge!");
    for (int i = 0; i < 5; i++) vuln();
    puts("bye");
    return 0;
}
