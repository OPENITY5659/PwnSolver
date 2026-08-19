// ret2libc_allprot.c - 全防护: canary + PIE + Full RELRO + FORTIFY (scanf %s)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static __attribute__((noinline)) void vuln(char *buf) {
    printf("Enter: ");
    fflush(stdout);
    scanf("%s", buf);
    write(1, buf, 0x100);
}

int main() {
    char b[0x30];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("All protection challenge!");
    for (int i = 0; i < 5; i++) vuln(b);
    puts("bye");
    return 0;
}
