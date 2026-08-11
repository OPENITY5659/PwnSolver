// ret2win.c - 经典ret2win题目
// 编译: gcc -fno-stack-protector -no-pie -z execstack -o ret2win ret2win.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char *gets(char *s);

void win() {
    printf("You win! Here is your shell:\n");
    system("/bin/sh");
}

void vuln() {
    char buf[32];
    printf("Enter your name: ");
    gets(buf);
    printf("Hello, %s\n", buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
