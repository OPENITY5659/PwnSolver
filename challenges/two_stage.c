// two_stage.c - 多轮输入: 菜单选择(scanf %d) → gets 溢出 → ret2libc
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *gets(char *s);

void vuln() {
    char buf[0x40];
    printf("Stage 2: enter your payload: ");
    fflush(stdout);
    gets(buf);
    puts(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    int choice;
    printf("=== Two Stage Service ===\n");
    printf("1. enter payload\n2. quit\n>>> ");
    fflush(stdout);
    if (scanf("%d", &choice) != 1) return 0;
    while (getchar() != '\n' && !feof(stdin));
    if (choice == 1) {
        vuln();
        puts("Stage 2 done.");
    } else {
        puts("Bye.");
    }
    return 0;
}
