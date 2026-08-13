// loop_menu.c - 多轮循环菜单 + 格式化字符串漏洞 (提示 "cmd> " 风格)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int secret = 0;

void win() {
    printf("Menu pwned! FLAG{loop_menu_fmt}\n");
    system("/bin/sh");
}

void handle_input() {
    char buf[0x80];
    printf("cmd> ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    buf[strcspn(buf, "\n")] = 0;
    if (!strcmp(buf, "quit")) return;
    printf("echo: ");
    printf(buf);        // 格式化字符串漏洞
    printf("\n");
    if (secret == 0xdeadbeef) {
        win();
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("=== Loop Menu ===\n");
    while (1) {
        handle_input();
        if (feof(stdin)) break;
    }
    return 0;
}
