// fmtstr.c - 格式化字符串漏洞
// 编译: gcc -fno-stack-protector -no-pie -o fmtstr fmtstr.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int secret = 0;

void win() {
    printf("Congratulations! Flag: FLAG{fmt_str_pwned}\n");
    system("/bin/sh");
}

void vuln() {
    char buf[128];
    printf("Enter format string: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    printf(buf);  // 格式化字符串漏洞!
    printf("\n");
    
    if (secret == 0xdeadbeef) {
        win();
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Format String Challenge!\n");
    vuln();
    return 0;
}
