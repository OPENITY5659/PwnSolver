// real_ctf_ret2libc.c - 模拟真实CTF比赛ret2libc题目
// 编译: gcc -fno-stack-protector -no-pie -O0 -o real_ret2libc real_ctf_ret2libc.c
// 特点: 有__libc_csu_init gadgets, NX enabled, no canary, no PIE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char *gets(char *s);

// 模拟真实场景: 有多个函数确保__libc_csu_init被保留
static int dummy_init(void) __attribute__((constructor));
static int dummy_init(void) { return 0; }

void welcome(void) {
    puts("====================================");
    puts("  CTF PWN Challenge - ret2libc");
    puts("  No system() in binary...");
    puts("  Find it in libc!");
    puts("====================================");
}

void get_input(void) {
    char buf[48];
    printf("Enter payload: ");
    fflush(stdout);
    gets(buf);  // BOOM! Buffer overflow
    printf("You entered: ");
    puts(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    welcome();
    get_input();
    puts("Goodbye!");
    return 0;
}
