// heap_uaf.c - UAF (Use-After-Free) heap challenge
// 编译: gcc -fno-stack-protector -no-pie -o heap_uaf heap_uaf.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char name[32];
    void (*print_func)(char *);
} User;

User *users[10];
int user_count = 0;

void win() {
    printf("You exploited UAF! Flag: FLAG{heap_uaf_pwned}\n");
    system("/bin/sh");
}

void normal_print(char *s) {
    printf("User: %s\n", s);
}

User *create_user(char *name) {
    User *u = (User *)malloc(sizeof(User));
    strcpy(u->name, name);
    u->print_func = normal_print;
    return u;
}

void delete_user(int idx) {
    if (idx >= 0 && idx < user_count && users[idx]) {
        free(users[idx]);
        // BUG: 没有设置 users[idx] = NULL — UAF!
    }
}

void print_user(int idx) {
    if (idx >= 0 && idx < user_count && users[idx]) {
        users[idx]->print_func(users[idx]->name);  // UAF: 可能已经free了
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    char input[64];
    int choice, idx;
    
    printf("=== Heap UAF Challenge ===\n");
    printf("Win function at: %p\n", win);
    
    while (1) {
        printf("\n1. Create user\n2. Delete user\n3. Print user\n4. Exit\n> ");
        fgets(input, sizeof(input), stdin);
        choice = atoi(input);
        
        switch (choice) {
            case 1:
                if (user_count >= 10) { printf("Full!\n"); break; }
                printf("Name: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = 0;
                users[user_count] = create_user(input);
                printf("Created user %d at %p\n", user_count, users[user_count]);
                user_count++;
                break;
            case 2:
                printf("Index: ");
                fgets(input, sizeof(input), stdin);
                idx = atoi(input);
                delete_user(idx);
                printf("Deleted user %d\n", idx);
                break;
            case 3:
                printf("Index: ");
                fgets(input, sizeof(input), stdin);
                idx = atoi(input);
                print_user(idx);
                break;
            case 4:
                return 0;
        }
    }
}
