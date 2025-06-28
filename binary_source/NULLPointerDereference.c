#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void segfault_handler(int sig) {
    printf("[+] Caught segmentation fault! Launching shell...\n");
    system("/bin/sh");
    exit(0);
}
int main() {
    signal(SIGSEGV, segfault_handler);
    FILE *file = fopen("non_existent_file.txt", "r");
    char buffer[100];
    fgets(buffer, sizeof(buffer), file);
    printf("Buffer: %s\n", buffer);
    fclose(file);
    return 0;
}