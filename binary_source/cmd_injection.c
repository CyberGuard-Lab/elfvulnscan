#include<stdio.h>

int main() {
    char str[] = "ping ";
    char ip[50];
    printf("Enter IP address: ");
    fgets(ip, sizeof(ip), stdin);
    // Remove newline character from fgets
    ip[strcspn(ip, "\n")] = 0;
    strncat(str, ip, sizeof(str) - strlen(str) - 1);
    printf("Executing command: %s\n", str);
    system(str);
    return 0;
}