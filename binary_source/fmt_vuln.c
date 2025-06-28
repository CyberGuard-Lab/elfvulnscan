#include<stdio.h>
#include<stdlib.h>
int main() {
    int choice = 0;
    
    char str[100];
    printf("Enter a string: ");
    fgets(str, sizeof(str), stdin);
    printf("You entered: ");
    printf(str);
    printf("\n");
}