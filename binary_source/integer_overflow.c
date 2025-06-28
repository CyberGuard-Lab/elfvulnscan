#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main() {
    int sum = 10;
    int tmp;
    int choice;
    printf("Enter a number: ");
    scanf("%d", &choice);
    while(choice == 1) {
        printf("Enter a number: ");
        scanf("%d", &tmp);
        if (tmp < 0) {
            printf("Negative number detected, exiting...\n");
            exit(1);
        }
        sum = sum + tmp;
        if(sum == 9) {
            printf("You have reached the magic number 9!\n");
            system("/bin/sh");
        } else {
            printf("Current sum: %d\n", sum);
        }
        printf("Enter 1 to continue or 0 to exit: ");
        scanf("%d", &choice);
    }
    return 0;
}
