#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));

    int number = rand() % 1000;

    int input_number;
    printf("Enter your number: ");
    scanf("%d", &input_number);

    if (input_number == number) {
        system("/bin/sh");
    } 
    return 0;
}
