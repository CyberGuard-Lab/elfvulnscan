// gcc heap_dbf.c  -o ../binary/heap_dbf -fno-stack-protector -z execstack -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void free_but_from_other_function(char *p) {
    free(p);
}

int main() {
    char *a = malloc(0x40);
    char *b = malloc(0x40);
    char *ptr = NULL;

    strcpy(a, "this is chunk a");
    strcpy(b, "this is chunk b");

    int choice;
    printf("Enter 1 or 2: ");
    scanf("%d", &choice);

    if (choice == 1) {
        ptr = a;
    } else {
        ptr = b;
    }

    free_but_from_other_function(ptr);  

    if (choice == 1) {
        free(a);  
    }

    return 0;
}
