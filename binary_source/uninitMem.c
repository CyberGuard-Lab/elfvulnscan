#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void func1() {
    int a;
    int b;
    char str[100];
    printf("Enter two integers:\n");
    scanf("%d", &a);
    scanf("%d", &b);
    if (a == 0) {
        printf("a is zero\n");
    } else {
        printf("a is not zero\n");
    }
    fgets(str, sizeof(str), stdin);
    printf("You entered: %s\n", str);
}

void func2() {
    int a;
    int b;
    if(a == 5) {
        system("/bin/sh");
    }
    a= 6;
    b = 7;
    printf("a: %d, b: %d\n", a, b);

}
int main() {
    func1();
    func2();
    return 0;
}