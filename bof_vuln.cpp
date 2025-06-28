#include <iostream>
#include <cstdio>
#include <cstdlib>
using namespace std;

// Khai báo extern "C" để tên hàm không bị mangle
extern "C" void shell() {
    system("/bin/sh");
}

// Tự định nghĩa gets unsafe
char* gets(char *buf) {
    int c;
    char *p = buf;
    while ((c = getchar()) != EOF && c != '\n') {
        *p++ = c;
    }
    *p = '\0';
    return buf;
}

void vuln() {
    char buf[64];
    printf("Enter data: ");
    gets(buf);
}

int main() {
    vuln();
    return 0;
}
