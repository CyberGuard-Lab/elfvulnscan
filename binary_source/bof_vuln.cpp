// Compile with: g++ bof_vuln.cpp -o ../binary/bof_vuln -fno-stack-protector -z execstack -no-pie
#include <iostream>
#include <cstdio>
#include <cstdlib>
using namespace std;

void shell() {
    system("/bin/sh");
}

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
