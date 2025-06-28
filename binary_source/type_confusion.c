// gcc type_confusion.c  -o ../binary/type_confusion -fno-stack-protector -z execstack -no-pie
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

struct dts
{
    char name[64];
    int age;
    int isGei;
};

struct bvh {
    char name[72];
};

void shell()
{
    system("/bin/sh");
}

int main() {
    struct dts *dts = malloc(sizeof(struct dts));
    strcpy(dts->name, "dinhthaison");
    dts->age = 18;
    dts->isGei = 0;
    struct bvh *b = (struct bvh *)dts;
    fgets(b->name, sizeof(b->name), stdin);
    if(dts->isGei != 0 ) {
        printf("You are a gei\n");
        shell();
    } else {
        printf("You are not a gei\n");
    }
    return 0;
}