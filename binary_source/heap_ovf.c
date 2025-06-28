#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data
{
    char name[64];
};

struct fp
{
    int (*fp)();
};

void winner()
{
    printf("win\n");
}

void lose()
{
    printf("lose\n");
}

int main(int argc, char **argv)
{
    struct data *d;
    struct fp *f;

    d = malloc(sizeof(struct data));
    f = malloc(sizeof(struct fp));
    f->fp = lose;

    printf("data is at %p, fp is at %p\n", d, f);
    char s[100];
    read(stdin, s, sizeof(s) - 1);
    strcpy(d->name, s);

    f->fp();
}