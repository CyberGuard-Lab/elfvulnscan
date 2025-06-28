#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct hooman
{
    char name[64];
    int age;
};

void shell()
{
    system("/bin/sh");
}

int main()
{
    struct hooman *h1, *h2;
    h1 = malloc(sizeof(struct hooman));
    h1->age = 0xbeef;
    h1->name[0] = 'S';
    h1->name[1] = 'o';
    h1->name[2] = 'n';
    h1->name[3] = 'd';
    h1->name[4] = 't';
    h1->name[5] = '\0';
    free(h1);
    h2 = malloc(sizeof(struct hooman));
    int tmp_age;
    char tmp_name[64];
    printf("Enter your age: ");
    scanf("%d", &tmp_age);
    if (tmp_age < 0 || tmp_age > 100)
    {
        printf("Invalid age!\n");
    }
    else
    {
        h2->age = tmp_age;
    }

    printf("Enter your name: ");
    fgets(tmp_name, sizeof(tmp_name), stdin);

    if (tmp_age > 100)
    {
        shell();
    }
    return 0;
}