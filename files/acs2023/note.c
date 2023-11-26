// gcc -o note note.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PAGE_N 16

struct page
{
    char *script;
    void (*emoj)();
};

struct page* note[PAGE_N];

void shell()
{
    system("/bin/sh");
}

void happy()
{
    printf("^_____^\n\n");
}

void sad()
{
    printf("T_____T\n\n");
}

void fine()
{
    printf("0_____0\n\n");
}

void bad()
{
    printf("-_____-\n\n");
}

void menu()
{
    printf("1. write\n");
    printf("2. re-write\n");
    printf("3. read\n");
    printf("4. erase\n");
    printf("5. exit\n");
    printf(">>> ");
}

void _write(int idx)
{
    char tmp[0x1000];
    int emoj;

    if (note[idx] != 0)
    {
        printf("[*] Not empty page\n");

        return;
    }

    printf("script: ");
    scanf("%s", tmp);

    printf("emoj: ");
    printf("\t1. happy\n");
    printf("\t2. sad\n");
    printf("\t3. fine\n");
    printf("\t4. bad\n");
    printf(">>> ");
    scanf("%d", &emoj);

    if (emoj > 4 || emoj < 1)
    {
        printf("[*] Not found emoj\n");

        return;
    }

    note[idx] = malloc(sizeof(struct page));
    printf("[!] write note %d @ %p\n", idx, note[idx]);
    note[idx]->script = malloc(strlen(tmp));
    printf("[!] script @ %p\n", note[idx]->script);
    memcpy(note[idx]->script, tmp, strlen(tmp));

    switch(emoj)
    {
    case 1:
        note[idx]->emoj = happy;
        break;
    case 2:
        note[idx]->emoj = sad;
        break;
    case 3:
        note[idx]->emoj = fine;
        break;
    case 4:
        note[idx]->emoj = bad;
        break;
    default:
        printf("[!] ERROR\n");
        exit(0);
    }

    printf("Write Success\n\n");
}

void _re_write(int idx)
{
    char tmp[0x1000];
    int emoj;

    if (note[idx] == 0)
    {
        printf("[*] empty page\n");

        return;
    }

    printf("script: ");
    scanf("%s", tmp);

    printf("emoj: ");
    printf("\t1. happy\n");
    printf("\t2. sad\n");
    printf("\t3. fine\n");
    printf("\t4. bad\n");
    printf(">>> ");
    scanf("%d", &emoj);

    if (emoj > 4 || emoj < 1)
    {
        printf("[*] Not found emoj\n");

        return;
    }

    if (strlen(tmp) > strlen(note[idx]->script))
    {
        free(note[idx]->script);
        note[idx]->script = malloc(strlen(tmp));
        printf("[!] rewrite script @ %p\n", note[idx]->script);
    }
    
    memcpy(note[idx]->script, tmp, strlen(tmp));

    switch(emoj)
    {
    case 1:
        note[idx]->emoj = happy;
        break;
    case 2:
        note[idx]->emoj = sad;
        break;
    case 3:
        note[idx]->emoj = fine;
        break;
    case 4:
        note[idx]->emoj = bad;
        break;
    default:
        printf("[!] ERROR\n");
        exit(0);
    }

    printf("Write Success\n\n");
}

void _read(int idx)
{    
    if (note[idx] == 0)
    {
        printf("[*] empty page\n");

        return;
    }

    note[idx]->emoj();
    printf("%s\n", note[idx]->script);
}

void _erase(int idx)
{
    if (note[idx] == 0)
    {
        printf("[*] empty page\n");

        return;
    }

    note[idx]->emoj = 0;
    printf("[!] erase note %d @ %p\n", idx, note[idx]);
    free(note[idx]->script);
    free(note[idx]);

    printf("Erase Success\n\n");
}

int main()
{
    int idx, n;

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("[*] shell(): %p\n", shell);
    printf("[!] size of page: %zd\n", sizeof(struct page));

    while (1)
    {        
        menu();
        scanf("%d", &n);

        if (n > 5 || n < 1)
        {
            printf("[*] Not found menu\n");

            continue;
        }

        if (n == 5) break;

        printf("index(1 ~ %d): ", PAGE_N);
        scanf("%d", &idx);

        if (idx > PAGE_N || idx < 1) 
        {
            printf("[*] Index is 1 ~ 16\n");

            continue;
        }

        switch(n)
        {
        case 1:
            _write(idx - 1);
            break;
        case 2:
            _re_write(idx - 1);
            break;
        case 3:
            _read(idx - 1);
            break;
        case 4:
            _erase(idx - 1);
            break;
        default:
            printf("[!] ERROR\n");
            exit(0);
        }
    }

    return 0;
}
