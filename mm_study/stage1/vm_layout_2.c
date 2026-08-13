#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int global_initialized = 123;
int global_bss;

const char global_read_only[] = "read-only global data";
const char *p_global_read_only = "hello world";

static int static_global = 456;

static void sample_function(void)
{

}

static void print_maps(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];

    if (fp == NULL) {
        perror("fopen /proc/self/maps");
        return;
    }

    printf("\n======= /proc/self/maps =======\n");

    while (fgets(line, sizeof(line), fp) != NULL)
        fputs(line, stdout);

    fclose(fp);
}

int main(int argc, char **argv)
{
    int stack_variable = 789;
    static int static_local = 100;
    int index = argc;
    //printf("global_readonly %c\n", index < 5 ? global_read_only[index] : 'x');
    printf("p_global_readonly %c\n", index < 5 ? p_global_read_only[index] : 'x');

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        perror("sysconf");
        return EXIT_FAILURE;
    }

    int *heap_memory = (int *)malloc((size_t)page_size);
    if (heap_memory == NULL) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    void *mapped_memory = mmap(NULL, (size_t)page_size, PROT_WRITE | PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mapped_memory == MAP_FAILED) {
        perror("mmap");
        free(heap_memory);
        return EXIT_FAILURE;
    }

    printf("PID                 : %ld\n", (long)getpid());
    printf("page size           : %ld bytes\n", (long)page_size);
    
    printf("\n============== virtual addresses ==============\n");
    printf("sample_function     : %p\n", (void *)sample_function);
    printf("global_initialized  : %p\n", (void *)&global_initialized);
    printf("global_bss          : %p\n", (void *)&global_bss);
    printf("global_read_only    : %p\n", (void *)global_read_only);
    printf("static_global       : %p\n", (void *)&static_global);
    printf("static_local        : %p\n", (void *)&static_local);
    printf("heap_memory         : %p\n", (void *)heap_memory);
    printf("mapped_memory       : %p\n", mapped_memory);
    printf("stack_variable      : %p\n", (void *)&stack_variable);

    print_maps();

    printf("\nPress Enter to exit....\n");
    fflush(stdout);
    sleep(120);

    if (munmap(mapped_memory, (size_t)page_size) != 0)
        perror("munmap");

    free(heap_memory);
    return EXIT_SUCCESS;
}
