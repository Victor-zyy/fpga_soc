#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int global_initialized = 123; //.data section
int global_bss;               //.bss section

const char global_read_only[] = "read-only global data"; //.rodata section

static int static_global = 456; //.data section

static void sample_function(void)//.text section because of the code to execute
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

    while (fgets(line, sizeof(line), fp) != NULL) // if fgets one line exceed 512 bytes what will happen
        fputs(line, stdout);

    fclose(fp);
}

int main(int argc, char **argv)
{
    int stack_variable = 789;   // stack auto variable
    static int static_local = 100; //.data section

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

    // private and anonymous
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
    getchar();

    if (munmap(mapped_memory, (size_t)page_size) != 0)
        perror("munmap");

    free(heap_memory);
    return EXIT_SUCCESS;
}
