#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "perf_counter.h"

#define TWO_MIB (2UL * 1024UL * 1024UL)

static volatile uint64_t read_sink;

struct usage_snapshot {
    long minor_faults;
    long major_faults;
};

struct mapping_stats {
    unsigned long size_kb;
    unsigned long rss_kb;
    unsigned long pss_kb;
    unsigned long private_dirty_kb;
    unsigned long referenced_kb;
    unsigned long anonymous_kb;
    unsigned long vm_pte_kb;
};

static struct usage_snapshot get_usage_snapshot(void)
{
    struct rusage usage;

    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage");
        exit(EXIT_FAILURE);
    }

    struct usage_snapshot result = {
        .minor_faults = usage.ru_minflt,
        .major_faults = usage.ru_majflt,
    };

    return result;
}

static int starts_with(const char *line, const char *prefix)
{
    return strncmp(line, prefix, strlen(prefix)) == 0;
}

static void read_vm_pte(struct mapping_stats *stats)
{
    FILE *fp;
    char line[512];

    fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        perror("fopen /proc/self/status");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "VmPTE: %lu kB",
                   &stats->vm_pte_kb) == 1) {
            break;
        }
    }

    fclose(fp);
}

static void read_mapping_stats(
    const void *address,
    struct mapping_stats *stats)
{
    FILE *fp;
    char line[512];
    uintptr_t target = (uintptr_t)address;
    int found = 0;

    memset(stats, 0, sizeof(*stats));

    fp = fopen("/proc/self/smaps", "r");
    if (fp == NULL) {
        perror("fopen /proc/self/smaps");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start;
        unsigned long end;

        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (found)
                break;

            if (target >= (uintptr_t)start &&
                target < (uintptr_t)end) {
                found = 1;
            }

            continue;
        }

        if (!found)
            continue;

        if (starts_with(line, "Size:"))
            (void)sscanf(line, "Size: %lu kB",
                         &stats->size_kb);
        else if (starts_with(line, "Rss:"))
            (void)sscanf(line, "Rss: %lu kB",
                         &stats->rss_kb);
        else if (starts_with(line, "Pss:"))
            (void)sscanf(line, "Pss: %lu kB",
                         &stats->pss_kb);
        else if (starts_with(line, "Private_Dirty:"))
            (void)sscanf(line, "Private_Dirty: %lu kB",
                         &stats->private_dirty_kb);
        else if (starts_with(line, "Referenced:"))
            (void)sscanf(line, "Referenced: %lu kB",
                         &stats->referenced_kb);
        else if (starts_with(line, "Anonymous:"))
            (void)sscanf(line, "Anonymous: %lu kB",
                         &stats->anonymous_kb);
    }

    fclose(fp);

    if (!found) {
        fprintf(stderr,
                "Could not find mapping containing %p\n",
                address);
        exit(EXIT_FAILURE);
    }

    read_vm_pte(stats);
}

/*
 * 先申请 length + alignment 字节，再裁剪出一个
 * alignment 对齐、长度为 length 的匿名VMA。
 */
static void *map_aligned(size_t length, size_t alignment)
{
    size_t total_length;
    void *raw_mapping;
    uintptr_t raw;
    uintptr_t aligned;
    size_t prefix_length;
    size_t suffix_length;

    if ((alignment & (alignment - 1)) != 0) {
        fprintf(stderr,
                "Alignment must be a power of two\n");
        return MAP_FAILED;
    }

    if (length > SIZE_MAX - alignment) {
        errno = EOVERFLOW;
        return MAP_FAILED;
    }

    total_length = length + alignment;

    raw_mapping = mmap(
        NULL,
        total_length,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);

    if (raw_mapping == MAP_FAILED)
        return MAP_FAILED;

    raw = (uintptr_t)raw_mapping;

    aligned = (raw + alignment - 1) &
              ~((uintptr_t)alignment - 1);

    prefix_length = (size_t)(aligned - raw);

    suffix_length =
        total_length - prefix_length - length;

    if (prefix_length != 0) {
        if (munmap((void *)raw, prefix_length) != 0) {
            perror("munmap prefix");
            (void)munmap(raw_mapping, total_length);
            return MAP_FAILED;
        }
    }

    if (suffix_length != 0) {
        void *suffix_address =
            (void *)(aligned + length);

        if (munmap(suffix_address, suffix_length) != 0) {
            perror("munmap suffix");
            (void)munmap((void *)aligned, length);
            return MAP_FAILED;
        }
    }

    return (void *)aligned;
}

static void print_stats(
    const char *name,
    const struct mapping_stats *stats)
{
    printf("\n========== %s ==========\n", name);
    printf("Size                 : %lu kB\n",
           stats->size_kb);
    printf("Rss                  : %lu kB\n",
           stats->rss_kb);
    printf("Pss                  : %lu kB\n",
           stats->pss_kb);
    printf("Private_Dirty        : %lu kB\n",
           stats->private_dirty_kb);
    printf("Referenced           : %lu kB\n",
           stats->referenced_kb);
    printf("Anonymous            : %lu kB\n",
           stats->anonymous_kb);
    printf("VmPTE                : %lu kB\n",
           stats->vm_pte_kb);
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s read|write "
            "<mapping_MiB> <touch_pages>\n",
            program);
}

int main(int argc, char **argv)
{
    const char *mode;
    char *end;
    unsigned long mapping_mib;
    unsigned long requested_pages;

    long page_size_long;
    size_t page_size;
    size_t mapping_length;
    size_t total_pages;
    size_t touch_pages;

    volatile unsigned char *memory;

    struct perf_group perf_group;
    struct perf_counts perf_counts;

    struct usage_snapshot usage_before;
    struct usage_snapshot usage_after;

    struct mapping_stats stats_before;
    struct mapping_stats stats_after;

    if (argc != 4) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    mode = argv[1];

    if (strcmp(mode, "read") != 0 &&
        strcmp(mode, "write") != 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    end = NULL;
    mapping_mib = strtoul(argv[2], &end, 0);

    if (end == argv[2] || *end != '\0' ||
        mapping_mib == 0) {
        fprintf(stderr,
                "Invalid mapping size: %s\n",
                argv[2]);
        return EXIT_FAILURE;
    }

    end = NULL;
    requested_pages = strtoul(argv[3], &end, 0);

    if (end == argv[3] || *end != '\0') {
        fprintf(stderr,
                "Invalid page count: %s\n",
                argv[3]);
        return EXIT_FAILURE;
    }

    page_size_long = sysconf(_SC_PAGESIZE);

    if (page_size_long <= 0) {
        perror("sysconf");
        return EXIT_FAILURE;
    }

    page_size = (size_t)page_size_long;
    mapping_length =
        (size_t)mapping_mib * 1024UL * 1024UL;

    mapping_length -= mapping_length % page_size;
    total_pages = mapping_length / page_size;
    touch_pages = (size_t)requested_pages;

    if (touch_pages > total_pages) {
        fprintf(stderr,
                "touch_pages=%zu exceeds total_pages=%zu\n",
                touch_pages,
                total_pages);
        return EXIT_FAILURE;
    }

    if (perf_group_open(&perf_group) != 0) {
        fprintf(stderr,
                "Unable to initialize perf counters\n");
        return EXIT_FAILURE;
    }

    /*
     * 预热perf控制路径，减少第一次enable/disable
     * 对正式测量的影响。
     */
    if (perf_group_start(&perf_group) != 0) {
        perf_group_close(&perf_group);
        return EXIT_FAILURE;
    }

    asm volatile("" ::: "memory");

    if (perf_group_stop(
            &perf_group,
            &perf_counts) != 0) {
        perf_group_close(&perf_group);
        return EXIT_FAILURE;
    }

    memory = map_aligned(mapping_length, TWO_MIB);

    if (memory == MAP_FAILED) {
        perror("map_aligned");
        perf_group_close(&perf_group);
        return EXIT_FAILURE;
    }

    printf("PID                  : %ld\n",
           (long)getpid());
    printf("mode                 : %s\n", mode);
    printf("page size            : %zu bytes\n",
           page_size);
    printf("mapping size         : %lu MiB\n",
           mapping_mib);
    printf("mapping address      : %p\n",
           (const void *)memory);
    printf("address mod 2 MiB    : 0x%lx\n",
           (unsigned long)
           ((uintptr_t)memory & (TWO_MIB - 1)));
    printf("total pages          : %zu\n",
           total_pages);
    printf("touch pages          : %zu\n",
           touch_pages);
    printf("touch bytes          : %zu kB\n",
           touch_pages * page_size / 1024);

    read_mapping_stats(
        (const void *)memory,
        &stats_before);

    print_stats("before touching", &stats_before);

    /*
     * 预热getrusage本身。
     */
    (void)get_usage_snapshot();

    usage_before = get_usage_snapshot();

    if (perf_group_start(&perf_group) != 0) {
        (void)munmap((void *)memory, mapping_length);
        perf_group_close(&perf_group);
        return EXIT_FAILURE;
    }

    if (strcmp(mode, "read") == 0) {
        uint64_t sum = 0;

        for (size_t page = 0;
             page < touch_pages;
             ++page) {
            sum += memory[page * page_size];
        }

        read_sink += sum;
    } else {
        for (size_t page = 0;
             page < touch_pages;
             ++page) {
            memory[page * page_size] = 1;
        }
    }

    if (perf_group_stop(
            &perf_group,
            &perf_counts) != 0) {
        (void)munmap((void *)memory, mapping_length);
        perf_group_close(&perf_group);
        return EXIT_FAILURE;
    }

    usage_after = get_usage_snapshot();

    read_mapping_stats(
        (const void *)memory,
        &stats_after);

    printf("\n========== measurement ==========\n");
    printf("minor faults delta   : %ld\n",
           usage_after.minor_faults -
           usage_before.minor_faults);
    printf("major faults delta   : %ld\n",
           usage_after.major_faults -
           usage_before.major_faults);
    printf("cycles               : %" PRIu64 "\n",
           perf_counts.cycles);
    printf("instructions         : %" PRIu64 "\n",
           perf_counts.instructions);

    if (touch_pages != 0) {
        printf("cycles/page          : %.2f\n",
               (double)perf_counts.cycles /
               (double)touch_pages);
        printf("instructions/page    : %.2f\n",
               (double)perf_counts.instructions /
               (double)touch_pages);

        if (perf_counts.cycles != 0) {
            printf("IPC                  : %.4f\n",
                   (double)perf_counts.instructions /
                   (double)perf_counts.cycles);
        }
    }

    print_stats("after touching", &stats_after);

    printf("\n========== deltas ==========\n");
    printf("Rss delta            : %ld kB\n",
           (long)stats_after.rss_kb -
           (long)stats_before.rss_kb);
    printf("Pss delta            : %ld kB\n",
           (long)stats_after.pss_kb -
           (long)stats_before.pss_kb);
    printf("Private_Dirty delta  : %ld kB\n",
           (long)stats_after.private_dirty_kb -
           (long)stats_before.private_dirty_kb);
    printf("Anonymous delta      : %ld kB\n",
           (long)stats_after.anonymous_kb -
           (long)stats_before.anonymous_kb);
    printf("VmPTE delta          : %ld kB\n",
           (long)stats_after.vm_pte_kb -
           (long)stats_before.vm_pte_kb);

    printf("read_sink            : %" PRIu64 "\n",
           read_sink);

    if (munmap((void *)memory, mapping_length) != 0)
        perror("munmap mapping");

    perf_group_close(&perf_group);
    return EXIT_SUCCESS;
}
