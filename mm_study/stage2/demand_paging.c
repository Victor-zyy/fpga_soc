#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include "perf_counter.h"

static volatile uint64_t read_sink;

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

static struct usage_snapshot get_usage_snapshot(void)
{
	struct rusage usage;	// have no idea of what it is

    /**
     *
     * get resources usage of one process
     * we only focus on the two variables
     * ru_minflt and ru_majflt
     * page reclaims (soft faults) and hard fault
     */
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

/*
 *
 *
 *
 * /proc/self/smaps
 *
 */
static void dump_mapping_smaps(const void *addr)
{
	FILE *fp;
	char line[512];
	uintptr_t target = (uintptr_t) addr;
	int found = 0;

	fp = fopen("/proc/self/smaps", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/smaps");
		return;
	}

	printf("\n=========== smaps for %p =========\n", addr);
	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if (found) {
				break;
			}

			if (target >= (uintptr_t) start &&
			    target < (uintptr_t) end) {
				found = 1;
				fputs(line, stdout);
			}

			continue;
		}

		if (!found)
			continue;

		if (starts_with(line, "Size:") ||
		    starts_with(line, "KernelPageSize:") ||
		    starts_with(line, "MMUPageSize:") ||
		    starts_with(line, "Rss:") ||
		    starts_with(line, "Pss:") ||
		    starts_with(line, "Shared_Clean:") ||
		    starts_with(line, "Shared_Dirty:") ||
		    starts_with(line, "Private_Clean:") ||
		    starts_with(line, "Private_Dirty:") ||
		    starts_with(line, "Referenced:") ||
		    starts_with(line, "Anonymous:") ||
		    starts_with(line, "AnonHugePages:") ||
		    starts_with(line, "VmFlags:")) {
			fputs(line, stdout);
		}
	}

	if (!found)
		printf("Mapping was not found in /proc/self/smaps\n");

	fclose(fp);
}

static void dump_status_summary(void)
{
	static const char *fields[] = {
		"VmSize:",
		"VmRss:",
		"RssAnon:",
		"RssFile:",
		"RssShmem:",
		"VmData:",
		"VmPTE:",
		NULL
	};

	FILE *fp;
	char line[512];

	fp = fopen("/proc/self/status", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/status");
		return;
	}

	printf("\n============ Process Status =========\n");

	while (fgets(line, sizeof(line), fp) != NULL) {
		for (size_t i = 0; fields[i] != NULL; ++i) {
			if (starts_with(line, fields[i])) {
				fputs(line, stdout);
				break;
			}
		}
	}

	fclose(fp);
}

static void print_measurement(const char *name,
			      size_t page_count,
			      struct usage_snapshot before,
			      struct usage_snapshot after,
			      const struct perf_counts *perf)
{

	long major_delta = after.major_faults - before.major_faults;
	long minor_delta = after.minor_faults - before.minor_faults;

	printf("\n========== %s ============\n", name);
	printf("pages               : %zu\n", page_count);
	printf("minor faults delta  : %ld\n", minor_delta);
	printf("major faults delta  : %ld\n", major_delta);

	printf("cycles              : %" PRIu64 "\n", perf->cycles);
	printf("instructions        : %" PRIu64 "\n", perf->instructions);

	if (page_count != 0) {
		printf("cycles/page         : %.2f\n",
		       (double)perf->cycles / (double)page_count);
		printf("intructions/page    : %.2f\n",
		       (double)perf->instructions / (double)page_count);
	}

	if (perf->cycles != 0) {
		printf("IPC                 : %.4f\n",
		       (double)perf->instructions / (double)perf->cycles);
	}

}

static void perform_read_pass(volatile unsigned char *memory,
			      size_t length,
			      size_t page_size,
			      const char *name, struct perf_group *perf_group)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	uint64_t sum = 0;

	size_t page_count = length / page_size;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0) {
		exit(EXIT_FAILURE);
	}
	for (size_t offset = 0; offset < length; offset += page_size) {
		sum += memory[offset];
	}

	if (perf_group_stop(perf_group, &perf) != 0) {
		exit(EXIT_FAILURE);
	}
	after = get_usage_snapshot();

	read_sink += sum;

	print_measurement(name, page_count, before, after, &perf);
}

static void perform_write_pass(volatile unsigned char *memory,
			       size_t length,
			       size_t page_size,
			       const char *name, struct perf_group *perf_group)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	size_t page_count = length / page_size;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0) {
		exit(EXIT_FAILURE);
	}

	for (size_t offset = 0; offset < length; offset += page_size)
		memory[offset] = (unsigned char)(offset / page_size);

	if (perf_group_stop(perf_group, &perf) != 0) {
		exit(EXIT_FAILURE);
	}

	after = get_usage_snapshot();

	print_measurement(name, page_count, before, after, &perf);
}

static void print_usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s untouched|read|write|readwrite [MiB] [sleep_seconds]\n",
		program);
}

int main(int argc, char **argv)
{
	const char *mode;	//mode to select
	size_t size_mib = 16;	// default parameters
	unsigned int sleep_seconds = 0;	//default parameters for sleep
	//
	long page_size_long;
	size_t page_size;
	size_t length;
	size_t page_count;
	struct perf_group perf_group;

	volatile unsigned char *memory;

	if (argc < 2 || argc > 4) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	mode = argv[1];

	if (strcmp(mode, "untouched") != 0 &&
	    strcmp(mode, "read") != 0 &&
	    strcmp(mode, "write") != 0 && strcmp(mode, "readwrite") != 0) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	// MiB using strtoul -- string to unsigned long if input is "str" or "" then the second argument never forwards so we need to judge the second argument to see if the function forwards or not.
    /**
     * strtoul base 0 is intelligent(when you input 0x--base 16 010 base--8 1-9base -- 10
     */
	if (argc >= 3) {
		char *end = NULL;
		unsigned long value = strtoul(argv[2], &end, 0);
		if (end == argv[2] || *end != '\0' || value == 0) {
			fprintf(stderr, "Invalid MiB value: %s\n", argv[2]);
			return EXIT_FAILURE;
		}
		size_mib = (size_t)value;
	}
	if (argc >= 4) {
		char *end = NULL;
		unsigned long value = strtoul(argv[3], &end, 0);

		if (end == argv[3] || *end != '\0') {
			fprintf(stderr, "Invalid sleep value: %s\n", argv[3]);
			return EXIT_FAILURE;
		}

		sleep_seconds = (unsigned int)value;
	}

	page_size_long = sysconf(_SC_PAGESIZE);
	if (page_size_long <= 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	page_size = (size_t)page_size_long;
	length = size_mib * 1024UL * 1024UL;

	length -= length % page_size;
	page_count = length / page_size;

	if (perf_group_open(&perf_group) != 0) {
		fprintf(stderr, "Unable to initialize perf counters\n");
		return EXIT_FAILURE;
	}

    /**
     *
     */
	(void)get_usage_snapshot();
	printf("PID             : %ld\n", (long)getpid());
	printf("mode            : %s\n", mode);
	printf("page size       : %zu bytes\n", page_size);
	printf("mapping size    : %zu MiB\n", length / 1024 / 1024);
	printf("page count      : %zu \n", page_count);

	struct usage_snapshot before_mmap = get_usage_snapshot();
	struct perf_counts mmap_perf;
	if (perf_group_start(&perf_group) != 0) {
		return EXIT_FAILURE;
	}

    // allocate 16MB
	memory = mmap(NULL,length,PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,                  -1, 0);

	if (perf_group_stop(&perf_group, &mmap_perf) != 0) {
		return EXIT_FAILURE;
	}
	struct usage_snapshot after_mmap = get_usage_snapshot();

	if (memory == MAP_FAILED) {
		perror("mmap");
		return EXIT_FAILURE;
	}

	printf("mapping address         : %p\n", (const void *)memory);
	printf("mmap minor faults       : %ld\n",
	       after_mmap.minor_faults - before_mmap.minor_faults);
	printf("mmap major faults       : %ld\n",
	       after_mmap.major_faults - before_mmap.major_faults);
	printf("mmap cycles             : %" PRIu64 "\n", mmap_perf.cycles);
	printf("mmap instructions       : %" PRIu64 "\n",
	       mmap_perf.instructions);

	printf("\n--- State after mmap, before touching pages ---\n");
	dump_mapping_smaps((const void *)memory);
	dump_status_summary();

	if (strcmp(mode, "read") == 0) {
		perform_read_pass(memory, length, page_size,
				  "first read pass", &perf_group);

		dump_mapping_smaps((const void *)memory);
		dump_status_summary();

		perform_read_pass(memory, length, page_size,
				  "second read pass", &perf_group);

		dump_mapping_smaps((const void *)memory);
	}

	if (strcmp(mode, "write") == 0) {
		perform_write_pass(memory, length, page_size,
				   "first write pass", &perf_group);

		dump_mapping_smaps((const void *)memory);
		dump_status_summary();

		perform_read_pass(memory, length, page_size,
				  "second write pass", &perf_group);

		dump_mapping_smaps((const void *)memory);
	}
	if (strcmp(mode, "readwrite") == 0) {
		/*
		 * 第一步：
		 * 首次读每个页面，建立指向共享零页的只读PTE。
		 */
		perform_read_pass(memory,
				  length,
				  page_size,
				  "first read pass: missing PTE -> shared zero page",
				  &perf_group);

		printf("\n--- State after first read pass ---\n");
		dump_mapping_smaps((const void *)memory);
		dump_status_summary();

		/*
		 * 第二步：
		 * 对已经映射到共享零页的页面执行Store。
		 * 预计每页产生一次写保护缺页，并转换成私有匿名页。
		 */
		perform_write_pass(memory,
				   length,
				   page_size,
				   "first write pass: shared zero page -> private page",
				   &perf_group);

		printf("\n--- State after write-protection faults ---\n");
		dump_mapping_smaps((const void *)memory);
		dump_status_summary();

		/*
		 * 第三步：
		 * 页面现在已经是私有、可写的，再写一次作为热路径基线。
		 */
		perform_write_pass(memory,
				   length,
				   page_size,
				   "second write pass: private writable pages",
				   &perf_group);

		printf("\n--- State after second write pass ---\n");
		dump_mapping_smaps((const void *)memory);
		dump_status_summary();
	}
	if (sleep_seconds != 0) {
		printf("\nSleeping for %u seconds. PID=%ld\n",
		       sleep_seconds, (long)getpid());
		fflush(stdout);
		sleep(sleep_seconds);

	}

	if (munmap((void *)memory, length) != 0) {
		perror("munmap");
		return EXIT_FAILURE;
	}
	perf_group_close(&perf_group);
	printf("\n read_sink            %" PRIu64 "\n", read_sink);
	return EXIT_SUCCESS;
}
