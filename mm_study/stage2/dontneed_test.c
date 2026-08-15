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

struct measurement {
	uint64_t cycles;
	uint64_t instructions;
	long minor_faults;
	long major_faults;
	uint64_t value;
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

static unsigned long read_vm_pte(void)
{
	FILE *fp;
	char line[512];
	unsigned long value = 0;

	fp = fopen("/proc/self/status", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/status");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &value) == 1)
			break;
	}

	fclose(fp);
	return value;
}

static void read_mapping_stats(const void *address, struct mapping_stats *stats)
{
	FILE *fp;
	char line[512];
	uintptr_t target = (uintptr_t) address;
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

			if (target >= (uintptr_t) start &&
			    target < (uintptr_t) end) {
				found = 1;
			}

			continue;
		}

		if (!found)
			continue;

		if (starts_with(line, "Size:"))
			(void)sscanf(line, "Size: %lu kB", &stats->size_kb);
		else if (starts_with(line, "Rss:"))
			(void)sscanf(line, "Rss: %lu kB", &stats->rss_kb);
		else if (starts_with(line, "Pss:"))
			(void)sscanf(line, "Pss: %lu kB", &stats->pss_kb);
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
			"Could not find mapping containing %p\n", address);
		exit(EXIT_FAILURE);
	}

	stats->vm_pte_kb = read_vm_pte();
}

static void print_mapping_stats(const char *name,
				const struct mapping_stats *stats,
				unsigned long vm_pte_baseline)
{
	printf("\n========== %s ==========\n", name);

	printf("Size                 : %lu kB\n", stats->size_kb);
	printf("Rss                  : %lu kB\n", stats->rss_kb);
	printf("Pss                  : %lu kB\n", stats->pss_kb);
	printf("Private_Dirty        : %lu kB\n", stats->private_dirty_kb);
	printf("Referenced           : %lu kB\n", stats->referenced_kb);
	printf("Anonymous            : %lu kB\n", stats->anonymous_kb);
	printf("VmPTE                : %lu kB\n", stats->vm_pte_kb);
	printf("VmPTE delta          : %ld kB\n",
	       (long)stats->vm_pte_kb - (long)vm_pte_baseline);
}

static unsigned char pattern_for_page(size_t page)
{
	/*
	 * 始终生成非零值，便于验证MADV_DONTNEED后数据确实丢失。
	 */
	return (unsigned char)((page % 251U) + 1U);
}

static uint64_t expected_pattern_sum(size_t pages)
{
	uint64_t sum = 0;

	for (size_t page = 0; page < pages; ++page)
		sum += pattern_for_page(page);

	return sum;
}

static struct measurement measure_write(struct perf_group *perf_group,
					volatile unsigned char *memory,
					size_t pages, size_t page_size)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < pages; ++page) {
		memory[page * page_size] = pattern_for_page(page);
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;
	result.minor_faults = after.minor_faults - before.minor_faults;
	result.major_faults = after.major_faults - before.major_faults;
	result.value = 0;

	return result;
}

static struct measurement measure_read(struct perf_group *perf_group,
				       volatile unsigned char *memory,
				       size_t pages, size_t page_size)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;
	uint64_t sum = 0;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < pages; ++page)
		sum += memory[page * page_size];

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	read_sink += sum;

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;
	result.minor_faults = after.minor_faults - before.minor_faults;
	result.major_faults = after.major_faults - before.major_faults;
	result.value = sum;

	return result;
}

static struct measurement measure_dontneed(struct perf_group *perf_group,
					   void *memory, size_t length)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	int ret = madvise(memory, length, MADV_DONTNEED);
	int saved_errno = errno;

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	if (ret != 0) {
		errno = saved_errno;
		perror("madvise MADV_DONTNEED");
		exit(EXIT_FAILURE);
	}

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;
	result.minor_faults = after.minor_faults - before.minor_faults;
	result.major_faults = after.major_faults - before.major_faults;
	result.value = 0;

	return result;
}

static void print_measurement(const char *name,
			      const struct measurement *measurement,
			      size_t pages)
{
	printf("\n========== %s ==========\n", name);

	printf("minor faults         : %ld\n", measurement->minor_faults);
	printf("major faults         : %ld\n", measurement->major_faults);
	printf("cycles               : %" PRIu64 "\n", measurement->cycles);
	printf("instructions         : %" PRIu64 "\n",
	       measurement->instructions);

	if (pages != 0) {
		printf("cycles/page          : %.2f\n",
		       (double)measurement->cycles / (double)pages);
		printf("instructions/page    : %.2f\n",
		       (double)measurement->instructions / (double)pages);
	}

	printf("value/sum            : %" PRIu64 "\n", measurement->value);
}

static void print_usage(const char *program)
{
	fprintf(stderr, "Usage: %s [MiB]\n", program);
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t page_size;
	size_t length;
	size_t pages;

	volatile unsigned char *memory;

	struct perf_group perf_group;
	struct perf_counts warmup_counts;

	struct measurement first_write;
	struct measurement verify_before;
	struct measurement dontneed;
	struct measurement read_after;
	struct measurement write_after;

	struct mapping_stats stats;
	unsigned long vm_pte_baseline;
	uint64_t expected_sum;

	long page_size_long;

	if (argc > 2) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (argc == 2) {
		char *end = NULL;
		unsigned long value = strtoul(argv[1], &end, 0);

		if (end == argv[1] || *end != '\0' || value == 0) {
			fprintf(stderr, "Invalid MiB value: %s\n", argv[1]);
			return EXIT_FAILURE;
		}

		size_mib = (size_t)value;
	}

	page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	page_size = (size_t)page_size_long;
	length = size_mib * 1024UL * 1024UL;
	length -= length % page_size;
	pages = length / page_size;

	if (perf_group_open(&perf_group) != 0) {
		fprintf(stderr, "Unable to initialize perf counters\n");
		return EXIT_FAILURE;
	}

	/*
	 * 预热perf事件控制路径。
	 */
	if (perf_group_start(&perf_group) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &warmup_counts) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	vm_pte_baseline = read_vm_pte();

	memory = mmap(NULL,
		      length,
		      PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (memory == MAP_FAILED) {
		perror("mmap");
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	expected_sum = expected_pattern_sum(pages);

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping address      : %p\n", (const void *)memory);
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);
	printf("expected pattern sum : %" PRIu64 "\n", expected_sum);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	read_mapping_stats((const void *)memory, &stats);
	print_mapping_stats("state immediately after mmap",
			    &stats, vm_pte_baseline);

	/*
	 * 第一步：分配并写入4096个私有匿名页。
	 */
	first_write = measure_write(&perf_group, memory, pages, page_size);

	print_measurement("first write: allocate private pages",
			  &first_write, pages);

	read_mapping_stats((const void *)memory, &stats);
	print_mapping_stats("state after first write", &stats, vm_pte_baseline);

	/*
	 * 验证丢弃前，数据确实存在。
	 */
	verify_before = measure_read(&perf_group, memory, pages, page_size);

	print_measurement("verify data before MADV_DONTNEED",
			  &verify_before, pages);

	printf("pattern valid before : %s\n",
	       verify_before.value == expected_sum ? "yes" : "NO");

	/*
	 * 第二步：丢弃匿名数据页和叶子映射。
	 */
	dontneed = measure_dontneed(&perf_group, (void *)memory, length);

	print_measurement("madvise MADV_DONTNEED", &dontneed, pages);

	read_mapping_stats((const void *)memory, &stats);
	print_mapping_stats("state immediately after MADV_DONTNEED",
			    &stats, vm_pte_baseline);

	/*
	 * 第三步：再次读取。
	 * 预期得到4096次minor fault和全零结果。
	 */
	read_after = measure_read(&perf_group, memory, pages, page_size);

	print_measurement("first read after MADV_DONTNEED", &read_after, pages);

	printf("all zero after discard: %s\n",
	       read_after.value == 0 ? "yes" : "NO");

	read_mapping_stats((const void *)memory, &stats);
	print_mapping_stats("state after first read following discard",
			    &stats, vm_pte_baseline);

	/*
	 * 第四步：对共享零页重新写入。
	 */
	write_after = measure_write(&perf_group, memory, pages, page_size);

	print_measurement("first write after zero-page reads",
			  &write_after, pages);

	read_mapping_stats((const void *)memory, &stats);
	print_mapping_stats("state after private pages are allocated again",
			    &stats, vm_pte_baseline);

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);

	if (munmap((void *)memory, length) != 0)
		perror("munmap");

	perf_group_close(&perf_group);
	return EXIT_SUCCESS;
}
