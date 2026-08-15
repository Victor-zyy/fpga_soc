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
	unsigned long vm_pte_kb = 0;

	fp = fopen("/proc/self/status", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/status");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &vm_pte_kb) == 1) {
			break;
		}
	}

	fclose(fp);
	return vm_pte_kb;
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

static struct measurement measure_access(struct perf_group *perf_group,
					 volatile unsigned char *memory,
					 size_t length,
					 size_t page_size, int perform_write)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	if (perform_write) {
		for (size_t offset = 0; offset < length; offset += page_size) {
			memory[offset] = 1;
		}
	} else {
		uint64_t sum = 0;

		for (size_t offset = 0; offset < length; offset += page_size) {
			sum += memory[offset];
		}

		read_sink += sum;
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;
	result.minor_faults = after.minor_faults - before.minor_faults;
	result.major_faults = after.major_faults - before.major_faults;

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
}

static void print_usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s "
		"lazy-rw|populate-r|populate-rw|"
		"populate-rw-nonblock [MiB]\n", program);
}

int main(int argc, char **argv)
{
	const char *mode;
	size_t size_mib = 16;
	size_t length;
	size_t pages;
	size_t page_size;

	int protection;
	int flags;
	int perform_write;

	volatile unsigned char *memory;

	struct perf_group perf_group;
	struct perf_counts perf_warmup;
	struct perf_counts mmap_perf;

	struct usage_snapshot mmap_before;
	struct usage_snapshot mmap_after;

	struct mapping_stats stats_after_mmap;
	struct mapping_stats stats_after_access;
	struct measurement first_access;

	unsigned long vm_pte_baseline;

	long page_size_long;

	if (argc < 2 || argc > 3) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	mode = argv[1];

	protection = PROT_READ | PROT_WRITE;
	flags = MAP_PRIVATE | MAP_ANONYMOUS;
	perform_write = 1;

	if (strcmp(mode, "lazy-rw") == 0) {
		/* Defaults are correct. */
	} else if (strcmp(mode, "populate-r") == 0) {
		protection = PROT_READ;
		flags |= MAP_POPULATE;
		perform_write = 0;
	} else if (strcmp(mode, "populate-rw") == 0) {
		flags |= MAP_POPULATE;
	} else if (strcmp(mode, "populate-rw-nonblock") == 0) {
		flags |= MAP_POPULATE | MAP_NONBLOCK;
	} else {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (argc == 3) {
		char *end = NULL;
		unsigned long value = strtoul(argv[2], &end, 0);

		if (end == argv[2] || *end != '\0' || value == 0) {
			fprintf(stderr, "Invalid MiB value: %s\n", argv[2]);
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
	 * 预热perf启停路径。
	 */
	if (perf_group_start(&perf_group) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &perf_warmup) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	vm_pte_baseline = read_vm_pte();

	mmap_before = get_usage_snapshot();

	if (perf_group_start(&perf_group) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	memory = mmap(NULL, length, protection, flags, -1, 0);

	if (perf_group_stop(&perf_group, &mmap_perf) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	mmap_after = get_usage_snapshot();

	if (memory == MAP_FAILED) {
		perror("mmap");
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());
	printf("mode                 : %s\n", mode);
	printf("mapping address      : %p\n", (const void *)memory);
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	printf("\n========== mmap measurement ==========\n");
	printf("minor faults         : %ld\n",
	       mmap_after.minor_faults - mmap_before.minor_faults);
	printf("major faults         : %ld\n",
	       mmap_after.major_faults - mmap_before.major_faults);
	printf("cycles               : %" PRIu64 "\n", mmap_perf.cycles);
	printf("instructions         : %" PRIu64 "\n", mmap_perf.instructions);
	printf("cycles/page          : %.2f\n",
	       (double)mmap_perf.cycles / (double)pages);
	printf("instructions/page    : %.2f\n",
	       (double)mmap_perf.instructions / (double)pages);

	read_mapping_stats((const void *)memory, &stats_after_mmap);

	print_mapping_stats("state immediately after mmap",
			    &stats_after_mmap, vm_pte_baseline);

	first_access = measure_access(&perf_group,
				      memory, length, page_size, perform_write);

	print_measurement(perform_write ?
			  "first user write pass" :
			  "first user read pass", &first_access, pages);

	read_mapping_stats((const void *)memory, &stats_after_access);

	print_mapping_stats("state after first user access",
			    &stats_after_access, vm_pte_baseline);

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);

	if (munmap((void *)memory, length) != 0)
		perror("munmap");

	perf_group_close(&perf_group);
	return EXIT_SUCCESS;
}
