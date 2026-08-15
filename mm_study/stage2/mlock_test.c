#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "perf_counter.h"

#define TWO_MIB (2UL * 1024UL * 1024UL)

#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 0x01
#endif

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
	unsigned long locked_kb;

	unsigned long vm_pte_kb;
	unsigned long vm_lck_kb;

	char vm_flags[256];
};

struct measurement {
	uint64_t cycles;
	uint64_t instructions;

	long minor_faults;
	long major_faults;

	int result;
	int error_number;
};

struct range_context {
	void *address;
	size_t length;
};

static int starts_with(const char *line, const char *prefix)
{
	return strncmp(line, prefix, strlen(prefix)) == 0;
}

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

static void read_process_status(unsigned long *vm_pte_kb,
				unsigned long *vm_lck_kb)
{
	FILE *fp;
	char line[512];

	*vm_pte_kb = 0;
	*vm_lck_kb = 0;

	fp = fopen("/proc/self/status", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/status");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (starts_with(line, "VmPTE:")) {
			(void)sscanf(line, "VmPTE: %lu kB", vm_pte_kb);
		} else if (starts_with(line, "VmLck:")) {
			(void)sscanf(line, "VmLck: %lu kB", vm_lck_kb);
		}
	}

	fclose(fp);
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

		if (starts_with(line, "Size:")) {
			(void)sscanf(line, "Size: %lu kB", &stats->size_kb);
		} else if (starts_with(line, "Rss:")) {
			(void)sscanf(line, "Rss: %lu kB", &stats->rss_kb);
		} else if (starts_with(line, "Pss:")) {
			(void)sscanf(line, "Pss: %lu kB", &stats->pss_kb);
		} else if (starts_with(line, "Private_Dirty:")) {
			(void)sscanf(line,
				     "Private_Dirty: %lu kB",
				     &stats->private_dirty_kb);
		} else if (starts_with(line, "Referenced:")) {
			(void)sscanf(line,
				     "Referenced: %lu kB",
				     &stats->referenced_kb);
		} else if (starts_with(line, "Anonymous:")) {
			(void)sscanf(line,
				     "Anonymous: %lu kB", &stats->anonymous_kb);
		} else if (starts_with(line, "Locked:")) {
			(void)sscanf(line, "Locked: %lu kB", &stats->locked_kb);
		} else if (starts_with(line, "VmFlags:")) {
			(void)snprintf(stats->vm_flags,
				       sizeof(stats->vm_flags),
				       "%s", line + strlen("VmFlags:"));

			stats->vm_flags[strcspn(stats->vm_flags, "\n")] = '\0';
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr,
			"Could not find mapping containing %p\n", address);
		exit(EXIT_FAILURE);
	}

	read_process_status(&stats->vm_pte_kb, &stats->vm_lck_kb);
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
	printf("Locked               : %lu kB\n", stats->locked_kb);
	printf("VmLck                : %lu kB\n", stats->vm_lck_kb);
	printf("VmPTE                : %lu kB\n", stats->vm_pte_kb);
	printf("VmPTE delta          : %ld kB\n",
	       (long)stats->vm_pte_kb - (long)vm_pte_baseline);
	printf("VmFlags              :%s\n", stats->vm_flags);
}

static void *map_aligned(size_t length, size_t alignment)
{
	size_t total_length;
	void *raw_mapping;
	uintptr_t raw;
	uintptr_t aligned;
	size_t prefix_length;
	size_t suffix_length;

	if ((alignment & (alignment - 1)) != 0) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	if (length > SIZE_MAX - alignment) {
		errno = EOVERFLOW;
		return MAP_FAILED;
	}

	total_length = length + alignment;

	raw_mapping = mmap(NULL,
			   total_length,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (raw_mapping == MAP_FAILED)
		return MAP_FAILED;

	raw = (uintptr_t) raw_mapping;

	aligned = (raw + alignment - 1) & ~((uintptr_t) alignment - 1);

	prefix_length = (size_t)(aligned - raw);

	suffix_length = total_length - prefix_length - length;

	if (prefix_length != 0) {
		if (munmap((void *)raw, prefix_length) != 0) {
			perror("munmap prefix");
			(void)munmap(raw_mapping, total_length);
			return MAP_FAILED;
		}
	}

	if (suffix_length != 0) {
		if (munmap((void *)(aligned + length), suffix_length) != 0) {
			perror("munmap suffix");
			(void)munmap((void *)aligned, length);
			return MAP_FAILED;
		}
	}

	return (void *)aligned;
}

static int call_mlock2_onfault(void *address, size_t length)
{
#if defined(SYS_mlock2)
	return (int)syscall(SYS_mlock2, address, length, MLOCK_ONFAULT);
#elif defined(__NR_mlock2)
	return (int)syscall(__NR_mlock2, address, length, MLOCK_ONFAULT);
#else
	(void)address;
	(void)length;
	errno = ENOSYS;
	return -1;
#endif
}

typedef int (*operation_function)(void *context);

static int operation_mlock(void *context)
{
	struct range_context *range = context;

	return mlock(range->address, range->length);
}

static int operation_mlock_onfault(void *context)
{
	struct range_context *range = context;

	return call_mlock2_onfault(range->address, range->length);
}

static int operation_munlock(void *context)
{
	struct range_context *range = context;

	return munlock(range->address, range->length);
}

static int operation_dontneed(void *context)
{
	struct range_context *range = context;

	return madvise(range->address, range->length, MADV_DONTNEED);
}

static struct measurement measure_operation(struct perf_group *perf_group,
					    operation_function operation,
					    void *context)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	errno = 0;
	result.result = operation(context);
	result.error_number = errno;

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static struct measurement measure_write_range(struct perf_group *perf_group,
					      volatile unsigned char *memory,
					      size_t first_page,
					      size_t page_count,
					      size_t page_size)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		memory[page * page_size] = (unsigned char)((page % 251U) + 1U);
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	result.result = 0;
	result.error_number = 0;

	return result;
}

static void print_measurement(const char *name,
			      const struct measurement *measurement,
			      size_t denominator_pages)
{
	printf("\n========== %s ==========\n", name);

	printf("return value          : %d\n", measurement->result);

	if (measurement->result != 0) {
		printf("errno                 : %d (%s)\n",
		       measurement->error_number,
		       strerror(measurement->error_number));
	}

	printf("minor faults         : %ld\n", measurement->minor_faults);
	printf("major faults         : %ld\n", measurement->major_faults);
	printf("cycles               : %" PRIu64 "\n", measurement->cycles);
	printf("instructions         : %" PRIu64 "\n",
	       measurement->instructions);

	if (denominator_pages != 0) {
		printf("cycles/page          : %.2f\n",
		       (double)measurement->cycles / (double)denominator_pages);

		printf("instructions/page    : %.2f\n",
		       (double)measurement->instructions /
		       (double)denominator_pages);
	}
}

static void print_memlock_limit(void)
{
	struct rlimit limit;

	if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
		perror("getrlimit RLIMIT_MEMLOCK");
		return;
	}

	printf("RLIMIT_MEMLOCK soft  : ");

	if (limit.rlim_cur == RLIM_INFINITY)
		printf("unlimited\n");
	else
		printf("%" PRIu64 " bytes\n", (uint64_t) limit.rlim_cur);

	printf("RLIMIT_MEMLOCK hard  : ");

	if (limit.rlim_max == RLIM_INFINITY)
		printf("unlimited\n");
	else
		printf("%" PRIu64 " bytes\n", (uint64_t) limit.rlim_max);
}

static void print_usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s eager|onfault " "[MiB] [partial_pages]\n", program);
}

int main(int argc, char **argv)
{
	const char *mode;
	size_t size_mib = 16;
	size_t partial_pages = 512;

	long page_size_long;
	size_t page_size;
	size_t length;
	size_t pages;

	volatile unsigned char *memory;

	struct perf_group perf_group;
	struct perf_counts warmup_counts;

	struct range_context range;
	struct mapping_stats stats;

	struct measurement lock_measurement;
	struct measurement first_write;
	struct measurement remaining_write;
	struct measurement dontneed_locked;
	struct measurement unlock_measurement;
	struct measurement dontneed_unlocked;

	unsigned long vm_pte_baseline;

	if (argc < 2 || argc > 4) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	mode = argv[1];

	if (strcmp(mode, "eager") != 0 && strcmp(mode, "onfault") != 0) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

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
			fprintf(stderr,
				"Invalid partial page count: %s\n", argv[3]);
			return EXIT_FAILURE;
		}

		partial_pages = (size_t)value;
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

	if (partial_pages > pages) {
		fprintf(stderr,
			"partial_pages=%zu exceeds total pages=%zu\n",
			partial_pages, pages);
		return EXIT_FAILURE;
	}

	if (perf_group_open(&perf_group) != 0) {
		fprintf(stderr, "Unable to initialize perf counters\n");
		return EXIT_FAILURE;
	}

	if (perf_group_start(&perf_group) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &warmup_counts) != 0) {
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	read_process_status(&vm_pte_baseline, &(unsigned long) { 0 });

	memory = map_aligned(length, TWO_MIB);

	if (memory == MAP_FAILED) {
		perror("map_aligned");
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	range.address = (void *)memory;
	range.length = length;

	printf("PID                  : %ld\n", (long)getpid());
	printf("mode                 : %s\n", mode);
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 2 MiB    : 0x%lx\n", (unsigned long)
	       ((uintptr_t) memory & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);
	printf("partial pages        : %zu\n", partial_pages);
	printf("partial size         : %zu kB\n",
	       partial_pages * page_size / 1024);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	print_memlock_limit();

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("state immediately after mmap",
			    &stats, vm_pte_baseline);

	if (strcmp(mode, "eager") == 0) {
		lock_measurement = measure_operation(&perf_group,
						     operation_mlock, &range);

		print_measurement("mlock: eager population and locking",
				  &lock_measurement, pages);

		if (lock_measurement.result != 0) {
			fprintf(stderr,
				"\nmlock failed. Check RLIMIT_MEMLOCK "
				"or reduce the mapping size.\n");

			(void)munmap((void *)memory, length);
			perf_group_close(&perf_group);
			return EXIT_FAILURE;
		}

		read_mapping_stats((const void *)memory, &stats);

		print_mapping_stats("state immediately after mlock",
				    &stats, vm_pte_baseline);

		first_write = measure_write_range(&perf_group,
						  memory, 0, pages, page_size);

		print_measurement("first user write after mlock",
				  &first_write, pages);

		read_mapping_stats((const void *)memory, &stats);

		print_mapping_stats("state after first user write",
				    &stats, vm_pte_baseline);
	} else {
		lock_measurement = measure_operation(&perf_group,
						     operation_mlock_onfault,
						     &range);

		print_measurement("mlock2 MLOCK_ONFAULT",
				  &lock_measurement, pages);

		if (lock_measurement.result != 0) {
			fprintf(stderr,
				"\nmlock2 failed. Check kernel support, "
				"RLIMIT_MEMLOCK, or mapping size.\n");

			(void)munmap((void *)memory, length);
			perf_group_close(&perf_group);
			return EXIT_FAILURE;
		}

		read_mapping_stats((const void *)memory, &stats);

		print_mapping_stats("state immediately after MLOCK_ONFAULT",
				    &stats, vm_pte_baseline);

		first_write = measure_write_range(&perf_group,
						  memory,
						  0, partial_pages, page_size);

		print_measurement("write only the partial range",
				  &first_write, partial_pages);

		read_mapping_stats((const void *)memory, &stats);

		print_mapping_stats("state after partial write",
				    &stats, vm_pte_baseline);

		remaining_write = measure_write_range(&perf_group,
						      memory,
						      partial_pages,
						      pages - partial_pages,
						      page_size);

		print_measurement("write the remaining range",
				  &remaining_write, pages - partial_pages);

		read_mapping_stats((const void *)memory, &stats);

		print_mapping_stats("state after all pages are touched",
				    &stats, vm_pte_baseline);
	}

	/*
	 * Standard MADV_DONTNEED is expected to fail while
	 * the VMA remains VM_LOCKED.
	 */
	dontneed_locked = measure_operation(&perf_group,
					    operation_dontneed, &range);

	print_measurement("MADV_DONTNEED while locked",
			  &dontneed_locked, pages);

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("state after rejected MADV_DONTNEED",
			    &stats, vm_pte_baseline);

	/*
	 * munlock changes reclaimability, but does not discard data.
	 */
	unlock_measurement = measure_operation(&perf_group,
					       operation_munlock, &range);

	print_measurement("munlock", &unlock_measurement, pages);

	if (unlock_measurement.result != 0) {
		(void)munmap((void *)memory, length);
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("state immediately after munlock",
			    &stats, vm_pte_baseline);

	/*
	 * The same MADV_DONTNEED should now succeed.
	 */
	dontneed_unlocked = measure_operation(&perf_group,
					      operation_dontneed, &range);

	print_measurement("MADV_DONTNEED after munlock",
			  &dontneed_unlocked, pages);

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("state after successful MADV_DONTNEED",
			    &stats, vm_pte_baseline);

	if (munmap((void *)memory, length) != 0)
		perror("munmap");

	perf_group_close(&perf_group);
	return EXIT_SUCCESS;
}
