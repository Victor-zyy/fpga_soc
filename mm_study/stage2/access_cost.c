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
static volatile uintptr_t empty_sink;

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

struct sample {
	uint64_t cycles;
	uint64_t instructions;
	uint64_t operations;
	long minor_faults;
	long major_faults;
};

enum test_kind {
	TEST_EMPTY,
	TEST_READ,
	TEST_WRITE
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

/*
 * 保留循环、页号计算和地址计算，但不进行真实Load/Store。
 *
 * 内联汇编阻止编译器证明计算结果无用并删除循环。
 */
static void run_empty(volatile unsigned char *memory,
		      size_t pages, size_t page_size, unsigned int repeats)
{
	uintptr_t accumulator = 0;

	for (unsigned int repeat = 0; repeat < repeats; ++repeat) {
		for (size_t page = 0; page < pages; ++page) {
			uintptr_t address =
			    (uintptr_t) & memory[page * page_size];

			asm volatile ("":"+r" (address)
				      ::"memory");

			accumulator += address & 0xffU;
		}
	}

	empty_sink += accumulator;
}

static void run_read(volatile unsigned char *memory,
		     size_t pages, size_t page_size, unsigned int repeats)
{
	uint64_t sum = 0;

	for (unsigned int repeat = 0; repeat < repeats; ++repeat) {
		for (size_t page = 0; page < pages; ++page) {
			sum += memory[page * page_size];
		}
	}

	read_sink += sum;
}

static void run_write(volatile unsigned char *memory,
		      size_t pages, size_t page_size, unsigned int repeats)
{
	for (unsigned int repeat = 0; repeat < repeats; ++repeat) {
		for (size_t page = 0; page < pages; ++page) {
			memory[page * page_size] =
			    (unsigned char)(page + repeat);
		}
	}
}

static struct sample measure(struct perf_group *perf_group,
			     enum test_kind kind,
			     volatile unsigned char *memory,
			     size_t pages,
			     size_t page_size, unsigned int repeats)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct sample result;

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	switch (kind) {
	case TEST_EMPTY:
		run_empty(memory, pages, page_size, repeats);
		break;

	case TEST_READ:
		run_read(memory, pages, page_size, repeats);
		break;

	case TEST_WRITE:
		run_write(memory, pages, page_size, repeats);
		break;
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;
	result.operations = (uint64_t) pages *(uint64_t) repeats;
	result.minor_faults = after.minor_faults - before.minor_faults;
	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static void print_sample(const char *name,
			 const struct sample *sample,
			 const struct sample *baseline)
{
	printf("\n========== %s ==========\n", name);

	printf("operations           : %" PRIu64 "\n", sample->operations);
	printf("minor faults         : %ld\n", sample->minor_faults);
	printf("major faults         : %ld\n", sample->major_faults);
	printf("cycles               : %" PRIu64 "\n", sample->cycles);
	printf("instructions         : %" PRIu64 "\n", sample->instructions);

	if (sample->operations != 0) {
		printf("raw cycles/op        : %.2f\n",
		       (double)sample->cycles / (double)sample->operations);

		printf("raw instructions/op  : %.2f\n",
		       (double)sample->instructions /
		       (double)sample->operations);
	}

	if (baseline != NULL &&
	    baseline->operations == sample->operations &&
	    sample->operations != 0) {
		int64_t net_cycles =
		    (int64_t) sample->cycles - (int64_t) baseline->cycles;

		int64_t net_instructions =
		    (int64_t) sample->instructions -
		    (int64_t) baseline->instructions;

		printf("baseline cycles      : %" PRIu64 "\n",
		       baseline->cycles);
		printf("baseline instructions: %" PRIu64 "\n",
		       baseline->instructions);

		printf("net cycles/op        : %.2f\n",
		       (double)net_cycles / (double)sample->operations);

		printf("net instructions/op  : %.2f\n",
		       (double)net_instructions / (double)sample->operations);
	}

	if (sample->cycles != 0) {
		printf("approximate IPC      : %.4f\n",
		       (double)sample->instructions / (double)sample->cycles);
	}
}

static void print_usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s zero-path|direct-write "
		"[MiB] [hot_repeats]\n", program);
}

/**
 * This function code is to compare the cycles between zero path and direct write path
 *
 */
int main(int argc, char **argv)
{
	const char *mode;
	size_t size_mib = 16;
	unsigned int hot_repeats = 100;

	long page_size_long;
	size_t page_size;
	size_t length;
	size_t pages;

	volatile unsigned char *memory;
	struct perf_group perf_group;
	struct perf_counts warmup_counts;

	struct sample baseline_one;
	struct sample baseline_hot;

	if (argc < 2 || argc > 4) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	mode = argv[1];

	if (strcmp(mode, "zero-path") != 0 && strcmp(mode, "direct-write") != 0) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (argc >= 3) {
		char *end = NULL;
		unsigned long value = strtoul(argv[2], &end, 0);

		if (end == argv[2] || *end != '\0' || value == 0) {
			fprintf(stderr, "Invalid MiB: %s\n", argv[2]);
			return EXIT_FAILURE;
		}

		size_mib = (size_t)value;
	}

	if (argc >= 4) {
		char *end = NULL;
		unsigned long value = strtoul(argv[3], &end, 0);

		if (end == argv[3] || *end != '\0' || value == 0) {
			fprintf(stderr, "Invalid repeat count: %s\n", argv[3]);
			return EXIT_FAILURE;
		}

		hot_repeats = (unsigned int)value;
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
	 * 预热perf事件启停路径。
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

	memory = map_aligned(length, TWO_MIB);

	if (memory == MAP_FAILED) {
		perror("map_aligned");
		perf_group_close(&perf_group);
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());
	printf("mode                 : %s\n", mode);
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 2 MiB    : 0x%lx\n", (unsigned long)
	       ((uintptr_t) memory & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("pages                : %zu\n", pages);
	printf("hot repeats          : %u\n", hot_repeats);
	printf("hot operations       : %" PRIu64 "\n",
	       (uint64_t) pages * hot_repeats);

	/*
	 * 基线也在尚未触碰的VMA上运行，但空循环不会真正访问页面。
	 */
	baseline_one = measure(&perf_group,
			       TEST_EMPTY, memory, pages, page_size, 1);

	baseline_hot = measure(&perf_group,
			       TEST_EMPTY,
			       memory, pages, page_size, hot_repeats);

	print_sample("empty baseline: one pass", &baseline_one, NULL);

	print_sample("empty baseline: repeated passes", &baseline_hot, NULL);

	if (strcmp(mode, "zero-path") == 0) {
		struct sample first_read;
		struct sample hot_zero_read;
		struct sample zero_to_private_write;
		struct sample hot_private_write;
		struct sample hot_private_read;

		/*
		 * 无PTE -> 共享零页PTE。
		 */
		first_read = measure(&perf_group,
				     TEST_READ, memory, pages, page_size, 1);

		/*
		 * 所有VA已经指向共享零页。
		 */
		hot_zero_read = measure(&perf_group,
					TEST_READ,
					memory, pages, page_size, hot_repeats);

		/*
		 * 共享只读零页 -> 私有可写匿名页。
		 */
		zero_to_private_write = measure(&perf_group,
						TEST_WRITE,
						memory, pages, page_size, 1);

		/*
		 * 普通私有页热写。
		 */
		hot_private_write = measure(&perf_group,
					    TEST_WRITE,
					    memory,
					    pages, page_size, hot_repeats);

		/*
		 * 普通私有页热读。
		 */
		hot_private_read = measure(&perf_group,
					   TEST_READ,
					   memory,
					   pages, page_size, hot_repeats);

		print_sample("first read: missing PTE -> zero page",
			     &first_read, &baseline_one);

		print_sample("hot zero-page read",
			     &hot_zero_read, &baseline_hot);

		print_sample("first write: zero page -> private page",
			     &zero_to_private_write, &baseline_one);

		print_sample("hot private-page write",
			     &hot_private_write, &baseline_hot);

		print_sample("hot private-page read",
			     &hot_private_read, &baseline_hot);
	} else {
		struct sample first_write;
		struct sample hot_write;
		struct sample hot_read;

		/*
		 * 无PTE -> 私有可写匿名页。
		 */
		first_write = measure(&perf_group,
				      TEST_WRITE, memory, pages, page_size, 1);

		hot_write = measure(&perf_group,
				    TEST_WRITE,
				    memory, pages, page_size, hot_repeats);

		hot_read = measure(&perf_group,
				   TEST_READ,
				   memory, pages, page_size, hot_repeats);

		print_sample("first write: missing PTE -> private page",
			     &first_write, &baseline_one);

		print_sample("hot private-page write",
			     &hot_write, &baseline_hot);

		print_sample("hot private-page read", &hot_read, &baseline_hot);
	}

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);
	printf("empty_sink           : 0x%" PRIxPTR "\n", empty_sink);

	if (munmap((void *)memory, length) != 0)
		perror("munmap");

	perf_group_close(&perf_group);
	return EXIT_SUCCESS;
}
