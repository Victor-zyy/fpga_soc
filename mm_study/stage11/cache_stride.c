#define _GNU_SOURCE

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "perf_counter.h"

#define PAGE_SIZE		4096UL
#define HUGEPAGE_SIZE		(2UL * 1024 * 1024)
#define CACHE_LINE		64UL
#define WORKING_SET		(1UL * 1024 * 1024)

#define ACCESSES		131072UL
#define MIN_WARM_ACCESSES	65536UL
#define WARM_CYCLES		2
#define REPEATS			5

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT		26
#endif

#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB		(21 << MAP_HUGE_SHIFT)
#endif

static volatile uintptr_t global_sink;

struct sample {
	uint64_t cycles;
	uint64_t instructions;
};

struct result {
	double median_cycles;
	double best_cycles;
	double median_instructions;
	long minor_faults;
	long major_faults;
};

struct stride_cycle {
	uintptr_t start;
	size_t nodes;
	size_t unique_lines;
};

struct smaps_info {
	long kernel_page_kb;
	long mmu_page_kb;
	long private_hugetlb_kb;
};

static void die(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
}

static void get_faults(long *minor, long *major)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage))
		die("getrusage");

	*minor = usage.ru_minflt;
	*major = usage.ru_majflt;
}

static unsigned char *map_huge_page(void)
{
	unsigned char *base;

	base = mmap(NULL, HUGEPAGE_SIZE,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS |
		    MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
	if (base == MAP_FAILED)
		die("mmap HugeTLB");

	if ((uintptr_t) base & (HUGEPAGE_SIZE - 1)) {
		fprintf(stderr, "HugeTLB mapping is not 2MiB aligned\n");
		exit(EXIT_FAILURE);
	}

	return base;
}

/*
 * Construct:
 *
 *	base
 *	  |
 *	  v
 *	base + stride
 *	  |
 *	  v
 *	base + 2 * stride
 *	  |
 *	 ...
 *	  |
 *	  +----------> base
 *
 * Every node stores the address of the next node. The next memory
 * access therefore depends on completion of the current load.
 */
static struct stride_cycle build_stride_cycle(unsigned char *base,
					      size_t stride)
{
	struct stride_cycle cycle;
	unsigned char *seen;
	size_t max_lines;
	size_t i;

	if (!stride || stride % sizeof(uintptr_t)) {
		fprintf(stderr, "invalid stride: %zu\n", stride);
		exit(EXIT_FAILURE);
	}

	cycle.nodes = WORKING_SET / stride;
	if (cycle.nodes < 2) {
		fprintf(stderr, "too few nodes for stride %zu\n", stride);
		exit(EXIT_FAILURE);
	}

	max_lines = WORKING_SET / CACHE_LINE;

	seen = calloc(max_lines, sizeof(*seen));
	if (!seen)
		die("calloc seen");

	cycle.unique_lines = 0;

	for (i = 0; i < cycle.nodes; i++) {
		size_t current_offset;
		size_t next_offset;
		size_t line;
		volatile uintptr_t *slot;

		current_offset = i * stride;

		if (i + 1 == cycle.nodes)
			next_offset = 0;
		else
			next_offset = (i + 1) * stride;

		slot = (volatile uintptr_t *)(base + current_offset);
		*slot = (uintptr_t) (base + next_offset);

		line = current_offset / CACHE_LINE;

		if (!seen[line]) {
			seen[line] = 1;
			cycle.unique_lines++;
		}
	}

	free(seen);

	cycle.start = (uintptr_t) base;

	return cycle;
}

static uintptr_t chase(uintptr_t p, size_t accesses)
{
	size_t i;

	for (i = 0; i < accesses; i++)
		p = *(volatile uintptr_t *)p;

	return p;
}

static void warm_cycle(const struct stride_cycle *cycle)
{
	size_t accesses;

	accesses = cycle->nodes * WARM_CYCLES;

	if (accesses < MIN_WARM_ACCESSES)
		accesses = MIN_WARM_ACCESSES;

	global_sink ^= chase(cycle->start, accesses);
}

static struct sample measure(struct perf_group *perf,
			     const struct stride_cycle *cycle)
{
	struct perf_counts counts;
	struct sample sample;
	uintptr_t p;

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	p = chase(cycle->start, ACCESSES);

	asm volatile ("":::"memory");

	if (perf_group_stop(perf, &counts))
		die("perf_group_stop");

	global_sink ^= p;

	sample.cycles = counts.cycles;
	sample.instructions = counts.instructions;

	return sample;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t aa = *(const uint64_t *)a;
	uint64_t bb = *(const uint64_t *)b;

	if (aa < bb)
		return -1;
	if (aa > bb)
		return 1;

	return 0;
}

static struct result run_test(struct perf_group *perf,
			      const struct stride_cycle *cycle)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	long min_before, maj_before;
	long min_after, maj_after;
	unsigned int repeat;

	warm_cycle(cycle);

	get_faults(&min_before, &maj_before);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		struct sample sample;

		warm_cycle(cycle);
		sample = measure(perf, cycle);

		cycles[repeat] = sample.cycles;
		instructions[repeat] = sample.instructions;
	}

	get_faults(&min_after, &maj_after);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		cycles_sorted[repeat] = cycles[repeat];
		instructions_sorted[repeat] = instructions[repeat];
	}

	qsort(cycles_sorted, REPEATS, sizeof(cycles_sorted[0]), cmp_u64);
	qsort(instructions_sorted, REPEATS,
	      sizeof(instructions_sorted[0]), cmp_u64);

	result.median_cycles = (double)cycles_sorted[REPEATS / 2] / ACCESSES;

	result.best_cycles = (double)cycles_sorted[0] / ACCESSES;

	result.median_instructions =
	    (double)instructions_sorted[REPEATS / 2] / ACCESSES;

	result.minor_faults = min_after - min_before;
	result.major_faults = maj_after - maj_before;

	return result;
}

static void read_smaps_info(void *address, struct smaps_info *info)
{
	FILE *fp;
	char line[512];
	uintptr_t target = (uintptr_t) address;
	int found = 0;

	memset(info, 0, sizeof(*info));

	info->kernel_page_kb = -1;
	info->mmu_page_kb = -1;
	info->private_hugetlb_kb = -1;

	fp = fopen("/proc/self/smaps", "r");
	if (!fp)
		die("fopen /proc/self/smaps");

	while (fgets(line, sizeof(line), fp)) {
		unsigned long start, end;

		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if (found)
				break;

			if (target >= start && target < end)
				found = 1;

			continue;
		}

		if (!found)
			continue;

		sscanf(line, "KernelPageSize: %ld kB", &info->kernel_page_kb);
		sscanf(line, "MMUPageSize: %ld kB", &info->mmu_page_kb);
		sscanf(line, "Private_Hugetlb: %ld kB",
		       &info->private_hugetlb_kb);
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "mapping not found in smaps\n");
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	static const size_t strides[] = {
		8, 16, 24, 32,
		40, 48, 56, 64,
		72, 80, 96, 128,
		192, 256,
	};

	struct smaps_info smaps;
	struct perf_group perf;
	unsigned char *base;
	size_t i;

	setvbuf(stdout, NULL, _IONBF, 0);

	if (sysconf(_SC_PAGESIZE) != PAGE_SIZE) {
		fprintf(stderr, "expected %lu-byte base pages\n", PAGE_SIZE);
		return EXIT_FAILURE;
	}

	if (perf_group_open(&perf)) {
		fprintf(stderr, "failed to open perf events\n");
		return EXIT_FAILURE;
	}

	base = map_huge_page();

	/*
	 * Instantiate the entire huge page before benchmarking.
	 */
	memset(base, 0, HUGEPAGE_SIZE);

	read_smaps_info(base, &smaps);

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping              : %p\n", base);
	printf("KernelPageSize       : %ld kB\n", smaps.kernel_page_kb);
	printf("MMUPageSize          : %ld kB\n", smaps.mmu_page_kb);
	printf("Private_Hugetlb      : %ld kB\n", smaps.private_hugetlb_kb);
	printf("cache line           : 64 B\n");
	printf("working-set span     : %lu KiB\n", WORKING_SET / 1024);
	printf("L2 capacity          : 128 KiB\n");
	printf("max stride           : 256 B\n");
	printf("min active line WS   : 256 KiB\n");
	printf("translation WS       : ~1 x 2MiB translation\n");
	printf("access pattern       : dependent fixed-stride chase\n");
	printf("timed accesses       : %lu\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Stride | nodes/cycle | line WS KiB | loads/line |"
	       " useful B/line | median cyc/load | best cyc/load |"
	       " median insn/load | minflt | majflt\n"
	       "--------+-------------+-------------+------------+"
	       "---------------+-----------------+---------------+"
	       "------------------+--------+-------\n");

	for (i = 0; i < ARRAY_SIZE(strides); i++) {
		struct stride_cycle cycle;
		struct result result;
		double loads_per_line;
		double useful_bytes_per_line;
		double line_ws_kb;

		cycle = build_stride_cycle(base, strides[i]);

		loads_per_line = (double)cycle.nodes / cycle.unique_lines;

		useful_bytes_per_line = loads_per_line * sizeof(uintptr_t);

		line_ws_kb = (double)(cycle.unique_lines * CACHE_LINE) / 1024.0;

		result = run_test(&perf, &cycle);

		printf("%6zu B | %11zu | %11.1f | %10.2f |"
		       " %13.2f | %15.2f | %13.2f |"
		       " %16.2f | %6ld | %6ld\n",
		       strides[i],
		       cycle.nodes,
		       line_ws_kb,
		       loads_per_line,
		       useful_bytes_per_line,
		       result.median_cycles,
		       result.best_cycles,
		       result.median_instructions,
		       result.minor_faults, result.major_faults);
	}

	printf("\nglobal sink          : 0x%016" PRIxPTR "\n", global_sink);

	if (munmap(base, HUGEPAGE_SIZE))
		die("munmap HugeTLB");

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
