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

#define MAX_WORKING_SET		(1536UL * 1024)

#define ACCESSES		65536UL
#define REPEATS			5
#define WARM_MIN_ACCESSES	4096UL
#define WARM_CYCLES		4

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

static uint64_t prng_next(uint64_t * state)
{
	uint64_t x = *state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;

	*state = x;

	return x;
}

/*
 * Construct one random cyclic linked list containing every cache line
 * in [base, base + working_set).
 *
 * Each cache line contains one pointer at offset zero:
 *
 *	line A -> line Q -> line F -> ... -> line A
 *
 * The next load address therefore depends on the previous load result.
 */
static uintptr_t build_random_cycle(unsigned char *base, size_t working_set)
{
	size_t nlines = working_set / CACHE_LINE;
	size_t *order;
	uint64_t state;
	size_t i;

	order = malloc(nlines * sizeof(*order));
	if (!order)
		die("malloc order");

	for (i = 0; i < nlines; i++)
		order[i] = i;

	/*
	 * Deterministic seed so repeated executions use the same
	 * permutation for a given working-set size.
	 */
	state = 0x9e3779b97f4a7c15ULL ^ working_set;

	for (i = nlines - 1; i > 0; i--) {
		size_t j;
		size_t tmp;

		j = prng_next(&state) % (i + 1);

		tmp = order[i];
		order[i] = order[j];
		order[j] = tmp;
	}

	for (i = 0; i < nlines; i++) {
		size_t current = order[i];
		size_t next = order[(i + 1) % nlines];
		uintptr_t *slot;

		slot = (uintptr_t *) (base + current * CACHE_LINE);
		*slot = (uintptr_t) (base + next * CACHE_LINE);
	}

	{
		uintptr_t start = (uintptr_t) (base + order[0] * CACHE_LINE);

		free(order);
		return start;
	}
}

static uintptr_t chase(uintptr_t p, size_t accesses)
{
	size_t i;

	for (i = 0; i < accesses; i++)
		p = *(volatile uintptr_t *)p;

	return p;
}

static void warm_cycle(uintptr_t start, size_t nlines)
{
	size_t accesses;

	accesses = nlines * WARM_CYCLES;
	if (accesses < WARM_MIN_ACCESSES)
		accesses = WARM_MIN_ACCESSES;

	global_sink ^= chase(start, accesses);
}

static struct sample measure(struct perf_group *perf, uintptr_t start)
{
	struct perf_counts counts;
	struct sample sample;
	uintptr_t p;

	p = start;

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	p = chase(p, ACCESSES);

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

/**
 *
 * run_test is the core of micro-benchmark
 *
 */
static struct result run_test(struct perf_group *perf,
			      unsigned char *base, size_t working_set)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	uintptr_t start;
	size_t nlines;
	long min_before, maj_before;
	long min_after, maj_after;
	unsigned int repeat;

	nlines = working_set / CACHE_LINE;

	start = build_random_cycle(base, working_set);

	/*
	 * The permutation builder and malloc/free may perturb the caches.
	 * Warm the actual pointer-chasing working set afterwards.
	 */
	warm_cycle(start, nlines);

	get_faults(&min_before, &maj_before);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		struct sample sample;

		warm_cycle(start, nlines);
		sample = measure(perf, start);

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
		fprintf(stderr, "HugeTLB mapping not found in smaps\n");
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	static const size_t working_sets_kb[] = {
		4, 8, 16, 24,
		28, 30, 32, 34,
		40, 48, 64, 96,
		112, 120, 124, 128,
		132, 136, 144, 160,
		192, 256, 384, 512,
		768, 1024, 1536,
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

	base = map_huge_page(); //2MB and hugeTLB

	/*
	 * Instantiate the huge page before entering the benchmark.
	 */
	memset(base, 0, HUGEPAGE_SIZE);

	read_smaps_info(base, &smaps);

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping              : %p\n", base);
	printf("mapping size         : 2 MiB HugeTLB\n");
	printf("2MiB aligned         : yes\n");
	printf("KernelPageSize       : %ld kB\n", smaps.kernel_page_kb);
	printf("MMUPageSize          : %ld kB\n", smaps.mmu_page_kb);
	printf("Private_Hugetlb      : %ld kB\n", smaps.private_hugetlb_kb);
	printf("L1D                  : 32 KiB, 64B line, 64 sets, 8-way\n");
	printf("L2                   : 128 KiB, 64B line, 512 sets, 4-way\n");
	printf("access pattern       : random dependent pointer chase\n");
	printf("timed accesses       : %lu\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Working set | cache lines | lines/L1set | median cyc/load |"
	       " best cyc/load | median insn/load | minflt | majflt\n"
	       "-------------+-------------+-------------+-----------------+"
	       "---------------+------------------+--------+-------\n");

	for (i = 0; i < ARRAY_SIZE(working_sets_kb); i++) {
		struct result result;
		size_t working_set;
		size_t nlines;
		double lines_per_l1_set;

		working_set = working_sets_kb[i] * 1024;
		nlines = working_set / CACHE_LINE;
		lines_per_l1_set = (double)nlines / 64.0;

		if (working_set > MAX_WORKING_SET) {
			fprintf(stderr, "working set exceeds maximum\n");
			break;
		}

		result = run_test(&perf, base, working_set);

		printf("%9zu KiB | %11zu | %11.2f | %15.2f |"
		       " %13.2f | %16.2f | %6ld | %6ld\n",
		       working_sets_kb[i],
		       nlines,
		       lines_per_l1_set,
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
