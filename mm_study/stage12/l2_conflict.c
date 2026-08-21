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

/*
 * L1:
 *   64 sets * 64B = 4KiB set-index period.
 *
 * L2:
 *   512 sets * 64B = 32KiB set-index period.
 */
#define CONTROL_STRIDE		(4UL * 1024)
#define CONFLICT_STRIDE		(32UL * 1024)

#define CONTROL_OFFSET		(1UL * 1024 * 1024)

#define MAX_LINES		8
#define ACCESSES		131072UL
#define WARM_ACCESSES		65536UL
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
 * Use exactly the same logical permutation for control and conflict.
 */
static void build_order(size_t *order, size_t nlines)
{
	uint64_t state;
	size_t i;

	for (i = 0; i < nlines; i++)
		order[i] = i;

	state = 0x9e3779b97f4a7c15ULL ^ nlines;

	for (i = nlines - 1; i > 0; i--) {
		size_t j;
		size_t tmp;

		j = prng_next(&state) % (i + 1);

		tmp = order[i];
		order[i] = order[j];
		order[j] = tmp;
	}
}

static uintptr_t build_chain(unsigned char *base, size_t stride,
			     const size_t *order, size_t nlines)
{
	size_t i;

	for (i = 0; i < nlines; i++) {
		size_t current = order[i];
		size_t next = order[(i + 1) % nlines];
		volatile uintptr_t *slot;

		slot = (volatile uintptr_t *)(base + current * stride);
		*slot = (uintptr_t) (base + next * stride);
	}

	return (uintptr_t) (base + order[0] * stride);
}

static uintptr_t chase(uintptr_t p, size_t accesses)
{
	size_t i;

	for (i = 0; i < accesses; i++)
		p = *(volatile uintptr_t *)p;

	return p;
}

static void warm_chain(uintptr_t start)
{
	global_sink ^= chase(start, WARM_ACCESSES);
}

static struct sample measure(struct perf_group *perf, uintptr_t start)
{
	struct perf_counts counts;
	struct sample sample;
	uintptr_t p;

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	p = chase(start, ACCESSES);

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

static struct result run_test(struct perf_group *perf, uintptr_t start)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	long min_before, maj_before;
	long min_after, maj_after;
	unsigned int repeat;

	warm_chain(start);

	get_faults(&min_before, &maj_before);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		struct sample sample;

		warm_chain(start);
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
		fprintf(stderr, "mapping not found in smaps\n");
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	static const size_t line_counts[] = {
		1, 2, 3, 4,
		5, 6, 7, 8,
	};

	struct smaps_info smaps;
	struct perf_group perf;
	unsigned char *base;
	unsigned char *control_base;
	unsigned char *conflict_base;
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
	 * Instantiate the complete huge page before measurement.
	 */
	memset(base, 0, HUGEPAGE_SIZE);

	conflict_base = base;
	control_base = base + CONTROL_OFFSET;

	read_smaps_info(base, &smaps);

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping              : %p\n", base);
	printf("KernelPageSize       : %ld kB\n", smaps.kernel_page_kb);
	printf("MMUPageSize          : %ld kB\n", smaps.mmu_page_kb);
	printf("Private_Hugetlb      : %ld kB\n", smaps.private_hugetlb_kb);
	printf("L1D                  : 64 sets, 8-way, 64B line\n");
	printf("L2                   : 512 sets, 4-way, 64B line\n");
	printf("L2 policy            : inclusive\n");
	printf("control stride       : 4 KiB\n");
	printf("conflict stride      : 32 KiB\n");
	printf("control L1 mapping   : same set\n");
	printf("conflict L1 mapping  : same set\n");
	printf("control L2 mapping   : different sets\n");
	printf("conflict L2 mapping  : same set\n");
	printf("max active footprint : %lu B\n", MAX_LINES * CACHE_LINE);
	printf("translation WS       : ~1 x 2MiB translation\n");
	printf("access pattern       : dependent random-order cycle\n");
	printf("timed accesses       : %lu\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Lines | active B | control cyc/load | conflict cyc/load |"
	       " conflict-control | conflict best | control insn/load |"
	       " conflict insn/load | minflt | majflt\n"
	       "-------+----------+------------------+-------------------+"
	       "------------------+---------------+-------------------+"
	       "--------------------+--------+-------\n");

	for (i = 0; i < ARRAY_SIZE(line_counts); i++) {
		size_t order[MAX_LINES];
		struct result control_result;
		struct result conflict_result;
		uintptr_t control_start;
		uintptr_t conflict_start;
		size_t nlines = line_counts[i];

		build_order(order, nlines);

		control_start = build_chain(control_base, CONTROL_STRIDE,
					    order, nlines);

		conflict_start = build_chain(conflict_base,
					     CONFLICT_STRIDE, order, nlines);

		control_result = run_test(&perf, control_start);
		conflict_result = run_test(&perf, conflict_start);

		printf("%6zu | %8zu | %16.2f | %17.2f |"
		       " %16.2f | %13.2f | %17.2f |"
		       " %18.2f | %6ld | %6ld\n",
		       nlines,
		       nlines * CACHE_LINE,
		       control_result.median_cycles,
		       conflict_result.median_cycles,
		       conflict_result.median_cycles -
		       control_result.median_cycles,
		       conflict_result.best_cycles,
		       control_result.median_instructions,
		       conflict_result.median_instructions,
		       control_result.minor_faults +
		       conflict_result.minor_faults,
		       control_result.major_faults +
		       conflict_result.major_faults);
	}

	printf("\nglobal sink          : 0x%016" PRIxPTR "\n", global_sink);

	if (munmap(base, HUGEPAGE_SIZE))
		die("munmap HugeTLB");

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
