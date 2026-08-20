#define _GNU_SOURCE

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "perf_counter.h"

#define PAGE_SIZE		4096UL
#define CACHE_LINE		64UL
#define PTE_SIZE		8UL

#define ALIGN_1G		(1UL * 1024 * 1024 * 1024)
#define REGION_SIZE		(2UL * 1024 * 1024)

#define TARGET_PAGES		40
#define MAX_REGIONS		40
#define ACCESSES		65536
#define REPEATS			5
#define WARM_ROUNDS		64

/*
 * One 64-byte cache line contains eight 8-byte PTEs.
 *
 * Using PTE indices 0, 8, 16, ... makes every target leaf PTE
 * occupy a different cache line even when multiple targets belong
 * to the same L0 page-table page.
 */
#define PTES_PER_CACHE_LINE	(CACHE_LINE / PTE_SIZE) 
#define TARGET_PAGE_STEP	PTES_PER_CACHE_LINE // 64bytes / 8bytes = 8 PTEs per CacheLine

#define TEST_SPAN		(MAX_REGIONS * REGION_SIZE) // 40 * 2MB
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

static volatile uint64_t global_sink;

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
	long vmpte_delta;
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

static long read_vmpte_kb(void)
{
	FILE *fp;
	char line[256];
	long value = -1;

	fp = fopen("/proc/self/status", "r");
	if (!fp)
		die("fopen /proc/self/status");

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "VmPTE: %ld kB", &value) == 1)
			break;
	}

	fclose(fp);

	if (value < 0) {
		fprintf(stderr, "VmPTE not found\n");
		exit(EXIT_FAILURE);
	}

	return value;
}

//overallocate + align
static unsigned char *reserve_1g_aligned(void **reservation_out,
					 size_t *reserve_size_out)
{
	unsigned char *reservation;
	size_t reserve_size = TEST_SPAN + ALIGN_1G;
	uintptr_t raw, aligned;

	reservation = mmap(NULL, reserve_size, PROT_NONE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (reservation == MAP_FAILED)
		die("mmap reservation");

	raw = (uintptr_t) reservation;
	aligned = (raw + ALIGN_1G - 1) & ~(uintptr_t) (ALIGN_1G - 1);

	if (aligned + TEST_SPAN > raw + reserve_size) {
		fprintf(stderr, "aligned reservation too small\n");
		exit(EXIT_FAILURE);
	}

	*reservation_out = reservation;
	*reserve_size_out = reserve_size;

	return (unsigned char *)aligned;
}

/*
 * Build exactly TARGET_PAGES 4 KiB mappings.
 *
 * The mappings are distributed round-robin across @nregions distinct
 * 2 MiB regions:
 *
 *	page 0 -> region 0
 *	page 1 -> region 1
 *	...
 *	page N -> region N % nregions
 *
 * Within a region, successive targets use leaf PTE indices:
 *
 *	0, 8, 16, 24, ...
 *
 * Therefore all 40 leaf PTEs occupy distinct 64-byte cache lines
 * regardless of nregions.
 */
static void build_targets(unsigned char *base, size_t nregions,
			  volatile uint64_t ** targets)
{
	size_t i;

	for (i = 0; i < TARGET_PAGES; i++) {
		size_t region = i % nregions;
		size_t ordinal = i / nregions;
		size_t pte_index = ordinal * TARGET_PAGE_STEP;
		size_t page_offset = pte_index * PAGE_SIZE;
		size_t data_offset = (i & 63UL) * CACHE_LINE; // different set of dcache line
		unsigned char *page;
		void *ret;

		if (pte_index >= 512) {
			fprintf(stderr, "leaf PTE index overflow\n");
			exit(EXIT_FAILURE);
		}

		page = base + region * REGION_SIZE + page_offset;

		ret = mmap(page, PAGE_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (ret == MAP_FAILED)
			die("mmap target");

		targets[i] = (volatile uint64_t *)(page + data_offset); // one page 页内的offset

		/*
		 * Allocate the physical anonymous page and install its PTE
		 * before entering the measured region.
		 */
		*targets[i] = 0x100000000ULL + i;
	}
}

static void warm_targets(volatile uint64_t * const *targets)
{
	uint64_t sum = 0;
	unsigned int round;
	size_t i;

	for (round = 0; round < WARM_ROUNDS; round++) {
		for (i = 0; i < TARGET_PAGES; i++)
			sum += *targets[i];
	}

	global_sink ^= sum;
}

static struct sample measure(struct perf_group *perf,
			     volatile uint64_t * const *targets)
{
	struct perf_counts counts;
	struct sample sample;
	uint64_t sum = 0;
	uint64_t i;
	size_t page = 0;

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	for (i = 0; i < ACCESSES; i++) {
		sum += *targets[page];

		if (++page == TARGET_PAGES)
			page = 0;
	}

	asm volatile ("":::"memory");

	if (perf_group_stop(perf, &counts))
		die("perf_group_stop");

	global_sink ^= sum;

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

// core source code for test PWC capacity
static struct result run_regions(struct perf_group *perf, size_t nregions)
{
	volatile uint64_t *targets[TARGET_PAGES];
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	unsigned char *base;
	void *reservation;
	size_t reserve_size;
	unsigned int repeat;
	long min_before, maj_before;
	long min_after, maj_after;
	long vmpte_before, vmpte_after;

    //40 pages and 1G memory area
	base = reserve_1g_aligned(&reservation, &reserve_size);

	vmpte_before = read_vmpte_kb();
	build_targets(base, nregions, targets);
	vmpte_after = read_vmpte_kb();

	/*
	 * Drive the DTLB/PTW/PWC into steady state before measurement.
	 */
	warm_targets(targets);

	get_faults(&min_before, &maj_before);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		struct sample sample;

		warm_targets(targets);
		sample = measure(perf, targets);

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
	result.vmpte_delta = vmpte_after - vmpte_before;

	if (munmap(reservation, reserve_size))
		die("munmap reservation");

	return result;
}

int main(void)
{
	static const size_t region_counts[] = {
		1, 2, 4, 6,
		7, 8, 9, 10,
		12, 16, 20, 40,
	};

	struct perf_group perf;
	size_t i;

	setvbuf(stdout, NULL, _IONBF, 0);

	if (sysconf(_SC_PAGESIZE) != PAGE_SIZE) {
		fprintf(stderr, "expected %lu-byte pages\n", PAGE_SIZE);
		return EXIT_FAILURE;
	}

	if (perf_group_open(&perf)) {
		fprintf(stderr, "failed to open perf events\n");
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());
	printf("target 4K pages      : %d\n", TARGET_PAGES);
	printf("DTLB entries         : 32\n");
	printf("PWC entries          : 8\n");
	printf("L2 TLB               : disabled\n");
	printf("VA window            : one 1GiB region\n");
	printf("shared L2 PTE        : yes\n");
	printf("leaf PTE lines       : %d fixed\n", TARGET_PAGES);
	printf("data footprint       : %.1f KiB\n",
	       (double)(TARGET_PAGES * CACHE_LINE) / 1024.0);
	printf("timed accesses       : %d\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Regions | approx nonleaf | VmPTE +KiB | median cyc/op |"
	       " best cyc/op | median insn/op | minflt | majflt\n"
	       "---------+----------------+------------+---------------+"
	       "-------------+----------------+--------+-------\n");

	for (i = 0; i < ARRAY_SIZE(region_counts); i++) {
		struct result result;
		size_t regions = region_counts[i];

		result = run_regions(&perf, regions);

		printf("%8zu | %14zu | %10ld | %13.2f | %11.2f |"
		       " %14.2f | %6ld | %6ld\n",
		       regions,
		       regions + 1,
		       result.vmpte_delta,
		       result.median_cycles,
		       result.best_cycles,
		       result.median_instructions,
		       result.minor_faults, result.major_faults);
	}

	printf("\nglobal sink          : 0x%016" PRIx64 "\n", global_sink);

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
