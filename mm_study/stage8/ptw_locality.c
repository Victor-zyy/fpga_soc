#define _GNU_SOURCE

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "perf_counter.h"

#define PAGE_SIZE	4096UL
#define CACHE_LINE	64UL

#define ALIGN_2M	(2UL * 1024 * 1024)
#define ALIGN_1G	(1UL * 1024 * 1024 * 1024)

#define STRIDE_4K	PAGE_SIZE
#define STRIDE_2M	ALIGN_2M
#define STRIDE_1G	ALIGN_1G

#define NPAGES		40
#define ACCESSES	65536
#define REPEATS		5
#define WARM_ROUNDS	64

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

struct layout {
	const char *name;
	const char *stride_name;
	size_t stride;
	size_t alignment;
};

static void die(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
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
		fprintf(stderr, "VmPTE not found in /proc/self/status\n");
		exit(EXIT_FAILURE);
	}

	return value;
}

static void get_faults(long *minor, long *major)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage))
		die("getrusage");

	*minor = usage.ru_minflt;
	*major = usage.ru_majflt;
}

static unsigned char *reserve_aligned(size_t span, size_t alignment,
				      void **reservation_out,
				      size_t *reserve_size_out)
{
	unsigned char *reservation;
	uintptr_t raw, aligned;
	size_t reserve_size;

	reserve_size = span + alignment;

	reservation = mmap(NULL, reserve_size, PROT_NONE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (reservation == MAP_FAILED)
		die("mmap reservation");

	raw = (uintptr_t) reservation;
	aligned = (raw + alignment - 1) & ~(uintptr_t) (alignment - 1);

	if (aligned + span > raw + reserve_size) {
		fprintf(stderr, "aligned reservation is too small\n");
		exit(EXIT_FAILURE);
	}

	*reservation_out = reservation;
	*reserve_size_out = reserve_size;

	return (unsigned char *)aligned;
}

static void build_mapping(unsigned char *base, size_t stride,
			  volatile uint64_t ** targets)
{
	size_t i;

	for (i = 0; i < NPAGES; i++) {
		unsigned char *page;
		size_t offset;
		void *ret;

		page = base + i * stride;

		ret = mmap(page, PAGE_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (ret == MAP_FAILED)
			die("mmap target page");

		/*
		 * Spread data lines across the 64 L1D sets.
		 *
		 * With only 40 pages, every selected line lands in a
		 * different set.
		 */
		offset = (i & 63UL) * CACHE_LINE;
		targets[i] = (volatile uint64_t *)(page + offset);

		/*
		 * Allocate the private page and install the PTE before
		 * entering any timed region.
		 */
		*targets[i] = 0x100000000ULL + i;
	}
}

static void warm_targets(volatile uint64_t * const *targets)
{
	uint64_t sum = 0;
	unsigned int round;
	size_t page;

	for (round = 0; round < WARM_ROUNDS; round++) {
		for (page = 0; page < NPAGES; page++)
			sum += *targets[page];
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

		if (++page == NPAGES)
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

static struct result run_layout(struct perf_group *perf,
				const struct layout *layout)
{
	volatile uint64_t *targets[NPAGES];
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	unsigned char *base;
	void *reservation;
	size_t reserve_size;
	size_t span;
	long min_before, maj_before;
	long min_after, maj_after;
	long vmpte_before, vmpte_after;
	unsigned int repeat;

	span = (NPAGES - 1) * layout->stride + PAGE_SIZE;

	base = reserve_aligned(span, layout->alignment,
			       &reservation, &reserve_size);

	vmpte_before = read_vmpte_kb();

	build_mapping(base, layout->stride, targets);

	vmpte_after = read_vmpte_kb();

	/*
	 * Establish steady-state data/TLB/PTW behavior before counting.
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
	static const struct layout layouts[] = {
		{
		 .name = "dense",
		 .stride_name = "4K",
		 .stride = STRIDE_4K,
		 .alignment = ALIGN_2M,
		  },
		{
		 .name = "2M-spread",
		 .stride_name = "2M",
		 .stride = STRIDE_2M,
		 .alignment = ALIGN_1G,
		  },
		{
		 .name = "1G-spread",
		 .stride_name = "1G",
		 .stride = STRIDE_1G,
		 .alignment = ALIGN_1G,
		  },
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
	printf("pages/layout         : %d\n", NPAGES);
	printf("DTLB entries         : 32 (hardware configuration)\n");
	printf("data lines/layout    : %d\n", NPAGES);
	printf("data footprint       : %.1f KiB\n",
	       (double)(NPAGES * CACHE_LINE) / 1024.0);
	printf("timed accesses       : %d\n", ACCESSES);
	printf("repeats/layout       : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Layout     | stride | VmPTE +KiB | median cyc/op |"
	       " best cyc/op | median insn/op | minflt | majflt\n"
	       "------------+--------+------------+---------------+"
	       "-------------+----------------+--------+-------\n");

	for (i = 0; i < sizeof(layouts) / sizeof(layouts[0]); i++) {
		struct result result;

		result = run_layout(&perf, &layouts[i]);

		printf(" %-10s | %6s | %10ld | %13.2f | %11.2f |"
		       " %14.2f | %6ld | %6ld\n",
		       layouts[i].name,
		       layouts[i].stride_name,
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
