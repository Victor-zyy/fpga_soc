#define _GNU_SOURCE

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "perf_counter.h"

#define ALIGN_2M	(2UL * 1024 * 1024)
#define KEEP_SIZE	(1UL * 1024 * 1024)

#define MAX_PAGES	256
#define ACCESSES	65536
#define REPEATS		5
#define WARM_ROUNDS	64

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

static volatile uint64_t global_sink;

struct sample {
	uint64_t cycles;
	uint64_t instructions;
};

static void die(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
}

static unsigned char *map_aligned_region(void)
{
	const size_t reserve_size = 2 * ALIGN_2M;
	unsigned char *reservation;
	uintptr_t raw, aligned;
	size_t prefix, suffix;

	reservation = mmap(NULL, reserve_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (reservation == MAP_FAILED)
		die("mmap");

	raw = (uintptr_t) reservation;
	aligned = (raw + ALIGN_2M - 1) & ~(uintptr_t) (ALIGN_2M - 1);

	prefix = aligned - raw;
	suffix = raw + reserve_size - (aligned + KEEP_SIZE);

	if (prefix && munmap(reservation, prefix))
		die("munmap prefix");

	if (suffix && munmap((void *)(aligned + KEEP_SIZE), suffix))
		die("munmap suffix");

	return (unsigned char *)aligned;
}

/*
 * Access one cache line from every 4 KiB page.
 *
 * L1D:
 *   line size = 64 B
 *   sets      = 64
 *   ways      = 8
 *
 * The L1 set index is entirely inside the page offset.  Using
 *
 *	offset = (page & 63) * 64
 *
 * distributes accesses over all 64 sets.  At MAX_PAGES=256 this
 * gives four lines per set, avoiding an artificial 8-way conflict.
 */
static inline volatile uint64_t *target_address(unsigned char *base,
						size_t page)
{
	size_t offset = (page & 63UL) << 6;

	return (volatile uint64_t *)(base + page * 4096UL + offset);
}

static void warm_working_set(unsigned char *base, size_t npages)
{
	uint64_t sum = 0;
	unsigned int round;
	size_t page;

	for (round = 0; round < WARM_ROUNDS; round++) {
		for (page = 0; page < npages; page++)
			sum += *target_address(base, page);
	}

	global_sink ^= sum;
}

static struct sample measure(struct perf_group *perf,
			     unsigned char *base, size_t npages)
{
	struct perf_counts counts;
	struct sample sample;
	uint64_t sum = 0;
	uint64_t i;
	size_t page = 0;

	if (perf_group_start(perf))
		die("perf_group_start");

	/*
	 * The accesses themselves are volatile.  The compiler barrier keeps
	 * surrounding compiler memory operations out of the intended region.
	 */
	asm volatile ("":::"memory");

	for (i = 0; i < ACCESSES; i++) {
		sum += *target_address(base, page);

		if (++page == npages)
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

static void get_faults(long *minor, long *major)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage))
		die("getrusage");

	*minor = usage.ru_minflt;
	*major = usage.ru_majflt;
}

int main(void)
{
	static const size_t page_counts[] = {
		4, 8, 16, 24,
		28, 30, 31, 32,
		33, 34, 36, 40,
		48, 64, 96, 128,
		192, 256,
	};

	struct perf_group perf;
	unsigned char *base;
	long page_size;
	size_t page, test;
	unsigned int repeat;

	setvbuf(stdout, NULL, _IONBF, 0);

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size != 4096) {
		fprintf(stderr, "expected 4096-byte pages, got %ld\n",
			page_size);
		return EXIT_FAILURE;
	}

	if (perf_group_open(&perf)) {
		fprintf(stderr, "failed to open perf events\n");
		return EXIT_FAILURE;
	}

	base = map_aligned_region();

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping              : %p\n", base);
	printf("mapping size         : %lu KiB\n",
	       (unsigned long)(KEEP_SIZE / 1024));
	printf("2MiB aligned         : %s\n",
	       ((uintptr_t) base & (ALIGN_2M - 1)) ? "NO" : "yes");
	printf("max pages            : %d\n", MAX_PAGES);
	printf("data footprint       : %d KiB\n", MAX_PAGES * 64 / 1024);
	printf("max lines/L1 set     : %d\n", MAX_PAGES / 64);
	printf("timed accesses       : %d\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	/*
	 * Allocate every anonymous page before timing anything.  Timed
	 * regions should therefore contain no demand faults.
	 */
	for (page = 0; page < MAX_PAGES; page++)
		*target_address(base, page) = 0x100000000ULL + page;

	/*
	 * Warm the complete 16 KiB data-line footprint once.
	 */
	warm_working_set(base, MAX_PAGES);

	printf("\n"
	       " Npages | median cyc/op | best cyc/op | median insn/op |"
	       " minflt | majflt\n"
	       "--------+---------------+-------------+----------------+"
	       "--------+-------\n");

	for (test = 0; test < ARRAY_SIZE(page_counts); test++) {
		uint64_t cycles[REPEATS];
		uint64_t instructions[REPEATS];
		uint64_t cycles_sorted[REPEATS];
		uint64_t instructions_sorted[REPEATS];
		uint64_t median_cycles, best_cycles, median_instructions;
		double median_cpa, best_cpa, median_ipa;
		long min_before, maj_before;
		long min_after, maj_after;
		size_t npages = page_counts[test];

		get_faults(&min_before, &maj_before);

		for (repeat = 0; repeat < REPEATS; repeat++) {
			struct sample sample;

			/*
			 * Put this particular working set into steady state
			 * immediately before its timed run.
			 */
			warm_working_set(base, npages);
			sample = measure(&perf, base, npages);

			cycles[repeat] = sample.cycles;
			instructions[repeat] = sample.instructions;
		}

		get_faults(&min_after, &maj_after);

		for (repeat = 0; repeat < REPEATS; repeat++) {
			cycles_sorted[repeat] = cycles[repeat];
			instructions_sorted[repeat] = instructions[repeat];
		}

		qsort(cycles_sorted, REPEATS, sizeof(cycles_sorted[0]),
		      cmp_u64);
		qsort(instructions_sorted, REPEATS,
		      sizeof(instructions_sorted[0]), cmp_u64);

		median_cycles = cycles_sorted[REPEATS / 2];
		best_cycles = cycles_sorted[0];
		median_instructions = instructions_sorted[REPEATS / 2];

		median_cpa = (double)median_cycles / ACCESSES;
		best_cpa = (double)best_cycles / ACCESSES;
		median_ipa = (double)median_instructions / ACCESSES;

		printf("%7zu | %13.2f | %11.2f | %14.2f |"
		       " %6ld | %6ld\n",
		       npages, median_cpa, best_cpa, median_ipa,
		       min_after - min_before, maj_after - maj_before);
	}

	printf("\nglobal sink          : 0x%016" PRIx64 "\n", global_sink);

	if (munmap(base, KEEP_SIZE))
		die("munmap");

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
