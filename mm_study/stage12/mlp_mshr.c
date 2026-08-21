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

#define STREAM_SIZE		(512UL * 1024)
#define STREAM_LINES		(STREAM_SIZE / CACHE_LINE)
#define MAX_STREAMS		8

#define MAPPING_SIZE		(MAX_STREAMS * STREAM_SIZE)

/*
 * 215040 is divisible by every integer from 1 through 8.
 *
 * Therefore every test executes exactly the same total number of
 * timed loads while changing only how many independent streams are
 * available.
 */
#define TOTAL_LOADS		215040UL
#define WARM_ROUNDS		(STREAM_LINES * 2)
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
	double median_cycles_round;
	double median_cycles_load;
	double best_cycles_load;
	double median_instructions_load;
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

static unsigned char *map_huge_region(void)
{
	unsigned char *base;

	base = mmap(NULL, MAPPING_SIZE,
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
 * Each stream is one independent random cyclic list.
 *
 * There is exactly one pointer per 64-byte cache line, so successive
 * accesses in a stream have no useful spatial locality.
 */
static uintptr_t build_stream(unsigned char *base, size_t stream)
{
	size_t *order;
	unsigned char *stream_base;
	uint64_t state;
	uintptr_t start;
	size_t i;

	stream_base = base + stream * STREAM_SIZE;

	order = malloc(STREAM_LINES * sizeof(*order));
	if (!order)
		die("malloc order");

	for (i = 0; i < STREAM_LINES; i++)
		order[i] = i;

	state = 0x9e3779b97f4a7c15ULL ^ ((uint64_t) stream << 32) ^ STREAM_SIZE;

	for (i = STREAM_LINES - 1; i > 0; i--) {
		size_t j;
		size_t tmp;

		j = prng_next(&state) % (i + 1);

		tmp = order[i];
		order[i] = order[j];
		order[j] = tmp;
	}

	for (i = 0; i < STREAM_LINES; i++) {
		size_t current = order[i];
		size_t next = order[(i + 1) % STREAM_LINES];
		volatile uintptr_t *slot;

		slot = (volatile uintptr_t *)
		    (stream_base + current * CACHE_LINE);

		*slot = (uintptr_t)
		    (stream_base + next * CACHE_LINE);
	}

	start = (uintptr_t)
	    (stream_base + order[0] * CACHE_LINE);

	free(order);

	return start;
}

#define NEXT_POINTER(p) \
	((uintptr_t)*(volatile uintptr_t *)(p))

/*
 * One iteration is called a "round".
 *
 * Loads belonging to different streams have no data dependency on
 * each other. Loads belonging to the same stream retain the pointer
 * dependency from one round to the next.
 */
static uintptr_t chase_streams(const uintptr_t * starts,
			       size_t nstreams, size_t rounds)
{
	uintptr_t p0 = starts[0];
	uintptr_t p1 = nstreams > 1 ? starts[1] : 0;
	uintptr_t p2 = nstreams > 2 ? starts[2] : 0;
	uintptr_t p3 = nstreams > 3 ? starts[3] : 0;
	uintptr_t p4 = nstreams > 4 ? starts[4] : 0;
	uintptr_t p5 = nstreams > 5 ? starts[5] : 0;
	uintptr_t p6 = nstreams > 6 ? starts[6] : 0;
	uintptr_t p7 = nstreams > 7 ? starts[7] : 0;
	size_t i;

	switch (nstreams) {
	case 1:
		for (i = 0; i < rounds; i++)
			p0 = NEXT_POINTER(p0);
		break;

	case 2:
		for (i = 0; i < rounds; i++) {
			p0 = NEXT_POINTER(p0);
			p1 = NEXT_POINTER(p1);
		}
		break;

	case 3:
		for (i = 0; i < rounds; i++) {
			p0 = NEXT_POINTER(p0);
			p1 = NEXT_POINTER(p1);
			p2 = NEXT_POINTER(p2);
		}
		break;

	case 4:
		for (i = 0; i < rounds; i++) {
			p0 = NEXT_POINTER(p0);
			p1 = NEXT_POINTER(p1);
			p2 = NEXT_POINTER(p2);
			p3 = NEXT_POINTER(p3);
		}
		break;

	case 5:
		for (i = 0; i < rounds; i++) {
			p0 = NEXT_POINTER(p0);
			p1 = NEXT_POINTER(p1);
			p2 = NEXT_POINTER(p2);
			p3 = NEXT_POINTER(p3);
			p4 = NEXT_POINTER(p4);
		}
		break;

	case 6:
		for (i = 0; i < rounds; i++) {
			p0 = NEXT_POINTER(p0);
			p1 = NEXT_POINTER(p1);
			p2 = NEXT_POINTER(p2);
			p3 = NEXT_POINTER(p3);
			p4 = NEXT_POINTER(p4);
			p5 = NEXT_POINTER(p5);
		}
		break;

	case 7:
		for (i = 0; i < rounds; i++) {
			p0 = NEXT_POINTER(p0);
			p1 = NEXT_POINTER(p1);
			p2 = NEXT_POINTER(p2);
			p3 = NEXT_POINTER(p3);
			p4 = NEXT_POINTER(p4);
			p5 = NEXT_POINTER(p5);
			p6 = NEXT_POINTER(p6);
		}
		break;

	case 8:
		for (i = 0; i < rounds; i++) {
			p0 = NEXT_POINTER(p0);
			p1 = NEXT_POINTER(p1);
			p2 = NEXT_POINTER(p2);
			p3 = NEXT_POINTER(p3);
			p4 = NEXT_POINTER(p4);
			p5 = NEXT_POINTER(p5);
			p6 = NEXT_POINTER(p6);
			p7 = NEXT_POINTER(p7);
		}
		break;

	default:
		fprintf(stderr, "invalid stream count: %zu\n", nstreams);
		exit(EXIT_FAILURE);
	}

	return p0 ^ p1 ^ p2 ^ p3 ^ p4 ^ p5 ^ p6 ^ p7;
}

static void warm_streams(const uintptr_t * starts, size_t nstreams)
{
	global_sink ^= chase_streams(starts, nstreams, WARM_ROUNDS);
}

static struct sample measure(struct perf_group *perf,
			     const uintptr_t * starts, size_t nstreams)
{
	struct perf_counts counts;
	struct sample sample;
	size_t rounds;

	rounds = TOTAL_LOADS / nstreams;

	if (rounds * nstreams != TOTAL_LOADS) {
		fprintf(stderr, "TOTAL_LOADS not divisible by %zu\n", nstreams);
		exit(EXIT_FAILURE);
	}

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	global_sink ^= chase_streams(starts, nstreams, rounds);

	asm volatile ("":::"memory");

	if (perf_group_stop(perf, &counts))
		die("perf_group_stop");

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
			      const uintptr_t * starts, size_t nstreams)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	size_t rounds;
	long min_before, maj_before;
	long min_after, maj_after;
	unsigned int repeat;

	rounds = TOTAL_LOADS / nstreams;

	warm_streams(starts, nstreams);

	get_faults(&min_before, &maj_before);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		struct sample sample;

		warm_streams(starts, nstreams);
		sample = measure(perf, starts, nstreams);

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

	result.median_cycles_round =
	    (double)cycles_sorted[REPEATS / 2] / rounds;

	result.median_cycles_load =
	    (double)cycles_sorted[REPEATS / 2] / TOTAL_LOADS;

	result.best_cycles_load = (double)cycles_sorted[0] / TOTAL_LOADS;

	result.median_instructions_load =
	    (double)instructions_sorted[REPEATS / 2] / TOTAL_LOADS;

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
	static const size_t stream_counts[] = {
		1, 2, 3, 4, 5, 6, 7, 8,
	};

	struct smaps_info smaps;
	struct perf_group perf;
	uintptr_t starts[MAX_STREAMS];
	unsigned char *base;
	double baseline_cycles = 0.0;
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

	base = map_huge_region();

	for (i = 0; i < MAX_STREAMS; i++)
		starts[i] = build_stream(base, i);

	/*
	 * All four MiB have now been written while building the chains,
	 * so both HugeTLB pages are instantiated before timing.
	 */
	read_smaps_info(base, &smaps);

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping              : %p\n", base);
	printf("mapping size         : %lu MiB\n",
	       MAPPING_SIZE / (1024 * 1024));
	printf("KernelPageSize       : %ld kB\n", smaps.kernel_page_kb);
	printf("MMUPageSize          : %ld kB\n", smaps.mmu_page_kb);
	printf("Private_Hugetlb      : %ld kB\n", smaps.private_hugetlb_kb);
	printf("HugeTLB translations : 2\n");
	printf("superpage TLB cap    : ~4 from stage 9.2\n");
	printf("stream working set   : %lu KiB\n", STREAM_SIZE / 1024);
	printf("lines/stream         : %lu\n", STREAM_LINES);
	printf("L2 capacity          : 128 KiB\n");
	printf("L2 MSHRs             : 7\n");
	printf("max streams          : %d\n", MAX_STREAMS);
	printf("timed total loads    : %lu/test\n", TOTAL_LOADS);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Streams | loads/round | median cyc/round |"
	       " median cyc/load | relative throughput |"
	       " best cyc/load | median insn/load | minflt | majflt\n"
	       "---------+-------------+------------------+"
	       "-----------------+---------------------+"
	       "---------------+------------------+--------+-------\n");

	for (i = 0; i < ARRAY_SIZE(stream_counts); i++) {
		struct result result;
		double throughput;
		size_t nstreams = stream_counts[i];

		result = run_test(&perf, starts, nstreams);

		if (nstreams == 1)
			baseline_cycles = result.median_cycles_load;

		throughput = baseline_cycles / result.median_cycles_load;

		printf("%8zu | %11zu | %16.2f |"
		       " %15.2f | %19.2fx |"
		       " %13.2f | %16.2f | %6ld | %6ld\n",
		       nstreams,
		       nstreams,
		       result.median_cycles_round,
		       result.median_cycles_load,
		       throughput,
		       result.best_cycles_load,
		       result.median_instructions_load,
		       result.minor_faults, result.major_faults);
	}

	printf("\nglobal sink          : 0x%016" PRIxPTR "\n", global_sink);

	if (munmap(base, MAPPING_SIZE))
		die("munmap HugeTLB");

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
