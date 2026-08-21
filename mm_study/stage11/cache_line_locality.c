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

#define NODES			(WORKING_SET / CACHE_LINE)
#define ACCESSES		65536UL
#define WARM_ACCESSES		NODES
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
	double median_cycles_node;
	double best_cycles_node;
	double median_cycles_load;
	double median_instructions_node;
	long minor_faults;
	long major_faults;
};

struct smaps_info {
	long kernel_page_kb;
	long mmu_page_kb;
	long private_hugetlb_kb;
};

typedef uintptr_t(*chase_fn_t) (uintptr_t start, size_t accesses,
				uint64_t * sum_out);

struct test_case {
	const char *name;
	size_t loads_per_line;
	chase_fn_t fn;
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

static uintptr_t build_random_cycle(unsigned char *base)
{
	size_t *order;
	uint64_t state;
	size_t i;

	order = malloc(NODES * sizeof(*order));
	if (!order)
		die("malloc order");

	for (i = 0; i < NODES; i++)
		order[i] = i;

	state = 0x9e3779b97f4a7c15ULL;

	for (i = NODES - 1; i > 0; i--) {
		size_t j;
		size_t tmp;

		j = prng_next(&state) % (i + 1);

		tmp = order[i];
		order[i] = order[j];
		order[j] = tmp;
	}

	for (i = 0; i < NODES; i++) {
		size_t current = order[i];
		size_t next = order[(i + 1) % NODES];
		volatile uint64_t *q;
		size_t word;

		q = (volatile uint64_t *)
		    (base + current * CACHE_LINE);

		q[0] = (uintptr_t) (base + next * CACHE_LINE);

		for (word = 1; word < 8; word++)
			q[word] = 0x100000000ULL + current * 8 + word;
	}

	{
		uintptr_t start;

		start = (uintptr_t) (base + order[0] * CACHE_LINE);
		free(order);

		return start;
	}
}

static uintptr_t chase_1(uintptr_t start, size_t accesses, uint64_t * sum_out)
{
	uintptr_t p = start;
	size_t i;

	for (i = 0; i < accesses; i++) {
		volatile uint64_t *q = (volatile uint64_t *)p;

		p = (uintptr_t) q[0];
	}

	*sum_out = 0;
	return p;
}

static uintptr_t chase_2(uintptr_t start, size_t accesses, uint64_t * sum_out)
{
	uintptr_t p = start;
	uint64_t sum = 0;
	size_t i;

	for (i = 0; i < accesses; i++) {
		volatile uint64_t *q = (volatile uint64_t *)p;
		uintptr_t next;

		next = (uintptr_t) q[0];
		sum += q[1];

		p = next;
	}

	*sum_out = sum;
	return p;
}

static uintptr_t chase_4(uintptr_t start, size_t accesses, uint64_t * sum_out)
{
	uintptr_t p = start;
	uint64_t sum = 0;
	size_t i;

	for (i = 0; i < accesses; i++) {
		volatile uint64_t *q = (volatile uint64_t *)p;
		uintptr_t next;

		next = (uintptr_t) q[0];

		sum += q[1];
		sum += q[2];
		sum += q[3];

		p = next;
	}

	*sum_out = sum;
	return p;
}

static uintptr_t chase_8(uintptr_t start, size_t accesses, uint64_t * sum_out)
{
	uintptr_t p = start;
	uint64_t sum = 0;
	size_t i;

	for (i = 0; i < accesses; i++) {
		volatile uint64_t *q = (volatile uint64_t *)p;
		uintptr_t next;

		next = (uintptr_t) q[0];

		sum += q[1];
		sum += q[2];
		sum += q[3];
		sum += q[4];
		sum += q[5];
		sum += q[6];
		sum += q[7];

		p = next;
	}

	*sum_out = sum;
	return p;
}

static void warm_test(uintptr_t start, const struct test_case *test)
{
	uint64_t sum;
	uintptr_t p;

	p = test->fn(start, WARM_ACCESSES, &sum);

	global_sink ^= p;
	global_sink ^= (uintptr_t) sum;
}

static struct sample measure(struct perf_group *perf, uintptr_t start,
			     const struct test_case *test)
{
	struct perf_counts counts;
	struct sample sample;
	uint64_t sum;
	uintptr_t p;

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	p = test->fn(start, ACCESSES, &sum);

	asm volatile ("":::"memory");

	if (perf_group_stop(perf, &counts))
		die("perf_group_stop");

	global_sink ^= p;
	global_sink ^= (uintptr_t) sum;

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

static struct result run_test(struct perf_group *perf, uintptr_t start,
			      const struct test_case *test)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	long min_before, maj_before;
	long min_after, maj_after;
	unsigned int repeat;

	warm_test(start, test);

	get_faults(&min_before, &maj_before);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		struct sample sample;

		warm_test(start, test);
		sample = measure(perf, start, test);

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

	result.median_cycles_node =
	    (double)cycles_sorted[REPEATS / 2] / ACCESSES;

	result.best_cycles_node = (double)cycles_sorted[0] / ACCESSES;

	result.median_cycles_load =
	    result.median_cycles_node / test->loads_per_line;

	result.median_instructions_node =
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
	static const struct test_case tests[] = {
		{
		 .name = "1 word",
		 .loads_per_line = 1,
		 .fn = chase_1,
		  },
		{
		 .name = "2 words",
		 .loads_per_line = 2,
		 .fn = chase_2,
		  },
		{
		 .name = "4 words",
		 .loads_per_line = 4,
		 .fn = chase_4,
		  },
		{
		 .name = "8 words",
		 .loads_per_line = 8,
		 .fn = chase_8,
		  },
	};

	struct smaps_info smaps;
	struct perf_group perf;
	unsigned char *base;
	uintptr_t start;
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
	 * Instantiate the HugeTLB page before benchmarking.
	 */
	memset(base, 0, HUGEPAGE_SIZE);

	start = build_random_cycle(base);

	read_smaps_info(base, &smaps);

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping              : %p\n", base);
	printf("KernelPageSize       : %ld kB\n", smaps.kernel_page_kb);
	printf("MMUPageSize          : %ld kB\n", smaps.mmu_page_kb);
	printf("Private_Hugetlb      : %ld kB\n", smaps.private_hugetlb_kb);
	printf("cache line           : 64 B\n");
	printf("working set          : %lu KiB\n", WORKING_SET / 1024);
	printf("cache lines          : %lu\n", NODES);
	printf("translation WS       : ~1 x 2MiB translation\n");
	printf("access pattern       : random dependent line chase\n");
	printf("timed nodes          : %lu\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Use/line | useful B | median cyc/node | best cyc/node |"
	       " median cyc/load | median insn/node | minflt | majflt\n"
	       "----------+----------+-----------------+---------------+"
	       "-----------------+------------------+--------+-------\n");

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct result result;

		result = run_test(&perf, start, &tests[i]);

		printf("%9zu | %8zu | %15.2f | %13.2f |"
		       " %15.2f | %16.2f | %6ld | %6ld\n",
		       tests[i].loads_per_line,
		       tests[i].loads_per_line * sizeof(uint64_t),
		       result.median_cycles_node,
		       result.best_cycles_node,
		       result.median_cycles_load,
		       result.median_instructions_node,
		       result.minor_faults, result.major_faults);
	}

	printf("\nglobal sink          : 0x%016" PRIxPTR "\n", global_sink);

	if (munmap(base, HUGEPAGE_SIZE))
		die("munmap HugeTLB");

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
