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

#define TARGETS			40
#define ACCESSES		65536
#define REPEATS			5
#define WARM_ROUNDS		64

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT		26
#endif

#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB		(21 << MAP_HUGE_SHIFT)
#endif

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
};

struct smaps_info {
	long kernel_page_kb;
	long mmu_page_kb;
	long rss_kb;
	long anonymous_kb;
	long anon_huge_kb;
	long private_hugetlb_kb;
	long shared_hugetlb_kb;
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

static unsigned char *map_base_2m(void)
{
	const size_t reserve_size = 2 * HUGEPAGE_SIZE;
	unsigned char *reservation;
	uintptr_t raw, aligned;
	size_t prefix, suffix;

	reservation = mmap(NULL, reserve_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (reservation == MAP_FAILED)
		die("mmap base pages");

	raw = (uintptr_t) reservation;
	aligned = (raw + HUGEPAGE_SIZE - 1) & ~(uintptr_t) (HUGEPAGE_SIZE - 1);

	prefix = aligned - raw;
	suffix = raw + reserve_size - (aligned + HUGEPAGE_SIZE);

	if (prefix && munmap(reservation, prefix))
		die("munmap base prefix");

	if (suffix && munmap((void *)(aligned + HUGEPAGE_SIZE), suffix))
		die("munmap base suffix");

	return (unsigned char *)aligned;
}

static unsigned char *map_huge_2m(void)
{
	unsigned char *base;

	base = mmap(NULL, HUGEPAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS |
		    MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
	if (base == MAP_FAILED)
		die("mmap MAP_HUGETLB");

	if ((uintptr_t) base & (HUGEPAGE_SIZE - 1)) {
		fprintf(stderr, "HugeTLB mapping is not 2MiB aligned\n");
		exit(EXIT_FAILURE);
	}

	return base;
}

static void build_targets(unsigned char *base, volatile uint64_t ** targets)
{
	size_t i;

	for (i = 0; i < TARGETS; i++) {
		size_t data_offset;

		/*
		 * Bits [11:6] select the L1D set on this Rocket.
		 * Give the 40 data lines distinct set indices.
		 */
		data_offset = (i & 63UL) * CACHE_LINE;

		targets[i] = (volatile uint64_t *)
		    (base + i * PAGE_SIZE + data_offset);

		/*
		 * Fault/allocate everything before the timed region.
		 */
		*targets[i] = 0x100000000ULL + i;
	}
}

static void warm_targets(volatile uint64_t * const *targets)
{
	uint64_t sum = 0;
	unsigned int round;
	size_t target;

	for (round = 0; round < WARM_ROUNDS; round++) {
		for (target = 0; target < TARGETS; target++)
			sum += *targets[target];
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
	size_t target = 0;

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	for (i = 0; i < ACCESSES; i++) {
		sum += *targets[target];

		if (++target == TARGETS)
			target = 0;
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

static struct result run_test(struct perf_group *perf,
			      volatile uint64_t * const *targets)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	long min_before, maj_before;
	long min_after, maj_after;
	unsigned int repeat;

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

	return result;
}

static void init_smaps_info(struct smaps_info *info)
{
	memset(info, 0, sizeof(*info));

	info->kernel_page_kb = -1;
	info->mmu_page_kb = -1;
	info->rss_kb = -1;
	info->anonymous_kb = -1;
	info->anon_huge_kb = -1;
	info->private_hugetlb_kb = -1;
	info->shared_hugetlb_kb = -1;
}

static void read_smaps_info(void *address, struct smaps_info *info)
{
	FILE *fp;
	char line[512];
	uintptr_t target = (uintptr_t) address;
	int found = 0;

	init_smaps_info(info);

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
		sscanf(line, "Rss: %ld kB", &info->rss_kb);
		sscanf(line, "Anonymous: %ld kB", &info->anonymous_kb);
		sscanf(line, "AnonHugePages: %ld kB", &info->anon_huge_kb);
		sscanf(line, "Private_Hugetlb: %ld kB",
		       &info->private_hugetlb_kb);
		sscanf(line, "Shared_Hugetlb: %ld kB",
		       &info->shared_hugetlb_kb);
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "mapping not found in smaps: %p\n", address);
		exit(EXIT_FAILURE);
	}
}

static void print_mapping_info(const char *name, unsigned char *base,
			       const struct smaps_info *info)
{
	printf("%-12s address         : %p\n", name, base);
	printf("%-12s 2MiB aligned    : %s\n", name,
	       ((uintptr_t) base & (HUGEPAGE_SIZE - 1)) ? "NO" : "yes");
	printf("%-12s KernelPageSize  : %ld kB\n", name, info->kernel_page_kb);
	printf("%-12s MMUPageSize     : %ld kB\n", name, info->mmu_page_kb);
	printf("%-12s Rss             : %ld kB\n", name, info->rss_kb);
	printf("%-12s Anonymous       : %ld kB\n", name, info->anonymous_kb);
	printf("%-12s AnonHugePages   : %ld kB\n", name, info->anon_huge_kb);
	printf("%-12s Private_Hugetlb : %ld kB\n",
	       name, info->private_hugetlb_kb);
}

int main(void)
{
	volatile uint64_t *base_targets[TARGETS];
	volatile uint64_t *huge_targets[TARGETS];
	struct smaps_info base_smaps;
	struct smaps_info huge_smaps;
	struct result base_result;
	struct result huge_result;
	struct perf_group perf;
	unsigned char *base;
	unsigned char *huge;

	setvbuf(stdout, NULL, _IONBF, 0);

	if (sysconf(_SC_PAGESIZE) != PAGE_SIZE) {
		fprintf(stderr, "expected %lu-byte base pages\n", PAGE_SIZE);
		return EXIT_FAILURE;
	}

	if (perf_group_open(&perf)) {
		fprintf(stderr, "failed to open perf events\n");
		return EXIT_FAILURE;
	}

	base = map_base_2m();
	huge = map_huge_2m();

	build_targets(base, base_targets);
	build_targets(huge, huge_targets);

	/*
	 * Warm before reading smaps so resident accounting reflects
	 * the mappings actually used by the benchmark.
	 */
	warm_targets(base_targets);
	warm_targets(huge_targets);

	read_smaps_info(base, &base_smaps);
	read_smaps_info(huge, &huge_smaps);

	printf("PID                  : %ld\n", (long)getpid());
	printf("targets/mapping      : %d\n", TARGETS);
	printf("target spacing       : 4 KiB\n");
	printf("data footprint       : %.1f KiB\n",
	       (double)(TARGETS * CACHE_LINE) / 1024.0);
	printf("DTLB entries         : 32\n");
	printf("HugeTLB size         : 2 MiB\n");
	printf("timed accesses       : %d\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n\n");

	print_mapping_info("base-4K", base, &base_smaps);
	printf("\n");
	print_mapping_info("huge-2M", huge, &huge_smaps);

	base_result = run_test(&perf, base_targets);
	huge_result = run_test(&perf, huge_targets);

	printf("\n"
	       " Mapping | logical targets | translations | median cyc/op |"
	       " best cyc/op | median insn/op | minflt | majflt\n"
	       "---------+-----------------+--------------+---------------+"
	       "-------------+----------------+--------+-------\n");

	printf(" base-4K | %15d | %12d | %13.2f | %11.2f |"
	       " %14.2f | %6ld | %6ld\n",
	       TARGETS, TARGETS,
	       base_result.median_cycles,
	       base_result.best_cycles,
	       base_result.median_instructions,
	       base_result.minor_faults, base_result.major_faults);

	printf(" huge-2M | %15d | %12d | %13.2f | %11.2f |"
	       " %14.2f | %6ld | %6ld\n",
	       TARGETS, 1,
	       huge_result.median_cycles,
	       huge_result.best_cycles,
	       huge_result.median_instructions,
	       huge_result.minor_faults, huge_result.major_faults);

	printf("\nglobal sink          : 0x%016" PRIx64 "\n", global_sink);

	if (munmap(base, HUGEPAGE_SIZE))
		die("munmap base");

	if (munmap(huge, HUGEPAGE_SIZE))
		die("munmap huge");

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
