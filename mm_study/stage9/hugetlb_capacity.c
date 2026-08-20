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
#define ALIGN_1G		(1UL * 1024 * 1024 * 1024)
#define CACHE_LINE		64UL

#define MAX_TARGETS		40
#define HUGE_SPAN		(MAX_TARGETS * HUGEPAGE_SIZE)

#define ACCESSES		65536
#define REPEATS			5
#define WARM_ROUNDS		64

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

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

struct huge_region {
	unsigned char *reservation;
	size_t reserve_size;
	unsigned char *base;
	size_t prefix;
	size_t suffix;
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

/*
 * Reserve enough virtual address space to find a 1GiB-aligned window,
 * then replace exactly HUGE_SPAN bytes at that address with a 2MiB
 * HugeTLB mapping.
 *
 * Since HUGE_SPAN = 80MiB < 1GiB, all huge pages remain under the same
 * VPN[2] and therefore share one Sv39 L2 non-leaf PTE.
 */
static struct huge_region map_huge_region(void)
{
	struct huge_region region;
	uintptr_t raw, aligned;
	void *ret;

	memset(&region, 0, sizeof(region));

	region.reserve_size = HUGE_SPAN + ALIGN_1G;

	region.reservation = mmap(NULL, region.reserve_size, PROT_NONE,
				  MAP_PRIVATE | MAP_ANONYMOUS |
				  MAP_NORESERVE, -1, 0);
	if (region.reservation == MAP_FAILED)
		die("mmap reservation");

	raw = (uintptr_t) region.reservation;
	aligned = (raw + ALIGN_1G - 1) & ~(uintptr_t) (ALIGN_1G - 1);

	if (aligned + HUGE_SPAN > raw + region.reserve_size) {
		fprintf(stderr, "1GiB-aligned reservation too small\n");
		exit(EXIT_FAILURE);
	}

	region.base = (unsigned char *)aligned;
	region.prefix = aligned - raw;
	region.suffix = raw + region.reserve_size - (aligned + HUGE_SPAN);

	ret = mmap(region.base, HUGE_SPAN,
		   PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS |
		   MAP_FIXED | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
	if (ret == MAP_FAILED)
		die("mmap HugeTLB region");

	if (ret != region.base) {
		fprintf(stderr, "MAP_FIXED returned unexpected address\n");
		exit(EXIT_FAILURE);
	}

	return region;
}

static void unmap_huge_region(struct huge_region *region)
{
	if (munmap(region->base, HUGE_SPAN))
		die("munmap HugeTLB region");

	if (region->prefix && munmap(region->reservation, region->prefix))
		die("munmap reservation prefix");

	if (region->suffix && munmap(region->base + HUGE_SPAN, region->suffix))
		die("munmap reservation suffix");
}

static void build_targets(unsigned char *base,
			  volatile uint64_t ** packed,
			  volatile uint64_t ** spread)
{
	size_t i;

	for (i = 0; i < MAX_TARGETS; i++) {
		size_t data_offset = (i & 63UL) * CACHE_LINE;

		/*
		 * PACKED:
		 *
		 * All targets live inside huge page 0. They occupy different
		 * 4KiB offsets but still share one 2MiB translation.
		 */
		packed[i] = (volatile uint64_t *)
		    (base + i * PAGE_SIZE + data_offset);

		/*
		 * SPREAD:
		 *
		 * One target per 2MiB huge page, giving one distinct
		 * superpage translation per target.
		 */
		spread[i] = (volatile uint64_t *)
		    (base + i * HUGEPAGE_SIZE + data_offset);

		/*
		 * Install/allocate all pages before timing.
		 */
		*packed[i] = 0x100000000ULL + i;
		*spread[i] = 0x200000000ULL + i;
	}
}

static void warm_targets(volatile uint64_t * const *targets, size_t ntargets)
{
	uint64_t sum = 0;
	unsigned int round;
	size_t i;

	for (round = 0; round < WARM_ROUNDS; round++) {
		for (i = 0; i < ntargets; i++)
			sum += *targets[i];
	}

	global_sink ^= sum;
}

static struct sample measure(struct perf_group *perf,
			     volatile uint64_t * const *targets,
			     size_t ntargets)
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

		if (++target == ntargets)
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
			      volatile uint64_t * const *targets,
			      size_t ntargets)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	long min_before, maj_before;
	long min_after, maj_after;
	unsigned int repeat;

	warm_targets(targets, ntargets);

	get_faults(&min_before, &maj_before);

	for (repeat = 0; repeat < REPEATS; repeat++) {
		struct sample sample;

		warm_targets(targets, ntargets);
		sample = measure(perf, targets, ntargets);

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
	static const size_t target_counts[] = {
		1, 2, 3, 4, 5, 6, 7, 8,
		10, 12, 16, 20, 24,
		28, 30, 31, 32, 33, 34, 36, 40,
	};

	volatile uint64_t *packed[MAX_TARGETS];
	volatile uint64_t *spread[MAX_TARGETS];
	struct huge_region region;
	struct smaps_info smaps;
	struct perf_group perf;
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

	region = map_huge_region();

	if ((uintptr_t) region.base & (ALIGN_1G - 1)) {
		fprintf(stderr, "HugeTLB region is not 1GiB aligned\n");
		return EXIT_FAILURE;
	}

	build_targets(region.base, packed, spread);

	/*
	 * Make sure every HugeTLB page has been instantiated before
	 * entering any measured region.
	 */
	warm_targets(spread, MAX_TARGETS);

	read_smaps_info(region.base, &smaps);

	printf("PID                  : %ld\n", (long)getpid());
	printf("HugeTLB mapping      : %p\n", region.base);
	printf("mapping span         : %lu MiB\n", HUGE_SPAN / (1024 * 1024));
	printf("1GiB aligned         : yes\n");
	printf("same VPN[2] window   : yes\n");
	printf("KernelPageSize       : %ld kB\n", smaps.kernel_page_kb);
	printf("MMUPageSize          : %ld kB\n", smaps.mmu_page_kb);
	printf("Private_Hugetlb      : %ld kB\n", smaps.private_hugetlb_kb);
	printf("max translations     : %d\n", MAX_TARGETS);
	printf("max data footprint   : %.1f KiB/test\n",
	       (double)(MAX_TARGETS * CACHE_LINE) / 1024.0);
	printf("timed accesses       : %d\n", ACCESSES);
	printf("repeats/test         : %d\n", REPEATS);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Nhuge | packed cyc/op | spread cyc/op | spread-packed |"
	       " spread best | packed insn/op | spread insn/op |"
	       " minflt | majflt\n"
	       "-------+---------------+---------------+---------------+"
	       "-------------+----------------+----------------+"
	       "--------+-------\n");

	for (i = 0; i < ARRAY_SIZE(target_counts); i++) {
		struct result packed_result;
		struct result spread_result;
		size_t n = target_counts[i];

		/*
		 * Both cases use exactly N data lines and the same loop.
		 *
		 * packed: one 2MiB translation
		 * spread: N distinct 2MiB translations
		 */
		packed_result = run_test(&perf, packed, n);
		spread_result = run_test(&perf, spread, n);

		printf("%6zu | %13.2f | %13.2f | %13.2f |"
		       " %11.2f | %14.2f | %14.2f |"
		       " %6ld | %6ld\n",
		       n,
		       packed_result.median_cycles,
		       spread_result.median_cycles,
		       spread_result.median_cycles -
		       packed_result.median_cycles,
		       spread_result.best_cycles,
		       packed_result.median_instructions,
		       spread_result.median_instructions,
		       packed_result.minor_faults +
		       spread_result.minor_faults,
		       packed_result.major_faults + spread_result.major_faults);
	}

	printf("\nglobal sink          : 0x%016" PRIx64 "\n", global_sink);

	unmap_huge_region(&region);
	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
