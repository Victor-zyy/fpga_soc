#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "perf_counter.h"

#define ONE_GIB (1UL << 30)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_SWAPPED        (1ULL << 62)
#define PM_PRESENT        (1ULL << 63)

static volatile uint64_t sink;

struct usage_snapshot {
	long minflt;
	long majflt;
};

struct perf_result {
	uint64_t cycles;
	uint64_t instructions;

	long minflt;
	long majflt;

	int ret;
	int error;
};

struct pagemap_entry {
	uint64_t raw;
	uint64_t pfn;

	int present;
	int swapped;
	int exclusive;
};

struct pagemap_summary {
	size_t pages;

	size_t present;
	size_t swapped;
	size_t exclusive;

	size_t nonzero_pfns;
	size_t unique_pfns;

	uint64_t sample_raw[3];
	uint64_t sample_pfn[3];
	int sample_present[3];
	int sample_exclusive[3];
};

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static struct usage_snapshot usage_now(void)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage) != 0)
		die("getrusage");

	struct usage_snapshot result = {
		.minflt = usage.ru_minflt,
		.majflt = usage.ru_majflt,
	};

	return result;
}

static unsigned long read_vm_pte(void)
{
	FILE *fp = fopen("/proc/self/status", "r");

	if (fp == NULL)
		die("fopen status");

	char line[512];
	unsigned long value = 0;
	int found = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &value) == 1) {
			found = 1;
			break;
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "VmPTE not found\n");
		exit(EXIT_FAILURE);
	}

	return value;
}

static void *map_aligned(size_t length, size_t alignment)
{
	if (length > SIZE_MAX - alignment) {
		errno = EOVERFLOW;
		return MAP_FAILED;
	}

	size_t reserve_length = length + alignment;

	/*
	 * 这里只是暂时保留虚拟地址。
	 * PROT_NONE匿名reservation不会消耗1 GiB物理RAM。
	 */
	void *reservation = mmap(NULL,
				 reserve_length,
				 PROT_NONE,
				 MAP_PRIVATE | MAP_ANONYMOUS,
				 -1,
				 0);

	if (reservation == MAP_FAILED)
		return MAP_FAILED;

	uintptr_t raw = (uintptr_t) reservation;

	uintptr_t aligned =
	    (raw + alignment - 1) & ~((uintptr_t) alignment - 1);

	if (munmap(reservation, reserve_length) != 0) {
		return MAP_FAILED;
	}

	void *mapping = mmap((void *)aligned,
			     length,
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			     -1,
			     0);

	if (mapping == MAP_FAILED)
		return MAP_FAILED;

	if ((uintptr_t) mapping != aligned) {
		(void)munmap(mapping, length);
		errno = EFAULT;
		return MAP_FAILED;
	}

	return mapping;
}

static struct perf_result measure_mprotect(struct perf_group *group,
					   void *address,
					   size_t length, int protection)
{
	struct usage_snapshot before = usage_now();

	struct perf_counts counts;

	if (perf_group_start(group) != 0)
		exit(EXIT_FAILURE);

	errno = 0;

	int ret = mprotect(address,
			   length,
			   protection);

	int saved_errno = errno;

	if (perf_group_stop(group, &counts) != 0) {
		exit(EXIT_FAILURE);
	}

	struct usage_snapshot after = usage_now();

	struct perf_result result = {
		.cycles = counts.cycles,
		.instructions = counts.instructions,

		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt,

		.ret = ret,
		.error = saved_errno,
	};

	return result;
}

static struct perf_result measure_read_range(struct perf_group *group,
					     volatile unsigned char *memory,
					     size_t first_page,
					     size_t pages, size_t page_size)
{
	struct usage_snapshot before = usage_now();

	struct perf_counts counts;

	uint64_t sum = 0;

	if (perf_group_start(group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + pages; ++page) {
		sum += memory[page * page_size];
	}

	if (perf_group_stop(group, &counts) != 0) {
		exit(EXIT_FAILURE);
	}

	struct usage_snapshot after = usage_now();

	sink += sum;

	struct perf_result result = {
		.cycles = counts.cycles,
		.instructions = counts.instructions,

		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt,

		.ret = 0,
		.error = 0,
	};

	printf("read sum             : %" PRIu64 "\n", sum);

	return result;
}

static unsigned char private_value(size_t page)
{
	return (unsigned char)(((page % 251U) + 1U) ^ 0x5aU);
}

static struct perf_result measure_write_range(struct perf_group *group,
					      volatile unsigned char *memory,
					      size_t first_page,
					      size_t pages, size_t page_size)
{
	struct usage_snapshot before = usage_now();

	struct perf_counts counts;

	if (perf_group_start(group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + pages; ++page) {
		memory[page * page_size] = private_value(page);
	}

	if (perf_group_stop(group, &counts) != 0) {
		exit(EXIT_FAILURE);
	}

	struct usage_snapshot after = usage_now();

	struct perf_result result = {
		.cycles = counts.cycles,
		.instructions = counts.instructions,

		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt,

		.ret = 0,
		.error = 0,
	};

	return result;
}

static void print_perf(const char *name,
		       const struct perf_result *result, size_t pages)
{
	printf("\n========== %s ==========\n", name);

	printf("return value         : %d\n", result->ret);

	if (result->ret != 0) {
		printf("errno                : %d (%s)\n",
		       result->error, strerror(result->error));
	}

	printf("minor faults         : %ld\n", result->minflt);

	printf("major faults         : %ld\n", result->majflt);

	printf("cycles               : %" PRIu64 "\n", result->cycles);

	printf("instructions         : %" PRIu64 "\n", result->instructions);

	if (pages != 0) {
		printf("cycles/page          : %.2f\n",
		       (double)result->cycles / (double)pages);

		printf("instructions/page    : %.2f\n",
		       (double)result->instructions / (double)pages);
	}
}

static int compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;

	uint64_t b = *(const uint64_t *)right;

	if (a < b)
		return -1;

	if (a > b)
		return 1;

	return 0;
}

static size_t count_unique(uint64_t * values, size_t count)
{
	if (count == 0)
		return 0;

	qsort(values, count, sizeof(*values), compare_u64);

	size_t unique = 1;

	for (size_t i = 1; i < count; ++i) {
		if (values[i] != values[i - 1])
			++unique;
	}

	return unique;
}

static int open_pagemap(void)
{
	int fd = open("/proc/self/pagemap",
		      O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		die("open pagemap");

	return fd;
}

static struct pagemap_entry read_pagemap(int fd,
					 const void *address, size_t page_size)
{
	uint64_t raw = 0;

	uint64_t vpn = (uint64_t) (uintptr_t) address / (uint64_t) page_size;

	off_t offset = (off_t) (vpn * sizeof(raw));

	ssize_t result = pread(fd,
			       &raw,
			       sizeof(raw),
			       offset);

	if (result != (ssize_t) sizeof(raw)) {
		if (result < 0)
			die("pread pagemap");

		fprintf(stderr, "short pagemap read: %zd\n", result);

		exit(EXIT_FAILURE);
	}

	struct pagemap_entry entry = {
		.raw = raw,

		.pfn = raw & PM_PFN_MASK,

		.present = (raw & PM_PRESENT) != 0,

		.swapped = (raw & PM_SWAPPED) != 0,

		.exclusive = (raw & PM_EXCLUSIVE) != 0,
	};

	return entry;
}

static struct pagemap_summary scan_pagemap(const void *mapping,
					   size_t first_page,
					   size_t pages, size_t page_size)
{
	struct pagemap_summary summary;

	memset(&summary, 0, sizeof(summary));

	summary.pages = pages;

	uint64_t *pfns = calloc(pages,
				sizeof(*pfns));

	if (pfns == NULL)
		die("calloc pfns");

	size_t pfn_count = 0;

	int fd = open_pagemap();

	size_t samples[3] = {
		0,
		pages > 1 ? 1 : 0,
		pages - 1
	};

	for (size_t i = 0; i < pages; ++i) {
		size_t page = first_page + i;

		const unsigned char *address =
		    (const unsigned char *)mapping + page * page_size;

		struct pagemap_entry entry = read_pagemap(fd,
							  address,
							  page_size);

		if (entry.present)
			++summary.present;

		if (entry.swapped)
			++summary.swapped;

		if (entry.present && entry.exclusive) {
			++summary.exclusive;
		}

		if (entry.present && entry.pfn != 0) {
			pfns[pfn_count++] = entry.pfn;
		}

		for (size_t s = 0; s < 3; ++s) {
			if (i == samples[s]) {
				summary.sample_raw[s] = entry.raw;

				summary.sample_pfn[s] = entry.pfn;

				summary.sample_present[s] = entry.present;

				summary.sample_exclusive[s] = entry.exclusive;
			}
		}
	}

	close(fd);

	summary.nonzero_pfns = pfn_count;

	summary.unique_pfns = count_unique(pfns, pfn_count);

	free(pfns);

	return summary;
}

static void print_pagemap_summary(const char *name,
				  const struct pagemap_summary *summary,
				  size_t first_page)
{
	printf("\n========== %s ==========\n", name);

	printf("pages                : %zu\n", summary->pages);

	printf("present              : %zu\n", summary->present);

	printf("swapped              : %zu\n", summary->swapped);

	printf("exclusive            : %zu\n", summary->exclusive);

	printf("nonzero PFNs         : %zu\n", summary->nonzero_pfns);

	printf("unique PFNs          : %zu\n", summary->unique_pfns);

	size_t local[3] = {
		0,
		summary->pages > 1 ? 1 : 0,
		summary->pages - 1
	};

	printf("\n");
	printf("page     raw pagemap          PFN           " "present excl\n");

	for (size_t s = 0; s < 3; ++s) {
		printf("%-8zu "
		       "0x%016" PRIx64 " "
		       "0x%011" PRIx64 " "
		       "%-7d %d\n",
		       first_page + local[s],
		       summary->sample_raw[s],
		       summary->sample_pfn[s],
		       summary->sample_present[s],
		       summary->sample_exclusive[s]);
	}
}

static size_t mincore_resident(void *address, size_t length, size_t page_size)
{
	size_t pages = (length + page_size - 1) / page_size;

	unsigned char *vec = calloc(pages, 1);

	if (vec == NULL)
		die("calloc mincore");

	if (mincore(address, length, vec) != 0) {
		die("mincore");
	}

	size_t resident = 0;

	for (size_t page = 0; page < pages; ++page) {
		if (vec[page] & 1)
			++resident;
	}

	free(vec);

	return resident;
}

static void print_layout(const char *name,
			 const void *mapping,
			 size_t length, unsigned long vm_pte_baseline)
{
	uintptr_t target_start = (uintptr_t) mapping;

	uintptr_t target_end = target_start + length;

	FILE *fp = fopen("/proc/self/smaps", "r");

	if (fp == NULL)
		die("fopen smaps");

	char line[1024];

	int active = 0;
	size_t vma_count = 0;

	unsigned long size_kb = 0;
	unsigned long rss_kb = 0;
	unsigned long pss_kb = 0;
	unsigned long private_dirty_kb = 0;
	unsigned long referenced_kb = 0;
	unsigned long anonymous_kb = 0;

	printf("\n========== %s ==========\n", name);

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;
		char perms[8];

		if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {
			active =
			    (uintptr_t) start < target_end &&
			    (uintptr_t) end > target_start;

			if (active) {
				++vma_count;

				printf("VMA %zu               : %s",
				       vma_count, line);
			}

			continue;
		}

		if (!active)
			continue;

		unsigned long value;

		if (sscanf(line, "Size: %lu kB", &value) == 1) {
			size_kb += value;
		} else if (sscanf(line, "Rss: %lu kB", &value) == 1) {
			rss_kb += value;
		} else if (sscanf(line, "Pss: %lu kB", &value) == 1) {
			pss_kb += value;
		} else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1) {
			private_dirty_kb += value;
		} else if (sscanf(line, "Referenced: %lu kB", &value) == 1) {
			referenced_kb += value;
		} else if (sscanf(line, "Anonymous: %lu kB", &value) == 1) {
			anonymous_kb += value;
		} else if (strncmp(line, "VmFlags:", 8) == 0) {
			printf("VmFlags              : %s", line + 8);
		}
	}

	fclose(fp);

	unsigned long vm_pte = read_vm_pte();

	printf("\nVMA count            : %zu\n", vma_count);

	printf("aggregate Size       : %lu kB\n", size_kb);

	printf("aggregate Rss        : %lu kB\n", rss_kb);

	printf("aggregate Pss        : %lu kB\n", pss_kb);

	printf("aggregate Private_Dirty: %lu kB\n", private_dirty_kb);

	printf("aggregate Referenced : %lu kB\n", referenced_kb);

	printf("aggregate Anonymous  : %lu kB\n", anonymous_kb);

	printf("VmPTE                : %lu kB\n", vm_pte);

	printf("VmPTE delta          : %ld kB\n",
	       (long)vm_pte - (long)vm_pte_baseline);
}

static void print_target_state(const char *name,
			       const void *mapping,
			       size_t length,
			       size_t first_page,
			       size_t pages,
			       size_t page_size, unsigned long vm_pte_baseline)
{
	print_layout(name, mapping, length, vm_pte_baseline);

	struct pagemap_summary summary = scan_pagemap(mapping,
						      first_page,
						      pages,
						      page_size);

	print_pagemap_summary("target pagemap state", &summary, first_page);

	void *target_address =
	    (unsigned char *)mapping + first_page * page_size;

	size_t target_length = pages * page_size;

	printf("\ntarget mincore       : %zu / %zu\n",
	       mincore_resident(target_address,
				target_length, page_size), pages);
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t target_first_page = 1024;
	size_t target_pages = 512;

	if (argc >= 2) {
		size_mib = (size_t)strtoul(argv[1], NULL, 0);
	}

	if (argc >= 3) {
		target_first_page = (size_t)strtoul(argv[2], NULL, 0);
	}

	if (argc >= 4) {
		target_pages = (size_t)strtoul(argv[3], NULL, 0);
	}

	if (argc > 4 || size_mib == 0) {
		fprintf(stderr,
			"Usage: %s " "[MiB] [first_page] [pages]\n", argv[0]);

		return EXIT_FAILURE;
	}

	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0)
		die("sysconf");

	size_t page_size = (size_t)page_size_long;

	size_t length = size_mib * 1024UL * 1024UL;

	length -= length % page_size;

	size_t pages = length / page_size;

	if (target_pages == 0 ||
	    target_first_page == 0 ||
	    target_first_page >= pages ||
	    target_pages >
	    pages - target_first_page ||
	    target_first_page + target_pages >= pages) {
		fprintf(stderr,
			"target must be a nonempty " "interior range\n");

		return EXIT_FAILURE;
	}

	size_t target_offset = target_first_page * page_size;

	size_t target_length = target_pages * page_size;

	unsigned long vm_pte_baseline = read_vm_pte();

	volatile unsigned char *memory = map_aligned(length,
						     ONE_GIB);

	if (memory == MAP_FAILED)
		die("map_aligned");

	struct perf_group perf_group;
	struct perf_counts warmup;

	if (perf_group_open(&perf_group) != 0) {
		return EXIT_FAILURE;
	}

	if (perf_group_start(&perf_group) != 0) {
		return EXIT_FAILURE;
	}

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &warmup) != 0) {
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());

	printf("mapping address      : %p\n", (const void *)memory);

	printf("address mod 1 GiB    : 0x%lx\n",
	       (unsigned long)((uintptr_t) memory & (ONE_GIB - 1)));

	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);

	printf("page size            : %zu bytes\n", page_size);

	printf("pages                : %zu\n", pages);

	printf("target range         : %zu-%zu\n",
	       target_first_page, target_first_page + target_pages - 1);

	printf("target size          : %zu kB\n", target_length / 1024);

	printf("target address       : %p\n", (const void *)
	       (memory + target_offset));

	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	/*
	 * 1. mmap之后完全不触页。
	 */
	print_target_state("1. untouched RW mapping",
			   (const void *)memory,
			   length,
			   target_first_page,
			   target_pages, page_size, vm_pte_baseline);

	/*
	 * 2. 未触页状态：RW -> R。
	 */
	struct perf_result rw_to_r = measure_mprotect(&perf_group,
						      (void *)(memory +
							       target_offset),
						      target_length,
						      PROT_READ);

	print_perf("2. untouched RW to R", &rw_to_r, target_pages);

	if (rw_to_r.ret != 0)
		return EXIT_FAILURE;

	print_target_state("2. state after untouched RW to R",
			   (const void *)memory,
			   length,
			   target_first_page,
			   target_pages, page_size, vm_pte_baseline);

	/*
	 * 3. 未触页状态：R -> RW。
	 */
	struct perf_result r_to_rw = measure_mprotect(&perf_group,
						      (void *)(memory +
							       target_offset),
						      target_length,
						      PROT_READ | PROT_WRITE);

	print_perf("3. untouched R to RW", &r_to_rw, target_pages);

	if (r_to_rw.ret != 0)
		return EXIT_FAILURE;

	print_target_state("3. state after untouched R to RW",
			   (const void *)memory,
			   length,
			   target_first_page,
			   target_pages, page_size, vm_pte_baseline);

	/*
	 * 4. 未触页状态：RW -> PROT_NONE。
	 */
	struct perf_result rw_to_none = measure_mprotect(&perf_group,
							 (void *)(memory +
								  target_offset),
							 target_length,
							 PROT_NONE);

	print_perf("4. untouched RW to PROT_NONE", &rw_to_none, target_pages);

	if (rw_to_none.ret != 0)
		return EXIT_FAILURE;

	print_target_state("4. state under untouched PROT_NONE",
			   (const void *)memory,
			   length,
			   target_first_page,
			   target_pages, page_size, vm_pte_baseline);

	/*
	 * 5. 未触页状态：NONE -> RW。
	 */
	struct perf_result none_to_rw = measure_mprotect(&perf_group,
							 (void *)(memory +
								  target_offset),
							 target_length,
							 PROT_READ |
							 PROT_WRITE);

	print_perf("5. untouched PROT_NONE to RW", &none_to_rw, target_pages);

	if (none_to_rw.ret != 0)
		return EXIT_FAILURE;

	print_target_state("5. state after untouched NONE to RW",
			   (const void *)memory,
			   length,
			   target_first_page,
			   target_pages, page_size, vm_pte_baseline);

	/*
	 * 6. 到现在为止一次用户Load/Store都没有发生。
	 *    现在第一次读取目标512页。
	 */
	printf("\n========== 6. first reads ==========\n");

	struct perf_result first_read = measure_read_range(&perf_group,
							   memory,
							   target_first_page,
							   target_pages,
							   page_size);

	print_perf("6. first read of target pages", &first_read, target_pages);

	print_target_state("6. state after first reads",
			   (const void *)memory,
			   length,
			   target_first_page,
			   target_pages, page_size, vm_pte_baseline);

	/*
	 * 7. 现在PTE已经存在并指向zero page。
	 *    第一次写目标512页。
	 */
	struct perf_result first_write = measure_write_range(&perf_group,
							     memory,
							     target_first_page,
							     target_pages,
							     page_size);

	print_perf("7. first writes to target pages",
		   &first_write, target_pages);

	print_target_state("7. state after first writes",
			   (const void *)memory,
			   length,
			   target_first_page,
			   target_pages, page_size, vm_pte_baseline);

	/*
	 * 8. 内容校验。
	 *
	 * offset0应为private pattern。
	 * offset1从未写过，应保持0。
	 */
	uint64_t sum0 = 0;
	uint64_t sum1 = 0;

	uint64_t expected0 = 0;

	for (size_t page =
	     target_first_page;
	     page < target_first_page + target_pages; ++page) {
		size_t offset = page * page_size;

		sum0 += memory[offset];
		sum1 += memory[offset + 1];

		expected0 += private_value(page);
	}

	sink += sum0 + sum1;

	printf("\n========== 8. final contents ==========\n");

	printf("offset 0 sum         : %" PRIu64 "\n", sum0);

	printf("expected offset 0    : %" PRIu64 "\n", expected0);

	printf("offset 1 sum         : %" PRIu64 "\n", sum1);

	printf("expected offset 1    : 0\n");

	printf("signature valid      : %s\n",
	       sum0 == expected0 && sum1 == 0 ? "yes" : "NO");

	printf("\nsink                 : %" PRIu64 "\n", sink);

	perf_group_close(&perf_group);

	if (munmap((void *)memory, length) != 0) {
		die("munmap");
	}

	return EXIT_SUCCESS;
}
