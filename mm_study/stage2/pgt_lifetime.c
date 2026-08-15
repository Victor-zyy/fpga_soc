#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#define ONE_MIB  (1024UL * 1024UL)
#define TWO_MIB  (2UL * ONE_MIB)
#define ONE_GIB  (1024UL * ONE_MIB)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

struct region_stats {
	unsigned long size_kb;
	unsigned long rss_kb;
	unsigned long pss_kb;
	unsigned long anonymous_kb;
	unsigned long private_dirty_kb;
	unsigned long referenced_kb;
	unsigned int vma_count;
};

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

static struct usage_snapshot read_usage(void)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage) != 0) {
		perror("getrusage");
		exit(EXIT_FAILURE);
	}

	struct usage_snapshot result = {
		.minor_faults = usage.ru_minflt,
		.major_faults = usage.ru_majflt,
	};

	return result;
}

static unsigned long read_vm_pte(void)
{
	FILE *fp;
	char line[512];
	unsigned long value = 0;

	fp = fopen("/proc/self/status", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/status");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &value) == 1)
			break;
	}

	fclose(fp);
	return value;
}

/*
 * 在正式记录baseline前，预热stdio及/proc读取路径，
 * 避免第一次fopen/fgets等操作改变本进程自身页表。
 */
static void warm_up_proc_files(void)
{
	static const char *paths[] = {
		"/proc/self/status",
		"/proc/self/maps",
		"/proc/self/smaps"
	};

	char buffer[4096];

	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
		FILE *fp = fopen(paths[i], "r");

		if (fp == NULL) {
			perror(paths[i]);
			exit(EXIT_FAILURE);
		}

		while (fgets(buffer, sizeof(buffer), fp) != NULL) ;

		fclose(fp);
	}
}

static void read_region_stats(uintptr_t range_start,
			      size_t range_length, struct region_stats *stats)
{
	FILE *fp;
	char line[512];

	uintptr_t range_end = range_start + range_length;
	int current_vma_overlaps = 0;

	memset(stats, 0, sizeof(*stats));

	fp = fopen("/proc/self/smaps", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/smaps");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long vma_start;
		unsigned long vma_end;

		if (sscanf(line, "%lx-%lx", &vma_start, &vma_end) == 2) {
			current_vma_overlaps =
			    (uintptr_t) vma_start < range_end &&
			    (uintptr_t) vma_end > range_start;

			if (current_vma_overlaps)
				++stats->vma_count;

			continue;
		}

		if (!current_vma_overlaps)
			continue;

		(void)sscanf(line, "Size: %lu kB", &stats->size_kb);

		unsigned long value;

		if (sscanf(line, "Rss: %lu kB", &value) == 1)
			stats->rss_kb += value;
		else if (sscanf(line, "Pss: %lu kB", &value) == 1)
			stats->pss_kb += value;
		else if (sscanf(line, "Anonymous: %lu kB", &value) == 1)
			stats->anonymous_kb += value;
		else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1)
			stats->private_dirty_kb += value;
		else if (sscanf(line, "Referenced: %lu kB", &value) == 1)
			stats->referenced_kb += value;

		/*
		 * Size需要跨多个VMA累加。
		 * 上面的直接sscanf只适用于单VMA，因此单独处理。
		 */
		if (sscanf(line, "Size: %lu kB", &value) == 1)
			stats->size_kb += value;
	}

	fclose(fp);
}

/*
 * 上面的Size解析不能既赋值又累加。
 * 使用这个修正版完成实际统计。
 */
static void read_region_stats_fixed(uintptr_t range_start,
				    size_t range_length,
				    struct region_stats *stats)
{
	FILE *fp;
	char line[512];

	uintptr_t range_end = range_start + range_length;
	int current_vma_overlaps = 0;

	memset(stats, 0, sizeof(*stats));

	fp = fopen("/proc/self/smaps", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/smaps");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long vma_start;
		unsigned long vma_end;
		unsigned long value;

		if (sscanf(line, "%lx-%lx", &vma_start, &vma_end) == 2) {
			current_vma_overlaps =
			    (uintptr_t) vma_start < range_end &&
			    (uintptr_t) vma_end > range_start;

			if (current_vma_overlaps)
				++stats->vma_count;

			continue;
		}

		if (!current_vma_overlaps)
			continue;

		if (sscanf(line, "Size: %lu kB", &value) == 1)
			stats->size_kb += value;
		else if (sscanf(line, "Rss: %lu kB", &value) == 1)
			stats->rss_kb += value;
		else if (sscanf(line, "Pss: %lu kB", &value) == 1)
			stats->pss_kb += value;
		else if (sscanf(line, "Anonymous: %lu kB", &value) == 1)
			stats->anonymous_kb += value;
		else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1)
			stats->private_dirty_kb += value;
		else if (sscanf(line, "Referenced: %lu kB", &value) == 1)
			stats->referenced_kb += value;
	}

	fclose(fp);
}

static void print_overlapping_maps(uintptr_t range_start, size_t range_length)
{
	FILE *fp;
	char line[512];

	uintptr_t range_end = range_start + range_length;

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		perror("fopen /proc/self/maps");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;

		if (sscanf(line, "%lx-%lx", &start, &end) != 2)
			continue;

		if ((uintptr_t) start < range_end &&
		    (uintptr_t) end > range_start) {
			printf("  %s", line);
		}
	}

	fclose(fp);
}

static void print_snapshot(const char *name,
			   uintptr_t base,
			   size_t length, unsigned long vm_pte_baseline)
{
	struct region_stats stats;
	unsigned long vm_pte;

	read_region_stats_fixed(base, length, &stats);
	vm_pte = read_vm_pte();

	printf("\n========== %s ==========\n", name);

	printf("overlapping VMAs     : %u\n", stats.vma_count);
	printf("mapped Size          : %lu kB\n", stats.size_kb);
	printf("Rss                  : %lu kB\n", stats.rss_kb);
	printf("Pss                  : %lu kB\n", stats.pss_kb);
	printf("Anonymous            : %lu kB\n", stats.anonymous_kb);
	printf("Private_Dirty        : %lu kB\n", stats.private_dirty_kb);
	printf("Referenced           : %lu kB\n", stats.referenced_kb);
	printf("VmPTE                : %lu kB\n", vm_pte);
	printf("VmPTE delta          : %ld kB\n",
	       (long)vm_pte - (long)vm_pte_baseline);

	printf("maps:\n");
	print_overlapping_maps(base, length);
}

/*
 * 临时预留一块大虚拟区域，选择其中一个1 GiB边界，
 * 然后只在该边界映射最终16 MiB。
 *
 * 临时预留使用PROT_NONE和MAP_NORESERVE，不触碰物理页。
 */
static void *map_isolated_1g_aligned(size_t length)
{
	size_t reserve_length;

	if (ONE_GIB > (SIZE_MAX - length) / 2) {
		errno = EOVERFLOW;
		return MAP_FAILED;
	}

	reserve_length = 2 * ONE_GIB + length;

	void *reservation = mmap(NULL,
				 reserve_length,
				 PROT_NONE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
				 -1,
				 0);

	if (reservation == MAP_FAILED)
		return MAP_FAILED;

	uintptr_t raw = (uintptr_t) reservation;

	uintptr_t aligned = (raw + ONE_GIB - 1) & ~((uintptr_t) ONE_GIB - 1);

	if (munmap(reservation, reserve_length) != 0) {
		int saved_errno = errno;
		errno = saved_errno;
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

static void *remap_exact(void *address, size_t length)
{
	void *result = mmap(address,
			    length,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			    -1,
			    0);

	if (result == MAP_FAILED)
		return MAP_FAILED;

	if (result != address) {
		(void)munmap(result, length);
		errno = EFAULT;
		return MAP_FAILED;
	}

	return result;
}

static void touch_write(volatile unsigned char *address,
			size_t length, size_t page_size, const char *name)
{
	struct usage_snapshot before = read_usage();

	size_t pages = length / page_size;

	for (size_t page = 0; page < pages; ++page) {
		address[page * page_size] = (unsigned char)((page % 251U) + 1U);
	}

	struct usage_snapshot after = read_usage();

	printf("\n---------- %s ----------\n", name);
	printf("pages touched        : %zu\n", pages);
	printf("minor faults         : %ld\n",
	       after.minor_faults - before.minor_faults);
	printf("major faults         : %ld\n",
	       after.major_faults - before.major_faults);
}

static void run_madvise(void *address, size_t length, const char *name)
{
	struct usage_snapshot before = read_usage();

	int result = madvise(address,
			     length,
			     MADV_DONTNEED);

	int saved_errno = errno;

	struct usage_snapshot after = read_usage();

	printf("\n---------- %s ----------\n", name);
	printf("return value          : %d\n", result);

	if (result != 0) {
		printf("errno                 : %d (%s)\n",
		       saved_errno, strerror(saved_errno));
		exit(EXIT_FAILURE);
	}

	printf("minor faults         : %ld\n",
	       after.minor_faults - before.minor_faults);
	printf("major faults         : %ld\n",
	       after.major_faults - before.major_faults);
}

static void run_munmap(void *address, size_t length, const char *name)
{
	struct usage_snapshot before = read_usage();

	int result = munmap(address, length);
	int saved_errno = errno;

	struct usage_snapshot after = read_usage();

	printf("\n---------- %s ----------\n", name);
	printf("address               : %p\n", address);
	printf("length                : %zu kB\n", length / 1024);
	printf("return value          : %d\n", result);

	if (result != 0) {
		printf("errno                 : %d (%s)\n",
		       saved_errno, strerror(saved_errno));
		exit(EXIT_FAILURE);
	}

	printf("minor faults         : %ld\n",
	       after.minor_faults - before.minor_faults);
	printf("major faults         : %ld\n",
	       after.major_faults - before.major_faults);
}

int main(void)
{
	const size_t length = 16UL * ONE_MIB;
	const size_t small_hole_offset = 1UL * ONE_MIB;
	const size_t large_hole_offset = 4UL * ONE_MIB;
	const size_t large_hole_length = 4UL * ONE_MIB;

	long page_size_long;
	size_t page_size;

	unsigned long vm_pte_baseline;

	volatile unsigned char *memory;
	void *small_hole;
	void *large_hole;

	setvbuf(stdout, NULL, _IONBF, 0);

	page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	page_size = (size_t)page_size_long;

	if (page_size != 4096) {
		fprintf(stderr,
			"This experiment expects 4 KiB pages; "
			"actual page size is %zu\n", page_size);
		return EXIT_FAILURE;
	}

	warm_up_proc_files();
	vm_pte_baseline = read_vm_pte();

	memory = map_isolated_1g_aligned(length);

	if (memory == MAP_FAILED) {
		perror("map_isolated_1g_aligned");
		return EXIT_FAILURE;
	}

	uintptr_t base = (uintptr_t) memory;

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 1 GiB    : 0x%" PRIxPTR "\n", base & (ONE_GIB - 1));
	printf("mapping size         : %zu MiB\n", length / ONE_MIB);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", length / page_size);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	print_snapshot("1. immediately after mmap",
		       base, length, vm_pte_baseline);

	touch_write(memory, length, page_size, "2. first write of all pages");

	print_snapshot("2. after first write", base, length, vm_pte_baseline);

	run_madvise((void *)memory, length, "3. MADV_DONTNEED entire mapping");

	print_snapshot("3. after MADV_DONTNEED", base, length, vm_pte_baseline);

	touch_write(memory, length, page_size, "4. write all pages again");

	print_snapshot("4. after repopulating all pages",
		       base, length, vm_pte_baseline);

	small_hole = (void *)(base + small_hole_offset);

	run_munmap(small_hole, page_size, "5. munmap one 4 KiB page");

	print_snapshot("5. after 4 KiB partial munmap",
		       base, length, vm_pte_baseline);

	if (remap_exact(small_hole, page_size) == MAP_FAILED) {
		perror("remap 4 KiB hole");
		return EXIT_FAILURE;
	}

	print_snapshot("6. after remapping 4 KiB, before touching",
		       base, length, vm_pte_baseline);

	touch_write((volatile unsigned char *)small_hole,
		    page_size, page_size, "6. touch remapped 4 KiB page");

	print_snapshot("6. after touching remapped 4 KiB",
		       base, length, vm_pte_baseline);

	large_hole = (void *)(base + large_hole_offset);

	run_munmap(large_hole,
		   large_hole_length, "7. munmap aligned 4 MiB range");

	print_snapshot("7. after aligned 4 MiB munmap",
		       base, length, vm_pte_baseline);

	if (remap_exact(large_hole, large_hole_length) == MAP_FAILED) {
		perror("remap 4 MiB hole");
		return EXIT_FAILURE;
	}

	print_snapshot("8. after remapping 4 MiB, before touching",
		       base, length, vm_pte_baseline);

	touch_write((volatile unsigned char *)large_hole,
		    large_hole_length,
		    page_size, "8. touch remapped 4 MiB range");

	print_snapshot("8. after touching remapped 4 MiB",
		       base, length, vm_pte_baseline);

	run_munmap((void *)memory, length, "9. complete munmap of 16 MiB");

	print_snapshot("9. after complete munmap",
		       base, length, vm_pte_baseline);

	return EXIT_SUCCESS;
}
