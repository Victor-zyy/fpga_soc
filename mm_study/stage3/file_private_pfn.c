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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "perf_counter.h"

#define TWO_MIB (2UL * 1024UL * 1024UL)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_SOFT_DIRTY     (1ULL << 55)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_UFFD_WP        (1ULL << 57)
#define PM_FILE_OR_SHANON (1ULL << 61)
#define PM_SWAPPED        (1ULL << 62)
#define PM_PRESENT        (1ULL << 63)

static volatile uint64_t read_sink;

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

struct signatures {
	uint64_t offset0_sum;
	uint64_t offset1_sum;
};

struct measurement {
	uint64_t cycles;
	uint64_t instructions;

	long minor_faults;
	long major_faults;

	struct signatures signatures;
};

struct mapping_stats {
	unsigned long size_kb;
	unsigned long rss_kb;
	unsigned long pss_kb;

	unsigned long shared_clean_kb;
	unsigned long shared_dirty_kb;
	unsigned long private_clean_kb;
	unsigned long private_dirty_kb;

	unsigned long referenced_kb;
	unsigned long anonymous_kb;
	unsigned long vm_pte_kb;

	char header[512];
	char vm_flags[256];
};

struct pagemap_entry {
	uint64_t raw;
	uint64_t pfn;

	int present;
	int swapped;
	int file_or_shared_anon;
	int exclusive;
	int soft_dirty;
};

struct pair_summary {
	size_t pages;

	size_t a_present;
	size_t b_present;
	size_t both_present;

	size_t a_file;
	size_t b_file;

	size_t a_exclusive;
	size_t b_exclusive;

	size_t pfn_comparable;
	size_t pfn_hidden;
	size_t same_pfn;
	size_t different_pfn;
};

typedef unsigned char (*value_function)(size_t page);

static int starts_with(const char *line, const char *prefix)
{
	return strncmp(line, prefix, strlen(prefix)) == 0;
}

static struct usage_snapshot get_usage_snapshot(void)
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

static void warm_up_proc_files(void)
{
	static const char *paths[] = {
		"/proc/self/status",
		"/proc/self/maps",
		"/proc/self/smaps"
	};

	char line[512];

	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
		FILE *fp = fopen(paths[i], "r");

		if (fp == NULL) {
			perror(paths[i]);
			exit(EXIT_FAILURE);
		}

		while (fgets(line, sizeof(line), fp) != NULL) ;

		fclose(fp);
	}
}

static void read_mapping_stats(const void *address, struct mapping_stats *stats)
{
	FILE *fp;
	char line[512];

	uintptr_t target = (uintptr_t) address;
	int found = 0;

	memset(stats, 0, sizeof(*stats));

	fp = fopen("/proc/self/smaps", "r");

	if (fp == NULL) {
		perror("fopen /proc/self/smaps");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;

		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if (found)
				break;

			if (target >= (uintptr_t) start &&
			    target < (uintptr_t) end) {
				found = 1;

				snprintf(stats->header,
					 sizeof(stats->header), "%s", line);

				stats->header[strcspn(stats->header, "\n")] =
				    '\0';
			}

			continue;
		}

		if (!found)
			continue;

		if (starts_with(line, "Size:")) {
			(void)sscanf(line, "Size: %lu kB", &stats->size_kb);
		} else if (starts_with(line, "Rss:")) {
			(void)sscanf(line, "Rss: %lu kB", &stats->rss_kb);
		} else if (starts_with(line, "Pss:")) {
			(void)sscanf(line, "Pss: %lu kB", &stats->pss_kb);
		} else if (starts_with(line, "Shared_Clean:")) {
			(void)sscanf(line, "Shared_Clean: %lu kB",
				     &stats->shared_clean_kb);
		} else if (starts_with(line, "Shared_Dirty:")) {
			(void)sscanf(line, "Shared_Dirty: %lu kB",
				     &stats->shared_dirty_kb);
		} else if (starts_with(line, "Private_Clean:")) {
			(void)sscanf(line, "Private_Clean: %lu kB",
				     &stats->private_clean_kb);
		} else if (starts_with(line, "Private_Dirty:")) {
			(void)sscanf(line, "Private_Dirty: %lu kB",
				     &stats->private_dirty_kb);
		} else if (starts_with(line, "Referenced:")) {
			(void)sscanf(line, "Referenced: %lu kB",
				     &stats->referenced_kb);
		} else if (starts_with(line, "Anonymous:")) {
			(void)sscanf(line, "Anonymous: %lu kB",
				     &stats->anonymous_kb);
		} else if (starts_with(line, "VmFlags:")) {
			snprintf(stats->vm_flags,
				 sizeof(stats->vm_flags),
				 "%s", line + strlen("VmFlags:"));

			stats->vm_flags[strcspn(stats->vm_flags, "\n")] = '\0';
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr,
			"Could not find mapping containing %p\n", address);

		exit(EXIT_FAILURE);
	}

	stats->vm_pte_kb = read_vm_pte();
}

static void print_mapping_stats(const char *name,
				const struct mapping_stats *stats,
				unsigned long vm_pte_baseline)
{
	printf("\n========== %s ==========\n", name);

	printf("mapping              : %s\n", stats->header);
	printf("Size                 : %lu kB\n", stats->size_kb);
	printf("Rss                  : %lu kB\n", stats->rss_kb);
	printf("Pss                  : %lu kB\n", stats->pss_kb);

	printf("Shared_Clean         : %lu kB\n", stats->shared_clean_kb);
	printf("Shared_Dirty         : %lu kB\n", stats->shared_dirty_kb);
	printf("Private_Clean        : %lu kB\n", stats->private_clean_kb);
	printf("Private_Dirty        : %lu kB\n", stats->private_dirty_kb);

	printf("Referenced           : %lu kB\n", stats->referenced_kb);
	printf("Anonymous            : %lu kB\n", stats->anonymous_kb);

	printf("VmPTE                : %lu kB\n", stats->vm_pte_kb);
	printf("VmPTE delta          : %ld kB\n",
	       (long)stats->vm_pte_kb - (long)vm_pte_baseline);

	printf("VmFlags              :%s\n", stats->vm_flags);
}

static unsigned char original_value(size_t page)
{
	return (unsigned char)((page % 251U) + 1U);
}

static unsigned char map_a_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0x5aU);
}

static unsigned char map_b_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0xa5U);
}

static struct signatures expected_uniform_signatures(size_t first_page,
						     size_t page_count,
						     value_function value_fn)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		unsigned char value = value_fn(page);

		result.offset0_sum += value;
		result.offset1_sum += value;
	}

	return result;
}

static struct signatures expected_mixed_signatures(size_t first_page,
						   size_t page_count,
						   value_function offset0_fn,
						   value_function offset1_fn)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		result.offset0_sum += offset0_fn(page);
		result.offset1_sum += offset1_fn(page);
	}

	return result;
}

static int signatures_equal(struct signatures left, struct signatures right)
{
	return left.offset0_sum == right.offset0_sum &&
	    left.offset1_sum == right.offset1_sum;
}

static void print_signatures(const char *name,
			     struct signatures actual,
			     struct signatures expected)
{
	printf("\n========== %s ==========\n", name);

	printf("offset 0 sum         : %" PRIu64 "\n", actual.offset0_sum);
	printf("expected offset 0    : %" PRIu64 "\n", expected.offset0_sum);

	printf("offset 1 sum         : %" PRIu64 "\n", actual.offset1_sum);
	printf("expected offset 1    : %" PRIu64 "\n", expected.offset1_sum);

	printf("signature valid      : %s\n",
	       signatures_equal(actual, expected) ? "yes" : "NO");
}

static void pwrite_full(int fd, const void *buffer, size_t length, off_t offset)
{
	const unsigned char *current = buffer;
	size_t remaining = length;

	while (remaining != 0) {
		ssize_t result = pwrite(fd,
					current,
					remaining,
					offset);

		if (result < 0) {
			if (errno == EINTR)
				continue;

			perror("pwrite");
			exit(EXIT_FAILURE);
		}

		if (result == 0) {
			fprintf(stderr, "pwrite returned zero\n");
			exit(EXIT_FAILURE);
		}

		current += result;
		remaining -= (size_t)result;
		offset += result;
	}
}

static void initialize_file(int fd, size_t pages, size_t page_size)
{
	unsigned char *buffer = malloc(page_size);

	if (buffer == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for (size_t page = 0; page < pages; ++page) {
		memset(buffer, original_value(page), page_size);

		pwrite_full(fd, buffer, page_size, (off_t) (page * page_size));
	}

	free(buffer);
}

static struct signatures read_file_signatures(int fd,
					      size_t first_page,
					      size_t page_count,
					      size_t page_size)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		unsigned char values[2];

		ssize_t read_result = pread(fd,
					    values,
					    sizeof(values),
					    (off_t) (page * page_size));

		if (read_result != (ssize_t) sizeof(values)) {
			if (read_result < 0)
				perror("pread");
			else
				fprintf(stderr,
					"short pread: %zd\n", read_result);

			exit(EXIT_FAILURE);
		}

		result.offset0_sum += values[0];
		result.offset1_sum += values[1];
	}

	return result;
}

static void *map_file_aligned(int fd, size_t length, size_t alignment)
{
	if (length > SIZE_MAX - alignment) {
		errno = EOVERFLOW;
		return MAP_FAILED;
	}

	size_t reserve_length = length + alignment;

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

	if (munmap(reservation, reserve_length) != 0)
		return MAP_FAILED;

	void *mapping = mmap((void *)aligned,
			     length,
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_FIXED_NOREPLACE,
			     fd,
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

static struct measurement measure_read_range(struct perf_group *perf_group,
					     volatile unsigned char *memory,
					     size_t first_page,
					     size_t page_count,
					     size_t page_size)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		size_t offset = page * page_size;

		result.signatures.offset0_sum += memory[offset];

		result.signatures.offset1_sum += memory[offset + 1];
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	read_sink +=
	    result.signatures.offset0_sum + result.signatures.offset1_sum;

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static struct measurement measure_private_write(struct perf_group *perf_group,
						volatile unsigned char *memory,
						size_t first_page,
						size_t page_count,
						size_t page_size,
						value_function value_fn)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		memory[page * page_size] = value_fn(page);
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static void print_measurement(const char *name,
			      const struct measurement *measurement,
			      size_t operations)
{
	printf("\n========== %s ==========\n", name);

	printf("minor faults         : %ld\n", measurement->minor_faults);
	printf("major faults         : %ld\n", measurement->major_faults);
	printf("cycles               : %" PRIu64 "\n", measurement->cycles);
	printf("instructions         : %" PRIu64 "\n",
	       measurement->instructions);

	if (operations != 0) {
		printf("cycles/page          : %.2f\n",
		       (double)measurement->cycles / (double)operations);

		printf("instructions/page    : %.2f\n",
		       (double)measurement->instructions / (double)operations);
	}

	printf("offset 0 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset0_sum);
	printf("offset 1 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset1_sum);
}

static struct pagemap_entry read_pagemap_entry(int pagemap_fd,
					       const void *address,
					       size_t page_size)
{
	uint64_t raw = 0;

	uint64_t virtual_page =
	    (uint64_t) (uintptr_t) address / (uint64_t) page_size;

	uint64_t byte_offset = virtual_page * sizeof(raw);

	ssize_t result = pread(pagemap_fd,
			       &raw,
			       sizeof(raw),
			       (off_t) byte_offset);

	if (result != (ssize_t) sizeof(raw)) {
		if (result < 0)
			perror("pread /proc/self/pagemap");
		else
			fprintf(stderr, "short pagemap read: %zd\n", result);

		exit(EXIT_FAILURE);
	}

	struct pagemap_entry entry = {
		.raw = raw,
		.pfn = raw & PM_PFN_MASK,
		.present = (raw & PM_PRESENT) != 0,
		.swapped = (raw & PM_SWAPPED) != 0,
		.file_or_shared_anon = (raw & PM_FILE_OR_SHANON) != 0,
		.exclusive = (raw & PM_EXCLUSIVE) != 0,
		.soft_dirty = (raw & PM_SOFT_DIRTY) != 0,
	};

	return entry;
}

static struct pair_summary scan_mapping_pair(int pagemap_fd,
					     const void *map_a,
					     const void *map_b,
					     size_t pages, size_t page_size)
{
	struct pair_summary summary;

	memset(&summary, 0, sizeof(summary));
	summary.pages = pages;

	for (size_t page = 0; page < pages; ++page) {
		const unsigned char *address_a =
		    (const unsigned char *)map_a + page * page_size;

		const unsigned char *address_b =
		    (const unsigned char *)map_b + page * page_size;

		struct pagemap_entry entry_a = read_pagemap_entry(pagemap_fd,
								  address_a,
								  page_size);

		struct pagemap_entry entry_b = read_pagemap_entry(pagemap_fd,
								  address_b,
								  page_size);

		if (entry_a.present)
			++summary.a_present;

		if (entry_b.present)
			++summary.b_present;

		if (entry_a.present && entry_a.file_or_shared_anon) {
			++summary.a_file;
		}

		if (entry_b.present && entry_b.file_or_shared_anon) {
			++summary.b_file;
		}

		if (entry_a.present && entry_a.exclusive)
			++summary.a_exclusive;

		if (entry_b.present && entry_b.exclusive)
			++summary.b_exclusive;

		if (!entry_a.present || !entry_b.present)
			continue;

		++summary.both_present;

		/*
		 * 在当前机器上真实PFN不可能全部为0。
		 * 若两边PFN都为0，通常表示权限导致PFN被隐藏。
		 */
		if (entry_a.pfn == 0 && entry_b.pfn == 0) {
			++summary.pfn_hidden;
			continue;
		}

		++summary.pfn_comparable;

		if (entry_a.pfn == entry_b.pfn)
			++summary.same_pfn;
		else
			++summary.different_pfn;
	}

	return summary;
}

static void print_pair_summary(const char *name,
			       const struct pair_summary *summary)
{
	printf("\n========== %s ==========\n", name);

	printf("pages compared       : %zu\n", summary->pages);
	printf("map_a present        : %zu\n", summary->a_present);
	printf("map_b present        : %zu\n", summary->b_present);
	printf("both present         : %zu\n", summary->both_present);

	printf("map_a file-bit pages : %zu\n", summary->a_file);
	printf("map_b file-bit pages : %zu\n", summary->b_file);

	printf("map_a exclusive      : %zu\n", summary->a_exclusive);
	printf("map_b exclusive      : %zu\n", summary->b_exclusive);

	printf("PFN comparable       : %zu\n", summary->pfn_comparable);
	printf("PFN hidden/zero      : %zu\n", summary->pfn_hidden);
	printf("same PFN             : %zu\n", summary->same_pfn);
	printf("different PFN        : %zu\n", summary->different_pfn);

	printf("PFN comparison usable: %s\n",
	       summary->pfn_comparable != 0 ? "yes" : "NO");
}

static void add_selected_index(size_t *indices,
			       size_t *count, size_t index, size_t pages)
{
	if (index >= pages)
		return;

	for (size_t i = 0; i < *count; ++i) {
		if (indices[i] == index)
			return;
	}

	indices[*count] = index;
	++(*count);
}

static void print_selected_entries(const char *name,
				   int pagemap_fd,
				   const void *map_a,
				   const void *map_b,
				   size_t pages,
				   size_t cow_pages, size_t page_size)
{
	size_t indices[8];
	size_t count = 0;

	add_selected_index(indices, &count, 0, pages);
	add_selected_index(indices, &count, 1, pages);

	if (cow_pages != 0)
		add_selected_index(indices, &count, cow_pages - 1, pages);

	add_selected_index(indices, &count, cow_pages, pages);

	add_selected_index(indices, &count, cow_pages + 1, pages);

	if (pages != 0)
		add_selected_index(indices, &count, pages - 1, pages);

	printf("\n========== %s ==========\n", name);

	printf("page     map_a PFN       map_b PFN       "
	       "same  Afile Bfile Aexcl Bexcl\n");

	for (size_t i = 0; i < count; ++i) {
		size_t page = indices[i];

		const unsigned char *address_a =
		    (const unsigned char *)map_a + page * page_size;

		const unsigned char *address_b =
		    (const unsigned char *)map_b + page * page_size;

		struct pagemap_entry entry_a = read_pagemap_entry(pagemap_fd,
								  address_a,
								  page_size);

		struct pagemap_entry entry_b = read_pagemap_entry(pagemap_fd,
								  address_b,
								  page_size);

		const char *same = "-";

		if (entry_a.present &&
		    entry_b.present &&
		    !(entry_a.pfn == 0 && entry_b.pfn == 0)) {
			same = entry_a.pfn == entry_b.pfn ? "yes" : "no";
		}

		printf("%-8zu 0x%011" PRIx64
		       " 0x%011" PRIx64
		       " %-5s %-5d %-5d %-5d %-5d\n",
		       page,
		       entry_a.pfn,
		       entry_b.pfn,
		       same,
		       entry_a.file_or_shared_anon,
		       entry_b.file_or_shared_anon,
		       entry_a.exclusive, entry_b.exclusive);
	}
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t cow_pages = 512;

	if (argc >= 2)
		size_mib = (size_t)strtoul(argv[1], NULL, 0);

	if (argc >= 3)
		cow_pages = (size_t)strtoul(argv[2], NULL, 0);

	if (argc > 3 || size_mib == 0) {
		fprintf(stderr, "Usage: %s [MiB] [cow_pages]\n", argv[0]);

		return EXIT_FAILURE;
	}

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	size_t page_size = (size_t)page_size_long;
	size_t length = size_mib * 1024UL * 1024UL;

	length -= length % page_size;

	size_t pages = length / page_size;

	if (cow_pages == 0 || cow_pages > pages) {
		fprintf(stderr,
			"Invalid cow_pages=%zu, pages=%zu\n", cow_pages, pages);

		return EXIT_FAILURE;
	}

	char file_path[128];

	snprintf(file_path,
		 sizeof(file_path),
		 "/file_private_pfn_%ld.bin", (long)getpid());

	int fd = open(file_path,
		      O_CREAT | O_TRUNC | O_RDWR,
		      0600);

	if (fd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	if (ftruncate(fd, (off_t) length) != 0) {
		perror("ftruncate");
		close(fd);
		unlink(file_path);
		return EXIT_FAILURE;
	}

	initialize_file(fd, pages, page_size);

	struct perf_group perf_group;
	struct perf_counts warmup_counts;

	if (perf_group_open(&perf_group) != 0) {
		close(fd);
		unlink(file_path);
		return EXIT_FAILURE;
	}

	if (perf_group_start(&perf_group) != 0)
		return EXIT_FAILURE;

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &warmup_counts) != 0) {
		return EXIT_FAILURE;
	}

	warm_up_proc_files();

	int pagemap_fd = open("/proc/self/pagemap",
			      O_RDONLY | O_CLOEXEC);

	if (pagemap_fd < 0) {
		perror("open /proc/self/pagemap");
		return EXIT_FAILURE;
	}

	unsigned long vm_pte_baseline = read_vm_pte();

	volatile unsigned char *map_a = map_file_aligned(fd,
							 length,
							 TWO_MIB);

	if (map_a == MAP_FAILED) {
		perror("map_file_aligned map_a");
		return EXIT_FAILURE;
	}

	volatile unsigned char *map_b = map_file_aligned(fd,
							 length,
							 TWO_MIB);

	if (map_b == MAP_FAILED) {
		perror("map_file_aligned map_b");
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());
	printf("file                 : %s\n", file_path);
	printf("map_a address        : %p\n", (const void *)map_a);
	printf("map_b address        : %p\n", (const void *)map_b);
	printf("map_a mod 2 MiB      : 0x%lx\n", (unsigned long)
	       ((uintptr_t) map_a & (TWO_MIB - 1)));
	printf("map_b mod 2 MiB      : 0x%lx\n", (unsigned long)
	       ((uintptr_t) map_b & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("pages                : %zu\n", pages);
	printf("COW pages            : %zu\n", cow_pages);
	printf("COW size             : %zu kB\n", cow_pages * page_size / 1024);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	struct mapping_stats stats_a;
	struct mapping_stats stats_b;

	read_mapping_stats((const void *)map_a, &stats_a);

	read_mapping_stats((const void *)map_b, &stats_b);

	print_mapping_stats("1. map_a immediately after mmap",
			    &stats_a, vm_pte_baseline);

	print_mapping_stats("1. map_b immediately after mmap",
			    &stats_b, vm_pte_baseline);

	struct pair_summary initial_pair = scan_mapping_pair(pagemap_fd,
							     (const void *)
							     map_a,
							     (const void *)
							     map_b,
							     pages,
							     page_size);

	print_pair_summary("1. pagemap immediately after mmap", &initial_pair);

	/*
	 * 两个映射分别读取全部文件页。
	 */
	struct measurement first_read_a = measure_read_range(&perf_group,
							     map_a,
							     0,
							     pages,
							     page_size);

	struct measurement first_read_b = measure_read_range(&perf_group,
							     map_b,
							     0,
							     pages,
							     page_size);

	print_measurement("2. first read through map_a", &first_read_a, pages);

	print_measurement("2. first read through map_b", &first_read_b, pages);

	struct signatures expected_initial = expected_uniform_signatures(0,
									 pages,
									 original_value);

	print_signatures("2. map_a initial contents",
			 first_read_a.signatures, expected_initial);

	print_signatures("2. map_b initial contents",
			 first_read_b.signatures, expected_initial);

	read_mapping_stats((const void *)map_a, &stats_a);

	read_mapping_stats((const void *)map_b, &stats_b);

	print_mapping_stats("2. map_a after both reads",
			    &stats_a, vm_pte_baseline);

	print_mapping_stats("2. map_b after both reads",
			    &stats_b, vm_pte_baseline);

	struct pair_summary after_reads = scan_mapping_pair(pagemap_fd,
							    (const void *)map_a,
							    (const void *)map_b,
							    pages,
							    page_size);

	print_pair_summary("2. PFNs after both mappings are read",
			   &after_reads);

	print_selected_entries("2. selected PFNs after both reads",
			       pagemap_fd,
			       (const void *)map_a,
			       (const void *)map_b,
			       pages, cow_pages, page_size);

	/*
	 * 只对map_a的前512页执行私有COW。
	 */
	struct measurement cow_a = measure_private_write(&perf_group,
							 map_a,
							 0,
							 cow_pages,
							 page_size,
							 map_a_value);

	print_measurement("3. private COW writes through map_a",
			  &cow_a, cow_pages);

	read_mapping_stats((const void *)map_a, &stats_a);

	read_mapping_stats((const void *)map_b, &stats_b);

	print_mapping_stats("3. map_a after its COW",
			    &stats_a, vm_pte_baseline);

	print_mapping_stats("3. map_b after map_a COW",
			    &stats_b, vm_pte_baseline);

	struct pair_summary after_a_cow = scan_mapping_pair(pagemap_fd,
							    (const void *)map_a,
							    (const void *)map_b,
							    pages,
							    page_size);

	print_pair_summary("3. PFNs after map_a COW", &after_a_cow);

	print_selected_entries("3. selected PFNs after map_a COW",
			       pagemap_fd,
			       (const void *)map_a,
			       (const void *)map_b,
			       pages, cow_pages, page_size);

	struct measurement check_a_after_a_cow = measure_read_range(&perf_group,
								    map_a,
								    0,
								    cow_pages,
								    page_size);

	struct measurement check_b_after_a_cow = measure_read_range(&perf_group,
								    map_b,
								    0,
								    cow_pages,
								    page_size);

	struct signatures expected_a_private = expected_mixed_signatures(0,
									 cow_pages,
									 map_a_value,
									 original_value);

	struct signatures expected_file = expected_uniform_signatures(0,
								      cow_pages,
								      original_value);

	print_signatures("3. map_a private contents",
			 check_a_after_a_cow.signatures, expected_a_private);

	print_signatures("3. map_b still sees file contents",
			 check_b_after_a_cow.signatures, expected_file);

	struct signatures file_after_a_cow = read_file_signatures(fd,
								  0,
								  cow_pages,
								  page_size);

	print_signatures("3. file remains unchanged after map_a COW",
			 file_after_a_cow, expected_file);

	/*
	 * 再对map_b的相同512页执行私有COW。
	 */
	struct measurement cow_b = measure_private_write(&perf_group,
							 map_b,
							 0,
							 cow_pages,
							 page_size,
							 map_b_value);

	print_measurement("4. private COW writes through map_b",
			  &cow_b, cow_pages);

	read_mapping_stats((const void *)map_a, &stats_a);

	read_mapping_stats((const void *)map_b, &stats_b);

	print_mapping_stats("4. map_a after both mappings COW",
			    &stats_a, vm_pte_baseline);

	print_mapping_stats("4. map_b after both mappings COW",
			    &stats_b, vm_pte_baseline);

	struct pair_summary after_both_cow = scan_mapping_pair(pagemap_fd,
							       (const void *)
							       map_a,
							       (const void *)
							       map_b,
							       pages,
							       page_size);

	print_pair_summary("4. PFNs after both mappings COW", &after_both_cow);

	print_selected_entries("4. selected PFNs after both mappings COW",
			       pagemap_fd,
			       (const void *)map_a,
			       (const void *)map_b,
			       pages, cow_pages, page_size);

	struct measurement final_a = measure_read_range(&perf_group,
							map_a,
							0,
							cow_pages,
							page_size);

	struct measurement final_b = measure_read_range(&perf_group,
							map_b,
							0,
							cow_pages,
							page_size);

	struct signatures expected_b_private = expected_mixed_signatures(0,
									 cow_pages,
									 map_b_value,
									 original_value);

	print_signatures("4. final map_a private contents",
			 final_a.signatures, expected_a_private);

	print_signatures("4. final map_b private contents",
			 final_b.signatures, expected_b_private);

	struct signatures final_file = read_file_signatures(fd,
							    0,
							    cow_pages,
							    page_size);

	print_signatures("4. file remains original", final_file, expected_file);

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);

	if (munmap((void *)map_b, length) != 0)
		perror("munmap map_b");

	if (munmap((void *)map_a, length) != 0)
		perror("munmap map_a");

	close(pagemap_fd);
	perf_group_close(&perf_group);
	close(fd);

	if (unlink(file_path) != 0)
		perror("unlink");

	return EXIT_SUCCESS;
}
