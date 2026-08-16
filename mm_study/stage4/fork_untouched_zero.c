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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "perf_counter.h"

#define TWO_MIB (2UL * 1024UL * 1024UL)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_FILE_OR_SHANON (1ULL << 61)
#define PM_SWAPPED        (1ULL << 62)
#define PM_PRESENT        (1ULL << 63)

#define KPF_ANON       12
#define KPF_ZERO_PAGE  24

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

	unsigned long shared_dirty_kb;
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
	int exclusive;
	int file_or_shared_anon;
};

struct pair_summary {
	size_t pages;

	size_t parent_present;
	size_t child_present;
	size_t both_present;

	size_t parent_exclusive;
	size_t child_exclusive;

	size_t parent_file_bit;
	size_t child_file_bit;

	size_t pfn_comparable;
	size_t pfn_hidden;

	size_t same_pfn;
	size_t different_pfn;

	size_t parent_unique_pfns;
	size_t child_unique_pfns;
};

struct pfn_snapshot {
	size_t pages;
	uint64_t *pfns;
	unsigned char *present;
};

typedef unsigned char (*value_function)(size_t page);

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static void write_full(int fd, const void *buffer, size_t length)
{
	const unsigned char *current = buffer;
	size_t remaining = length;

	while (remaining != 0) {
		ssize_t result = write(fd, current, remaining);

		if (result < 0) {
			if (errno == EINTR)
				continue;

			die("write");
		}

		if (result == 0) {
			fprintf(stderr, "write returned zero\n");
			exit(EXIT_FAILURE);
		}

		current += result;
		remaining -= (size_t)result;
	}
}

static void read_full(int fd, void *buffer, size_t length)
{
	unsigned char *current = buffer;
	size_t remaining = length;

	while (remaining != 0) {
		ssize_t result = read(fd, current, remaining);

		if (result < 0) {
			if (errno == EINTR)
				continue;

			die("read");
		}

		if (result == 0) {
			fprintf(stderr, "unexpected pipe EOF\n");
			exit(EXIT_FAILURE);
		}

		current += result;
		remaining -= (size_t)result;
	}
}

static struct usage_snapshot get_usage_snapshot(void)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage) != 0)
		die("getrusage");

	struct usage_snapshot result = {
		.minor_faults = usage.ru_minflt,
		.major_faults = usage.ru_majflt,
	};

	return result;
}

static int starts_with(const char *line, const char *prefix)
{
	return strncmp(line, prefix, strlen(prefix)) == 0;
}

static void build_proc_path(char *buffer,
			    size_t buffer_size, pid_t pid, const char *name)
{
	snprintf(buffer, buffer_size, "/proc/%ld/%s", (long)pid, name);
}

static unsigned long read_vm_pte(pid_t pid)
{
	char path[128];
	char line[512];
	unsigned long value = 0;

	build_proc_path(path, sizeof(path), pid, "status");

	FILE *fp = fopen(path, "r");

	if (fp == NULL)
		die("fopen status");

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &value) == 1) {
			break;
		}
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

	for (size_t index = 0;
	     index < sizeof(paths) / sizeof(paths[0]); ++index) {
		FILE *fp = fopen(paths[index], "r");

		if (fp == NULL)
			die(paths[index]);

		while (fgets(line, sizeof(line), fp) != NULL) ;

		fclose(fp);
	}
}

static void read_mapping_stats(pid_t pid,
			       const void *address, struct mapping_stats *stats)
{
	char path[128];
	char line[512];

	uintptr_t target = (uintptr_t) address;
	int found = 0;

	memset(stats, 0, sizeof(*stats));

	build_proc_path(path, sizeof(path), pid, "smaps");

	FILE *fp = fopen(path, "r");

	if (fp == NULL)
		die("fopen smaps");

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
		} else if (starts_with(line, "Shared_Dirty:")) {
			(void)sscanf(line,
				     "Shared_Dirty: %lu kB",
				     &stats->shared_dirty_kb);
		} else if (starts_with(line, "Private_Dirty:")) {
			(void)sscanf(line,
				     "Private_Dirty: %lu kB",
				     &stats->private_dirty_kb);
		} else if (starts_with(line, "Referenced:")) {
			(void)sscanf(line,
				     "Referenced: %lu kB",
				     &stats->referenced_kb);
		} else if (starts_with(line, "Anonymous:")) {
			(void)sscanf(line,
				     "Anonymous: %lu kB", &stats->anonymous_kb);
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
			"could not find mapping containing %p "
			"in process %ld\n", address, (long)pid);

		exit(EXIT_FAILURE);
	}

	stats->vm_pte_kb = read_vm_pte(pid);
}

static void print_mapping_stats(const char *name,
				pid_t pid,
				const struct mapping_stats *stats,
				unsigned long vm_pte_baseline)
{
	printf("\n========== %s ==========\n", name);

	printf("PID                  : %ld\n", (long)pid);
	printf("mapping              : %s\n", stats->header);
	printf("Size                 : %lu kB\n", stats->size_kb);
	printf("Rss                  : %lu kB\n", stats->rss_kb);
	printf("Pss                  : %lu kB\n", stats->pss_kb);
	printf("Shared_Dirty         : %lu kB\n", stats->shared_dirty_kb);
	printf("Private_Dirty        : %lu kB\n", stats->private_dirty_kb);
	printf("Referenced           : %lu kB\n", stats->referenced_kb);
	printf("Anonymous            : %lu kB\n", stats->anonymous_kb);
	printf("VmPTE                : %lu kB\n", stats->vm_pte_kb);
	printf("VmPTE delta          : %ld kB\n",
	       (long)stats->vm_pte_kb - (long)vm_pte_baseline);
	printf("VmFlags              :%s\n", stats->vm_flags);
}

static void *map_anon_aligned(size_t length, size_t alignment)
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

static unsigned char parent_value(size_t page)
{
	unsigned char base = (unsigned char)((page % 251U) + 1U);

	return (unsigned char)(base ^ 0x5aU);
}

static unsigned char child_value(size_t page)
{
	unsigned char base = (unsigned char)((page % 251U) + 1U);

	return (unsigned char)(base ^ 0xa5U);
}

static struct signatures read_signatures(volatile unsigned char *memory,
					 size_t first_page,
					 size_t page_count, size_t page_size)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		size_t offset = page * page_size;

		result.offset0_sum += memory[offset];
		result.offset1_sum += memory[offset + 1];
	}

	read_sink += result.offset0_sum + result.offset1_sum;

	return result;
}

static struct signatures expected_zero_signatures(void)
{
	struct signatures result = { 0, 0 };
	return result;
}

static struct signatures expected_private_signatures(size_t first_page,
						     size_t page_count,
						     value_function value_fn)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		result.offset0_sum += value_fn(page);
	}

	return result;
}

static int signatures_equal(struct signatures left, struct signatures right)
{
	return left.offset0_sum == right.offset0_sum &&
	    left.offset1_sum == right.offset1_sum;
}

static void print_signature_check(const char *name,
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

	if (perf_group_stop(perf_group, &perf) != 0) {
		exit(EXIT_FAILURE);
	}

	after = get_usage_snapshot();

	read_sink +=
	    result.signatures.offset0_sum + result.signatures.offset1_sum;

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static struct measurement measure_write_range(struct perf_group *perf_group,
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

	if (perf_group_stop(perf_group, &perf) != 0) {
		exit(EXIT_FAILURE);
	}

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	result.signatures =
	    read_signatures(memory, first_page, page_count, page_size);

	return result;
}

static void print_measurement(const char *name,
			      const struct measurement *measurement,
			      size_t pages)
{
	printf("\n========== %s ==========\n", name);

	printf("minor faults         : %ld\n", measurement->minor_faults);
	printf("major faults         : %ld\n", measurement->major_faults);
	printf("cycles               : %" PRIu64 "\n", measurement->cycles);
	printf("instructions         : %" PRIu64 "\n",
	       measurement->instructions);

	if (pages != 0) {
		printf("cycles/page          : %.2f\n",
		       (double)measurement->cycles / (double)pages);

		printf("instructions/page    : %.2f\n",
		       (double)measurement->instructions / (double)pages);
	}

	printf("offset 0 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset0_sum);
	printf("offset 1 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset1_sum);
}

static int open_pagemap(pid_t pid)
{
	char path[128];

	build_proc_path(path, sizeof(path), pid, "pagemap");

	int fd = open(path,
		      O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		die("open pagemap");

	return fd;
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
		.file_or_shared_anon = (raw & PM_FILE_OR_SHANON) != 0,
	};

	return entry;
}

static uint64_t read_kpageflags(int kpageflags_fd, uint64_t pfn)
{
	uint64_t flags = 0;

	ssize_t result = pread(kpageflags_fd,
			       &flags,
			       sizeof(flags),
			       (off_t) (pfn * sizeof(flags)));

	if (result != (ssize_t) sizeof(flags)) {
		if (result < 0)
			die("pread kpageflags");

		fprintf(stderr, "short kpageflags read: %zd\n", result);

		exit(EXIT_FAILURE);
	}

	return flags;
}

static int flag_is_set(uint64_t flags, unsigned int bit)
{
	return (flags & (1ULL << bit)) != 0;
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

static size_t count_unique_pfns(uint64_t * pfns, size_t count)
{
	if (count == 0)
		return 0;

	qsort(pfns, count, sizeof(*pfns), compare_u64);

	size_t unique = 1;

	for (size_t index = 1; index < count; ++index) {
		if (pfns[index] != pfns[index - 1])
			++unique;
	}

	return unique;
}

static struct pair_summary scan_process_pair(pid_t parent_pid,
					     pid_t child_pid,
					     const void *address,
					     size_t pages, size_t page_size)
{
	struct pair_summary summary;

	memset(&summary, 0, sizeof(summary));
	summary.pages = pages;

	uint64_t *parent_pfns = calloc(pages, sizeof(*parent_pfns));

	uint64_t *child_pfns = calloc(pages, sizeof(*child_pfns));

	if (parent_pfns == NULL || child_pfns == NULL) {
		die("calloc PFNs");
	}

	size_t parent_pfn_count = 0;
	size_t child_pfn_count = 0;

	int parent_pagemap = open_pagemap(parent_pid);

	int child_pagemap = open_pagemap(child_pid);

	for (size_t page = 0; page < pages; ++page) {
		const unsigned char *page_address =
		    (const unsigned char *)address + page * page_size;

		struct pagemap_entry parent_entry =
		    read_pagemap_entry(parent_pagemap,
				       page_address,
				       page_size);

		struct pagemap_entry child_entry =
		    read_pagemap_entry(child_pagemap,
				       page_address,
				       page_size);

		if (parent_entry.present) {
			++summary.parent_present;

			if (parent_entry.pfn != 0) {
				parent_pfns[parent_pfn_count++] =
				    parent_entry.pfn;
			}
		}

		if (child_entry.present) {
			++summary.child_present;

			if (child_entry.pfn != 0) {
				child_pfns[child_pfn_count++] = child_entry.pfn;
			}
		}

		if (parent_entry.present && parent_entry.exclusive) {
			++summary.parent_exclusive;
		}

		if (child_entry.present && child_entry.exclusive) {
			++summary.child_exclusive;
		}

		if (parent_entry.present && parent_entry.file_or_shared_anon) {
			++summary.parent_file_bit;
		}

		if (child_entry.present && child_entry.file_or_shared_anon) {
			++summary.child_file_bit;
		}

		if (!parent_entry.present || !child_entry.present) {
			continue;
		}

		++summary.both_present;

		if (parent_entry.pfn == 0 && child_entry.pfn == 0) {
			++summary.pfn_hidden;
			continue;
		}

		++summary.pfn_comparable;

		if (parent_entry.pfn == child_entry.pfn) {
			++summary.same_pfn;
		} else {
			++summary.different_pfn;
		}
	}

	close(child_pagemap);
	close(parent_pagemap);

	summary.parent_unique_pfns =
	    count_unique_pfns(parent_pfns, parent_pfn_count);

	summary.child_unique_pfns =
	    count_unique_pfns(child_pfns, child_pfn_count);

	free(child_pfns);
	free(parent_pfns);

	return summary;
}

static void print_pair_summary(const char *name,
			       const struct pair_summary *summary)
{
	printf("\n========== %s ==========\n", name);

	printf("pages compared       : %zu\n", summary->pages);
	printf("parent present       : %zu\n", summary->parent_present);
	printf("child present        : %zu\n", summary->child_present);
	printf("both present         : %zu\n", summary->both_present);

	printf("parent exclusive     : %zu\n", summary->parent_exclusive);
	printf("child exclusive      : %zu\n", summary->child_exclusive);

	printf("parent file-bit      : %zu\n", summary->parent_file_bit);
	printf("child file-bit       : %zu\n", summary->child_file_bit);

	printf("parent unique PFNs   : %zu\n", summary->parent_unique_pfns);
	printf("child unique PFNs    : %zu\n", summary->child_unique_pfns);

	printf("PFN comparable       : %zu\n", summary->pfn_comparable);
	printf("PFN hidden/zero      : %zu\n", summary->pfn_hidden);
	printf("same PFN             : %zu\n", summary->same_pfn);
	printf("different PFN        : %zu\n", summary->different_pfn);
}

static void add_selected_page(size_t *indices,
			      size_t *count, size_t page, size_t pages)
{
	if (page >= pages)
		return;

	for (size_t index = 0; index < *count; ++index) {
		if (indices[index] == page)
			return;
	}

	indices[*count] = page;
	++(*count);
}

static void print_selected_entries(const char *name,
				   pid_t parent_pid,
				   pid_t child_pid,
				   const void *address,
				   size_t pages,
				   size_t private_pages,
				   size_t page_size, int kpageflags_fd)
{
	size_t selected[8];
	size_t count = 0;

	add_selected_page(selected, &count, 0, pages);
	add_selected_page(selected, &count, 1, pages);

	if (private_pages != 0) {
		add_selected_page(selected, &count, private_pages - 1, pages);
	}

	add_selected_page(selected, &count, private_pages, pages);

	add_selected_page(selected, &count, private_pages + 1, pages);

	if (pages != 0) {
		add_selected_page(selected, &count, pages - 1, pages);
	}

	int parent_pagemap = open_pagemap(parent_pid);

	int child_pagemap = open_pagemap(child_pid);

	printf("\n========== %s ==========\n", name);

	printf("page     parent PFN      child PFN       "
	       "same Pzero Czero Panon Canon Pexcl Cexcl\n");

	for (size_t index = 0; index < count; ++index) {
		size_t page = selected[index];

		const unsigned char *page_address =
		    (const unsigned char *)address + page * page_size;

		struct pagemap_entry parent_entry =
		    read_pagemap_entry(parent_pagemap,
				       page_address,
				       page_size);

		struct pagemap_entry child_entry =
		    read_pagemap_entry(child_pagemap,
				       page_address,
				       page_size);

		uint64_t parent_flags = 0;
		uint64_t child_flags = 0;

		if (parent_entry.present && parent_entry.pfn != 0) {
			parent_flags =
			    read_kpageflags(kpageflags_fd, parent_entry.pfn);
		}

		if (child_entry.present && child_entry.pfn != 0) {
			child_flags =
			    read_kpageflags(kpageflags_fd, child_entry.pfn);
		}

		const char *same = "-";

		if (parent_entry.present &&
		    child_entry.present &&
		    !(parent_entry.pfn == 0 && child_entry.pfn == 0)) {
			same =
			    parent_entry.pfn == child_entry.pfn ? "yes" : "no";
		}

		printf("%-8zu "
		       "0x%011" PRIx64 " "
		       "0x%011" PRIx64 " "
		       "%-4s %-5d %-5d %-5d %-5d %-5d %-5d\n",
		       page,
		       parent_entry.pfn,
		       child_entry.pfn,
		       same,
		       flag_is_set(parent_flags,
				   KPF_ZERO_PAGE),
		       flag_is_set(child_flags,
				   KPF_ZERO_PAGE),
		       flag_is_set(parent_flags,
				   KPF_ANON),
		       flag_is_set(child_flags,
				   KPF_ANON),
		       parent_entry.exclusive, child_entry.exclusive);
	}

	close(child_pagemap);
	close(parent_pagemap);
}

static struct pfn_snapshot capture_snapshot(pid_t pid,
					    const void *address,
					    size_t first_page,
					    size_t page_count, size_t page_size)
{
	struct pfn_snapshot snapshot;

	memset(&snapshot, 0, sizeof(snapshot));

	snapshot.pages = page_count;

	snapshot.pfns = calloc(page_count, sizeof(*snapshot.pfns));

	snapshot.present = calloc(page_count, sizeof(*snapshot.present));

	if (snapshot.pfns == NULL || snapshot.present == NULL) {
		die("calloc snapshot");
	}

	int pagemap_fd = open_pagemap(pid);

	for (size_t index = 0; index < page_count; ++index) {
		size_t page = first_page + index;

		const unsigned char *page_address =
		    (const unsigned char *)address + page * page_size;

		struct pagemap_entry entry = read_pagemap_entry(pagemap_fd,
								page_address,
								page_size);

		snapshot.pfns[index] = entry.pfn;

		snapshot.present[index] = (unsigned char)entry.present;
	}

	close(pagemap_fd);
	return snapshot;
}

static void compare_snapshots(const char *name,
			      const struct pfn_snapshot *before,
			      const struct pfn_snapshot *after,
			      size_t first_page)
{
	if (before->pages != after->pages) {
		fprintf(stderr, "snapshot size mismatch\n");

		exit(EXIT_FAILURE);
	}

	size_t comparable = 0;
	size_t unchanged = 0;
	size_t changed = 0;
	size_t unavailable = 0;

	for (size_t index = 0; index < before->pages; ++index) {
		if (!before->present[index] ||
		    !after->present[index] ||
		    (before->pfns[index] == 0 && after->pfns[index] == 0)) {
			++unavailable;
			continue;
		}

		++comparable;

		if (before->pfns[index] == after->pfns[index]) {
			++unchanged;
		} else {
			++changed;
		}
	}

	printf("\n========== %s ==========\n", name);

	printf("first page           : %zu\n", first_page);
	printf("pages                : %zu\n", before->pages);
	printf("PFN comparable       : %zu\n", comparable);
	printf("PFN unavailable      : %zu\n", unavailable);
	printf("PFN unchanged        : %zu\n", unchanged);
	printf("PFN changed          : %zu\n", changed);

	if (before->pages != 0) {
		size_t samples[3] = {
			0,
			before->pages > 1 ? 1 : 0,
			before->pages - 1
		};

		printf("\n");
		printf("page     before PFN      after PFN       same\n");

		for (size_t index = 0; index < 3; ++index) {
			size_t local = samples[index];
			size_t page = first_page + local;

			printf("%-8zu "
			       "0x%011" PRIx64 " "
			       "0x%011" PRIx64 " "
			       "%s\n",
			       page,
			       before->pfns[local],
			       after->pfns[local],
			       before->pfns[local] ==
			       after->pfns[local] ? "yes" : "no");
		}
	}
}

static void free_snapshot(struct pfn_snapshot *snapshot)
{
	free(snapshot->pfns);
	free(snapshot->present);

	memset(snapshot, 0, sizeof(*snapshot));
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t private_pages = 512;

	if (argc >= 2) {
		size_mib = (size_t)strtoul(argv[1], NULL, 0);
	}

	if (argc >= 3) {
		private_pages = (size_t)strtoul(argv[2], NULL, 0);
	}

	if (argc > 3 || size_mib == 0) {
		fprintf(stderr, "Usage: %s [MiB] [private_pages]\n", argv[0]);

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

	if (private_pages == 0 || private_pages > pages) {
		fprintf(stderr,
			"invalid private_pages=%zu, pages=%zu\n",
			private_pages, pages);

		return EXIT_FAILURE;
	}

	warm_up_proc_files();

	pid_t parent_pid = getpid();

	unsigned long vm_pte_baseline = read_vm_pte(parent_pid);

	volatile unsigned char *memory = map_anon_aligned(length,
							  TWO_MIB);

	if (memory == MAP_FAILED)
		die("map_anon_aligned");

	struct perf_group parent_perf;
	struct perf_counts warmup_counts;

	if (perf_group_open(&parent_perf) != 0)
		return EXIT_FAILURE;

	if (perf_group_start(&parent_perf) != 0)
		return EXIT_FAILURE;

	asm volatile ("":::"memory");

	if (perf_group_stop(&parent_perf, &warmup_counts) != 0) {
		return EXIT_FAILURE;
	}

	int kpageflags_fd = open("/proc/kpageflags",
				 O_RDONLY | O_CLOEXEC);

	if (kpageflags_fd < 0)
		die("open /proc/kpageflags");

	printf("parent PID           : %ld\n", (long)parent_pid);
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 2 MiB    : 0x%lx\n", (unsigned long)
	       ((uintptr_t) memory & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);
	printf("private pages        : %zu\n", private_pages);
	printf("private size         : %zu kB\n",
	       private_pages * page_size / 1024);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	struct mapping_stats parent_stats;

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	print_mapping_stats("1. untouched parent mapping before fork",
			    parent_pid, &parent_stats, vm_pte_baseline);

	int parent_to_child[2];
	int child_to_parent[2];

	if (pipe(parent_to_child) != 0)
		die("pipe parent_to_child");

	if (pipe(child_to_parent) != 0)
		die("pipe child_to_parent");

	pid_t child_pid = fork();

	if (child_pid < 0)
		die("fork");

	if (child_pid == 0) {
		close(parent_to_child[1]);
		close(child_to_parent[0]);
		close(kpageflags_fd);

		perf_group_close(&parent_perf);

		struct perf_group child_perf;
		struct perf_counts child_warmup;

		if (perf_group_open(&child_perf) != 0)
			_exit(EXIT_FAILURE);

		if (perf_group_start(&child_perf) != 0)
			_exit(EXIT_FAILURE);

		asm volatile ("":::"memory");

		if (perf_group_stop(&child_perf, &child_warmup) != 0) {
			_exit(EXIT_FAILURE);
		}

		char ready = 'R';

		write_full(child_to_parent[1], &ready, sizeof(ready));

		char command;

		read_full(parent_to_child[0], &command, sizeof(command));

		if (command != 'R')
			_exit(EXIT_FAILURE);

		struct measurement child_zero_read =
		    measure_read_range(&child_perf,
				       memory,
				       0,
				       pages,
				       page_size);

		write_full(child_to_parent[1],
			   &child_zero_read, sizeof(child_zero_read));

		read_full(parent_to_child[0], &command, sizeof(command));

		if (command != 'C')
			_exit(EXIT_FAILURE);

		struct signatures child_view = read_signatures(memory,
							       0,
							       private_pages,
							       page_size);

		write_full(child_to_parent[1], &child_view, sizeof(child_view));

		read_full(parent_to_child[0], &command, sizeof(command));

		if (command != 'W')
			_exit(EXIT_FAILURE);

		struct measurement child_private_write =
		    measure_write_range(&child_perf,
					memory,
					0,
					private_pages,
					page_size,
					child_value);

		write_full(child_to_parent[1],
			   &child_private_write, sizeof(child_private_write));

		read_full(parent_to_child[0], &command, sizeof(command));

		perf_group_close(&child_perf);

		if (command != 'E')
			_exit(EXIT_FAILURE);

		close(parent_to_child[0]);
		close(child_to_parent[1]);

		_exit(EXIT_SUCCESS);
	}

	close(parent_to_child[0]);
	close(child_to_parent[1]);

	char ready;

	read_full(child_to_parent[0], &ready, sizeof(ready));

	if (ready != 'R') {
		fprintf(stderr, "child did not become ready\n");

		return EXIT_FAILURE;
	}

	printf("\nchild PID            : %ld\n", (long)child_pid);

	struct mapping_stats child_stats;

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	read_mapping_stats(child_pid, (const void *)memory, &child_stats);

	print_mapping_stats("2. parent immediately after fork",
			    parent_pid, &parent_stats, vm_pte_baseline);

	print_mapping_stats("2. child immediately after fork",
			    child_pid, &child_stats, vm_pte_baseline);

	struct pair_summary immediately_after_fork =
	    scan_process_pair(parent_pid,
			      child_pid,
			      (const void *)memory,
			      pages,
			      page_size);

	print_pair_summary("2. pagemap immediately after fork",
			   &immediately_after_fork);

	/*
	 * 父子分别读取全部页面。
	 */
	struct measurement parent_zero_read = measure_read_range(&parent_perf,
								 memory,
								 0,
								 pages,
								 page_size);

	char command = 'R';

	write_full(parent_to_child[1], &command, sizeof(command));

	struct measurement child_zero_read;

	read_full(child_to_parent[0],
		  &child_zero_read, sizeof(child_zero_read));

	print_measurement("3. parent first read of untouched pages",
			  &parent_zero_read, pages);

	print_measurement("3. child first read of untouched pages",
			  &child_zero_read, pages);

	struct signatures expected_zero = expected_zero_signatures();

	print_signature_check("3. parent sees zero contents",
			      parent_zero_read.signatures, expected_zero);

	print_signature_check("3. child sees zero contents",
			      child_zero_read.signatures, expected_zero);

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	read_mapping_stats(child_pid, (const void *)memory, &child_stats);

	print_mapping_stats("3. parent after zero-page reads",
			    parent_pid, &parent_stats, vm_pte_baseline);

	print_mapping_stats("3. child after zero-page reads",
			    child_pid, &child_stats, vm_pte_baseline);

	struct pair_summary after_zero_reads = scan_process_pair(parent_pid,
								 child_pid,
								 (const void *)
								 memory,
								 pages,
								 page_size);

	print_pair_summary("3. PFNs after both map the zero page",
			   &after_zero_reads);

	print_selected_entries("3. selected entries after zero-page reads",
			       parent_pid,
			       child_pid,
			       (const void *)memory,
			       pages, private_pages, page_size, kpageflags_fd);

	/*
	 * 父进程首先写前512页。
	 */
	struct pfn_snapshot parent_before_write = capture_snapshot(parent_pid,
								   (const void
								    *)memory,
								   0,
								   private_pages,
								   page_size);

	struct measurement parent_private_write =
	    measure_write_range(&parent_perf,
				memory,
				0,
				private_pages,
				page_size,
				parent_value);

	struct pfn_snapshot parent_after_write = capture_snapshot(parent_pid,
								  (const void *)
								  memory,
								  0,
								  private_pages,
								  page_size);

	print_measurement("4. parent zero-page to private writes",
			  &parent_private_write, private_pages);

	compare_snapshots("4. parent PFNs change from zero page",
			  &parent_before_write, &parent_after_write, 0);

	struct signatures expected_parent_private =
	    expected_private_signatures(0,
					private_pages,
					parent_value);

	print_signature_check("4. parent private contents",
			      parent_private_write.signatures,
			      expected_parent_private);

	/*
	 * 子进程此时仍应看到零。
	 */
	command = 'C';

	write_full(parent_to_child[1], &command, sizeof(command));

	struct signatures child_view_after_parent;

	read_full(child_to_parent[0],
		  &child_view_after_parent, sizeof(child_view_after_parent));

	print_signature_check("4. child still sees zero contents",
			      child_view_after_parent, expected_zero);

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	read_mapping_stats(child_pid, (const void *)memory, &child_stats);

	print_mapping_stats("4. parent after its private allocation",
			    parent_pid, &parent_stats, vm_pte_baseline);

	print_mapping_stats("4. child after parent writes",
			    child_pid, &child_stats, vm_pte_baseline);

	struct pair_summary after_parent_write = scan_process_pair(parent_pid,
								   child_pid,
								   (const void
								    *)memory,
								   pages,
								   page_size);

	print_pair_summary("4. PFNs after only parent writes",
			   &after_parent_write);

	print_selected_entries("4. selected entries after parent writes",
			       parent_pid,
			       child_pid,
			       (const void *)memory,
			       pages, private_pages, page_size, kpageflags_fd);

	/*
	 * 子进程再写相同的512页。
	 */
	command = 'W';

	write_full(parent_to_child[1], &command, sizeof(command));

	struct measurement child_private_write;

	read_full(child_to_parent[0],
		  &child_private_write, sizeof(child_private_write));

	print_measurement("5. child zero-page to private writes",
			  &child_private_write, private_pages);

	struct signatures expected_child_private =
	    expected_private_signatures(0,
					private_pages,
					child_value);

	print_signature_check("5. child private contents",
			      child_private_write.signatures,
			      expected_child_private);

	struct signatures parent_final_view = read_signatures(memory,
							      0,
							      private_pages,
							      page_size);

	print_signature_check("5. parent retains its own contents",
			      parent_final_view, expected_parent_private);

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	read_mapping_stats(child_pid, (const void *)memory, &child_stats);

	print_mapping_stats("5. parent after both processes write",
			    parent_pid, &parent_stats, vm_pte_baseline);

	print_mapping_stats("5. child after both processes write",
			    child_pid, &child_stats, vm_pte_baseline);

	struct pair_summary after_both_write = scan_process_pair(parent_pid,
								 child_pid,
								 (const void *)
								 memory,
								 pages,
								 page_size);

	print_pair_summary("5. PFNs after both processes write",
			   &after_both_write);

	print_selected_entries("5. selected entries after both write",
			       parent_pid,
			       child_pid,
			       (const void *)memory,
			       pages, private_pages, page_size, kpageflags_fd);

	command = 'E';

	write_full(parent_to_child[1], &command, sizeof(command));

	int child_status = 0;

	if (waitpid(child_pid, &child_status, 0) < 0) {
		die("waitpid");
	}

	printf("\n========== 6. child exit ==========\n");

	printf("child exited normally: %s\n",
	       WIFEXITED(child_status) ? "yes" : "NO");

	if (WIFEXITED(child_status)) {
		printf("child exit status    : %d\n",
		       WEXITSTATUS(child_status));
	}

	printf("read_sink            : %" PRIu64 "\n", read_sink);

	free_snapshot(&parent_before_write);
	free_snapshot(&parent_after_write);

	close(kpageflags_fd);
	close(parent_to_child[1]);
	close(child_to_parent[0]);

	perf_group_close(&parent_perf);

	if (munmap((void *)memory, length) != 0) {
		die("munmap");
	}

	return EXIT_SUCCESS;
}
