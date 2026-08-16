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
#define PM_SOFT_DIRTY     (1ULL << 55)
#define PM_EXCLUSIVE      (1ULL << 56)
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

	size_t parent_present;
	size_t child_present;
	size_t both_present;

	size_t parent_file_bit;
	size_t child_file_bit;

	size_t parent_exclusive;
	size_t child_exclusive;

	size_t pfn_comparable;
	size_t pfn_hidden;

	size_t same_pfn;
	size_t different_pfn;
};

struct child_report {
	struct measurement cow_measurement;
};

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

static int starts_with(const char *line, const char *prefix)
{
	return strncmp(line, prefix, strlen(prefix)) == 0;
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
		} else if (starts_with(line, "Shared_Clean:")) {
			(void)sscanf(line,
				     "Shared_Clean: %lu kB",
				     &stats->shared_clean_kb);
		} else if (starts_with(line, "Shared_Dirty:")) {
			(void)sscanf(line,
				     "Shared_Dirty: %lu kB",
				     &stats->shared_dirty_kb);
		} else if (starts_with(line, "Private_Clean:")) {
			(void)sscanf(line,
				     "Private_Clean: %lu kB",
				     &stats->private_clean_kb);
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

static unsigned char child_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0x5aU);
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

static struct signatures expected_uniform(size_t first_page, size_t page_count)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		unsigned char value = original_value(page);

		result.offset0_sum += value;
		result.offset1_sum += value;
	}

	return result;
}

static struct signatures expected_child_private(size_t first_page,
						size_t page_count)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		result.offset0_sum += child_value(page);
		result.offset1_sum += original_value(page);
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

	if (munmap(reservation, reserve_length) != 0)
		return MAP_FAILED;

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

static struct measurement measure_initial_fill(struct perf_group *perf_group,
					       volatile unsigned char *memory,
					       size_t pages, size_t page_size)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < pages; ++page) {
		size_t offset = page * page_size;
		unsigned char value = original_value(page);

		memory[offset] = value;
		memory[offset + 1] = value;
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	result.signatures = read_signatures(memory, 0, pages, page_size);

	return result;
}

static struct measurement measure_child_cow(struct perf_group *perf_group,
					    volatile unsigned char *memory,
					    size_t cow_pages, size_t page_size)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < cow_pages; ++page) {
		memory[page * page_size] = child_value(page);
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	result.signatures = read_signatures(memory, 0, cow_pages, page_size);

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
		.file_or_shared_anon = (raw & PM_FILE_OR_SHANON) != 0,
		.exclusive = (raw & PM_EXCLUSIVE) != 0,
		.soft_dirty = (raw & PM_SOFT_DIRTY) != 0,
	};

	return entry;
}

static struct pair_summary scan_process_pair(pid_t parent_pid,
					     pid_t child_pid,
					     const void *address,
					     size_t pages, size_t page_size)
{
	struct pair_summary summary;

	memset(&summary, 0, sizeof(summary));
	summary.pages = pages;

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

		if (parent_entry.present)
			++summary.parent_present;

		if (child_entry.present)
			++summary.child_present;

		if (parent_entry.present && parent_entry.file_or_shared_anon) {
			++summary.parent_file_bit;
		}

		if (child_entry.present && child_entry.file_or_shared_anon) {
			++summary.child_file_bit;
		}

		if (parent_entry.present && parent_entry.exclusive) {
			++summary.parent_exclusive;
		}

		if (child_entry.present && child_entry.exclusive) {
			++summary.child_exclusive;
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

		if (parent_entry.pfn == child_entry.pfn)
			++summary.same_pfn;
		else
			++summary.different_pfn;
	}

	close(child_pagemap);
	close(parent_pagemap);

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

	printf("parent file-bit      : %zu\n", summary->parent_file_bit);
	printf("child file-bit       : %zu\n", summary->child_file_bit);

	printf("parent exclusive     : %zu\n", summary->parent_exclusive);
	printf("child exclusive      : %zu\n", summary->child_exclusive);

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
				   pid_t parent_pid,
				   pid_t child_pid,
				   const void *address,
				   size_t pages,
				   size_t cow_pages, size_t page_size)
{
	size_t indices[8];
	size_t count = 0;

	add_selected_index(indices, &count, 0, pages);
	add_selected_index(indices, &count, 1, pages);

	if (cow_pages != 0) {
		add_selected_index(indices, &count, cow_pages - 1, pages);
	}

	add_selected_index(indices, &count, cow_pages, pages);

	add_selected_index(indices, &count, cow_pages + 1, pages);

	if (pages != 0) {
		add_selected_index(indices, &count, pages - 1, pages);
	}

	int parent_pagemap = open_pagemap(parent_pid);

	int child_pagemap = open_pagemap(child_pid);

	printf("\n========== %s ==========\n", name);

	printf("page     parent PFN      child PFN       "
	       "same  Pexcl Cexcl Pfile Cfile\n");

	for (size_t i = 0; i < count; ++i) {
		size_t page = indices[i];

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

		const char *same = "-";

		if (parent_entry.present &&
		    child_entry.present &&
		    !(parent_entry.pfn == 0 && child_entry.pfn == 0)) {
			same =
			    parent_entry.pfn == child_entry.pfn ? "yes" : "no";
		}

		printf("%-8zu 0x%011" PRIx64
		       " 0x%011" PRIx64
		       " %-5s %-5d %-5d %-5d %-5d\n",
		       page,
		       parent_entry.pfn,
		       child_entry.pfn,
		       same,
		       parent_entry.exclusive,
		       child_entry.exclusive,
		       parent_entry.file_or_shared_anon,
		       child_entry.file_or_shared_anon);
	}

	close(child_pagemap);
	close(parent_pagemap);
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t cow_pages = 512;

	if (argc >= 2) {
		size_mib = (size_t)strtoul(argv[1], NULL, 0);
	}

	if (argc >= 3) {
		cow_pages = (size_t)strtoul(argv[2], NULL, 0);
	}

	if (argc > 3 || size_mib == 0) {
		fprintf(stderr, "Usage: %s [MiB] [cow_pages]\n", argv[0]);

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

	if (cow_pages == 0 || cow_pages > pages) {
		fprintf(stderr,
			"invalid cow_pages=%zu, pages=%zu\n", cow_pages, pages);

		return EXIT_FAILURE;
	}

	warm_up_proc_files();

	unsigned long vm_pte_baseline = read_vm_pte(getpid());

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

	printf("parent PID           : %ld\n", (long)getpid());
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 2 MiB    : 0x%lx\n", (unsigned long)
	       ((uintptr_t) memory & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);
	printf("child COW pages      : %zu\n", cow_pages);
	printf("child COW size       : %zu kB\n", cow_pages * page_size / 1024);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	struct measurement initial_fill = measure_initial_fill(&parent_perf,
							       memory,
							       pages,
							       page_size);

	print_measurement("1. parent initial anonymous allocation",
			  &initial_fill, pages);

	struct signatures expected_all = expected_uniform(0, pages);

	print_signature_check("1. parent initial contents",
			      initial_fill.signatures, expected_all);

	struct mapping_stats parent_stats;

	read_mapping_stats(getpid(), (const void *)memory, &parent_stats);

	print_mapping_stats("1. parent before fork",
			    getpid(), &parent_stats, vm_pte_baseline);

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

		if (command != 'W')
			_exit(EXIT_FAILURE);

		struct child_report report;

		memset(&report, 0, sizeof(report));

		report.cow_measurement =
		    measure_child_cow(&child_perf,
				      memory, cow_pages, page_size);

		write_full(child_to_parent[1], &report, sizeof(report));

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

	pid_t parent_pid = getpid();

	printf("\nchild PID            : %ld\n", (long)child_pid);

	struct mapping_stats child_stats;

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	read_mapping_stats(child_pid, (const void *)memory, &child_stats);

	print_mapping_stats("2. parent immediately after fork",
			    parent_pid, &parent_stats, vm_pte_baseline);

	print_mapping_stats("2. child immediately after fork",
			    child_pid, &child_stats, vm_pte_baseline);

	struct pair_summary after_fork = scan_process_pair(parent_pid,
							   child_pid,
							   (const void *)memory,
							   pages,
							   page_size);

	print_pair_summary("2. PFNs immediately after fork", &after_fork);

	print_selected_entries("2. selected PFNs immediately after fork",
			       parent_pid,
			       child_pid,
			       (const void *)memory,
			       pages, cow_pages, page_size);

	char command = 'W';

	write_full(parent_to_child[1], &command, sizeof(command));

	struct child_report child_report;

	read_full(child_to_parent[0], &child_report, sizeof(child_report));

	print_measurement("3. child private COW writes",
			  &child_report.cow_measurement, cow_pages);

	struct signatures expected_child = expected_child_private(0,
								  cow_pages);

	print_signature_check("3. child private contents",
			      child_report.cow_measurement.signatures,
			      expected_child);

	struct signatures parent_after_child_cow = read_signatures(memory,
								   0,
								   cow_pages,
								   page_size);

	struct signatures expected_parent = expected_uniform(0,
							     cow_pages);

	print_signature_check("3. parent still sees original contents",
			      parent_after_child_cow, expected_parent);

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	read_mapping_stats(child_pid, (const void *)memory, &child_stats);

	print_mapping_stats("3. parent after child COW",
			    parent_pid, &parent_stats, vm_pte_baseline);

	print_mapping_stats("3. child after its COW",
			    child_pid, &child_stats, vm_pte_baseline);

	struct pair_summary after_child_cow = scan_process_pair(parent_pid,
								child_pid,
								(const void *)
								memory,
								pages,
								page_size);

	print_pair_summary("3. PFNs after child COW", &after_child_cow);

	print_selected_entries("3. selected PFNs after child COW",
			       parent_pid,
			       child_pid,
			       (const void *)memory,
			       pages, cow_pages, page_size);

	command = 'E';

	write_full(parent_to_child[1], &command, sizeof(command));

	int child_status = 0;

	if (waitpid(child_pid, &child_status, 0) < 0) {
		die("waitpid");
	}

	printf("\n========== 4. child exit ==========\n");

	printf("child exited normally: %s\n",
	       WIFEXITED(child_status) ? "yes" : "NO");

	if (WIFEXITED(child_status)) {
		printf("child exit status    : %d\n",
		       WEXITSTATUS(child_status));
	}

	printf("read_sink            : %" PRIu64 "\n", read_sink);

	close(parent_to_child[1]);
	close(child_to_parent[0]);

	perf_group_close(&parent_perf);

	if (munmap((void *)memory, length) != 0)
		die("munmap");

	return EXIT_SUCCESS;
}
