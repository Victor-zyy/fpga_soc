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

static volatile uint64_t read_sink;

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

struct measurement {
	uint64_t cycles;
	uint64_t instructions;

	long minor_faults;
	long major_faults;
};

struct signatures {
	uint64_t offset0_sum;
	uint64_t offset1_sum;
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

	size_t comparable;
	size_t unavailable;

	size_t same_pfn;
	size_t different_pfn;
};

struct pfn_snapshot {
	size_t pages;

	uint64_t *pfns;
	unsigned char *present;
	unsigned char *exclusive;
};

struct child_cow_report {
	struct measurement measurement;
	struct signatures contents;
};

struct child_view_report {
	struct signatures range_a;
	struct signatures range_b;
	struct signatures range_c;
};

struct process_status {
	int proc_exists;
	int state_found;
	char state;

	int vm_pte_found;
	unsigned long vm_pte_kb;
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
		ssize_t result = write(fd,
				       current,
				       remaining);

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
		ssize_t result = read(fd,
				      current,
				      remaining);

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
	int found = 0;

	build_proc_path(path, sizeof(path), pid, "status");

	FILE *fp = fopen(path, "r");

	if (fp == NULL)
		die("fopen status");

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &value) == 1) {
			found = 1;
			break;
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "VmPTE not found for PID %ld\n", (long)pid);

		exit(EXIT_FAILURE);
	}

	return value;
}

static struct process_status read_process_status(pid_t pid)
{
	struct process_status result;

	memset(&result, 0, sizeof(result));

	char path[128];
	char line[512];

	build_proc_path(path, sizeof(path), pid, "status");

	FILE *fp = fopen(path, "r");

	if (fp == NULL)
		return result;

	result.proc_exists = 1;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char state;

		if (sscanf(line, "State:\t%c", &state) == 1) {
			result.state_found = 1;
			result.state = state;
		}

		if (sscanf(line, "VmPTE: %lu kB", &result.vm_pte_kb) == 1) {
			result.vm_pte_found = 1;
		}
	}

	fclose(fp);
	return result;
}

static char read_process_state(pid_t pid)
{
	char path[128];
	char line[1024];

	build_proc_path(path, sizeof(path), pid, "stat");

	FILE *fp = fopen(path, "r");

	if (fp == NULL)
		return '\0';

	if (fgets(line, sizeof(line), fp) == NULL) {
		fclose(fp);
		return '\0';
	}

	fclose(fp);

	char *right_parenthesis = strrchr(line, ')');

	if (right_parenthesis == NULL || right_parenthesis[1] != ' ') {
		return '\0';
	}

	return right_parenthesis[2];
}

static void wait_for_zombie(pid_t pid)
{
	for (unsigned int attempt = 0; attempt < 10000; ++attempt) {
		char state = read_process_state(pid);

		if (state == 'Z')
			return;

		if (state == '\0') {
			fprintf(stderr,
				"child disappeared before zombie observation\n");

			exit(EXIT_FAILURE);
		}

		usleep(1000);
	}

	fprintf(stderr, "timeout waiting for zombie child\n");
	exit(EXIT_FAILURE);
}

static int mapping_exists_in_smaps(pid_t pid, const void *address)
{
	char path[128];
	char line[512];

	uintptr_t target = (uintptr_t) address;

	build_proc_path(path, sizeof(path), pid, "smaps");

	FILE *fp = fopen(path, "r");

	if (fp == NULL)
		return 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;

		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if (target >= (uintptr_t) start &&
			    target < (uintptr_t) end) {
				fclose(fp);
				return 1;
			}
		}
	}

	fclose(fp);
	return 0;
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

static void print_process_status(const char *name,
				 pid_t pid, const void *mapping)
{
	struct process_status status = read_process_status(pid);

	printf("\n========== %s ==========\n", name);

	printf("PID                  : %ld\n", (long)pid);
	printf("/proc entry exists   : %s\n",
	       status.proc_exists ? "yes" : "no");

	if (!status.proc_exists)
		return;

	printf("state available      : %s\n",
	       status.state_found ? "yes" : "no");

	if (status.state_found) {
		printf("process state        : %c\n", status.state);
	}

	printf("VmPTE field present  : %s\n",
	       status.vm_pte_found ? "yes" : "no");

	if (status.vm_pte_found) {
		printf("VmPTE                : %lu kB\n", status.vm_pte_kb);
	}

	printf("mapping in smaps     : %s\n",
	       mapping_exists_in_smaps(pid, mapping) ? "yes" : "no");
}

static unsigned char original_value(size_t page)
{
	return (unsigned char)((page % 251U) + 1U);
}

static unsigned char child_cow_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0x5aU);
}

static unsigned char parent_cow_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0xa5U);
}

static unsigned char post_exit_a_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0x3cU);
}

static unsigned char post_exit_b_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0xc3U);
}

static unsigned char post_exit_c_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0x69U);
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

static struct signatures expected_signatures(size_t first_page,
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
		unsigned char value = original_value(page);
		size_t offset = page * page_size;

		memory[offset] = value;
		memory[offset + 1] = value;
	}

	if (perf_group_stop(perf_group, &perf) != 0) {
		exit(EXIT_FAILURE);
	}

	after = get_usage_snapshot();

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
		.pfn = raw & PM_PFN_MASK,

		.present = (raw & PM_PRESENT) != 0,

		.swapped = (raw & PM_SWAPPED) != 0,

		.exclusive = (raw & PM_EXCLUSIVE) != 0,

		.file_or_shared_anon = (raw & PM_FILE_OR_SHANON) != 0,
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
			++summary.unavailable;
			continue;
		}

		++summary.comparable;

		if (parent_entry.pfn == child_entry.pfn) {
			++summary.same_pfn;
		} else {
			++summary.different_pfn;
		}
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

	printf("parent exclusive     : %zu\n", summary->parent_exclusive);
	printf("child exclusive      : %zu\n", summary->child_exclusive);

	printf("parent file-bit      : %zu\n", summary->parent_file_bit);
	printf("child file-bit       : %zu\n", summary->child_file_bit);

	printf("PFN comparable       : %zu\n", summary->comparable);
	printf("PFN unavailable      : %zu\n", summary->unavailable);
	printf("same PFN             : %zu\n", summary->same_pfn);
	printf("different PFN        : %zu\n", summary->different_pfn);
}

static void print_pair_samples(const char *name,
			       pid_t parent_pid,
			       pid_t child_pid,
			       const void *address,
			       size_t pages,
			       size_t range_pages, size_t page_size)
{
	size_t samples[8];
	size_t count = 0;

#define ADD_SAMPLE(value)                                                   \
    do {                                                                    \
        size_t sample_value = (value);                                      \
        if (sample_value < pages) {                                         \
            int duplicate = 0;                                              \
            for (size_t i = 0; i < count; ++i) {                            \
                if (samples[i] == sample_value)                             \
                    duplicate = 1;                                          \
            }                                                               \
            if (!duplicate)                                                 \
                samples[count++] = sample_value;                            \
        }                                                                   \
    } while (0)

	ADD_SAMPLE(0);
	ADD_SAMPLE(range_pages - 1);
	ADD_SAMPLE(range_pages);
	ADD_SAMPLE(2 * range_pages - 1);
	ADD_SAMPLE(2 * range_pages);
	ADD_SAMPLE(3 * range_pages - 1);
	ADD_SAMPLE(3 * range_pages);
	ADD_SAMPLE(pages - 1);

#undef ADD_SAMPLE

	int parent_pagemap = open_pagemap(parent_pid);

	int child_pagemap = open_pagemap(child_pid);

	printf("\n========== %s ==========\n", name);

	printf("page     parent PFN      child PFN       "
	       "same  Pexcl Cexcl\n");

	for (size_t index = 0; index < count; ++index) {
		size_t page = samples[index];

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

		printf("%-8zu "
		       "0x%011" PRIx64 " "
		       "0x%011" PRIx64 " "
		       "%-5s %-5d %-5d\n",
		       page,
		       parent_entry.pfn,
		       child_entry.pfn,
		       same, parent_entry.exclusive, child_entry.exclusive);
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

	snapshot.exclusive = calloc(page_count, sizeof(*snapshot.exclusive));

	if (snapshot.pfns == NULL ||
	    snapshot.present == NULL || snapshot.exclusive == NULL) {
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
		snapshot.exclusive[index] = (unsigned char)entry.exclusive;
	}

	close(pagemap_fd);
	return snapshot;
}

static void print_snapshot_summary(const char *name,
				   const struct pfn_snapshot *snapshot)
{
	size_t present = 0;
	size_t exclusive = 0;

	for (size_t page = 0; page < snapshot->pages; ++page) {
		if (snapshot->present[page])
			++present;

		if (snapshot->present[page] && snapshot->exclusive[page]) {
			++exclusive;
		}
	}

	printf("\n========== %s ==========\n", name);

	printf("pages                : %zu\n", snapshot->pages);
	printf("present              : %zu\n", present);
	printf("exclusive            : %zu\n", exclusive);
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
	size_t unavailable = 0;
	size_t unchanged = 0;
	size_t changed = 0;

	for (size_t page = 0; page < before->pages; ++page) {
		if (!before->present[page] ||
		    !after->present[page] ||
		    (before->pfns[page] == 0 && after->pfns[page] == 0)) {
			++unavailable;
			continue;
		}

		++comparable;

		if (before->pfns[page] == after->pfns[page]) {
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
		size_t selected[3] = {
			0,
			before->pages > 1 ? 1 : 0,
			before->pages - 1
		};

		printf("\n");
		printf("page     before PFN      after PFN       same\n");

		for (size_t index = 0; index < 3; ++index) {
			size_t local = selected[index];
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
	free(snapshot->exclusive);

	memset(snapshot, 0, sizeof(*snapshot));
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t range_pages = 512;

	if (argc >= 2) {
		size_mib = (size_t)strtoul(argv[1], NULL, 0);
	}

	if (argc >= 3) {
		range_pages = (size_t)strtoul(argv[2], NULL, 0);
	}

	if (argc > 3 || size_mib == 0) {
		fprintf(stderr, "Usage: %s [MiB] [range_pages]\n", argv[0]);

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

	if (range_pages == 0 || 3 * range_pages > pages) {
		fprintf(stderr,
			"range_pages=%zu invalid for pages=%zu\n",
			range_pages, pages);

		return EXIT_FAILURE;
	}

	size_t range_a_first = 0;
	size_t range_b_first = range_pages;
	size_t range_c_first = 2 * range_pages;
	size_t range_d_first = 3 * range_pages;

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

	printf("parent PID           : %ld\n", (long)parent_pid);
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 2 MiB    : 0x%lx\n", (unsigned long)
	       ((uintptr_t) memory & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("pages                : %zu\n", pages);
	printf("range A              : %zu-%zu\n",
	       range_a_first, range_a_first + range_pages - 1);
	printf("range B              : %zu-%zu\n",
	       range_b_first, range_b_first + range_pages - 1);
	printf("range C              : %zu-%zu\n",
	       range_c_first, range_c_first + range_pages - 1);
	printf("range D              : %zu-%zu\n", range_d_first, pages - 1);
	printf("range size           : %zu kB\n",
	       range_pages * page_size / 1024);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	struct measurement initial_fill = measure_initial_fill(&parent_perf,
							       memory,
							       pages,
							       page_size);

	print_measurement("1. parent initial anonymous allocation",
			  &initial_fill, pages);

	struct mapping_stats parent_stats;

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	print_mapping_stats("1. parent before fork",
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

		struct child_cow_report cow_report;

		memset(&cow_report, 0, sizeof(cow_report));

		cow_report.measurement =
		    measure_write_range(&child_perf,
					memory,
					range_a_first,
					range_pages,
					page_size, child_cow_value);

		cow_report.contents =
		    read_signatures(memory,
				    range_a_first, range_pages, page_size);

		write_full(child_to_parent[1], &cow_report, sizeof(cow_report));

		read_full(parent_to_child[0], &command, sizeof(command));

		if (command != 'S')
			_exit(EXIT_FAILURE);

		struct child_view_report view_report;

		view_report.range_a =
		    read_signatures(memory,
				    range_a_first, range_pages, page_size);

		view_report.range_b =
		    read_signatures(memory,
				    range_b_first, range_pages, page_size);

		view_report.range_c =
		    read_signatures(memory,
				    range_c_first, range_pages, page_size);

		write_full(child_to_parent[1],
			   &view_report, sizeof(view_report));

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

	struct pair_summary after_fork = scan_process_pair(parent_pid,
							   child_pid,
							   (const void *)memory,
							   pages,
							   page_size);

	print_pair_summary("2. PFNs immediately after fork", &after_fork);

	/*
	 * 子进程COW区域A。
	 */
	char command = 'W';

	write_full(parent_to_child[1], &command, sizeof(command));

	struct child_cow_report child_cow;

	read_full(child_to_parent[0], &child_cow, sizeof(child_cow));

	print_measurement("3. child COW of range A",
			  &child_cow.measurement, range_pages);

	struct signatures expected_child_a = expected_signatures(range_a_first,
								 range_pages,
								 child_cow_value,
								 original_value);

	print_signature_check("3. child range A contents",
			      child_cow.contents, expected_child_a);

	/*
	 * 父进程COW区域B。
	 */
	struct measurement parent_cow = measure_write_range(&parent_perf,
							    memory,
							    range_b_first,
							    range_pages,
							    page_size,
							    parent_cow_value);

	print_measurement("3. parent COW of range B", &parent_cow, range_pages);

	/*
	 * 让子进程读取A、B、C三个区域，确认互不影响。
	 */
	command = 'S';

	write_full(parent_to_child[1], &command, sizeof(command));

	struct child_view_report child_view;

	read_full(child_to_parent[0], &child_view, sizeof(child_view));

	struct signatures expected_original_a =
	    expected_signatures(range_a_first,
				range_pages,
				original_value,
				original_value);

	struct signatures expected_original_b =
	    expected_signatures(range_b_first,
				range_pages,
				original_value,
				original_value);

	struct signatures expected_original_c =
	    expected_signatures(range_c_first,
				range_pages,
				original_value,
				original_value);

	print_signature_check("3. child retains its range A COW contents",
			      child_view.range_a, expected_child_a);

	print_signature_check("3. child still sees original range B",
			      child_view.range_b, expected_original_b);

	print_signature_check("3. child sees original range C",
			      child_view.range_c, expected_original_c);

	struct signatures parent_a = read_signatures(memory,
						     range_a_first,
						     range_pages,
						     page_size);

	struct signatures parent_b = read_signatures(memory,
						     range_b_first,
						     range_pages,
						     page_size);

	struct signatures parent_c = read_signatures(memory,
						     range_c_first,
						     range_pages,
						     page_size);

	struct signatures expected_parent_b = expected_signatures(range_b_first,
								  range_pages,
								  parent_cow_value,
								  original_value);

	print_signature_check("3. parent still sees original range A",
			      parent_a, expected_original_a);

	print_signature_check("3. parent sees its range B COW contents",
			      parent_b, expected_parent_b);

	print_signature_check("3. parent sees original range C",
			      parent_c, expected_original_c);

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	read_mapping_stats(child_pid, (const void *)memory, &child_stats);

	print_mapping_stats("3. parent after both COW operations",
			    parent_pid, &parent_stats, vm_pte_baseline);

	print_mapping_stats("3. child after both COW operations",
			    child_pid, &child_stats, vm_pte_baseline);

	struct pair_summary after_both_cow = scan_process_pair(parent_pid,
							       child_pid,
							       (const void *)
							       memory,
							       pages,
							       page_size);

	print_pair_summary("3. PFNs after both COW operations",
			   &after_both_cow);

	print_pair_samples("3. selected PFNs before child exit",
			   parent_pid,
			   child_pid,
			   (const void *)memory, pages, range_pages, page_size);

	print_process_status("3. child process while alive",
			     child_pid, (const void *)memory);

	/*
	 * 记录子进程退出前父进程的全部PFN。
	 */
	struct pfn_snapshot parent_before_exit = capture_snapshot(parent_pid,
								  (const void *)
								  memory,
								  0,
								  pages,
								  page_size);

	print_snapshot_summary("4. parent PFNs before child exit",
			       &parent_before_exit);

	/*
	 * 让子进程退出，但暂不waitpid。
	 */
	command = 'E';

	write_full(parent_to_child[1], &command, sizeof(command));

	wait_for_zombie(child_pid);

	print_process_status("4. child after exit, before waitpid",
			     child_pid, (const void *)memory);

	/*
	 * 子进程已经释放mm，此时父进程应已收敛。
	 */
	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	print_mapping_stats("4. parent while child is zombie",
			    parent_pid, &parent_stats, vm_pte_baseline);

	struct pfn_snapshot parent_after_exit = capture_snapshot(parent_pid,
								 (const void *)
								 memory,
								 0,
								 pages,
								 page_size);

	print_snapshot_summary("4. parent PFNs after child mm release",
			       &parent_after_exit);

	compare_snapshots("4. parent PFNs across child exit",
			  &parent_before_exit, &parent_after_exit, 0);

	/*
	 * 现在回收zombie task。
	 */
	int child_status = 0;

	if (waitpid(child_pid, &child_status, 0) < 0) {
		die("waitpid");
	}

	printf("\n========== 5. child reaped ==========\n");

	printf("child exited normally: %s\n",
	       WIFEXITED(child_status) ? "yes" : "NO");

	if (WIFEXITED(child_status)) {
		printf("child exit status    : %d\n",
		       WEXITSTATUS(child_status));
	}

	print_process_status("5. child after waitpid",
			     child_pid, (const void *)memory);

	/*
	 * 区域A：
	 * 子进程曾COW，父进程未写。
	 * 预计写保护fault，但原地复用。
	 */
	struct pfn_snapshot a_before = capture_snapshot(parent_pid,
							(const void *)memory,
							range_a_first,
							range_pages,
							page_size);

	struct measurement post_exit_a = measure_write_range(&parent_perf,
							     memory,
							     range_a_first,
							     range_pages,
							     page_size,
							     post_exit_a_value);

	struct pfn_snapshot a_after = capture_snapshot(parent_pid,
						       (const void *)memory,
						       range_a_first,
						       range_pages,
						       page_size);

	print_measurement("6. write range A after child exit",
			  &post_exit_a, range_pages);

	compare_snapshots("6. range A PFN comparison",
			  &a_before, &a_after, range_a_first);

	/*
	 * 区域B：
	 * 父进程已在子进程存活时完成COW，PTE应已可写。
	 */
	struct pfn_snapshot b_before = capture_snapshot(parent_pid,
							(const void *)memory,
							range_b_first,
							range_pages,
							page_size);

	struct measurement post_exit_b = measure_write_range(&parent_perf,
							     memory,
							     range_b_first,
							     range_pages,
							     page_size,
							     post_exit_b_value);

	struct pfn_snapshot b_after = capture_snapshot(parent_pid,
						       (const void *)memory,
						       range_b_first,
						       range_pages,
						       page_size);

	print_measurement("7. write range B after child exit",
			  &post_exit_b, range_pages);

	compare_snapshots("7. range B PFN comparison",
			  &b_before, &b_after, range_b_first);

	/*
	 * 区域C：
	 * 父子存活期间一直共享。
	 * 子退出后页面独占，但PTE仍预计写保护。
	 */
	struct pfn_snapshot c_before = capture_snapshot(parent_pid,
							(const void *)memory,
							range_c_first,
							range_pages,
							page_size);

	struct measurement post_exit_c = measure_write_range(&parent_perf,
							     memory,
							     range_c_first,
							     range_pages,
							     page_size,
							     post_exit_c_value);

	struct pfn_snapshot c_after = capture_snapshot(parent_pid,
						       (const void *)memory,
						       range_c_first,
						       range_pages,
						       page_size);

	print_measurement("8. write range C after child exit",
			  &post_exit_c, range_pages);

	compare_snapshots("8. range C PFN comparison",
			  &c_before, &c_after, range_c_first);

	/*
	 * 最终内容验证。
	 */
	struct signatures final_a = read_signatures(memory,
						    range_a_first,
						    range_pages,
						    page_size);

	struct signatures final_b = read_signatures(memory,
						    range_b_first,
						    range_pages,
						    page_size);

	struct signatures final_c = read_signatures(memory,
						    range_c_first,
						    range_pages,
						    page_size);

	struct signatures final_d = read_signatures(memory,
						    range_d_first,
						    pages - range_d_first,
						    page_size);

	struct signatures expected_final_a = expected_signatures(range_a_first,
								 range_pages,
								 post_exit_a_value,
								 original_value);

	struct signatures expected_final_b = expected_signatures(range_b_first,
								 range_pages,
								 post_exit_b_value,
								 original_value);

	struct signatures expected_final_c = expected_signatures(range_c_first,
								 range_pages,
								 post_exit_c_value,
								 original_value);

	struct signatures expected_final_d = expected_signatures(range_d_first,
								 pages -
								 range_d_first,
								 original_value,
								 original_value);

	print_signature_check("9. final range A", final_a, expected_final_a);

	print_signature_check("9. final range B", final_b, expected_final_b);

	print_signature_check("9. final range C", final_c, expected_final_c);

	print_signature_check("9. final untouched range D",
			      final_d, expected_final_d);

	read_mapping_stats(parent_pid, (const void *)memory, &parent_stats);

	print_mapping_stats("9. final parent mapping",
			    parent_pid, &parent_stats, vm_pte_baseline);

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);

	free_snapshot(&parent_before_exit);
	free_snapshot(&parent_after_exit);

	free_snapshot(&a_before);
	free_snapshot(&a_after);

	free_snapshot(&b_before);
	free_snapshot(&b_after);

	free_snapshot(&c_before);
	free_snapshot(&c_after);

	close(parent_to_child[1]);
	close(child_to_parent[0]);

	perf_group_close(&parent_perf);

	if (munmap((void *)memory, length) != 0) {
		die("munmap");
	}

	return EXIT_SUCCESS;
}
