#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
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

/*
 * 预期访问异常探测状态。
 */
static sigjmp_buf probe_jump;

static volatile sig_atomic_t probe_active;
static volatile sig_atomic_t probe_completed;
static volatile sig_atomic_t probe_signal;
static volatile sig_atomic_t probe_si_code;

static volatile uintptr_t probe_si_address;
static volatile unsigned char probe_read_value;

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

struct perf_measurement {
	uint64_t cycles;
	uint64_t instructions;

	long minor_faults;
	long major_faults;
};

struct syscall_measurement {
	struct perf_measurement perf;

	int result;
	int error_number;
};

struct signatures {
	uint64_t offset0_sum;
	uint64_t offset1_sum;
};

struct range_stats {
	size_t vma_count;

	unsigned long size_kb;
	unsigned long rss_kb;
	unsigned long pss_kb;

	unsigned long shared_clean_kb;
	unsigned long shared_dirty_kb;
	unsigned long private_clean_kb;
	unsigned long private_dirty_kb;

	unsigned long referenced_kb;
	unsigned long anonymous_kb;
};

struct pagemap_entry {
	uint64_t pfn;

	int present;
	int swapped;
	int exclusive;
	int file_or_shared_anon;
};

struct pfn_snapshot {
	size_t pages;

	uint64_t *pfns;
	unsigned char *present;
	unsigned char *exclusive;
	unsigned char *file_bit;
};

struct access_probe {
	int completed;
	int signal_number;
	int si_code;

	uintptr_t fault_address;
	unsigned char read_value;

	long minor_faults;
	long major_faults;
};

typedef unsigned char (*value_function)(size_t page);

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
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

static void warm_up_proc_files(void)
{
	static const char *paths[] = {
		"/proc/self/status",
		"/proc/self/maps",
		"/proc/self/smaps"
	};

	char buffer[512];

	for (size_t index = 0;
	     index < sizeof(paths) / sizeof(paths[0]); ++index) {
		int flags = O_RDONLY | O_CLOEXEC;

		int fd = open(paths[index], flags);

		if (fd < 0)
			die(paths[index]);

		while (read(fd, buffer, sizeof(buffer)) > 0) ;

		close(fd);
	}
}

static unsigned long read_vm_pte(void)
{
	FILE *fp;
	char line[512];

	unsigned long vm_pte_kb = 0;
	int found = 0;

	fp = fopen("/proc/self/status", "r");

	if (fp == NULL)
		die("fopen /proc/self/status");

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &vm_pte_kb) == 1) {
			found = 1;
			break;
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "VmPTE not found\n");
		exit(EXIT_FAILURE);
	}

	return vm_pte_kb;
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

static unsigned char original_value(size_t page)
{
	return (unsigned char)((page % 251U) + 1U);
}

static unsigned char restored_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0x5aU);
}

static unsigned char hot_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0xa5U);
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
					     value_function offset0_function,
					     value_function offset1_function)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		result.offset0_sum += offset0_function(page);

		result.offset1_sum += offset1_function(page);
	}

	return result;
}

static int signatures_equal(struct signatures left, struct signatures right)
{
	return
	    left.offset0_sum == right.offset0_sum &&
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

static struct perf_measurement measure_initial_fill(struct perf_group
						    *perf_group,
						    volatile unsigned char
						    *memory, size_t pages,
						    size_t page_size)
{
	struct perf_measurement result;
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

static struct perf_measurement measure_write_range(struct perf_group
						   *perf_group,
						   volatile unsigned char
						   *memory, size_t first_page,
						   size_t page_count,
						   size_t page_size,
						   value_function value_fn)
{
	struct perf_measurement result;
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

static struct syscall_measurement measure_mprotect(struct perf_group
						   *perf_group, void *address,
						   size_t length,
						   int protection)
{
	struct syscall_measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	errno = 0;

	result.result = mprotect(address, length, protection);

	result.error_number = errno;

	if (perf_group_stop(perf_group, &perf) != 0) {
		exit(EXIT_FAILURE);
	}

	after = get_usage_snapshot();

	result.perf.cycles = perf.cycles;
	result.perf.instructions = perf.instructions;

	result.perf.minor_faults = after.minor_faults - before.minor_faults;

	result.perf.major_faults = after.major_faults - before.major_faults;

	return result;
}

static void print_perf_measurement(const char *name,
				   const struct perf_measurement *measurement,
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

static void print_syscall_measurement(const char *name,
				      const struct syscall_measurement
				      *measurement, size_t pages)
{
	printf("\n========== %s ==========\n", name);

	printf("return value         : %d\n", measurement->result);

	if (measurement->result != 0) {
		printf("errno                : %d (%s)\n",
		       measurement->error_number,
		       strerror(measurement->error_number));
	}

	print_perf_measurement("mprotect performance",
			       &measurement->perf, pages);
}

static void add_smaps_value(struct range_stats *stats, const char *line)
{
	unsigned long value;

	if (sscanf(line, "Size: %lu kB", &value) == 1) {
		stats->size_kb += value;
	} else if (sscanf(line, "Rss: %lu kB", &value) == 1) {
		stats->rss_kb += value;
	} else if (sscanf(line, "Pss: %lu kB", &value) == 1) {
		stats->pss_kb += value;
	} else if (sscanf(line, "Shared_Clean: %lu kB", &value) == 1) {
		stats->shared_clean_kb += value;
	} else if (sscanf(line, "Shared_Dirty: %lu kB", &value) == 1) {
		stats->shared_dirty_kb += value;
	} else if (sscanf(line, "Private_Clean: %lu kB", &value) == 1) {
		stats->private_clean_kb += value;
	} else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1) {
		stats->private_dirty_kb += value;
	} else if (sscanf(line, "Referenced: %lu kB", &value) == 1) {
		stats->referenced_kb += value;
	} else if (sscanf(line, "Anonymous: %lu kB", &value) == 1) {
		stats->anonymous_kb += value;
	}
}

static void print_range_layout(const char *name,
			       const void *mapping,
			       size_t length, unsigned long vm_pte_baseline)
{
	uintptr_t target_start = (uintptr_t) mapping;

	uintptr_t target_end = target_start + length;

	struct range_stats stats;

	memset(&stats, 0, sizeof(stats));

	FILE *fp = fopen("/proc/self/smaps", "r");

	if (fp == NULL)
		die("fopen /proc/self/smaps");

	char line[1024];
	int current_overlaps = 0;

	printf("\n========== %s ==========\n", name);

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long vma_start;
		unsigned long vma_end;
		char permissions[8];

		if (sscanf(line,
			   "%lx-%lx %7s",
			   &vma_start, &vma_end, permissions) == 3) {
			current_overlaps =
			    (uintptr_t) vma_start < target_end &&
			    (uintptr_t) vma_end > target_start;

			if (current_overlaps) {
				++stats.vma_count;

				printf("VMA %zu               : %s",
				       stats.vma_count, line);
			}

			continue;
		}

		if (!current_overlaps)
			continue;

		add_smaps_value(&stats, line);

		if (starts_with(line, "VmFlags:")) {
			printf("VmFlags              : %s",
			       line + strlen("VmFlags:"));
		}
	}

	fclose(fp);

	unsigned long vm_pte = read_vm_pte();

	printf("\nVMA count            : %zu\n", stats.vma_count);

	printf("aggregate Size       : %lu kB\n", stats.size_kb);
	printf("aggregate Rss        : %lu kB\n", stats.rss_kb);
	printf("aggregate Pss        : %lu kB\n", stats.pss_kb);

	printf("aggregate Shared_Clean : %lu kB\n", stats.shared_clean_kb);
	printf("aggregate Shared_Dirty : %lu kB\n", stats.shared_dirty_kb);
	printf("aggregate Private_Clean: %lu kB\n", stats.private_clean_kb);
	printf("aggregate Private_Dirty: %lu kB\n", stats.private_dirty_kb);

	printf("aggregate Referenced : %lu kB\n", stats.referenced_kb);
	printf("aggregate Anonymous  : %lu kB\n", stats.anonymous_kb);

	printf("VmPTE                : %lu kB\n", vm_pte);
	printf("VmPTE delta          : %ld kB\n",
	       (long)vm_pte - (long)vm_pte_baseline);
}

static int open_pagemap(void)
{
	int fd = open("/proc/self/pagemap",
		      O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		die("open /proc/self/pagemap");

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

static struct pfn_snapshot capture_snapshot(const void *mapping,
					    size_t first_page,
					    size_t page_count, size_t page_size)
{
	struct pfn_snapshot snapshot;

	memset(&snapshot, 0, sizeof(snapshot));

	snapshot.pages = page_count;

	snapshot.pfns = calloc(page_count, sizeof(*snapshot.pfns));

	snapshot.present = calloc(page_count, sizeof(*snapshot.present));

	snapshot.exclusive = calloc(page_count, sizeof(*snapshot.exclusive));

	snapshot.file_bit = calloc(page_count, sizeof(*snapshot.file_bit));

	if (snapshot.pfns == NULL ||
	    snapshot.present == NULL ||
	    snapshot.exclusive == NULL || snapshot.file_bit == NULL) {
		die("calloc snapshot");
	}

	int pagemap_fd = open_pagemap();

	for (size_t index = 0; index < page_count; ++index) {
		size_t page = first_page + index;

		const unsigned char *address =
		    (const unsigned char *)mapping + page * page_size;

		struct pagemap_entry entry = read_pagemap_entry(pagemap_fd,
								address,
								page_size);

		snapshot.pfns[index] = entry.pfn;

		snapshot.present[index] = (unsigned char)entry.present;

		snapshot.exclusive[index] = (unsigned char)entry.exclusive;

		snapshot.file_bit[index] = (unsigned char)
		    entry.file_or_shared_anon;
	}

	close(pagemap_fd);
	return snapshot;
}

static void print_snapshot_summary(const char *name,
				   const struct pfn_snapshot *snapshot)
{
	size_t present = 0;
	size_t exclusive = 0;
	size_t file_bit = 0;

	for (size_t page = 0; page < snapshot->pages; ++page) {
		if (snapshot->present[page])
			++present;

		if (snapshot->present[page] && snapshot->exclusive[page]) {
			++exclusive;
		}

		if (snapshot->present[page] && snapshot->file_bit[page]) {
			++file_bit;
		}
	}

	printf("\n========== %s ==========\n", name);

	printf("pages                : %zu\n", snapshot->pages);
	printf("present              : %zu\n", present);
	printf("exclusive            : %zu\n", exclusive);
	printf("file-bit             : %zu\n", file_bit);
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

		for (size_t sample = 0; sample < 3; ++sample) {
			size_t local = samples[sample];
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
	free(snapshot->file_bit);

	memset(snapshot, 0, sizeof(*snapshot));
}

static void access_signal_handler(int signal_number,
				  siginfo_t * signal_info, void *context)
{
	(void)context;

	if (!probe_active)
		_exit(128 + signal_number);

	probe_signal = signal_number;
	probe_si_code = signal_info->si_code;
	probe_si_address = (uintptr_t) signal_info->si_addr;

	probe_completed = 0;
	probe_active = 0;

	siglongjmp(probe_jump, 1);
}

static void install_access_handlers(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));

	action.sa_sigaction = access_signal_handler;

	action.sa_flags = SA_SIGINFO; // three parameters function call

	if (sigemptyset(&action.sa_mask) != 0)
		die("sigemptyset");

	if (sigaction(SIGSEGV, &action, NULL) != 0)
		die("sigaction SIGSEGV");

	if (sigaction(SIGBUS, &action, NULL) != 0)
		die("sigaction SIGBUS");
}

static void reset_probe_state(void)
{
	probe_active = 0;
	probe_completed = 0;
	probe_signal = 0;
	probe_si_code = 0;
	probe_si_address = 0;
	probe_read_value = 0;
}

static struct access_probe probe_read(volatile unsigned char *address)
{
	struct usage_snapshot before;
	struct usage_snapshot after;

	reset_probe_state();

	before = get_usage_snapshot();

	if (sigsetjmp(probe_jump, 1) == 0) {
		probe_active = 1;

		probe_read_value = *address;

		probe_completed = 1;
		probe_active = 0;
	} else {
		probe_active = 0;
	}

	after = get_usage_snapshot();

	struct access_probe result = {
		.completed = probe_completed,

		.signal_number = probe_signal,

		.si_code = probe_si_code,

		.fault_address = probe_si_address,

		.read_value = probe_read_value,

		.minor_faults = after.minor_faults - before.minor_faults,

		.major_faults = after.major_faults - before.major_faults,
	};

	return result;
}

static struct access_probe probe_write(volatile unsigned char *address,
				       unsigned char value)
{
	struct usage_snapshot before;
	struct usage_snapshot after;

	reset_probe_state();

	before = get_usage_snapshot();

	if (sigsetjmp(probe_jump, 1) == 0) {
		probe_active = 1;

		*address = value;

		probe_completed = 1;
		probe_active = 0;
	} else {
		probe_active = 0;
	}

	after = get_usage_snapshot();

	struct access_probe result = {
		.completed = probe_completed,

		.signal_number = probe_signal,

		.si_code = probe_si_code,

		.fault_address = probe_si_address,

		.read_value = 0,

		.minor_faults = after.minor_faults - before.minor_faults,

		.major_faults = after.major_faults - before.major_faults,
	};

	return result;
}

static const char *signal_name(int signal_number)
{
	if (signal_number == SIGSEGV)
		return "SIGSEGV";

	if (signal_number == SIGBUS)
		return "SIGBUS";

	if (signal_number == 0)
		return "none";

	return "other";
}

static const char *segv_code_name(int signal_number, int si_code)
{
	if (signal_number != SIGSEGV)
		return "not-SIGSEGV";

	if (si_code == SEGV_MAPERR)
		return "SEGV_MAPERR";

	if (si_code == SEGV_ACCERR)
		return "SEGV_ACCERR";

	return "other";
}

static void print_access_probe(const char *name,
			       const struct access_probe *probe,
			       const void *expected_address)
{
	printf("\n========== %s ==========\n", name);

	printf("access completed     : %s\n", probe->completed ? "yes" : "no");

	printf("signal               : %d (%s)\n",
	       probe->signal_number, signal_name(probe->signal_number));

	printf("si_code              : %d (%s)\n",
	       probe->si_code,
	       segv_code_name(probe->signal_number, probe->si_code));

	printf("si_addr              : %p\n", (void *)probe->fault_address);

	printf("expected address     : %p\n", expected_address);

	printf("address matches      : %s\n",
	       probe->fault_address ==
	       (uintptr_t) expected_address ? "yes" : "no");

	printf("read value           : %u\n", (unsigned int)probe->read_value);

	printf("minor faults         : %ld\n", probe->minor_faults);
	printf("major faults         : %ld\n", probe->major_faults);
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t protected_first_page = 1024;
	size_t protected_pages = 512;

	if (argc >= 2) {
		size_mib = (size_t)strtoul(argv[1], NULL, 0);
	}

	if (argc >= 3) {
		protected_first_page = (size_t)strtoul(argv[2], NULL, 0);
	}

	if (argc >= 4) {
		protected_pages = (size_t)strtoul(argv[3], NULL, 0);
	}

	if (argc > 4 || size_mib == 0) {
		fprintf(stderr,
			"Usage: %s "
			"[MiB] [protected_first_page] "
			"[protected_pages]\n", argv[0]);

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

	if (protected_pages == 0 ||
	    protected_first_page == 0 ||
	    protected_first_page >= pages ||
	    protected_pages >
	    pages - protected_first_page ||
	    protected_first_page + protected_pages >= pages) {
		fprintf(stderr,
			"protected range must be a nonempty "
			"interior subrange\n");

		return EXIT_FAILURE;
	}

	size_t protected_offset = protected_first_page * page_size;

	size_t protected_length = protected_pages * page_size;

	warm_up_proc_files();

	unsigned long vm_pte_baseline = read_vm_pte();

	volatile unsigned char *memory = map_anon_aligned(length,
							  TWO_MIB);

	if (memory == MAP_FAILED)
		die("map_anon_aligned");

	install_access_handlers();

	struct perf_group perf_group;
	struct perf_counts warmup_counts;

	if (perf_group_open(&perf_group) != 0)
		return EXIT_FAILURE;

	if (perf_group_start(&perf_group) != 0)
		return EXIT_FAILURE;

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &warmup_counts) != 0) {
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 2 MiB    : 0x%lx\n", (unsigned long)
	       ((uintptr_t) memory & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);

	printf("protected first page : %zu\n", protected_first_page);
	printf("protected last page  : %zu\n",
	       protected_first_page + protected_pages - 1);
	printf("protected pages      : %zu\n", protected_pages);
	printf("protected size       : %zu kB\n", protected_length / 1024);
	printf("protected address    : %p\n", (const void *)
	       (memory + protected_offset));

	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	/*
	 * 1. 分配并写满所有匿名页。
	 */
	struct perf_measurement initial_fill = measure_initial_fill(&perf_group,
								    memory,
								    pages,
								    page_size);

	print_perf_measurement("1. initial anonymous allocation",
			       &initial_fill, pages);

	struct signatures initial_contents = read_signatures(memory,
							     0,
							     pages,
							     page_size);

	struct signatures expected_initial = expected_signatures(0,
								 pages,
								 original_value,
								 original_value);

	print_signature_check("1. initial contents",
			      initial_contents, expected_initial);

	print_range_layout("1. initial single RW VMA",
			   (const void *)memory, length, vm_pte_baseline);

	struct pfn_snapshot before_read_only =
	    capture_snapshot((const void *)memory,
			     protected_first_page,
			     protected_pages,
			     page_size);

	print_snapshot_summary("1. protected range before mprotect",
			       &before_read_only);

	/*
	 * 2. 将内部2 MiB改为只读。
	 */
	struct syscall_measurement make_read_only =
	    measure_mprotect(&perf_group,
			     (void *)(memory + protected_offset),
			     protected_length,
			     PROT_READ);

	print_syscall_measurement("2. mprotect middle range RW to R",
				  &make_read_only, protected_pages);

	if (make_read_only.result != 0)
		return EXIT_FAILURE;

	print_range_layout("2. layout after RW to R",
			   (const void *)memory, length, vm_pte_baseline);

	struct pfn_snapshot after_read_only =
	    capture_snapshot((const void *)memory,
			     protected_first_page,
			     protected_pages,
			     page_size);

	print_snapshot_summary("2. protected range after RW to R",
			       &after_read_only);

	compare_snapshots("2. PFNs across RW to R",
			  &before_read_only,
			  &after_read_only, protected_first_page);

	/*
	 * 3. 在只读区域进行允许的Load。
	 */
	size_t probe_page = protected_first_page + 7;

	volatile unsigned char *probe_address = memory + probe_page * page_size;

	unsigned char expected_probe_value = original_value(probe_page);

	struct access_probe read_probe = probe_read(probe_address);

	print_access_probe("3. read probe on read-only VMA",
			   &read_probe, (const void *)probe_address);

	printf("expected read value  : %u\n",
	       (unsigned int)expected_probe_value);

	printf("value matches        : %s\n",
	       read_probe.completed &&
	       read_probe.read_value == expected_probe_value ? "yes" : "NO");

	if (!read_probe.completed)
		return EXIT_FAILURE;

	/*
	 * 4. 在只读区域进行不允许的Store。
	 */
	unsigned char denied_value = (unsigned char)
	    (expected_probe_value ^ 0xffU);

	struct access_probe write_probe = probe_write(probe_address,
						      denied_value);

	print_access_probe("4. denied write probe on read-only VMA",
			   &write_probe, (const void *)probe_address);

	printf("expected signal      : SIGSEGV\n");
	printf("expected si_code     : SEGV_ACCERR\n");

	printf("permission fault valid: %s\n",
	       !write_probe.completed &&
	       write_probe.signal_number == SIGSEGV &&
	       write_probe.si_code == SEGV_ACCERR &&
	       write_probe.fault_address ==
	       (uintptr_t) probe_address ? "yes" : "NO");

	if (write_probe.completed) {
		fprintf(stderr,
			"unexpected successful write to "
			"read-only mapping\n");

		return EXIT_FAILURE;
	}

	unsigned char value_after_denied = *probe_address;

	printf("value after denied write: %u\n",
	       (unsigned int)value_after_denied);

	printf("contents unchanged   : %s\n",
	       value_after_denied == expected_probe_value ? "yes" : "NO");

	struct signatures read_only_contents = read_signatures(memory,
							       protected_first_page,
							       protected_pages,
							       page_size);

	struct signatures expected_read_only =
	    expected_signatures(protected_first_page,
				protected_pages,
				original_value,
				original_value);

	print_signature_check("4. protected range after denied write",
			      read_only_contents, expected_read_only);

	struct pfn_snapshot after_denied_write =
	    capture_snapshot((const void *)memory,
			     protected_first_page,
			     protected_pages,
			     page_size);

	compare_snapshots("4. PFNs across denied write",
			  &after_read_only,
			  &after_denied_write, protected_first_page);

	/*
	 * 5. 恢复RW。
	 */
	struct syscall_measurement restore_rw = measure_mprotect(&perf_group,
								 (void *)(memory
									  +
									  protected_offset),
								 protected_length,
								 PROT_READ |
								 PROT_WRITE);

	print_syscall_measurement("5. mprotect middle range R to RW",
				  &restore_rw, protected_pages);

	if (restore_rw.result != 0)
		return EXIT_FAILURE;

	print_range_layout("5. layout after R to RW",
			   (const void *)memory, length, vm_pte_baseline);

	struct pfn_snapshot after_restore =
	    capture_snapshot((const void *)memory,
			     protected_first_page,
			     protected_pages,
			     page_size);

	print_snapshot_summary("5. protected range after restoring RW",
			       &after_restore);

	compare_snapshots("5. PFNs across R to RW",
			  &after_denied_write,
			  &after_restore, protected_first_page);

	/*
	 * 6. 恢复RW后的第一次批量写。
	 *
	 * exclusive匿名页预计由mprotect主动恢复PTE写权限，
	 * 因此预计0次minor fault。
	 */
	struct perf_measurement first_restored_write =
	    measure_write_range(&perf_group,
				memory,
				protected_first_page,
				protected_pages,
				page_size,
				restored_value);

	print_perf_measurement("6. first write after restoring RW",
			       &first_restored_write, protected_pages);

	struct pfn_snapshot after_first_write =
	    capture_snapshot((const void *)memory,
			     protected_first_page,
			     protected_pages,
			     page_size);

	compare_snapshots("6. PFNs across first restored write",
			  &after_restore,
			  &after_first_write, protected_first_page);

	struct signatures restored_contents = read_signatures(memory,
							      protected_first_page,
							      protected_pages,
							      page_size);

	struct signatures expected_restored =
	    expected_signatures(protected_first_page,
				protected_pages,
				restored_value,
				original_value);

	print_signature_check("6. contents after first restored write",
			      restored_contents, expected_restored);

	/*
	 * 7. 对同一范围再次热写。
	 */
	struct perf_measurement hot_write = measure_write_range(&perf_group,
								memory,
								protected_first_page,
								protected_pages,
								page_size,
								hot_value);

	print_perf_measurement("7. second hot write",
			       &hot_write, protected_pages);

	struct pfn_snapshot after_hot_write =
	    capture_snapshot((const void *)memory,
			     protected_first_page,
			     protected_pages,
			     page_size);

	compare_snapshots("7. PFNs across hot write",
			  &after_first_write,
			  &after_hot_write, protected_first_page);

	/*
	 * 8. 最终内容与VMA状态。
	 */
	struct signatures final_left = read_signatures(memory,
						       0,
						       protected_first_page,
						       page_size);

	struct signatures final_middle = read_signatures(memory,
							 protected_first_page,
							 protected_pages,
							 page_size);

	size_t right_first_page = protected_first_page + protected_pages;

	size_t right_pages = pages - right_first_page;

	struct signatures final_right = read_signatures(memory,
							right_first_page,
							right_pages,
							page_size);

	struct signatures expected_left = expected_signatures(0,
							      protected_first_page,
							      original_value,
							      original_value);

	struct signatures expected_middle =
	    expected_signatures(protected_first_page,
				protected_pages,
				hot_value,
				original_value);

	struct signatures expected_right = expected_signatures(right_first_page,
							       right_pages,
							       original_value,
							       original_value);

	print_signature_check("8. final left range", final_left, expected_left);

	print_signature_check("8. final middle range",
			      final_middle, expected_middle);

	print_signature_check("8. final right range",
			      final_right, expected_right);

	print_range_layout("8. final mapping",
			   (const void *)memory, length, vm_pte_baseline);

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);

	free_snapshot(&before_read_only);
	free_snapshot(&after_read_only);
	free_snapshot(&after_denied_write);
	free_snapshot(&after_restore);
	free_snapshot(&after_first_write);
	free_snapshot(&after_hot_write);

	perf_group_close(&perf_group);

	if (munmap((void *)memory, length) != 0) {
		die("munmap");
	}

	return EXIT_SUCCESS;
}
