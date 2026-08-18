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
	int file_bit;
};

struct pfn_snapshot {
	size_t pages;

	uint64_t *raw;
	uint64_t *pfn;
	unsigned char *present;
	unsigned char *exclusive;
};

struct probe_result {
	int completed;

	int signal_number;
	int si_code;

	uintptr_t fault_address;

	long minflt;
	long majflt;

	unsigned char read_value;
};

static sigjmp_buf probe_env;

static volatile sig_atomic_t probe_active;
static volatile sig_atomic_t probe_completed;
static volatile sig_atomic_t probe_signal;
static volatile sig_atomic_t probe_code;

static volatile uintptr_t probe_address;
static volatile unsigned char probe_read_value;

static volatile uint64_t sink;

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
		.majflt = usage.ru_majflt
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

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &value) == 1) {
			break;
		}
	}

	fclose(fp);

	return value;
}

static void *map_aligned(size_t length, size_t alignment)
{
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

	return mmap((void *)aligned,
		    length,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
}

static unsigned char initial_value(size_t page)
{
	return (unsigned char)((page % 251U) + 1U);
}

static unsigned char final_value(size_t page)
{
	return (unsigned char)(initial_value(page) ^ 0x5aU);
}

static struct perf_result measure_initial_fill(struct perf_group *group,
					       volatile unsigned char *memory,
					       size_t pages, size_t page_size)
{
	struct usage_snapshot before = usage_now();

	struct perf_counts counts;

	if (perf_group_start(group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < pages; ++page) {
		size_t offset = page * page_size;

		unsigned char value = initial_value(page);

		memory[offset] = value;
		memory[offset + 1] = value;
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
		.error = 0
	};

	return result;
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
		.error = saved_errno
	};

	return result;
}

static struct perf_result measure_write(struct perf_group *group,
					volatile unsigned char *memory,
					size_t first_page,
					size_t pages, size_t page_size)
{
	struct usage_snapshot before = usage_now();

	struct perf_counts counts;

	if (perf_group_start(group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + pages; ++page) {
		memory[page * page_size] = final_value(page);
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
		.error = 0
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
	uint64_t raw;

	uint64_t vpn = (uint64_t) (uintptr_t) address / page_size;

	ssize_t result = pread(fd,
			       &raw,
			       sizeof(raw),
			       (off_t) (vpn * sizeof(raw)));

	if (result != sizeof(raw))
		die("pread pagemap");

	struct pagemap_entry entry = {
		.raw = raw,
		.pfn = raw & PM_PFN_MASK,

		.present = !!(raw & PM_PRESENT),

		.swapped = !!(raw & PM_SWAPPED),

		.exclusive = !!(raw & PM_EXCLUSIVE),

		.file_bit = !!(raw & PM_FILE_OR_SHANON)
	};

	return entry;
}

static struct pfn_snapshot capture_snapshot(const void *mapping,
					    size_t first_page,
					    size_t pages, size_t page_size)
{
	struct pfn_snapshot snapshot;

	memset(&snapshot, 0, sizeof(snapshot));

	snapshot.pages = pages;

	snapshot.raw = calloc(pages, sizeof(*snapshot.raw));

	snapshot.pfn = calloc(pages, sizeof(*snapshot.pfn));

	snapshot.present = calloc(pages, sizeof(*snapshot.present));

	snapshot.exclusive = calloc(pages, sizeof(*snapshot.exclusive));

	if (!snapshot.raw ||
	    !snapshot.pfn || !snapshot.present || !snapshot.exclusive) {
		die("calloc snapshot");
	}

	int fd = open_pagemap();

	for (size_t i = 0; i < pages; ++i) {
		size_t page = first_page + i;

		const unsigned char *address =
		    (const unsigned char *)mapping + page * page_size;

		struct pagemap_entry entry = read_pagemap(fd,
							  address,
							  page_size);

		snapshot.raw[i] = entry.raw;

		snapshot.pfn[i] = entry.pfn;

		snapshot.present[i] = entry.present;

		snapshot.exclusive[i] = entry.exclusive;
	}

	close(fd);

	return snapshot;
}

static void free_snapshot(struct pfn_snapshot *snapshot)
{
	free(snapshot->raw);
	free(snapshot->pfn);
	free(snapshot->present);
	free(snapshot->exclusive);

	memset(snapshot, 0, sizeof(*snapshot));
}

static void print_snapshot(const char *name,
			   const struct pfn_snapshot *snapshot,
			   size_t first_page)
{
	size_t present = 0;
	size_t exclusive = 0;

	for (size_t i = 0; i < snapshot->pages; ++i) {
		present += snapshot->present[i];
		exclusive += snapshot->exclusive[i];
	}

	printf("\n========== %s ==========\n", name);

	printf("pages                : %zu\n", snapshot->pages);
	printf("pagemap present      : %zu\n", present);
	printf("exclusive            : %zu\n", exclusive);

	size_t sample[3] = {
		0,
		snapshot->pages > 1 ? 1 : 0,
		snapshot->pages - 1
	};

	printf("\n");
	printf("page     raw pagemap          PFN           present excl\n");

	for (size_t i = 0; i < 3; ++i) {
		size_t local = sample[i];

		printf("%-8zu 0x%016" PRIx64
		       " 0x%011" PRIx64
		       " %-7d %d\n",
		       first_page + local,
		       snapshot->raw[local],
		       snapshot->pfn[local],
		       snapshot->present[local], snapshot->exclusive[local]);
	}
}

static void compare_snapshots(const char *name,
			      const struct pfn_snapshot *before,
			      const struct pfn_snapshot *after,
			      size_t first_page)
{
	size_t comparable = 0;
	size_t same = 0;
	size_t changed = 0;

	for (size_t i = 0; i < before->pages; ++i) {
		if (!before->present[i] || !after->present[i]) {
			continue;
		}

		++comparable;

		if (before->pfn[i] == after->pfn[i]) {
			++same;
		} else {
			++changed;
		}
	}

	printf("\n========== %s ==========\n", name);

	printf("first page           : %zu\n", first_page);
	printf("pages                : %zu\n", before->pages);

	printf("PFN comparable       : %zu\n", comparable);
	printf("PFN unchanged        : %zu\n", same);
	printf("PFN changed          : %zu\n", changed);
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

	unsigned long rss = 0;
	unsigned long pss = 0;
	unsigned long anonymous = 0;
	unsigned long private_dirty = 0;

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

		if (sscanf(line, "Rss: %lu kB", &value) == 1) {
			rss += value;
		} else if (sscanf(line, "Pss: %lu kB", &value) == 1) {
			pss += value;
		} else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1) {
			private_dirty += value;
		} else if (sscanf(line, "Anonymous: %lu kB", &value) == 1) {
			anonymous += value;
		} else if (strncmp(line, "VmFlags:", 8) == 0) {
			printf("VmFlags              : %s", line + 8);
		}
	}

	fclose(fp);

	unsigned long vm_pte = read_vm_pte();

	printf("\nVMA count            : %zu\n", vma_count);

	printf("aggregate Rss        : %lu kB\n", rss);
	printf("aggregate Pss        : %lu kB\n", pss);
	printf("aggregate Private_Dirty: %lu kB\n", private_dirty);
	printf("aggregate Anonymous  : %lu kB\n", anonymous);

	printf("VmPTE                : %lu kB\n", vm_pte);
	printf("VmPTE delta          : %ld kB\n",
	       (long)vm_pte - (long)vm_pte_baseline);
}

static void signal_handler(int signal_number, siginfo_t * info, void *context)
{
	(void)context;

	if (!probe_active)
		_exit(128 + signal_number);

	probe_signal = signal_number;
	probe_code = info->si_code;

	probe_address = (uintptr_t) info->si_addr;

	probe_completed = 0;
	probe_active = 0;

	siglongjmp(probe_env, 1);
}

static void install_handlers(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));

	action.sa_sigaction = signal_handler;

	action.sa_flags = SA_SIGINFO;

	sigemptyset(&action.sa_mask);

	if (sigaction(SIGSEGV, &action, NULL) != 0) {
		die("sigaction SIGSEGV");
	}

	if (sigaction(SIGBUS, &action, NULL) != 0) {
		die("sigaction SIGBUS");
	}
}

static void reset_probe(void)
{
	probe_active = 0;
	probe_completed = 0;
	probe_signal = 0;
	probe_code = 0;
	probe_address = 0;
	probe_read_value = 0;
}

static struct probe_result probe_read(volatile unsigned char *address)
{
	struct usage_snapshot before = usage_now();

	reset_probe();

	if (sigsetjmp(probe_env, 1) == 0) {
		probe_active = 1;

		probe_read_value = *address;

		probe_completed = 1;
		probe_active = 0;
	}

	struct usage_snapshot after = usage_now();

	struct probe_result result = {
		.completed = probe_completed,

		.signal_number = probe_signal,

		.si_code = probe_code,

		.fault_address = probe_address,

		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt,

		.read_value = probe_read_value
	};

	return result;
}

static struct probe_result probe_write(volatile unsigned char *address,
				       unsigned char value)
{
	struct usage_snapshot before = usage_now();

	reset_probe();

	if (sigsetjmp(probe_env, 1) == 0) {
		probe_active = 1;

		*address = value;

		probe_completed = 1;
		probe_active = 0;
	}

	struct usage_snapshot after = usage_now();

	struct probe_result result = {
		.completed = probe_completed,

		.signal_number = probe_signal,

		.si_code = probe_code,

		.fault_address = probe_address,

		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt,

		.read_value = 0
	};

	return result;
}

static void print_probe(const char *name,
			const struct probe_result *probe,
			const void *expected_address)
{
	printf("\n========== %s ==========\n", name);

	printf("access completed     : %s\n", probe->completed ? "yes" : "no");

	printf("signal               : %d\n", probe->signal_number);

	printf("si_code              : %d", probe->si_code);

	if (probe->signal_number == SIGSEGV) {
		if (probe->si_code == SEGV_ACCERR)
			printf(" (SEGV_ACCERR)");

		if (probe->si_code == SEGV_MAPERR)
			printf(" (SEGV_MAPERR)");
	}

	printf("\n");

	if (probe->signal_number != 0) {
		printf("si_addr              : %p\n",
		       (void *)probe->fault_address);

		printf("expected address     : %p\n", expected_address);

		printf("address matches      : %s\n",
		       probe->fault_address ==
		       (uintptr_t) expected_address ? "yes" : "NO");
	}

	printf("minor faults         : %ld\n", probe->minflt);
	printf("major faults         : %ld\n", probe->majflt);
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t protected_first_page = 1024;
	size_t protected_pages = 512;

	if (argc >= 2)
		size_mib = strtoul(argv[1], NULL, 0);

	if (argc >= 3)
		protected_first_page = strtoul(argv[2], NULL, 0);

	if (argc >= 4)
		protected_pages = strtoul(argv[3], NULL, 0);

	setvbuf(stdout, NULL, _IONBF, 0);

	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);

	size_t length = size_mib * 1024UL * 1024UL;

	size_t pages = length / page_size;

	if (protected_first_page == 0 ||
	    protected_pages == 0 ||
	    protected_first_page + protected_pages >= pages) {
		fprintf(stderr, "protected range must be interior\n");

		return EXIT_FAILURE;
	}

	size_t protected_offset = protected_first_page * page_size;

	size_t protected_length = protected_pages * page_size;

	unsigned long vm_pte_baseline = read_vm_pte();

	volatile unsigned char *memory = map_aligned(length,
						     TWO_MIB);

	if (memory == MAP_FAILED)
		die("map_aligned");

	install_handlers();

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

	printf("address mod 2 MiB    : 0x%lx\n",
	       (unsigned long)((uintptr_t) memory & (TWO_MIB - 1)));

	printf("mapping size         : %zu MiB\n", size_mib);

	printf("pages                : %zu\n", pages);

	printf("protected range      : %zu-%zu\n",
	       protected_first_page,
	       protected_first_page + protected_pages - 1);

	printf("protected size       : %zu kB\n", protected_length / 1024);

	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	/*
	 * 1. 初始分配。
	 */
	struct perf_result initial = measure_initial_fill(&perf_group,
							  memory,
							  pages,
							  page_size);

	print_perf("1. initial anonymous allocation", &initial, pages);

	print_layout("1. initial RW layout",
		     (const void *)memory, length, vm_pte_baseline);

	struct pfn_snapshot before_none = capture_snapshot((const void *)memory,
							   protected_first_page,
							   protected_pages,
							   page_size);

	print_snapshot("1. target range before PROT_NONE",
		       &before_none, protected_first_page);

	printf("\nmincore before       : %zu / %zu\n",
	       mincore_resident((void *)(memory + protected_offset),
				protected_length, page_size), protected_pages);

	/*
	 * 2. RW -> NONE。
	 */
	struct perf_result make_none = measure_mprotect(&perf_group,
							(void *)(memory +
								 protected_offset),
							protected_length,
							PROT_NONE);

	print_perf("2. mprotect RW to PROT_NONE", &make_none, protected_pages);

	if (make_none.ret != 0)
		return EXIT_FAILURE;

	print_layout("2. layout under PROT_NONE",
		     (const void *)memory, length, vm_pte_baseline);

	struct pfn_snapshot under_none = capture_snapshot((const void *)memory,
							  protected_first_page,
							  protected_pages,
							  page_size);

	print_snapshot("2. pagemap under PROT_NONE",
		       &under_none, protected_first_page);

	compare_snapshots("2. PFNs across RW to NONE",
			  &before_none, &under_none, protected_first_page);

	printf("\nmincore under NONE   : %zu / %zu\n",
	       mincore_resident((void *)(memory + protected_offset),
				protected_length, page_size), protected_pages);

	/*
	 * 3. Load。
	 */
	size_t probe_page = protected_first_page + 7;

	volatile unsigned char *address = memory + probe_page * page_size;

	struct probe_result read_result = probe_read(address);

	print_probe("3. read from PROT_NONE",
		    &read_result, (const void *)address);

	/*
	 * 4. Store。
	 */
	struct probe_result write_result = probe_write(address,
						       0xee);

	print_probe("4. write to PROT_NONE",
		    &write_result, (const void *)address);

	struct pfn_snapshot after_faults =
	    capture_snapshot((const void *)memory,
			     protected_first_page,
			     protected_pages,
			     page_size);

	compare_snapshots("4. PFNs across denied accesses",
			  &under_none, &after_faults, protected_first_page);

	/*
	 * 5. NONE -> RW。
	 */
	struct perf_result restore = measure_mprotect(&perf_group,
						      (void *)(memory +
							       protected_offset),
						      protected_length,
						      PROT_READ | PROT_WRITE);

	print_perf("5. mprotect PROT_NONE to RW", &restore, protected_pages);

	if (restore.ret != 0)
		return EXIT_FAILURE;

	print_layout("5. layout after restoring RW",
		     (const void *)memory, length, vm_pte_baseline);

	struct pfn_snapshot restored = capture_snapshot((const void *)memory,
							protected_first_page,
							protected_pages,
							page_size);

	print_snapshot("5. pagemap after restoring RW",
		       &restored, protected_first_page);

	compare_snapshots("5. PFNs across NONE to RW",
			  &after_faults, &restored, protected_first_page);

	printf("\nmincore restored     : %zu / %zu\n",
	       mincore_resident((void *)(memory + protected_offset),
				protected_length, page_size), protected_pages);

	/*
	 * 6. 恢复后第一次读。
	 */
	struct probe_result restored_read = probe_read(address);

	print_probe("6. first read after restoring RW",
		    &restored_read, (const void *)address);

	printf("read value           : %u\n", (unsigned int)
	       restored_read.read_value);

	printf("expected value       : %u\n", (unsigned int)
	       initial_value(probe_page));

	/*
	 * 7. 恢复后批量写。
	 */
	struct perf_result restored_write = measure_write(&perf_group,
							  memory,
							  protected_first_page,
							  protected_pages,
							  page_size);

	print_perf("7. first writes after restoring RW",
		   &restored_write, protected_pages);

	struct pfn_snapshot after_write = capture_snapshot((const void *)memory,
							   protected_first_page,
							   protected_pages,
							   page_size);

	compare_snapshots("7. PFNs across restored writes",
			  &restored, &after_write, protected_first_page);

	/*
	 * 简单内容校验。
	 */
	uint64_t offset0_sum = 0;
	uint64_t offset1_sum = 0;

	uint64_t expected0 = 0;
	uint64_t expected1 = 0;

	for (size_t page =
	     protected_first_page;
	     page < protected_first_page + protected_pages; ++page) {
		size_t offset = page * page_size;

		offset0_sum += memory[offset];
		offset1_sum += memory[offset + 1];

		expected0 += final_value(page);
		expected1 += initial_value(page);
	}

	sink += offset0_sum + offset1_sum;

	printf("\n========== 8. final contents ==========\n");

	printf("offset 0 sum         : %" PRIu64 "\n", offset0_sum);
	printf("expected offset 0    : %" PRIu64 "\n", expected0);

	printf("offset 1 sum         : %" PRIu64 "\n", offset1_sum);
	printf("expected offset 1    : %" PRIu64 "\n", expected1);

	printf("signature valid      : %s\n",
	       offset0_sum == expected0 &&
	       offset1_sum == expected1 ? "yes" : "NO");

	print_layout("8. final mapping",
		     (const void *)memory, length, vm_pte_baseline);

	printf("\nsink                 : %" PRIu64 "\n", sink);

	free_snapshot(&before_none);
	free_snapshot(&under_none);
	free_snapshot(&after_faults);
	free_snapshot(&restored);
	free_snapshot(&after_write);

	perf_group_close(&perf_group);

	if (munmap((void *)memory, length) != 0) {
		die("munmap");
	}

	return EXIT_SUCCESS;
}
