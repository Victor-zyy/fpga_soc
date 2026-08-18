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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "perf_counter.h"

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

struct vma_info {
	char header[512];
	char vmflags[512];

	unsigned long rss_kb;
	unsigned long pss_kb;
	unsigned long shared_dirty_kb;
	unsigned long private_dirty_kb;
	unsigned long anonymous_kb;
};

struct probe_result {
	int completed;
	int signal_number;
	int si_code;

	uintptr_t fault_address;

	long minflt;
	long majflt;
};

static sigjmp_buf probe_env;

static volatile sig_atomic_t probe_active;
static volatile sig_atomic_t probe_completed;
static volatile sig_atomic_t probe_signal;
static volatile sig_atomic_t probe_code;
static volatile uintptr_t probe_fault_address;

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

static void pwrite_u32(int fd, off_t offset, uint32_t value)
{
	ssize_t result = pwrite(fd, &value, sizeof(value), offset);

	if (result != (ssize_t) sizeof(value))
		die("pwrite");
}

static uint32_t pread_u32(int fd, off_t offset)
{
	uint32_t value = 0;

	ssize_t result = pread(fd, &value, sizeof(value), offset);

	if (result != (ssize_t) sizeof(value))
		die("pread");

	return value;
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

static struct perf_result measure_store(struct perf_group *group,
					volatile uint32_t * address,
					uint32_t value)
{
	struct usage_snapshot before = usage_now();

	struct perf_counts counts;

	if (perf_group_start(group) != 0)
		exit(EXIT_FAILURE);

	*address = value;

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

static void print_perf(const char *name, const struct perf_result *result)
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
}

static struct pagemap_entry read_pagemap(const void *address, size_t page_size)
{
	int fd = open("/proc/self/pagemap",
		      O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		die("open pagemap");

	uint64_t raw = 0;

	uint64_t vpn = (uint64_t) (uintptr_t) address / page_size;

	ssize_t result = pread(fd,
			       &raw,
			       sizeof(raw),
			       (off_t) (vpn * sizeof(raw)));

	close(fd);

	if (result != (ssize_t) sizeof(raw))
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

static void print_pagemap(const char *name, const struct pagemap_entry *entry)
{
	printf("\n========== %s ==========\n", name);

	printf("raw pagemap          : 0x%016" PRIx64 "\n", entry->raw);

	printf("present              : %d\n", entry->present);

	printf("exclusive            : %d\n", entry->exclusive);

	printf("file-bit             : %d\n", entry->file_bit);

	printf("PFN                  : 0x%011" PRIx64 "\n", entry->pfn);
}

static void compare_pagemap(const char *name,
			    const struct pagemap_entry *before,
			    const struct pagemap_entry *after)
{
	printf("\n========== %s ==========\n", name);

	printf("before PFN           : 0x%011" PRIx64 "\n", before->pfn);

	printf("after PFN            : 0x%011" PRIx64 "\n", after->pfn);

	printf("PFN unchanged        : %s\n",
	       before->present &&
	       after->present && before->pfn == after->pfn ? "yes" : "no");

	printf("PFN changed          : %s\n",
	       before->present &&
	       after->present && before->pfn != after->pfn ? "yes" : "no");

	printf("file-bit before      : %d\n", before->file_bit);

	printf("file-bit after       : %d\n", after->file_bit);
}

static void read_vma_info(const void *address, struct vma_info *info)
{
	memset(info, 0, sizeof(*info));

	uintptr_t target = (uintptr_t) address;

	FILE *fp = fopen("/proc/self/smaps", "r");

	if (fp == NULL)
		die("fopen smaps");

	char line[1024];
	int active = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;

		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			active =
			    target >= (uintptr_t) start &&
			    target < (uintptr_t) end;

			if (active) {
				snprintf(info->header,
					 sizeof(info->header), "%s", line);

				info->header[strcspn(info->header,
						     "\n")] = '\0';
			}

			continue;
		}

		if (!active)
			continue;

		unsigned long value;

		if (sscanf(line, "Rss: %lu kB", &value) == 1) {
			info->rss_kb = value;
		} else if (sscanf(line, "Pss: %lu kB", &value) == 1) {
			info->pss_kb = value;
		} else if (sscanf(line, "Shared_Dirty: %lu kB", &value) == 1) {
			info->shared_dirty_kb = value;
		} else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1) {
			info->private_dirty_kb = value;
		} else if (sscanf(line, "Anonymous: %lu kB", &value) == 1) {
			info->anonymous_kb = value;
		} else if (strncmp(line, "VmFlags:", 8) == 0) {
			snprintf(info->vmflags,
				 sizeof(info->vmflags), "%s", line + 8);

			info->vmflags[strcspn(info->vmflags, "\n")] = '\0';
		}
	}

	fclose(fp);
}

static void print_vma_info(const char *name, const struct vma_info *info)
{
	printf("\n========== %s ==========\n", name);

	printf("mapping              : %s\n", info->header);

	printf("Rss                  : %lu kB\n", info->rss_kb);

	printf("Pss                  : %lu kB\n", info->pss_kb);

	printf("Shared_Dirty         : %lu kB\n", info->shared_dirty_kb);

	printf("Private_Dirty        : %lu kB\n", info->private_dirty_kb);

	printf("Anonymous            : %lu kB\n", info->anonymous_kb);

	printf("VmFlags              :%s\n", info->vmflags);

	printf("has mw               : %s\n",
	       strstr(info->vmflags, " mw") != NULL ? "yes" : "no");

	printf("has sh               : %s\n",
	       strstr(info->vmflags, " sh") != NULL ? "yes" : "no");

	printf("has ms               : %s\n",
	       strstr(info->vmflags, " ms") != NULL ? "yes" : "no");
}

static void signal_handler(int signal_number, siginfo_t * info, void *context)
{
	(void)context;

	if (!probe_active)
		_exit(128 + signal_number);

	probe_signal = signal_number;

	probe_code = info->si_code;

	probe_fault_address = (uintptr_t) info->si_addr;

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

	if (sigemptyset(&action.sa_mask) != 0) {
		die("sigemptyset");
	}

	if (sigaction(SIGSEGV, &action, NULL) != 0) {
		die("sigaction");
	}

	if (sigaction(SIGBUS, &action, NULL) != 0) {
		die("sigaction");
	}
}

static struct probe_result probe_write(volatile uint32_t * address,
				       uint32_t value)
{
	struct usage_snapshot before = usage_now();

	probe_active = 0;
	probe_completed = 0;
	probe_signal = 0;
	probe_code = 0;
	probe_fault_address = 0;

	if (sigsetjmp(probe_env, 1) == 0) {
		probe_active = 1;

		*address = value;

		probe_completed = 1;
		probe_active = 0;
	}

	probe_active = 0;

	struct usage_snapshot after = usage_now();

	struct probe_result result = {
		.completed = probe_completed,

		.signal_number = probe_signal,

		.si_code = probe_code,

		.fault_address = probe_fault_address,

		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt
	};

	return result;
}

static void print_probe(const char *name,
			const struct probe_result *result, const void *expected)
{
	printf("\n========== %s ==========\n", name);

	printf("access completed     : %s\n", result->completed ? "yes" : "no");

	printf("signal               : %d\n", result->signal_number);

	printf("si_code              : %d", result->si_code);

	if (result->signal_number == SIGSEGV) {
		if (result->si_code == SEGV_ACCERR)
			printf(" (SEGV_ACCERR)");
		else if (result->si_code == SEGV_MAPERR)
			printf(" (SEGV_MAPERR)");
	}

	printf("\n");

	if (result->signal_number != 0) {
		printf("si_addr              : %p\n", (void *)
		       result->fault_address);

		printf("expected address     : %p\n", expected);

		printf("address matches      : %s\n",
		       result->fault_address ==
		       (uintptr_t) expected ? "yes" : "NO");
	}

	printf("minor faults         : %ld\n", result->minflt);

	printf("major faults         : %ld\n", result->majflt);
}

static void prefault_read(const char *name, volatile uint32_t * address)
{
	struct usage_snapshot before = usage_now();

	uint32_t value = *address;

	struct usage_snapshot after = usage_now();

	printf("\n========== %s ==========\n", name);

	printf("value                : 0x%08x\n", value);

	printf("minor faults         : %ld\n", after.minflt - before.minflt);

	printf("major faults         : %ld\n", after.majflt - before.majflt);
}

static void direct_mmap_matrix(int fd_ro, size_t page_size)
{
	printf("\n========== 0. direct mmap permission matrix ==========\n");

	errno = 0;

	void *private_rw = mmap(NULL,
				page_size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE,
				fd_ro,
				0);

	printf("RO fd + PRIVATE + RW : %s",
	       private_rw == MAP_FAILED ? "FAILED" : "success");

	if (private_rw == MAP_FAILED) {
		printf(" errno=%d (%s)", errno, strerror(errno));
	}

	printf("\n");

	if (private_rw != MAP_FAILED)
		munmap(private_rw, page_size);

	errno = 0;

	void *shared_rw = mmap(NULL,
			       page_size,
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED,
			       fd_ro,
			       page_size);

	printf("RO fd + SHARED  + RW : %s",
	       shared_rw == MAP_FAILED ? "FAILED" : "success");

	if (shared_rw == MAP_FAILED) {
		printf(" errno=%d (%s)", errno, strerror(errno));
	}

	printf("\n");

	if (shared_rw != MAP_FAILED)
		munmap(shared_rw, page_size);
}

int main(void)
{
	const char *path = "stage5_5_backing.bin";

	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0)
		die("sysconf");

	size_t page_size = (size_t)page_size_long;

	unlink(path);

	int fd_rw = open(path,
			 O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC,
			 0600);

	if (fd_rw < 0)
		die("open O_RDWR");

	if (ftruncate(fd_rw, (off_t) (3 * page_size)) != 0) {
		die("ftruncate");
	}

	const uint32_t original_a = 0x11111111U;

	const uint32_t original_b = 0x22222222U;

	const uint32_t original_c = 0x33333333U;

	pwrite_u32(fd_rw, 0, original_a);

	pwrite_u32(fd_rw, (off_t) page_size, original_b);

	pwrite_u32(fd_rw, (off_t) (2 * page_size), original_c);

	int fd_ro = open(path,
			 O_RDONLY | O_CLOEXEC);

	if (fd_ro < 0)
		die("open O_RDONLY");

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

	printf("page size            : %zu bytes\n", page_size);

	printf("file                 : %s\n", path);

	printf("initial A            : 0x%08x\n", pread_u32(fd_ro, 0));

	printf("initial B            : 0x%08x\n",
	       pread_u32(fd_ro, (off_t) page_size));

	printf("initial C            : 0x%08x\n",
	       pread_u32(fd_ro, (off_t) (2 * page_size)));

	/*
	 * 先直接验证mmap时的权限规则。
	 */
	direct_mmap_matrix(fd_ro, page_size);

	/*
	 * A:
	 * O_RDONLY + MAP_PRIVATE + PROT_READ
	 */
	volatile uint32_t *map_a = mmap(NULL,
					page_size,
					PROT_READ,
					MAP_PRIVATE,
					fd_ro,
					0);

	if (map_a == MAP_FAILED)
		die("mmap A");

	/*
	 * B:
	 * O_RDONLY + MAP_SHARED + PROT_READ
	 */
	volatile uint32_t *map_b = mmap(NULL,
					page_size,
					PROT_READ,
					MAP_SHARED,
					fd_ro,
					(off_t) page_size);

	if (map_b == MAP_FAILED)
		die("mmap B");

	/*
	 * C:
	 * O_RDWR + MAP_SHARED + PROT_READ
	 */
	volatile uint32_t *map_c = mmap(NULL,
					page_size,
					PROT_READ,
					MAP_SHARED,
					fd_rw,
					(off_t) (2 * page_size));

	if (map_c == MAP_FAILED)
		die("mmap C");

	printf("\nmap A                : %p\n", (const void *)map_a);

	printf("map B                : %p\n", (const void *)map_b);

	printf("map C                : %p\n", (const void *)map_c);

	/*
	 * 先read fault，让三者都具有现成的file-backed PTE。
	 */
	prefault_read("1A. prefault PRIVATE + RO fd", map_a);

	prefault_read("1B. prefault SHARED + RO fd", map_b);

	prefault_read("1C. prefault SHARED + RW fd", map_c);

	struct vma_info a_info;
	struct vma_info b_info;
	struct vma_info c_info;

	read_vma_info((const void *)map_a, &a_info);

	read_vma_info((const void *)map_b, &b_info);

	read_vma_info((const void *)map_c, &c_info);

	print_vma_info("1A. PRIVATE + RO fd before mprotect", &a_info);

	print_vma_info("1B. SHARED + RO fd before mprotect", &b_info);

	print_vma_info("1C. SHARED + RW fd before mprotect", &c_info);

	struct pagemap_entry a0 = read_pagemap((const void *)map_a,
					       page_size);

	struct pagemap_entry b0 = read_pagemap((const void *)map_b,
					       page_size);

	struct pagemap_entry c0 = read_pagemap((const void *)map_c,
					       page_size);

	print_pagemap("1A. A pagemap before mprotect", &a0);

	print_pagemap("1B. B pagemap before mprotect", &b0);

	print_pagemap("1C. C pagemap before mprotect", &c0);

	/*
	 * ==========================================================
	 * A: PRIVATE + O_RDONLY
	 * ==========================================================
	 */
	struct perf_result a_protect = measure_mprotect(&perf_group,
							(void *)map_a,
							page_size,
							PROT_READ | PROT_WRITE);

	print_perf("2A. PRIVATE RO-fd: R to RW", &a_protect);

	read_vma_info((const void *)map_a, &a_info);

	print_vma_info("2A. A after mprotect RW", &a_info);

	struct pagemap_entry a1 = read_pagemap((const void *)map_a,
					       page_size);

	compare_pagemap("2A. A PFN across mprotect", &a0, &a1);

	const uint32_t private_value1 = 0xa1a1a1a1U;

	struct perf_result a_write1 = measure_store(&perf_group,
						    map_a,
						    private_value1);

	print_perf("2A. A first write after mprotect", &a_write1);

	struct pagemap_entry a2 = read_pagemap((const void *)map_a,
					       page_size);

	compare_pagemap("2A. A PFN across first write", &a1, &a2);

	read_vma_info((const void *)map_a, &a_info);

	print_vma_info("2A. A after first private write", &a_info);

	printf("\nA mapping value      : 0x%08x\n", *map_a);

	printf("A backing file value : 0x%08x\n", pread_u32(fd_ro, 0));

	/*
	 * A第二次写：
	 * COW完成后应直接热写。
	 */
	struct perf_result a_write2 = measure_store(&perf_group,
						    map_a,
						    0xa2a2a2a2U);

	print_perf("2A. A second private write", &a_write2);

	/*
	 * ==========================================================
	 * B: SHARED + O_RDONLY
	 * ==========================================================
	 */
	struct perf_result b_protect = measure_mprotect(&perf_group,
							(void *)map_b,
							page_size,
							PROT_READ | PROT_WRITE);

	print_perf("2B. SHARED RO-fd: R to RW", &b_protect);

	read_vma_info((const void *)map_b, &b_info);

	print_vma_info("2B. B after rejected mprotect", &b_info);

	struct pagemap_entry b1 = read_pagemap((const void *)map_b,
					       page_size);

	compare_pagemap("2B. B PFN across mprotect attempt", &b0, &b1);

	struct probe_result b_write = probe_write(map_b,
						  0xb1b1b1b1U);

	print_probe("2B. B write after rejected mprotect",
		    &b_write, (const void *)map_b);

	printf("\nB mapping value      : 0x%08x\n", *map_b);

	printf("B backing file value : 0x%08x\n",
	       pread_u32(fd_ro, (off_t) page_size));

	/*
	 * ==========================================================
	 * C: SHARED + O_RDWR
	 * ==========================================================
	 */
	struct perf_result c_protect = measure_mprotect(&perf_group,
							(void *)map_c,
							page_size,
							PROT_READ | PROT_WRITE);

	print_perf("2C. SHARED RW-fd: R to RW", &c_protect);

	read_vma_info((const void *)map_c, &c_info);

	print_vma_info("2C. C after mprotect RW", &c_info);

	struct pagemap_entry c1 = read_pagemap((const void *)map_c,
					       page_size);

	compare_pagemap("2C. C PFN across mprotect", &c0, &c1);

	const uint32_t shared_value1 = 0xc1c1c1c1U;

	struct perf_result c_write1 = measure_store(&perf_group,
						    map_c,
						    shared_value1);

	print_perf("2C. C first shared write", &c_write1);

	struct pagemap_entry c2 = read_pagemap((const void *)map_c,
					       page_size);

	compare_pagemap("2C. C PFN across first shared write", &c1, &c2);

	read_vma_info((const void *)map_c, &c_info);

	print_vma_info("2C. C after first shared write", &c_info);

	printf("\nC mapping value      : 0x%08x\n", *map_c);

	printf("C backing file value : 0x%08x\n",
	       pread_u32(fd_ro, (off_t) (2 * page_size)));

	/*
	 * C第二次写：
	 * 首次shared write fault完成后应直接写。
	 */
	struct perf_result c_write2 = measure_store(&perf_group,
						    map_c,
						    0xc2c2c2c2U);

	print_perf("2C. C second shared write", &c_write2);

	struct pagemap_entry c3 = read_pagemap((const void *)map_c,
					       page_size);

	compare_pagemap("2C. C PFN across second shared write", &c2, &c3);

	printf("\n========== 3. final backing file ==========\n");

	printf("file page A          : 0x%08x "
	       "(expected 0x%08x)\n", pread_u32(fd_ro, 0), original_a);

	printf("file page B          : 0x%08x "
	       "(expected 0x%08x)\n",
	       pread_u32(fd_ro, (off_t) page_size), original_b);

	printf("file page C          : 0x%08x "
	       "(expected 0xc2c2c2c2)\n",
	       pread_u32(fd_ro, (off_t) (2 * page_size)));

	printf("\n========== 4. semantic summary ==========\n");

	printf("A private mprotect RW success : %s\n",
	       a_protect.ret == 0 ? "yes" : "NO");

	printf("A first write COW fault        : %s\n",
	       a_write1.minflt == 1 && a1.pfn != a2.pfn ? "yes" : "NO");

	printf("A backing unchanged            : %s\n",
	       pread_u32(fd_ro, 0) == original_a ? "yes" : "NO");

	printf("B shared RO mprotect EACCES    : %s\n",
	       b_protect.ret == -1 && b_protect.error == EACCES ? "yes" : "NO");

	printf("B write denied                 : %s\n",
	       !b_write.completed &&
	       b_write.signal_number ==
	       SIGSEGV && b_write.si_code == SEGV_ACCERR ? "yes" : "NO");

	printf("C shared mprotect RW success   : %s\n",
	       c_protect.ret == 0 ? "yes" : "NO");

	printf("C first write same PFN         : %s\n",
	       c1.present && c2.present && c1.pfn == c2.pfn ? "yes" : "NO");

	printf("C backing changed              : %s\n",
	       pread_u32(fd_ro,
			 (off_t) (2 * page_size)) ==
	       0xc2c2c2c2U ? "yes" : "NO");

	perf_group_close(&perf_group);

	munmap((void *)map_a, page_size);

	munmap((void *)map_b, page_size);

	munmap((void *)map_c, page_size);

	close(fd_ro);
	close(fd_rw);

	unlink(path);

	return EXIT_SUCCESS;
}
