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
#include <sys/syscall.h>
#include <unistd.h>

#include <asm/unistd.h>

#include "perf_counter.h"

#ifndef __NR_riscv_flush_icache
#define __NR_riscv_flush_icache \
    (__NR_arch_specific_syscall + 15)
#endif

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_SWAPPED        (1ULL << 62)
#define PM_PRESENT        (1ULL << 63)

typedef long (*jit_function_t)(void);

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

struct probe_result {
	int completed;

	int signal_number;
	int si_code;

	uintptr_t fault_address;

	long minflt;
	long majflt;

	uint32_t read_value;
	long exec_result;
};

static sigjmp_buf probe_env;

static volatile sig_atomic_t probe_active;
static volatile sig_atomic_t probe_completed;
static volatile sig_atomic_t probe_signal;
static volatile sig_atomic_t probe_code;

static volatile uintptr_t probe_fault_address;
static volatile uint32_t probe_read_value;
static volatile long probe_exec_result;

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

/*
 * 建立5页reservation：
 *
 * guard | RW work page | RW code page | RW work page | guard
 *
 * 我们只扫描中间3页。
 */
static void *create_guarded_mapping(size_t page_size, void **reservation_out)
{
	size_t reserve_length = 5 * page_size;

	void *reservation = mmap(NULL,
				 reserve_length,
				 PROT_NONE,
				 MAP_PRIVATE | MAP_ANONYMOUS,
				 -1,
				 0);

	if (reservation == MAP_FAILED)
		return MAP_FAILED;

	unsigned char *work = (unsigned char *)reservation + page_size;

	void *result = mmap(work,
			    3 * page_size,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
			    -1,
			    0);

	if (result == MAP_FAILED) {
		int saved_errno = errno;

		munmap(reservation, reserve_length);

		errno = saved_errno;

		return MAP_FAILED;
	}

	if (result != (void *)work) {
		munmap(reservation, reserve_length);

		errno = EFAULT;

		return MAP_FAILED;
	}

	*reservation_out = reservation;

	return result;
}

static unsigned long read_vm_pte(void)
{
	FILE *fp = fopen("/proc/self/status", "r");

	if (fp == NULL)
		die("fopen status");

	char line[512];

	unsigned long vm_pte = 0;
	int found = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &vm_pte) == 1) {
			found = 1;
			break;
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "VmPTE not found\n");

		exit(EXIT_FAILURE);
	}

	return vm_pte;
}

static void print_layout(const char *name,
			 const void *work,
			 size_t length, unsigned long vm_pte_baseline)
{
	uintptr_t target_start = (uintptr_t) work;

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
			    (uintptr_t) start <
			    target_end && (uintptr_t) end > target_start;

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

	printf("\n");
	printf("VMA count            : %zu\n", vma_count);
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

static int open_pagemap(void)
{
	int fd = open("/proc/self/pagemap",
		      O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		die("open pagemap");

	return fd;
}

static struct pagemap_entry read_pagemap(const void *address, size_t page_size)
{
	int fd = open_pagemap();

	uint64_t raw = 0;

	uint64_t vpn = (uint64_t) (uintptr_t) address / (uint64_t) page_size;

	off_t offset = (off_t) (vpn * sizeof(raw));

	ssize_t result = pread(fd,
			       &raw,
			       sizeof(raw),
			       offset);

	close(fd);

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

static void print_pagemap(const char *name,
			  const void *address, size_t page_size)
{
	struct pagemap_entry entry = read_pagemap(address,
						  page_size);

	printf("\n========== %s ==========\n", name);

	printf("address              : %p\n", address);

	printf("raw pagemap          : 0x%016" PRIx64 "\n", entry.raw);

	printf("present              : %d\n", entry.present);

	printf("swapped              : %d\n", entry.swapped);

	printf("exclusive            : %d\n", entry.exclusive);

	printf("PFN                  : 0x%011" PRIx64 "\n", entry.pfn);
}

static void compare_pfn(const char *name,
			const struct pagemap_entry *before,
			const struct pagemap_entry *after)
{
	printf("\n========== %s ==========\n", name);

	printf("before PFN           : 0x%011" PRIx64 "\n", before->pfn);

	printf("after PFN            : 0x%011" PRIx64 "\n", after->pfn);

	printf("PFN unchanged        : %s\n",
	       before->present &&
	       after->present && before->pfn == after->pfn ? "yes" : "NO");
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

static int flush_instruction_cache(void *start, void *end)
{
	errno = 0;

	long result = syscall(__NR_riscv_flush_icache,
			      (uintptr_t) start,
			      (uintptr_t) end,
			      0UL);

	if (result != 0) {
		printf("riscv_flush_icache   : %ld "
		       "errno=%d (%s)\n", result, errno, strerror(errno));

		return -1;
	}

	printf("riscv_flush_icache   : success\n");

	return 0;
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
		die("sigaction SIGSEGV");
	}

	if (sigaction(SIGBUS, &action, NULL) != 0) {
		die("sigaction SIGBUS");
	}

	if (sigaction(SIGILL, &action, NULL) != 0) {
		die("sigaction SIGILL");
	}
}

static void reset_probe(void)
{
	probe_active = 0;
	probe_completed = 0;
	probe_signal = 0;
	probe_code = 0;

	probe_fault_address = 0;

	probe_read_value = 0;
	probe_exec_result = 0;
}

static struct probe_result finish_probe(struct usage_snapshot before)
{
	struct usage_snapshot after = usage_now();

	struct probe_result result = {
		.completed = probe_completed,

		.signal_number = probe_signal,

		.si_code = probe_code,

		.fault_address = probe_fault_address,

		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt,

		.read_value = probe_read_value,

		.exec_result = probe_exec_result,
	};

	return result;
}

static struct probe_result probe_read_u32(volatile uint32_t * address)
{
	struct usage_snapshot before = usage_now();

	reset_probe();

	if (sigsetjmp(probe_env, 1) == 0) {
		probe_active = 1;

		probe_read_value = *address;

		probe_completed = 1;
		probe_active = 0;
	}

	probe_active = 0;

	return finish_probe(before);
}

static struct probe_result probe_write_u32(volatile uint32_t * address,
					   uint32_t value)
{
	struct usage_snapshot before = usage_now();

	reset_probe();

	if (sigsetjmp(probe_env, 1) == 0) {
		probe_active = 1;

		*address = value;

		probe_completed = 1;
		probe_active = 0;
	}

	probe_active = 0;

	return finish_probe(before);
}

static struct probe_result probe_execute(void *address)
{
	struct usage_snapshot before = usage_now();

	reset_probe();

	if (sigsetjmp(probe_env, 1) == 0) {
		probe_active = 1;

		jit_function_t function = (jit_function_t)
		    (uintptr_t) address;

		probe_exec_result = function();

		probe_completed = 1;
		probe_active = 0;
	}

	probe_active = 0;

	return finish_probe(before);
}

static const char *signal_name(int signal_number)
{
	switch (signal_number) {
	case 0:
		return "none";

	case SIGSEGV:
		return "SIGSEGV";

	case SIGBUS:
		return "SIGBUS";

	case SIGILL:
		return "SIGILL";

	default:
		return "other";
	}
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

static void print_probe(const char *name,
			const struct probe_result *probe,
			const void *expected_fault_address)
{
	printf("\n========== %s ==========\n", name);

	printf("access completed     : %s\n", probe->completed ? "yes" : "no");

	printf("signal               : %d (%s)\n",
	       probe->signal_number, signal_name(probe->signal_number));

	printf("si_code              : %d (%s)\n",
	       probe->si_code,
	       segv_code_name(probe->signal_number, probe->si_code));

	if (probe->signal_number != 0) {
		printf("si_addr              : %p\n", (void *)
		       probe->fault_address);

		printf("expected address     : %p\n", expected_fault_address);

		printf("address matches      : %s\n",
		       probe->fault_address == (uintptr_t)
		       expected_fault_address ? "yes" : "NO");
	}

	printf("minor faults         : %ld\n", probe->minflt);

	printf("major faults         : %ld\n", probe->majflt);

	if (probe->completed) {
		printf("read value           : 0x%08x\n", probe->read_value);

		printf("exec result          : %ld\n", probe->exec_result);
	}
}

static void write_code(void *code_page, uint32_t first_instruction)
{
	/*
	 * addi a0, zero, immediate
	 * ret
	 */
	uint32_t code[2] = {
		first_instruction,
		0x00008067U
	};

	memcpy(code_page, code, sizeof(code));

	printf("code[0]              : 0x%08x\n", code[0]);

	printf("code[1]              : 0x%08x\n", code[1]);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0)
		die("sysconf");

	size_t page_size = (size_t)page_size_long;

	unsigned long vm_pte_baseline = read_vm_pte();

	void *reservation = NULL;

	unsigned char *work = create_guarded_mapping(page_size,
						     &reservation);

	if (work == MAP_FAILED)
		die("create_guarded_mapping");

	size_t work_length = 3 * page_size;

	unsigned char *code_page = work + page_size;

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

	printf("reservation          : %p\n", reservation);

	printf("work mapping         : %p\n", work);

	printf("code page            : %p\n", code_page);

	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	/*
	 * RV64:
	 *
	 *   addi a0, zero, 42
	 *   ret
	 *
	 * 0x02a00513
	 * 0x00008067
	 */
	printf("\n========== 1. write code while RW ==========\n");

	write_code(code_page, 0x02a00513U);

	if (flush_instruction_cache(code_page, code_page + 8) != 0) {
		return EXIT_FAILURE;
	}

	print_layout("1. initial RW layout",
		     work, work_length, vm_pte_baseline);

	struct pagemap_entry initial_entry = read_pagemap(code_page,
							  page_size);

	print_pagemap("1. code page under RW", code_page, page_size);

	/*
	 * RW页：数据Load应成功。
	 */
	struct probe_result rw_read = probe_read_u32((volatile uint32_t *)
						     code_page);

	print_probe("2. data read under RW", &rw_read, code_page);

	/*
	 * RW页：Instruction fetch应该被NX拒绝。
	 */
	struct probe_result rw_exec = probe_execute(code_page);

	print_probe("2. execute under RW", &rw_exec, code_page);

	printf("expected              : SIGSEGV / SEGV_ACCERR\n");

	/*
	 * RW -> RX。
	 */
	struct perf_result to_rx = measure_mprotect(&perf_group,
						    code_page,
						    page_size,
						    PROT_READ | PROT_EXEC);

	print_perf("3. mprotect RW to RX", &to_rx);

	if (to_rx.ret != 0)
		return EXIT_FAILURE;

	print_layout("3. layout under RX", work, work_length, vm_pte_baseline);

	struct pagemap_entry rx_entry = read_pagemap(code_page,
						     page_size);

	compare_pfn("3. PFN across RW to RX", &initial_entry, &rx_entry);

	/*
	 * RX:
	 * - read OK
	 * - execute OK, result=42
	 * - write denied
	 */
	struct probe_result rx_read = probe_read_u32((volatile uint32_t *)
						     code_page);

	print_probe("4. data read under RX", &rx_read, code_page);

	struct probe_result rx_exec = probe_execute(code_page);

	print_probe("4. execute under RX", &rx_exec, code_page);

	printf("expected exec result : 42\n");
	printf("exec result valid    : %s\n",
	       rx_exec.completed && rx_exec.exec_result == 42 ? "yes" : "NO");

	/*
	 * 写同样的机器指令值。
	 * 即使意外成功，也不会破坏代码。
	 */
	struct probe_result rx_write = probe_write_u32((volatile uint32_t *)
						       code_page,
						       0x02a00513U);

	print_probe("4. write under RX", &rx_write, code_page);

	printf("expected              : SIGSEGV / SEGV_ACCERR\n");

	/*
	 * RX -> X-only。
	 */
	struct perf_result to_x = measure_mprotect(&perf_group,
						   code_page,
						   page_size,
						   PROT_EXEC);

	print_perf("5. mprotect RX to X-only", &to_x);

	if (to_x.ret != 0)
		return EXIT_FAILURE;

	print_layout("5. layout under X-only",
		     work, work_length, vm_pte_baseline);

	struct pagemap_entry x_entry = read_pagemap(code_page,
						    page_size);

	compare_pfn("5. PFN across RX to X-only", &rx_entry, &x_entry);

	/*
	 * X-only：
	 * instruction fetch成功。
	 */
	struct probe_result x_exec = probe_execute(code_page);

	print_probe("6. execute under X-only", &x_exec, code_page);

	printf("expected exec result : 42\n");
	printf("exec result valid    : %s\n",
	       x_exec.completed && x_exec.exec_result == 42 ? "yes" : "NO");

	/*
	 * X-only：
	 * 普通数据Load应该失败。
	 */
	struct probe_result x_read = probe_read_u32((volatile uint32_t *)
						    code_page);

	print_probe("6. data read under X-only", &x_read, code_page);

	printf("expected              : SIGSEGV / SEGV_ACCERR\n");

	/*
	 * X-only：
	 * 数据Store也应该失败。
	 */
	struct probe_result x_write = probe_write_u32((volatile uint32_t *)
						      code_page,
						      0x02a00513U);

	print_probe("6. data write under X-only", &x_write, code_page);

	printf("expected              : SIGSEGV / SEGV_ACCERR\n");

	/*
	 * X-only -> RW。
	 *
	 * 恢复写权限，同时去掉X。
	 */
	struct perf_result x_to_rw = measure_mprotect(&perf_group,
						      code_page,
						      page_size,
						      PROT_READ | PROT_WRITE);

	print_perf("7. mprotect X-only to RW", &x_to_rw);

	if (x_to_rw.ret != 0)
		return EXIT_FAILURE;

	print_layout("7. layout after restoring RW",
		     work, work_length, vm_pte_baseline);

	struct pagemap_entry rw_again_entry = read_pagemap(code_page,
							   page_size);

	compare_pfn("7. PFN across X-only to RW", &x_entry, &rw_again_entry);

	/*
	 * X已去掉，所以旧代码即使仍在那里，也不能执行。
	 */
	struct probe_result rw_again_exec = probe_execute(code_page);

	print_probe("7. execute after restoring RW", &rw_again_exec, code_page);

	printf("expected              : SIGSEGV / SEGV_ACCERR\n");

	/*
	 * 把函数改成：
	 *
	 *   addi a0, zero, 77
	 *   ret
	 */
	printf("\n========== 8. modify code while RW ==========\n");

	write_code(code_page, 0x04d00513U);

	if (flush_instruction_cache(code_page, code_page + 8) != 0) {
		return EXIT_FAILURE;
	}

	struct pagemap_entry modified_entry = read_pagemap(code_page,
							   page_size);

	compare_pfn("8. PFN across code modification",
		    &rw_again_entry, &modified_entry);

	/*
	 * RW -> RX again。
	 */
	struct perf_result modified_to_rx = measure_mprotect(&perf_group,
							     code_page,
							     page_size,
							     PROT_READ |
							     PROT_EXEC);

	print_perf("9. mprotect modified code RW to RX", &modified_to_rx);

	if (modified_to_rx.ret != 0)
		return EXIT_FAILURE;

	struct pagemap_entry final_entry = read_pagemap(code_page,
							page_size);

	compare_pfn("9. final PFN comparison", &modified_entry, &final_entry);

	print_layout("9. final RX layout", work, work_length, vm_pte_baseline);

	struct probe_result final_exec = probe_execute(code_page);

	print_probe("10. execute modified code under RX",
		    &final_exec, code_page);

	printf("expected exec result : 77\n");

	printf("exec result valid    : %s\n",
	       final_exec.completed &&
	       final_exec.exec_result == 77 ? "yes" : "NO");

	printf("\n========== final summary ==========\n");

	printf("RW execute denied    : %s\n",
	       !rw_exec.completed &&
	       rw_exec.signal_number ==
	       SIGSEGV && rw_exec.si_code == SEGV_ACCERR ? "yes" : "NO");

	printf("RX execute works     : %s\n",
	       rx_exec.completed && rx_exec.exec_result == 42 ? "yes" : "NO");

	printf("RX write denied      : %s\n",
	       !rx_write.completed &&
	       rx_write.signal_number ==
	       SIGSEGV && rx_write.si_code == SEGV_ACCERR ? "yes" : "NO");

	printf("X-only execute works : %s\n",
	       x_exec.completed && x_exec.exec_result == 42 ? "yes" : "NO");

	printf("X-only read denied   : %s\n",
	       !x_read.completed &&
	       x_read.signal_number ==
	       SIGSEGV && x_read.si_code == SEGV_ACCERR ? "yes" : "NO");

	printf("X-only write denied  : %s\n",
	       !x_write.completed &&
	       x_write.signal_number ==
	       SIGSEGV && x_write.si_code == SEGV_ACCERR ? "yes" : "NO");

	printf("modified code works  : %s\n",
	       final_exec.completed &&
	       final_exec.exec_result == 77 ? "yes" : "NO");

	perf_group_close(&perf_group);

	if (munmap(reservation, 5 * page_size) != 0) {
		die("munmap");
	}

	return EXIT_SUCCESS;
}
