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

#define PM_PFN_MASK   ((1ULL << 55) - 1ULL)
#define PM_SOFT_DIRTY (1ULL << 55)
#define PM_EXCLUSIVE  (1ULL << 56)
#define PM_PRESENT    (1ULL << 63)

struct pm_entry {
	uint64_t raw;
	uint64_t pfn;

	int present;
	int soft_dirty;
	int exclusive;
};

struct usage_snapshot {
	long minflt;
	long majflt;
};

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

static struct pm_entry read_pagemap(int fd,
				    const void *address, size_t page_size)
{
	uint64_t raw = 0;

	uint64_t vpn = (uint64_t) (uintptr_t) address / (uint64_t) page_size;

	ssize_t result = pread(fd,
			       &raw,
			       sizeof(raw),
			       (off_t) (vpn * sizeof(raw)));

	if (result != (ssize_t) sizeof(raw)) {
		if (result < 0)
			die("pread pagemap");

		fprintf(stderr, "short pagemap read: %zd\n", result);

		exit(EXIT_FAILURE);
	}

	struct pm_entry entry = {
		.raw = raw,
		.pfn = raw & PM_PFN_MASK,

		.present = !!(raw & PM_PRESENT),

		.soft_dirty = !!(raw & PM_SOFT_DIRTY),

		.exclusive = !!(raw & PM_EXCLUSIVE)
	};

	return entry;
}

static void print_pm(const char *name, const struct pm_entry *entry)
{
	printf("\n========== %s ==========\n", name);

	printf("raw pagemap          : 0x%016" PRIx64 "\n", entry->raw);

	printf("present              : %d\n", entry->present);

	printf("soft-dirty bit55     : %d\n", entry->soft_dirty);

	printf("exclusive            : %d\n", entry->exclusive);

	printf("PFN                  : 0x%011" PRIx64 "\n", entry->pfn);
}

static int token_exists(const char *text, const char *token)
{
	char copy[512];

	snprintf(copy, sizeof(copy), "%s", text);

	char *save = NULL;

	for (char *word =
	     strtok_r(copy, " \t\n", &save);
	     word != NULL; word = strtok_r(NULL, " \t\n", &save)) {
		if (strcmp(word, token) == 0)
			return 1;
	}

	return 0;
}

static int read_vmflags(const void *address, char *buffer, size_t size)
{
	uintptr_t target = (uintptr_t) address;

	FILE *fp = fopen("/proc/self/smaps", "r");

	if (fp == NULL)
		die("fopen smaps");

	char line[1024];
	int active = 0;
	int found = 0;

	buffer[0] = '\0';

	while (fgets(line, sizeof(line), fp) != NULL) {

		unsigned long start;
		unsigned long end;
		char perms[8];

		if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {

			active =
			    target >= (uintptr_t) start &&
			    target < (uintptr_t) end;

			continue;
		}

		if (!active)
			continue;

		if (strncmp(line, "VmFlags:", 8) == 0) {

			snprintf(buffer, size, "%s", line + 8);

			buffer[strcspn(buffer, "\n")] = '\0';

			found = 1;
			break;
		}
	}

	fclose(fp);

	return found;
}

static void print_vmflags(const char *name, const void *address)
{
	char flags[512];

	printf("\n========== %s ==========\n", name);

	if (!read_vmflags(address, flags, sizeof(flags))) {

		printf("VmFlags              : not found\n");
		return;
	}

	printf("VmFlags              :%s\n", flags);

	printf("has sd               : %s\n",
	       token_exists(flags, "sd") ? "yes" : "no");
}

static ssize_t clear_soft_dirty(void)
{
	int fd = open("/proc/self/clear_refs",
		      O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		die("open clear_refs");

	const char value[] = "4\n";

	errno = 0;

	ssize_t result = write(fd,
			       value,
			       sizeof(value) - 1);

	int saved_errno = errno;

	close(fd);

	errno = saved_errno;

	return result;
}

static void measure_read(volatile uint32_t * address)
{
	struct usage_snapshot before = usage_now();

	uint32_t value = *address;

	struct usage_snapshot after = usage_now();

	sink += value;

	printf("read value           : 0x%08x\n", value);

	printf("minor faults         : %ld\n", after.minflt - before.minflt);

	printf("major faults         : %ld\n", after.majflt - before.majflt);
}

static void measure_write(volatile uint32_t * address, uint32_t value)
{
	struct usage_snapshot before = usage_now();

	*address = value;

	struct usage_snapshot after = usage_now();

	printf("write value          : 0x%08x\n", value);

	printf("minor faults         : %ld\n", after.minflt - before.minflt);

	printf("major faults         : %ld\n", after.majflt - before.majflt);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0)
		die("sysconf");

	size_t page_size = (size_t)page_size_long;

	int pagemap_fd = open("/proc/self/pagemap",
			      O_RDONLY | O_CLOEXEC);

	if (pagemap_fd < 0)
		die("open pagemap");

	/*
	 * Two ordinary private anonymous pages.
	 * Touch them before clear_refs so they have real,
	 * writable anonymous PTEs.
	 */
	volatile uint32_t *mapping = mmap(NULL,
					  2 * page_size,
					  PROT_READ | PROT_WRITE,
					  MAP_PRIVATE | MAP_ANONYMOUS,
					  -1,
					  0);

	if (mapping == MAP_FAILED)
		die("mmap");

	volatile uint32_t *page0 = mapping;

	volatile uint32_t *page1 = (volatile uint32_t *)
	    ((volatile unsigned char *)mapping + page_size);

	*page0 = 0x11111111U;
	*page1 = 0x22222222U;

	printf("PID                  : %ld\n", (long)getpid());

	printf("page size            : %zu bytes\n", page_size);

	printf("page0                : %p\n", (const void *)page0);

	printf("page1                : %p\n", (const void *)page1);

	/*
	 * ---------------------------------------------------------
	 * 1. State before clear_refs.
	 * ---------------------------------------------------------
	 */
	struct pm_entry p0_initial = read_pagemap(pagemap_fd,
						  (const void *)page0,
						  page_size);

	struct pm_entry p1_initial = read_pagemap(pagemap_fd,
						  (const void *)page1,
						  page_size);

	print_vmflags("1. VMA before clear_refs", (const void *)page0);

	print_pm("1. page0 before clear_refs", &p0_initial);

	print_pm("1. page1 before clear_refs", &p1_initial);

	/*
	 * ---------------------------------------------------------
	 * 2. clear_refs = 4.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 2. write 4 to clear_refs ==========\n");

	errno = 0;

	ssize_t clear1 = clear_soft_dirty();

	printf("write return         : %zd\n", clear1);

	if (clear1 < 0) {
		printf("errno                : %d (%s)\n",
		       errno, strerror(errno));
	}

	struct pm_entry p0_clear = read_pagemap(pagemap_fd,
						(const void *)page0,
						page_size);

	struct pm_entry p1_clear = read_pagemap(pagemap_fd,
						(const void *)page1,
						page_size);

	print_vmflags("2. VMA immediately after clear_refs",
		      (const void *)page0);

	print_pm("2. page0 immediately after clear_refs", &p0_clear);

	print_pm("2. page1 immediately after clear_refs", &p1_clear);

	/*
	 * ---------------------------------------------------------
	 * 3. Pure Load after clear_refs.
	 *
	 * Supported soft-dirty:
	 *   expected 0 faults, bit55 remains 0.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 3. Load page0 after clear_refs ==========\n");

	measure_read(page0);

	struct pm_entry p0_after_read = read_pagemap(pagemap_fd,
						     (const void *)page0,
						     page_size);

	print_pm("3. page0 after Load", &p0_after_read);

	/*
	 * ---------------------------------------------------------
	 * 4. Store after clear_refs.
	 *
	 * Supported soft-dirty:
	 *   write-protected PTE -> minor fault
	 *   bit55 0 -> 1
	 *   PFN unchanged
	 *
	 * Unsupported/inactive:
	 *   direct write
	 *   0 minor faults
	 *   bit55 remains 0
	 * ---------------------------------------------------------
	 */
	printf("\n========== 4. Store page1 after clear_refs ==========\n");

	measure_write(page1, 0x33333333U);

	struct pm_entry p1_after_write = read_pagemap(pagemap_fd,
						      (const void *)page1,
						      page_size);

	print_pm("4. page1 after Store", &p1_after_write);

	printf("\nPFN before clear     : 0x%011" PRIx64 "\n", p1_initial.pfn);

	printf("PFN after Store      : 0x%011" PRIx64 "\n", p1_after_write.pfn);

	printf("PFN unchanged        : %s\n",
	       p1_initial.present &&
	       p1_after_write.present &&
	       p1_initial.pfn == p1_after_write.pfn ? "yes" : "NO");

	/*
	 * ---------------------------------------------------------
	 * 5. Create a brand-new VMA AFTER clear_refs.
	 *
	 * On a working soft-dirty implementation, new VMAs are
	 * deliberately considered soft-dirty so address reuse can
	 * be detected.
	 * ---------------------------------------------------------
	 */
	volatile uint32_t *new_page = mmap(NULL,
					   page_size,
					   PROT_READ | PROT_WRITE,
					   MAP_PRIVATE | MAP_ANONYMOUS,
					   -1,
					   0);

	if (new_page == MAP_FAILED)
		die("mmap new page");

	struct pm_entry new_untouched = read_pagemap(pagemap_fd,
						     (const void *)new_page,
						     page_size);

	print_vmflags("5. brand-new VMA after clear_refs",
		      (const void *)new_page);

	print_pm("5. brand-new untouched page", &new_untouched);

	/*
	 * ---------------------------------------------------------
	 * 6. Clear a second time, then write page1 again.
	 * This tests repeatability.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 6. second clear_refs ==========\n");

	ssize_t clear2 = clear_soft_dirty();

	printf("write return         : %zd\n", clear2);

	struct pm_entry p1_clear2 = read_pagemap(pagemap_fd,
						 (const void *)page1,
						 page_size);

	struct pm_entry new_clear2 = read_pagemap(pagemap_fd,
						  (const void *)new_page,
						  page_size);

	print_pm("6. page1 after second clear", &p1_clear2);

	print_pm("6. new page after second clear", &new_clear2);

	print_vmflags("6. new VMA after second clear", (const void *)new_page);

	printf("\n========== 7. second Store page1 ==========\n");

	struct usage_snapshot before_write2 = usage_now();

	*page1 = 0x44444444U;

	struct usage_snapshot after_write2 = usage_now();

	long second_write_minflt = after_write2.minflt - before_write2.minflt;

	long second_write_majflt = after_write2.majflt - before_write2.majflt;

	printf("minor faults         : %ld\n", second_write_minflt);

	printf("major faults         : %ld\n", second_write_majflt);

	struct pm_entry p1_after_write2 = read_pagemap(pagemap_fd,
						       (const void *)page1,
						       page_size);

	print_pm("7. page1 after second Store", &p1_after_write2);

	/*
	 * ---------------------------------------------------------
	 * Runtime interpretation.
	 * ---------------------------------------------------------
	 */
	char final_flags[512] = { 0 };

	int have_flags = read_vmflags((const void *)page1,
				      final_flags,
				      sizeof(final_flags));

	int sd_vmflag = have_flags && token_exists(final_flags,
						   "sd");

	int any_soft_dirty =
	    p0_initial.soft_dirty ||
	    p1_initial.soft_dirty ||
	    p1_after_write.soft_dirty ||
	    new_untouched.soft_dirty || p1_after_write2.soft_dirty;

	int tracked_write_fault = second_write_minflt > 0;

	printf("\n========== 8. runtime interpretation ==========\n");

	printf("any bit55 observed   : %s\n", any_soft_dirty ? "yes" : "no");

	printf("VmFlags sd observed  : %s\n", sd_vmflag ? "yes" : "no");

	printf("post-clear write fault: %s\n",
	       tracked_write_fault ? "yes" : "no");

	if (!any_soft_dirty && !sd_vmflag && !tracked_write_fault) {

		printf("soft-dirty status    : "
		       "appears unsupported/inactive\n");

	} else {
		printf("soft-dirty status    : "
		       "tracking behavior observed\n");
	}

	printf("\nfinal page0 value    : 0x%08x\n", *page0);

	printf("final page1 value    : 0x%08x\n", *page1);

	printf("sink                 : %" PRIu64 "\n", sink);

	munmap((void *)new_page, page_size);

	munmap((void *)mapping, 2 * page_size);

	close(pagemap_fd);

	return EXIT_SUCCESS;
}
