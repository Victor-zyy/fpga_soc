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
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 0x01
#endif

#define TEST_PAGES 3

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_PRESENT        (1ULL << 63)

enum {
	KPF_LOCKED = 0,
	KPF_ERROR = 1,
	KPF_REFERENCED = 2,
	KPF_UPTODATE = 3,
	KPF_DIRTY = 4,
	KPF_LRU = 5,
	KPF_ACTIVE = 6,
	KPF_SLAB = 7,
	KPF_WRITEBACK = 8,
	KPF_RECLAIM = 9,
	KPF_BUDDY = 10,
	KPF_MMAP = 11,
	KPF_ANON = 12,
	KPF_SWAPCACHE = 13,
	KPF_SWAPBACKED = 14,
	KPF_COMPOUND_HEAD = 15,
	KPF_COMPOUND_TAIL = 16,
	KPF_HUGE = 17,
	KPF_UNEVICTABLE = 18,
	KPF_HWPOISON = 19,
	KPF_NOPAGE = 20,
	KPF_KSM = 21,
	KPF_THP = 22,
	KPF_OFFLINE = 23,
	KPF_ZERO_PAGE = 24,
	KPF_IDLE = 25,
	KPF_PGTABLE = 26
};

static const char *kpf_names[27] = {
	"LOCKED",
	"ERROR",
	"REFERENCED",
	"UPTODATE",
	"DIRTY",
	"LRU",
	"ACTIVE",
	"SLAB",
	"WRITEBACK",
	"RECLAIM",
	"BUDDY",
	"MMAP",
	"ANON",
	"SWAPCACHE",
	"SWAPBACKED",
	"COMPOUND_HEAD",
	"COMPOUND_TAIL",
	"HUGE",
	"UNEVICTABLE",
	"HWPOISON",
	"NOPAGE",
	"KSM",
	"THP",
	"OFFLINE",
	"ZERO_PAGE",
	"IDLE",
	"PGTABLE"
};

struct usage_snapshot {
	long minflt;
	long majflt;
};

struct page_snapshot {
	uintptr_t address;

	uint64_t pagemap_raw;
	uint64_t pfn;

	int present;
	int exclusive;

	int resident;

	int physical_valid;
	uint64_t kpagecount;
	uint64_t kpageflags;
};

struct vma_info {
	char header[512];
	char vmflags[512];

	unsigned long rss_kb;
	unsigned long anonymous_kb;
	unsigned long locked_kb;
};

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static int flag_set(uint64_t flags, unsigned int bit)
{
	return !!(flags & (1ULL << bit));
}

static struct usage_snapshot usage_now(void)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage) != 0) {
		die("getrusage");
	}

	struct usage_snapshot result = {
		.minflt = usage.ru_minflt,
		.majflt = usage.ru_majflt
	};

	return result;
}

static uint64_t read_indexed_u64(int fd, uint64_t index, const char *what)
{
	uint64_t value = 0;

	off_t offset = (off_t) (index * sizeof(value));

	ssize_t result = pread(fd,
			       &value,
			       sizeof(value),
			       offset);

	if (result != (ssize_t) sizeof(value)) {
		if (result < 0) {
			perror(what);
		} else {
			fprintf(stderr, "%s: short read %zd\n", what, result);
		}

		exit(EXIT_FAILURE);
	}

	return value;
}

static struct page_snapshot snapshot_page(const void *address,
					  size_t page_size,
					  int pagemap_fd,
					  int kpagecount_fd, int kpageflags_fd)
{
	struct page_snapshot result;

	memset(&result, 0, sizeof(result));

	result.address = (uintptr_t) address;

	uint64_t vpn = (uint64_t) (uintptr_t) address / page_size;

	result.pagemap_raw = read_indexed_u64(pagemap_fd, vpn, "pagemap");

	result.pfn = result.pagemap_raw & PM_PFN_MASK;

	result.present = !!(result.pagemap_raw & PM_PRESENT);

	result.exclusive = !!(result.pagemap_raw & PM_EXCLUSIVE);

	unsigned char vec = 0;

	if (mincore((void *)address, page_size, &vec) == 0) {
		result.resident = !!(vec & 1);
	}

	if (result.present && result.pfn != 0) {

		result.physical_valid = 1;

		result.kpagecount =
		    read_indexed_u64(kpagecount_fd, result.pfn, "kpagecount");

		result.kpageflags =
		    read_indexed_u64(kpageflags_fd, result.pfn, "kpageflags");
	}

	return result;
}

static void print_all_flags(uint64_t flags)
{
	printf("kpageflags set       :");

	int any = 0;

	for (unsigned int bit = 0; bit < 27; ++bit) {

		if (flag_set(flags, bit)) {
			printf(" %s", kpf_names[bit]);
			any = 1;
		}
	}

	if (!any)
		printf(" none");

	printf("\n");
}

static void print_snapshot(const char *name,
			   const struct page_snapshot *snapshot)
{
	printf("\n========== %s ==========\n", name);

	printf("VA                   : %p\n", (void *)snapshot->address);

	printf("pagemap raw          : 0x%016"
	       PRIx64 "\n", snapshot->pagemap_raw);

	printf("present              : %d\n", snapshot->present);

	printf("exclusive            : %d\n", snapshot->exclusive);

	printf("PFN                  : 0x%011" PRIx64 "\n", snapshot->pfn);

	printf("resident             : %d\n", snapshot->resident);

	if (!snapshot->physical_valid) {
		printf("kpagecount           : N/A\n");
		printf("kpageflags           : N/A\n");
		return;
	}

	printf("kpagecount           : %" PRIu64 "\n", snapshot->kpagecount);

	printf("kpageflags raw       : 0x%016"
	       PRIx64 "\n", snapshot->kpageflags);

	print_all_flags(snapshot->kpageflags);

	printf("\nselected flags:\n");

	printf("  LOCKED             : %d\n",
	       flag_set(snapshot->kpageflags, KPF_LOCKED));

	printf("  LRU                : %d\n",
	       flag_set(snapshot->kpageflags, KPF_LRU));

	printf("  ACTIVE             : %d\n",
	       flag_set(snapshot->kpageflags, KPF_ACTIVE));

	printf("  MMAP               : %d\n",
	       flag_set(snapshot->kpageflags, KPF_MMAP));

	printf("  ANON               : %d\n",
	       flag_set(snapshot->kpageflags, KPF_ANON));

	printf("  SWAPBACKED         : %d\n",
	       flag_set(snapshot->kpageflags, KPF_SWAPBACKED));

	printf("  UNEVICTABLE        : %d\n",
	       flag_set(snapshot->kpageflags, KPF_UNEVICTABLE));

	printf("  REFERENCED         : %d\n",
	       flag_set(snapshot->kpageflags, KPF_REFERENCED));

	printf("  DIRTY              : %d\n",
	       flag_set(snapshot->kpageflags, KPF_DIRTY));
}

static void read_vma_info(const void *address, struct vma_info *info)
{
	memset(info, 0, sizeof(*info));

	uintptr_t target = (uintptr_t) address;

	FILE *fp = fopen("/proc/self/smaps",
			 "r");

	if (fp == NULL)
		die("fopen smaps");

	char line[1024];
	int active = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {

		unsigned long start;
		unsigned long end;
		char perms[8];

		if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {

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

		} else if (sscanf(line, "Anonymous: %lu kB", &value) == 1) {

			info->anonymous_kb = value;

		} else if (sscanf(line, "Locked: %lu kB", &value) == 1) {

			info->locked_kb = value;

		} else if (strncmp(line, "VmFlags:", 8) == 0) {

			snprintf(info->vmflags,
				 sizeof(info->vmflags), "%s", line + 8);

			info->vmflags[strcspn(info->vmflags, "\n")] = '\0';

			break;
		}
	}

	fclose(fp);
}

static int has_token(const char *text, const char *token)
{
	char copy[512];

	snprintf(copy, sizeof(copy), "%s", text);

	char *save = NULL;

	for (char *word =
	     strtok_r(copy,
		      " \t\n",
		      &save);
	     word != NULL; word = strtok_r(NULL, " \t\n", &save)) {

		if (strcmp(word, token) == 0) {
			return 1;
		}
	}

	return 0;
}

static unsigned long read_vmlck(void)
{
	FILE *fp = fopen("/proc/self/status",
			 "r");

	if (fp == NULL)
		die("fopen status");

	char line[512];

	unsigned long value = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {

		if (sscanf(line, "VmLck: %lu kB", &value) == 1) {
			break;
		}
	}

	fclose(fp);

	return value;
}

static void print_vma_info(const char *name, const void *address)
{
	struct vma_info info;

	read_vma_info(address, &info);

	printf("\n========== %s ==========\n", name);

	printf("mapping              : %s\n", info.header);

	printf("Rss                  : %lu kB\n", info.rss_kb);

	printf("Anonymous            : %lu kB\n", info.anonymous_kb);

	printf("Locked               : %lu kB\n", info.locked_kb);

	printf("VmLck process total  : %lu kB\n", read_vmlck());

	printf("VmFlags              :%s\n", info.vmflags);

	printf("has lo               : %s\n",
	       has_token(info.vmflags, "lo") ? "yes" : "no");

	printf("has lf               : %s\n",
	       has_token(info.vmflags, "lf") ? "yes" : "no");
}

static int do_mlock2_onfault(const void *address, size_t length)
{
#if defined(SYS_mlock2)
	return (int)syscall(SYS_mlock2, address, length, MLOCK_ONFAULT);
#elif defined(__NR_mlock2)
	return (int)syscall(__NR_mlock2, address, length, MLOCK_ONFAULT);
#else
	(void)address;
	(void)length;

	errno = ENOSYS;
	return -1;
#endif
}

static void compare_identity(const char *name,
			     const struct page_snapshot *before,
			     const struct page_snapshot *after)
{
	printf("\n========== %s ==========\n", name);

	printf("before PFN           : 0x%011" PRIx64 "\n", before->pfn);

	printf("after PFN            : 0x%011" PRIx64 "\n", after->pfn);

	printf("PFN unchanged        : %s\n",
	       before->present &&
	       after->present && before->pfn == after->pfn ? "yes" : "no");

	if (before->physical_valid && after->physical_valid) {

		printf("before count         : %" PRIu64 "\n",
		       before->kpagecount);

		printf("after count          : %" PRIu64 "\n",
		       after->kpagecount);

		printf("before UNEVICTABLE   : %d\n",
		       flag_set(before->kpageflags, KPF_UNEVICTABLE));

		printf("after UNEVICTABLE    : %d\n",
		       flag_set(after->kpageflags, KPF_UNEVICTABLE));

		printf("before LRU           : %d\n",
		       flag_set(before->kpageflags, KPF_LRU));

		printf("after LRU            : %d\n",
		       flag_set(after->kpageflags, KPF_LRU));

		printf("before ANON          : %d\n",
		       flag_set(before->kpageflags, KPF_ANON));

		printf("after ANON           : %d\n",
		       flag_set(after->kpageflags, KPF_ANON));
	}
}

static volatile uint32_t *page_ptr(volatile unsigned char *mapping,
				   size_t page_size, size_t page)
{
	return (volatile uint32_t *)
	    (mapping + page * page_size);
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

	int kpagecount_fd = open("/proc/kpagecount",
				 O_RDONLY | O_CLOEXEC);

	if (kpagecount_fd < 0)
		die("open kpagecount");

	int kpageflags_fd = open("/proc/kpageflags",
				 O_RDONLY | O_CLOEXEC);

	if (kpageflags_fd < 0)
		die("open kpageflags");

	volatile unsigned char *mapping = mmap(NULL,
					       TEST_PAGES * page_size,
					       PROT_READ | PROT_WRITE,
					       MAP_PRIVATE | MAP_ANONYMOUS,
					       -1,
					       0);

	if (mapping == MAP_FAILED)
		die("mmap");

	volatile uint32_t *control = page_ptr(mapping,
					      page_size,
					      0);

	volatile uint32_t *lock_target = page_ptr(mapping,
						  page_size,
						  1);

	volatile uint32_t *onfault_target = page_ptr(mapping,
						     page_size,
						     2);

	/*
	 * page0 and page1 become ordinary private anonymous pages.
	 * page2 deliberately remains untouched.
	 */
	*control = 0x11111111U;
	*lock_target = 0x22222222U;

	printf("PID                  : %ld\n", (long)getpid());

	printf("page size            : %zu\n", page_size);

	printf("mapping              : %p\n", (const void *)mapping);

	printf("control page         : %p\n", (const void *)control);

	printf("mlock target         : %p\n", (const void *)lock_target);

	printf("onfault target       : %p\n", (const void *)onfault_target);

	/*
	 * ---------------------------------------------------------
	 * 0. Initial state.
	 * ---------------------------------------------------------
	 */
	struct page_snapshot control_initial =
	    snapshot_page((const void *)control,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot target_initial =
	    snapshot_page((const void *)lock_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot onfault_initial =
	    snapshot_page((const void *)onfault_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("0A. control initial", &control_initial);

	print_snapshot("0B. mlock target initial", &target_initial);

	print_snapshot("0C. onfault target untouched", &onfault_initial);

	print_vma_info("0. VMA before locking", (const void *)lock_target);

	/*
	 * ---------------------------------------------------------
	 * 1. mlock an already-resident ordinary anon page.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 1. mlock resident page ==========\n");

	errno = 0;

	int lock_ret = mlock((const void *)lock_target,
			     page_size);

	printf("mlock return         : %d\n", lock_ret);

	if (lock_ret != 0) {
		printf("errno                : %d (%s)\n",
		       errno, strerror(errno));

		return EXIT_FAILURE;
	}

	struct page_snapshot target_locked =
	    snapshot_page((const void *)lock_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot control_during_lock =
	    snapshot_page((const void *)control,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("1A. target after mlock", &target_locked);

	print_vma_info("1A. target VMA after mlock", (const void *)lock_target);

	compare_identity("1A. target transition into mlock",
			 &target_initial, &target_locked);

	print_snapshot("1B. control while target locked", &control_during_lock);

	/*
	 * ---------------------------------------------------------
	 * 2. munlock the same resident page.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 2. munlock resident page ==========\n");

	if (munlock((const void *)lock_target, page_size) != 0) {
		die("munlock target");
	}

	struct page_snapshot target_unlocked =
	    snapshot_page((const void *)lock_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("2. target after munlock", &target_unlocked);

	print_vma_info("2. target VMA after munlock",
		       (const void *)lock_target);

	compare_identity("2. target transition out of mlock",
			 &target_locked, &target_unlocked);

	/*
	 * ---------------------------------------------------------
	 * 3. MLOCK_ONFAULT on untouched page.
	 *
	 * Important:
	 * this should establish locking policy without creating
	 * a PTE/PFN for this page yet.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 3. mlock2 MLOCK_ONFAULT ==========\n");

	errno = 0;

	int onfault_ret = do_mlock2_onfault((const void *)onfault_target,
					    page_size);

	printf("mlock2 return        : %d\n", onfault_ret);

	if (onfault_ret != 0) {
		printf("errno                : %d (%s)\n",
		       errno, strerror(errno));

		return EXIT_FAILURE;
	}

	struct page_snapshot onfault_policy =
	    snapshot_page((const void *)onfault_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("3. onfault page before access", &onfault_policy);

	print_vma_info("3. onfault VMA before access",
		       (const void *)onfault_target);

	/*
	 * ---------------------------------------------------------
	 * 4. First Store into the MLOCK_ONFAULT page.
	 *
	 * It must now allocate the ordinary anonymous page.
	 * Since the VMA is locked-on-fault, inspect whether the new
	 * physical page is immediately UNEVICTABLE.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 4. first Store into onfault page ==========\n");

	struct usage_snapshot before = usage_now();

	*onfault_target = 0x33333333U;
	/*
	 * Force a local LRU/mlock batch drain without touching the
	 * lock state of onfault_target itself.
	 *
	 * mlock(control) runs mlock_vma_pages_range(), whose
	 * lru_add_drain() will also drain the pending per-CPU
	 * mlock_new_folio batch for onfault_target.
	 */
	if (mlock((const void *)control, page_size) != 0)
		die("mlock control drain trigger");

	struct page_snapshot onfault_after_drain =
	    snapshot_page((const void *)onfault_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("4B. onfault page after forced batch drain",
		       &onfault_after_drain);

	print_vma_info("4B. onfault VMA after forced batch drain",
		       (const void *)onfault_target);

	/*
	 * Unlock only the control page again.
	 * onfault_target remains VM_LOCKED|VM_LOCKONFAULT.
	 */
	if (munlock((const void *)control, page_size) != 0)
		die("munlock control drain trigger");

	struct page_snapshot onfault_after_control_unlock =
	    snapshot_page((const void *)onfault_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("4C. onfault page after control munlock",
		       &onfault_after_control_unlock);

	struct usage_snapshot after = usage_now();

	long store_minflt = after.minflt - before.minflt;

	long store_majflt = after.majflt - before.majflt;

	printf("minor faults         : %ld\n", store_minflt);

	printf("major faults         : %ld\n", store_majflt);

	struct page_snapshot onfault_materialized =
	    snapshot_page((const void *)onfault_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("4. onfault page after first Store",
		       &onfault_materialized);

	print_vma_info("4. onfault VMA after first Store",
		       (const void *)onfault_target);

	/*
	 * ---------------------------------------------------------
	 * 5. munlock the MLOCK_ONFAULT page.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 5. munlock onfault page ==========\n");

	if (munlock((const void *)onfault_target, page_size) != 0) {
		die("munlock onfault");
	}

	struct page_snapshot onfault_unlocked =
	    snapshot_page((const void *)onfault_target,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("5. onfault page after munlock", &onfault_unlocked);

	print_vma_info("5. onfault VMA after munlock",
		       (const void *)onfault_target);

	compare_identity("5. onfault physical identity across munlock",
			 &onfault_materialized, &onfault_unlocked);

	/*
	 * ---------------------------------------------------------
	 * Semantic summary.
	 * ---------------------------------------------------------
	 */
	int resident_mlock_transition =
	    target_initial.present &&
	    target_locked.present &&
	    target_initial.pfn ==
	    target_locked.pfn && !flag_set(target_initial.kpageflags,
					   KPF_UNEVICTABLE) &&
	    flag_set(target_locked.kpageflags,
		     KPF_UNEVICTABLE);

	int resident_munlock_transition =
	    target_locked.pfn ==
	    target_unlocked.pfn && flag_set(target_locked.kpageflags,
					    KPF_UNEVICTABLE) &&
	    !flag_set(target_unlocked.kpageflags,
		      KPF_UNEVICTABLE);

	int onfault_no_materialization =
	    !onfault_policy.present && onfault_policy.pfn == 0;

	int onfault_locked_after_store =
	    onfault_materialized.present &&
	    onfault_materialized.physical_valid &&
	    flag_set(onfault_materialized.kpageflags,
		     KPF_UNEVICTABLE);

	int onfault_munlock_transition =
	    onfault_materialized.pfn ==
	    onfault_unlocked.pfn && flag_set(onfault_materialized.kpageflags,
					     KPF_UNEVICTABLE) &&
	    !flag_set(onfault_unlocked.kpageflags,
		      KPF_UNEVICTABLE);

	int lru_survives_mlock =
	    target_locked.physical_valid && flag_set(target_locked.kpageflags,
						     KPF_LRU);

	printf("\n========== final semantic summary ==========\n");

	printf("resident mlock same PFN + UNEVICTABLE 0->1 : %s\n",
	       resident_mlock_transition ? "yes" : "NO");

	printf("resident munlock same PFN + UNEVICTABLE 1->0: %s\n",
	       resident_munlock_transition ? "yes" : "NO");

	printf("MLOCK_ONFAULT leaves untouched page absent  : %s\n",
	       onfault_no_materialization ? "yes" : "NO");

	printf("onfault first Store creates UNEVICTABLE page: %s\n",
	       onfault_locked_after_store ? "yes" : "NO");

	printf("onfault munlock same PFN + UNEVICTABLE 1->0 : %s\n",
	       onfault_munlock_transition ? "yes" : "NO");

	printf("KPF_LRU remains set while mlocked           : %s\n",
	       lru_survives_mlock ? "yes" : "NO");

	printf("first onfault Store minor fault             : %ld\n",
	       store_minflt);

	printf("\nfinal values:\n");
	printf("control              : 0x%08x\n", *control);
	printf("mlock target         : 0x%08x\n", *lock_target);
	printf("onfault target       : 0x%08x\n", *onfault_target);

	munmap((void *)mapping, TEST_PAGES * page_size);

	close(kpageflags_fd);
	close(kpagecount_fd);
	close(pagemap_fd);

	return EXIT_SUCCESS;
}
