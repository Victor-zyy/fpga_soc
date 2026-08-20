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

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_FILE_OR_SHANON (1ULL << 61)
#define PM_PRESENT        (1ULL << 63)

enum {
	KPF_LRU = 5,
	KPF_BUDDY = 10,
	KPF_MMAP = 11,
	KPF_ANON = 12,
	KPF_SWAPBACKED = 14,
	KPF_ZERO_PAGE = 24
};

struct usage_snapshot {
	long minflt;
	long majflt;
};

struct page_snapshot {
	uint64_t raw;
	uint64_t pfn;

	int present;
	int exclusive;
	int file_or_shared_anon;

	int mincore_rc;
	int mincore_errno;
	int resident;

	int maps_present;

	int physical_valid;
	uint64_t count;
	uint64_t flags;
};

struct pfn_snapshot {
	uint64_t pfn;
	uint64_t count;
	uint64_t flags;
};

static volatile uint64_t sink;

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

	ssize_t result = pread(fd,
			       &value,
			       sizeof(value),
			       (off_t) (index * sizeof(value)));

	if (result != (ssize_t) sizeof(value)) {
		if (result < 0)
			perror(what);
		else
			fprintf(stderr, "%s: short read %zd\n", what, result);

		exit(EXIT_FAILURE);
	}

	return value;
}

static int maps_contains(const void *address)
{
	uintptr_t target = (uintptr_t) address;

	FILE *fp = fopen("/proc/self/maps", "r");

	if (fp == NULL)
		die("fopen maps");

	char line[1024];
	int found = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {

		unsigned long start;
		unsigned long end;

		if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
			continue;
		}

		if (target >= (uintptr_t) start && target < (uintptr_t) end) {

			found = 1;
			break;
		}
	}

	fclose(fp);

	return found;
}

static struct page_snapshot snapshot_va(const void *address,
					size_t page_size,
					int pagemap_fd,
					int kpagecount_fd, int kpageflags_fd)
{
	struct page_snapshot s;

	memset(&s, 0, sizeof(s));

	uint64_t vpn = (uint64_t) (uintptr_t) address / page_size;

	s.raw = read_indexed_u64(pagemap_fd, vpn, "pagemap");

	s.pfn = s.raw & PM_PFN_MASK;

	s.present = !!(s.raw & PM_PRESENT);

	s.exclusive = !!(s.raw & PM_EXCLUSIVE);

	s.file_or_shared_anon = !!(s.raw & PM_FILE_OR_SHANON);

	unsigned char vec = 0;

	errno = 0;

	s.mincore_rc = mincore((void *)address, page_size, &vec);

	s.mincore_errno = errno;

	if (s.mincore_rc == 0)
		s.resident = !!(vec & 1);

	s.maps_present = maps_contains(address);

	if (s.present && s.pfn != 0) {

		s.physical_valid = 1;

		s.count = read_indexed_u64(kpagecount_fd, s.pfn, "kpagecount");

		s.flags = read_indexed_u64(kpageflags_fd, s.pfn, "kpageflags");
	}

	return s;
}

static struct pfn_snapshot snapshot_old_pfn(uint64_t pfn,
					    int kpagecount_fd,
					    int kpageflags_fd)
{
	struct pfn_snapshot s = {
		.pfn = pfn,

		.count = read_indexed_u64(kpagecount_fd,
					  pfn,
					  "old kpagecount"),

		.flags = read_indexed_u64(kpageflags_fd,
					  pfn,
					  "old kpageflags")
	};

	return s;
}

static void print_flags(uint64_t flags)
{
	printf("  LRU                : %d\n", flag_set(flags, KPF_LRU));

	printf("  BUDDY              : %d\n", flag_set(flags, KPF_BUDDY));

	printf("  MMAP               : %d\n", flag_set(flags, KPF_MMAP));

	printf("  ANON               : %d\n", flag_set(flags, KPF_ANON));

	printf("  SWAPBACKED         : %d\n", flag_set(flags, KPF_SWAPBACKED));

	printf("  ZERO_PAGE          : %d\n", flag_set(flags, KPF_ZERO_PAGE));
}

static void print_va(const char *name, const struct page_snapshot *s)
{
	printf("\n========== %s ==========\n", name);

	printf("maps contains VA     : %s\n", s->maps_present ? "yes" : "no");

	printf("pagemap raw          : 0x%016" PRIx64 "\n", s->raw);

	printf("present              : %d\n", s->present);

	printf("exclusive            : %d\n", s->exclusive);

	printf("file/shared-anon     : %d\n", s->file_or_shared_anon);

	printf("PFN                  : 0x%011" PRIx64 "\n", s->pfn);

	printf("mincore rc           : %d\n", s->mincore_rc);

	if (s->mincore_rc != 0) {
		printf("mincore errno        : %d (%s)\n",
		       s->mincore_errno, strerror(s->mincore_errno));
	} else {
		printf("resident             : %d\n", s->resident);
	}

	if (!s->physical_valid) {
		printf("kpagecount           : N/A\n");
		printf("kpageflags           : N/A\n");
		return;
	}

	printf("kpagecount           : %" PRIu64 "\n", s->count);

	printf("kpageflags raw       : 0x%016" PRIx64 "\n", s->flags);

	print_flags(s->flags);
}

static void print_old_pfn(const char *name, const struct pfn_snapshot *s)
{
	printf("\n========== %s ==========\n", name);

	printf("historical PFN       : 0x%011" PRIx64 "\n", s->pfn);

	printf("current kpagecount   : %" PRIu64 "\n", s->count);

	printf("current kpageflags   : 0x%016" PRIx64 "\n", s->flags);

	print_flags(s->flags);

	printf("NOTE                 : this describes the "
	       "PFN slot NOW, not necessarily the old page\n");
}

static volatile uint32_t *map_guarded_page(size_t page_size,
					   void **reservation_out)
{
	unsigned char *reservation = mmap(NULL,
					  3 * page_size,
					  PROT_NONE,
					  MAP_PRIVATE | MAP_ANONYMOUS,
					  -1,
					  0);

	if (reservation == MAP_FAILED)
		die("mmap reservation");

	void *middle = reservation + page_size;

	void *mapped = mmap(middle,
			    page_size,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
			    -1,
			    0);

	if (mapped == MAP_FAILED)
		die("mmap middle");

	*reservation_out = reservation;

	return (volatile uint32_t *)mapped;
}

static volatile uint32_t *remap_middle(void *reservation, size_t page_size)
{
	void *target = (unsigned char *)reservation + page_size;

	void *mapped = mmap(target,
			    page_size,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
			    -1,
			    0);

	if (mapped == MAP_FAILED)
		die("remap middle");

	return (volatile uint32_t *)mapped;
}

static void print_fault_delta(const char *name,
			      struct usage_snapshot before,
			      struct usage_snapshot after)
{
	printf("\n========== %s ==========\n", name);

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

	int kpagecount_fd = open("/proc/kpagecount",
				 O_RDONLY | O_CLOEXEC);

	if (kpagecount_fd < 0)
		die("open kpagecount");

	int kpageflags_fd = open("/proc/kpageflags",
				 O_RDONLY | O_CLOEXEC);

	if (kpageflags_fd < 0)
		die("open kpageflags");

	printf("PID                  : %ld\n", (long)getpid());

	printf("page size            : %zu\n", page_size);

	/*
	 * =========================================================
	 * CASE A
	 * MADV_DONTNEED
	 * =========================================================
	 */

	void *dontneed_reservation = NULL;

	volatile uint32_t *dontneed_page = map_guarded_page(page_size,
							    &dontneed_reservation);

	printf("\n##################################################\n"
	       "# CASE A: MADV_DONTNEED\n"
	       "##################################################\n");

	printf("target VA            : %p\n", (const void *)dontneed_page);

	*dontneed_page = 0xa1a1a1a1U;

	struct page_snapshot a_before = snapshot_va((const void *)dontneed_page,
						    page_size,
						    pagemap_fd,
						    kpagecount_fd,
						    kpageflags_fd);

	print_va("A0. private anon before DONTNEED", &a_before);

	uint64_t a_old_pfn = a_before.pfn;

	if (madvise((void *)dontneed_page, page_size, MADV_DONTNEED) != 0) {
		die("madvise DONTNEED");
	}

	/*
	 * Snapshot the VA immediately after the zap.
	 */
	struct page_snapshot a_dropped =
	    snapshot_va((const void *)dontneed_page,
			page_size,
			pagemap_fd,
			kpagecount_fd,
			kpageflags_fd);

	print_va("A1. VA immediately after DONTNEED", &a_dropped);

	/*
	 * The old PFN number is now only historical information.
	 */
	struct pfn_snapshot a_old_after = snapshot_old_pfn(a_old_pfn,
							   kpagecount_fd,
							   kpageflags_fd);

	print_old_pfn("A2. historical PFN after DONTNEED", &a_old_after);

	/*
	 * First Load after DONTNEED.
	 */
	struct usage_snapshot a_read_before = usage_now();

	uint32_t a_read_value = *dontneed_page;

	struct usage_snapshot a_read_after = usage_now();

	sink += a_read_value;

	print_fault_delta("A3. first Load after DONTNEED",
			  a_read_before, a_read_after);

	printf("read value           : 0x%08x\n", a_read_value);

	struct page_snapshot a_zero = snapshot_va((const void *)dontneed_page,
						  page_size,
						  pagemap_fd,
						  kpagecount_fd,
						  kpageflags_fd);

	print_va("A4. after first Load", &a_zero);

	/*
	 * First Store after DONTNEED.
	 */
	struct usage_snapshot a_write_before = usage_now();

	*dontneed_page = 0xa2a2a2a2U;

	struct usage_snapshot a_write_after = usage_now();

	print_fault_delta("A5. first Store after DONTNEED",
			  a_write_before, a_write_after);

	struct page_snapshot a_private_again =
	    snapshot_va((const void *)dontneed_page,
			page_size,
			pagemap_fd,
			kpagecount_fd,
			kpageflags_fd);

	print_va("A6. private anon after refault Store", &a_private_again);

	printf("\nA old PFN            : 0x%011" PRIx64 "\n", a_old_pfn);

	printf("A new PFN            : 0x%011"
	       PRIx64 "\n", a_private_again.pfn);

	printf("numeric PFN reused   : %s\n",
	       a_old_pfn == a_private_again.pfn ? "yes" : "no");

	printf("final value          : 0x%08x\n", *dontneed_page);

	/*
	 * =========================================================
	 * CASE B
	 * munmap
	 * =========================================================
	 */

	void *munmap_reservation = NULL;

	volatile uint32_t *munmap_page = map_guarded_page(page_size,
							  &munmap_reservation);

	printf("\n##################################################\n"
	       "# CASE B: munmap\n"
	       "##################################################\n");

	printf("target VA            : %p\n", (const void *)munmap_page);

	*munmap_page = 0xb1b1b1b1U;

	struct page_snapshot b_before = snapshot_va((const void *)munmap_page,
						    page_size,
						    pagemap_fd,
						    kpagecount_fd,
						    kpageflags_fd);

	print_va("B0. private anon before munmap", &b_before);

	uint64_t b_old_pfn = b_before.pfn;

	void *munmap_target = (void *)munmap_page;

	if (munmap(munmap_target, page_size) != 0) {
		die("munmap middle page");
	}

	struct page_snapshot b_unmapped = snapshot_va(munmap_target,
						      page_size,
						      pagemap_fd,
						      kpagecount_fd,
						      kpageflags_fd);

	print_va("B1. same VA immediately after munmap", &b_unmapped);

	struct pfn_snapshot b_old_after = snapshot_old_pfn(b_old_pfn,
							   kpagecount_fd,
							   kpageflags_fd);

	print_old_pfn("B2. historical PFN after munmap", &b_old_after);

	/*
	 * Recreate a completely new VMA at exactly the same virtual
	 * address.  This demonstrates that "same VA" does not imply
	 * continuity of the old mapping.
	 */
	volatile uint32_t *remapped = remap_middle(munmap_reservation,
						   page_size);

	printf("\nremapped VA          : %p\n", (const void *)remapped);

	struct page_snapshot b_new_vma = snapshot_va((const void *)remapped,
						     page_size,
						     pagemap_fd,
						     kpagecount_fd,
						     kpageflags_fd);

	print_va("B3. new untouched VMA at same VA", &b_new_vma);

	/*
	 * First Load in the newly-created VMA.
	 */
	struct usage_snapshot b_read_before = usage_now();

	uint32_t b_read_value = *remapped;

	struct usage_snapshot b_read_after = usage_now();

	sink += b_read_value;

	print_fault_delta("B4. first Load in new VMA",
			  b_read_before, b_read_after);

	printf("read value           : 0x%08x\n", b_read_value);

	struct page_snapshot b_zero = snapshot_va((const void *)remapped,
						  page_size,
						  pagemap_fd,
						  kpagecount_fd,
						  kpageflags_fd);

	print_va("B5. new VMA after first Load", &b_zero);

	/*
	 * First Store in the new VMA.
	 */
	struct usage_snapshot b_write_before = usage_now();

	*remapped = 0xb2b2b2b2U;

	struct usage_snapshot b_write_after = usage_now();

	print_fault_delta("B6. first Store in new VMA",
			  b_write_before, b_write_after);

	struct page_snapshot b_private_again =
	    snapshot_va((const void *)remapped,
			page_size,
			pagemap_fd,
			kpagecount_fd,
			kpageflags_fd);

	print_va("B7. new private anon page", &b_private_again);

	printf("\nB historical PFN     : 0x%011" PRIx64 "\n", b_old_pfn);

	printf("B new PFN            : 0x%011"
	       PRIx64 "\n", b_private_again.pfn);

	printf("numeric PFN reused   : %s\n",
	       b_old_pfn == b_private_again.pfn ? "yes" : "no");

	printf("final value          : 0x%08x\n", *remapped);

	/*
	 * =========================================================
	 * Semantic summary
	 * =========================================================
	 */

	int a_drop_keeps_vma =
	    a_dropped.maps_present &&
	    !a_dropped.present &&
	    a_dropped.mincore_rc == 0 && !a_dropped.resident;

	int a_read_zero =
	    a_read_value == 0 &&
	    a_zero.present && a_zero.physical_valid && flag_set(a_zero.flags,
								KPF_ZERO_PAGE);

	int a_write_private =
	    a_private_again.present &&
	    a_private_again.exclusive && flag_set(a_private_again.flags,
						  KPF_ANON) &&
	    *dontneed_page == 0xa2a2a2a2U;

	int b_unmap_removes_vma =
	    !b_unmapped.maps_present &&
	    !b_unmapped.present &&
	    b_unmapped.mincore_rc != 0 && b_unmapped.mincore_errno == ENOMEM;

	int b_remap_absent_page =
	    b_new_vma.maps_present &&
	    !b_new_vma.present &&
	    b_new_vma.mincore_rc == 0 && !b_new_vma.resident;

	int b_read_zero_ok =
	    b_read_value == 0 &&
	    b_zero.present && b_zero.physical_valid && flag_set(b_zero.flags,
								KPF_ZERO_PAGE);

	int b_write_private =
	    b_private_again.present &&
	    b_private_again.exclusive && flag_set(b_private_again.flags,
						  KPF_ANON) &&
	    *remapped == 0xb2b2b2b2U;

	printf("\n========== final semantic summary ==========\n");

	printf("DONTNEED keeps VMA but removes resident PTE : %s\n",
	       a_drop_keeps_vma ? "yes" : "NO");

	printf("DONTNEED first Load returns zero page       : %s\n",
	       a_read_zero ? "yes" : "NO");

	printf("DONTNEED first Store creates private anon   : %s\n",
	       a_write_private ? "yes" : "NO");

	printf("munmap removes VMA + mincore gives ENOMEM   : %s\n",
	       b_unmap_removes_vma ? "yes" : "NO");

	printf("same VA remap starts with absent PTE        : %s\n",
	       b_remap_absent_page ? "yes" : "NO");

	printf("remapped first Load returns zero page       : %s\n",
	       b_read_zero_ok ? "yes" : "NO");

	printf("remapped first Store creates private anon   : %s\n",
	       b_write_private ? "yes" : "NO");

	printf("\nNOTE: old PFN count/flags are observational only;\n"
	       "      once the VA->PFN mapping disappears, the old PFN\n"
	       "      number no longer identifies the former page object.\n");

	printf("\nsink                 : %" PRIu64 "\n", sink);

	/*
	 * Cleanup complete guarded regions.
	 */
	munmap(dontneed_reservation, 3 * page_size);

	munmap(munmap_reservation, 3 * page_size);

	close(kpageflags_fd);
	close(kpagecount_fd);
	close(pagemap_fd);

	return EXIT_SUCCESS;
}
